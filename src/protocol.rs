use serde::{Deserialize, Serialize};
use std::{
    net::{SocketAddr, SocketAddrV6},
    time::Duration,
};
use tokio::{net::UdpSocket, select, time::sleep_until};
use tracing::{debug, info, instrument};

use crate::{
    bridge, map_debug, map_info,
    network::{self, InetTraversal},
    utils, Config, IoResult, PeeringProtocol, SilentResult, State,
};

pub const JUMPER_PREFIX: &[u8; 4] = b"jmpr";
pub const PROTOCOL_VERSION: u8 = 4;

#[derive(Serialize, Deserialize)]
pub struct Header {
    pub version: u8,
    /// Some random number. Used as an id in traversal messages and as a conversation id in KCP.
    pub rand: u32,
    /// Some random number. Used for authenticating traversal messages.
    pub secret_rand: u32,
    /// Protocols connecting bridge the routers.
    /// Note that quic and tls differentiate client and server sides.
    pub supported_protocols: Vec<PeeringProtocol>,
    pub server_available: Vec<PeeringProtocol>,
    /// Candidate external addresses. Only one per ipv4/6 is currently supported.
    pub candidates: Vec<SocketAddr>,
    pub yggdrasil_dpi: bool,
}

/// Try to negotiate a traversal session. Socket must already be connected.
#[instrument(parent = None, name = "Session ", skip_all, fields(peer = %peer_addr))]
pub async fn try_session(
    config: Config,
    state: State,
    socket: UdpSocket,
    peer_addr: SocketAddrV6,
) -> SilentResult<()> {
    let (supported_protocols, server_available) = {
        let lock = state.router.read().await;
        (
            lock.supported_protocols.clone(),
            lock.server_available.clone(),
        )
    };

    let mappings = state.watch_external.borrow().clone();

    let self_header = Header {
        version: PROTOCOL_VERSION,
        rand: rand::random(),
        secret_rand: rand::random(),
        supported_protocols,
        server_available,
        candidates: mappings.iter().map(|m| m.external).collect(),
        yggdrasil_dpi: config.yggdrasil_dpi,
    };

    let remote_header = utils::timeout(
        Duration::from_secs(10),
        exchange_headers(&socket, &self_header),
    )
    .await
    .map_err(map_info!("Failed to exchange headers"))?;

    if remote_header.version != PROTOCOL_VERSION {
        info!(
            "Incompatible protocol version: {} (we are {})",
            remote_header.version, PROTOCOL_VERSION,
        );
        return Err(());
    };

    if self_header.rand == remote_header.rand
        || self_header.secret_rand == remote_header.secret_rand
    {
        info!("You're lucky");
        return Ok(());
    }

    let session_id = {
        let mut arr = [self_header.rand, remote_header.rand];
        arr.sort();
        ((arr[1] as u64) << 32) | (arr[0] as u64)
    };

    let shared_secret = {
        let mut arr = [self_header.secret_rand, remote_header.secret_rand];
        arr.sort();
        format!("{:08x}{:08x}", arr[0], arr[1])
    };

    let filter_cand = |h: &Header, is_ipv4| {
        h.candidates
            .iter()
            .find(|c| c.is_ipv4() == is_ipv4)
            .cloned()
    };
    let cand =
        |is_ipv4| filter_cand(&self_header, is_ipv4).zip(filter_cand(&remote_header, is_ipv4));

    let Some((self_cand, remote_cand)) = cand(true).or_else(|| cand(false)) else {
        debug!("No common address ipv4/ipv6 address with remote");
        return Err(());
    };

    let Some(local) = mappings
        .iter()
        .find(|m| m.external == self_cand)
        .map(|m| m.local)
    else {
        info!("Local candidate no longer available");
        return Err(());
    };

    let params = network::TraversalParams {
        retry_count: config.nat_traversal_udp_retry_count,
        cycle: config.nat_traversal_udp_cycle,
    };
    let inet = InetTraversal {
        session_id,
        shared_secret,
    };
    let inet_sock = network::traverse_udp(&state, &params, &local, &remote_cand, Some(&inet))
        .await
        .map_err(map_debug!("NAT traversal failed"))?
        .map_err(map_debug!("NAT traversal unsuccessful"))?;

    let yggdrasil_dpi = self_header.yggdrasil_dpi && remote_header.yggdrasil_dpi;

    let direction = if yggdrasil_dpi {
        // Prioritize tcp if yggdrasil_dpi enabled
        bridge::protocol_supported(&self_header, &remote_header, PeeringProtocol::Tcp)
    } else {
        bridge::peering_direction(&self_header, &remote_header)
    };

    let Some((protocol, connection_mode)) = direction else {
        info!("No common protocols");
        return Err(());
    };

    let params = bridge::BridgeParams {
        protocol,
        connection_mode,
        peer_addr: remote_cand,
        peer_conv: 1.min(self_header.rand ^ remote_header.rand), // easily fakable, but we just need something on both sides
        yggdrasil_dpi,
        monitor_address: *peer_addr.ip(),
    };

    bridge::start_bridge(config, state, inet_sock, params).await
}

/// Classic stop-and-wait ARQ without a packet count. Timeout should be provided externally.
async fn exchange_headers(socket: &UdpSocket, header: &Header) -> IoResult<Header> {
    let rto = Duration::from_millis(400);

    let mut ack = Vec::new();
    ack.extend(JUMPER_PREFIX);
    ack.extend(&[0, 0]);

    let mut header_buf = ack.clone();
    serde_json::to_writer(&mut header_buf, header).expect("Can't serialize header");

    let mut remote_header = None;
    let mut got_ack = false;

    let mut buf = Box::new([0u8; 1024]);

    let mut next_rto = tokio::time::Instant::now().checked_add(rto).unwrap();

    debug!("Sending header");

    // We shouldn't get any errors at this stage
    socket.send(&header_buf).await?;

    loop {
        let res = select! {
            res = socket.recv(&mut buf[..]) => res,
            _ = sleep_until(next_rto), if !got_ack => {
                debug!("Sending header");
                socket.send(&header_buf).await?;
                next_rto = tokio::time::Instant::now().checked_add(rto).unwrap();
                continue;
            },
        };
        let buf = &buf[..res?];
        debug!("Recv: {:?}", String::from_utf8_lossy(buf));

        if !buf.starts_with(&ack) {
            debug!("Receipt doesn't look like a header");
            continue;
        }

        if buf == ack {
            got_ack = true;
        } else {
            remote_header = Some(serde_json::from_slice::<Header>(&buf[ack.len()..])?);
            socket.send(&ack).await?;
        }

        if got_ack {
            if let Some(remote_header) = remote_header {
                return Ok(remote_header);
            }
        }
    }
}
