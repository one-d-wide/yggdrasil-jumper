use serde::{Deserialize, Serialize};

use std::{
    net::{Ipv6Addr, SocketAddr},
    str::FromStr,
};
use strum_macros::{EnumString, IntoStaticStr};
use tokio::{
    net::{TcpStream, UdpSocket},
    select, spawn,
    time::Instant,
};
use tracing::{debug, info, instrument, warn};
use yggdrasilctl::RouterVersion;

use crate::{
    map_debug, map_warn, protocol, proxy_tcp, proxy_udp, utils, Config, SessionStage, SilentResult,
    State,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionMode {
    Any,
    ToEndpoint,
    AsEndpoint,
}

impl ConnectionMode {
    pub fn to_endpoint(self) -> bool {
        matches!(self, Self::Any | Self::ToEndpoint)
    }
    pub fn as_endpoint(self) -> bool {
        matches!(self, Self::Any | Self::AsEndpoint)
    }
}

#[derive(Debug)]
pub enum RouterStream {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(EnumString, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum PeeringProtocol {
    Tcp,
    Tls,
    Quic,
}

impl PeeringProtocol {
    pub fn is_supported_by_router(&self, version: &RouterVersion) -> bool {
        match self {
            Self::Tcp | Self::Tls => true,
            Self::Quic => !matches!(
                version,
                RouterVersion::__v0_4_4 | RouterVersion::v0_4_5__v0_4_7
            ),
        }
    }

    pub fn scheme(&self) -> &'static str {
        self.into()
    }
}

pub fn peering_direction(
    self_header: &protocol::Header,
    remote_header: &protocol::Header,
) -> Option<(PeeringProtocol, ConnectionMode)> {
    // Prioritize Quic
    if let Some(res) = protocol_supported(self_header, remote_header, PeeringProtocol::Quic) {
        return Some(res);
    }

    // Then Tcp
    if let Some(res) = protocol_supported(self_header, remote_header, PeeringProtocol::Tcp) {
        return Some(res);
    }

    // And finally Tls
    protocol_supported(self_header, remote_header, PeeringProtocol::Tls)
}

pub fn protocol_supported(
    self_header: &protocol::Header,
    remote_header: &protocol::Header,
    prot: PeeringProtocol,
) -> Option<(PeeringProtocol, ConnectionMode)> {
    if !self_header.supported_protocols.contains(&prot)
        || !remote_header.supported_protocols.contains(&prot)
    {
        return None;
    }

    let self_serv = self_header.server_available.contains(&prot);
    let remote_serv = remote_header.server_available.contains(&prot);

    let mode = if self_serv && remote_serv {
        if self_header.rand < remote_header.rand {
            ConnectionMode::ToEndpoint
        } else {
            ConnectionMode::AsEndpoint
        }
    } else if self_serv {
        ConnectionMode::ToEndpoint
    } else if remote_serv {
        ConnectionMode::AsEndpoint
    } else if matches!(prot, PeeringProtocol::Tcp) {
        ConnectionMode::Any
    } else {
        return None;
    };

    Some((prot, mode))
}

pub struct BridgeParams {
    pub protocol: PeeringProtocol,
    pub connection_mode: ConnectionMode,
    pub peer_addr: SocketAddr,
    pub peer_conv: u32,
    pub yggdrasil_dpi: bool,
    pub monitor_address: Ipv6Addr,
}

#[instrument(parent = None, name = "Bridge ", skip_all,
    fields(peer = utils::pretty_ip(params.monitor_address), remote = %params.peer_addr,
            uri = %uri, dpi = ?params.yggdrasil_dpi))]
async fn bridge(
    config: Config,
    state: State,
    peer: UdpSocket,
    ygg: RouterStream,
    uri: String,
    params: BridgeParams,
) -> SilentResult<()> {
    info!("Connected");

    let (mut term_rx, _guard) = match ygg {
        RouterStream::Udp(ygg) => proxy_udp::setup_proxy_udp(&config, &state, ygg, peer).await?,
        RouterStream::Tcp(ygg) => {
            proxy_tcp::setup_proxy_tcp(&config, &state, ygg, peer, &params).await?
        }
    };

    let mut watch_peers = state.watch_peers.clone();
    let mut watch_sessions = state.watch_sessions.clone();
    let mut delay_shutdown = Some(Instant::now());

    // Record the bridge
    let old = state
        .active_sessions
        .write()
        .await
        .insert(params.monitor_address, SessionStage::Bridge);
    if let Some(SessionStage::Bridge) = old {
        // Multiple connections with the same identifiers are not allowed by the OS.
        warn!("Bridge is already exist");
        return Err(());
    }

    // Remove record when bridge is closed
    let _bridge_record_guard = utils::defer_async({
        let state = state.clone();
        async move {
            state
                .active_sessions
                .write()
                .await
                .remove(&params.monitor_address);
        }
    });

    // Wait until bridge is unused
    loop {
        select! {
            _ = term_rx.recv() => {
                info!("Connection broken");
                return Err(());
            }

            // Return if peer is not connected or wrong node is peered
            err = watch_peers.changed() => {
                err.map_err(|_| ())?;
                let peers = watch_peers.borrow();

                if let Some(ref timer) = delay_shutdown {
                   if timer.elapsed() > config.peer_unconnected_check_delay {
                        delay_shutdown = None;
                   }
                }

                // Return if peer is not connected
                if delay_shutdown.is_none()
                    && !peers
                        .iter()
                        .filter(|peer| peer.up)
                        .any(|peer| peer.remote.as_ref() == Some(&uri))
                {
                    info!("Bridge is not connected as peer");
                    return Err(());
                }

                // Return if peer is on unexpected address
                if let Some(connected_address) = peers.iter()
                        .filter(|peer| peer.remote.as_ref() == Some(&uri))
                        .filter_map(|peer| peer.address)
                        .find(|address| address != &params.monitor_address)
                {
                    warn!("Bridge had been connected to the wrong node: {connected_address}");
                    return Err(());
                }
            },

            // Return if session is closed
            err = watch_sessions.changed()  => {
                err.map_err(|_| ())?;
                if ! watch_sessions.borrow().iter().any(|session| session.address == params.monitor_address) {
                    info!("Associated session is closed");
                    return Err(());
                }
            },

            // Return if cancelled
            _ = state.cancellation.cancelled() => return Ok(()),
        }
    }
}

/// Generate yggdrasil peer uri for the bridge
fn peer_uri(protocol: PeeringProtocol, local_addr: &SocketAddr) -> String {
    format!(
        "{}://{}:{}",
        protocol.scheme(),
        match local_addr {
            SocketAddr::V4(_) => "127.0.0.1",
            SocketAddr::V6(_) => "[::1]",
        },
        local_addr.port(),
    )
}

async fn connect_to_peer(
    config: &Config,
    protocol: PeeringProtocol,
    addr: &str,
) -> SilentResult<(RouterStream, String)> {
    let addr = tokio::net::lookup_host(addr)
        .await
        .map_err(map_warn!("Failed lookup {addr}"))?
        .next()
        .ok_or_else(|| warn!("Failed to lookup suitable address for {addr}"))?;

    match protocol {
        PeeringProtocol::Tcp | PeeringProtocol::Tls => {
            let ygg = utils::create_tcp_socket_in_domain(&addr, 0)?;

            let ygg = utils::timeout(config.connect_as_client_timeout, ygg.connect(addr))
                .await
                .map_err(map_warn!(
                    "Failed to connect to router listen socket at {addr}"
                ))?;

            let local_addr = ygg
                .local_addr()
                .map_err(map_warn!("Failed to get socket address"))?;

            Ok((RouterStream::Tcp(ygg), peer_uri(protocol, &local_addr)))
        }
        PeeringProtocol::Quic => {
            let ygg = utils::create_udp_socket_in_domain(&addr, 0)?;

            ygg.connect(addr)
                .await
                .map_err(map_warn!("Failed to connect UDP socket to {addr}"))
                .ok();

            let local_addr = ygg
                .local_addr()
                .map_err(map_warn!("Failed to get socket address"))?;

            Ok((RouterStream::Udp(ygg), peer_uri(protocol, &local_addr)))
        }
    }
}

async fn connect_as_peer(
    config: &Config,
    state: &State,
    protocol: PeeringProtocol,
) -> SilentResult<(RouterStream, String, impl Drop)> {
    match protocol {
        PeeringProtocol::Tcp | PeeringProtocol::Tls => {
            let ygg = utils::create_tcp_socket_ipv4(0)?
                .listen(1)
                .map_err(map_warn!("Failed to create local inbound socket"))?;

            let local_addr = ygg
                .local_addr()
                .map_err(map_warn!("Failed to get socket address"))?;

            // Register socket as a peer
            let uri = peer_uri(protocol, &local_addr);
            let remove_peer_guard = add_peer(state.clone(), uri.clone()).await?;

            // Await incoming connection
            let (ygg, _) = utils::timeout(config.connect_as_client_timeout, ygg.accept())
                .await
                .map_err(map_warn!("Failed to accept yggdrasil connection"))?;

            Ok((RouterStream::Tcp(ygg), uri, remove_peer_guard))
        }
        PeeringProtocol::Quic => {
            let ygg = utils::create_udp_socket_ipv4(0)?;

            let local_addr = ygg
                .local_addr()
                .map_err(map_warn!("Failed to get socket address"))?;

            // Register socket as a peer
            let uri = peer_uri(protocol, &local_addr);
            let remove_peer_guard = add_peer(state.clone(), uri.clone()).await?;

            // Await incoming packets
            let sender = utils::timeout(config.connect_as_client_timeout, ygg.peek_sender())
                .await
                .map_err(map_warn!("Failed to peek yggdrasil connection"))?;

            // Connect socket to the sender of the first received packet
            ygg.connect(sender)
                .await
                .map_err(map_warn!("Failed to connect to yggdrasil socket"))?;

            Ok((RouterStream::Udp(ygg), uri, remove_peer_guard))
        }
    }
}

/// Register peering socket as a server
async fn remove_peer(state: &State, uri: String) -> SilentResult<()> {
    state
        .router
        .write()
        .await
        .admin_api
        .remove_peer(uri, None)
        .await
        .map_err(map_debug!("Failed to query admin api"))?
        .map_err(map_debug!("Failed to remove local socket from peer list"))?;
    Ok(())
}

async fn add_peer(state: State, uri: String) -> SilentResult<impl Drop> {
    state
        .router
        .write()
        .await
        .admin_api
        .add_peer(uri.clone(), None)
        // .add_peer(format!("{uri}?password={shared_secret}"), None) // Only works with both as-client peerings
        .await
        .map_err(map_warn!("Failed to query admin api"))?
        .map_err(map_warn!("Failed to add local socket as peer"))?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    spawn({
        // Make sure we remove the peer before allowing the program to terminate
        let cancellation = state.cancellation.get_active();
        async move {
            if let Some(cancellation) = &cancellation {
                select! {
                    _ = rx => {},
                    _ = cancellation.cancelled() => {},
                }
            }
            remove_peer(&state, uri).await.ok();
        }
    });

    Ok(utils::defer(move || {
        let _ = tx.send(());
    }))
}

#[instrument(parent = None, name = "Starting bridge ", skip_all,
    fields(mode = ?params.connection_mode, peer = utils::pretty_ip(params.monitor_address), remote = %params.peer_addr))]
pub async fn start_bridge(
    config: Config,
    state: State,
    socket: UdpSocket,
    params: BridgeParams,
) -> SilentResult<()> {
    debug!("Started");

    // Try connect to the router listen address directly
    if params.connection_mode.to_endpoint() {
        for url in config.yggdrasil_listen.iter() {
            let Some((scheme, link)) = url.split_once("://") else {
                warn!("Can't find protocol separator :// in {url:?}");
                continue;
            };
            let Ok(scheme) = PeeringProtocol::from_str(scheme) else {
                warn!("Unrecognized scheme {scheme:?} from {url:?}");
                continue;
            };
            let addr = link.split("?").next().unwrap_or(link);

            if scheme != params.protocol {
                debug!("Router peer not suitable: {url:?}");
                continue;
            }

            let Ok((ygg, peering_uri)) = connect_to_peer(&config, params.protocol, addr).await
            else {
                continue;
            };

            return bridge(config, state, socket, ygg, peering_uri, params).await;
        }
    }

    // Fallback. Try connect router to self temporary socket
    if !params.connection_mode.as_endpoint() {
        warn!("Failed to find suitable server socket");
        return Err(());
    }

    let (ygg, peering_uri, _remove_peer_guard) =
        connect_as_peer(&config, &state, params.protocol).await?;

    // Run bridge
    bridge(config, state, socket, ygg, peering_uri, params).await
}
