use bytecodec::{Decode, EncodeExt};
use rand::seq::SliceRandom;
use std::{net::SocketAddr, time::Instant};
use stun_codec::{
    rfc5389::{
        attributes::{self},
        methods::BINDING,
        Attribute,
    },
    Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId,
};
use tokio::{
    join,
    sync::watch,
    time::{sleep, sleep_until},
};
use tracing::{debug, error, instrument, warn};

use crate::{
    map_info, map_warn, stun,
    utils::{self},
    Config, SessionStage, SilentResult, State,
};

#[derive(Debug, Clone, PartialEq)]
pub struct Mapping {
    pub external: SocketAddr,
    pub local: SocketAddr,
}

/// Monitor external internet addresses
#[instrument(parent = None, name = "External address watcher", skip_all)]
pub async fn monitor(
    config: Config,
    state: State,
    watch_external: watch::Sender<Vec<Mapping>>,
    mut external_required: watch::Receiver<Instant>,
    locals: Vec<SocketAddr>,
) -> SilentResult<()> {
    struct Server<'a> {
        server: &'a str,
        available: bool,
    }
    let mut servers: Vec<Server> = config
        .stun_servers
        .iter()
        .map(|s| Server {
            server: s.as_str(),
            available: true,
        })
        .collect();

    if locals.is_empty() {
        error!("Couldn't find any sockets");
        return Err(());
    }

    loop {
        let mut external = Vec::<Mapping>::new();

        for local in &locals {
            // Reset protocol status for every known server if they all were rendered inaccessible
            if servers.iter().all(|s| !s.available) {
                for server in servers.iter_mut() {
                    server.available = true;
                }
            }

            if config.stun_randomize {
                servers.shuffle(&mut rand::rng());
            }

            for server in servers.iter_mut().filter(|s| s.available) {
                match lookup(&config, local, server.server).await {
                    Ok(address) => {
                        external.push(address);
                        break;
                    }
                    Err(()) => server.available = false,
                }
            }
        }

        // Update watchers if external addresses changed
        if watch_external.borrow().as_slice() != external.as_slice() {
            watch_external.send(external).unwrap();
        }

        // Check is external address unresolved or update required
        let required = watch_external.borrow().is_empty()
            || external_required.borrow_and_update().elapsed()
                < config.resolve_external_address_delay;

        if required {
            // Delay next request
            sleep(config.resolve_external_address_delay).await;
        } else {
            debug!("No update required, suspending");
            loop {
                // Wait until any new session is started
                let (err, _) = join!(
                    external_required.changed(),
                    sleep(config.resolve_external_address_delay)
                );
                if err.is_err() {
                    return Err(());
                }

                // Check if any bridge is running
                if !state
                    .active_sessions
                    .read()
                    .await
                    .iter()
                    .any(|(_, v)| SessionStage::is_bridge(v))
                {
                    break;
                }
            }
        }
    }
}

/// Lookup external internet address
#[instrument(parent = None, name = "Lookup ", skip_all, fields(local = %local, server = %server))]
pub async fn lookup(config: &Config, local: &SocketAddr, server: &str) -> SilentResult<Mapping> {
    // Create server connection
    let mut socket: tokio::net::UdpSocket =
        utils::create_udp_socket_in_domain(local, local.port())?;
    socket
        .connect(server)
        .await
        .map_err(map_info!("Failed to connect to {server}"))?;

    // Perform stun request
    let external_address = stun::lookup_external_address(config, &mut socket).await?;

    debug!("Resolved: {}", external_address);

    Ok(Mapping {
        local: *local,
        external: external_address,
    })
}

const STUN_BUF_SIZE: usize = 256;

#[instrument(name = " STUN protocol", skip_all)]
pub async fn lookup_external_address(
    config: &Config,
    socket: &mut impl utils::RwSocket,
) -> SilentResult<SocketAddr> {
    let request = MessageEncoder::<Attribute>::new()
        .encode_into_bytes(Message::new(
            MessageClass::Request,
            BINDING,
            TransactionId::new([0; 12]),
        ))
        .expect("Failed to encode STUN request");

    let timeout = if socket.is_unreliable() {
        utils::Timeout::new(
            config.stun_udp_response_timeout,
            config.stun_udp_retry_count,
            config.stun_udp_exponential_timeout,
        )
    } else {
        utils::Timeout::new_linear(config.stun_tcp_response_timeout, 1)
    };

    let mut is_idle = true; // Whether we not got a reply
    let mut decoder = MessageDecoder::<Attribute>::new();
    'resend: for timeout in timeout {
        let timeout = tokio::time::Instant::now().checked_add(timeout).unwrap();

        tokio::select! {
            res = socket.write_all(&request[..]) => res,
            _ = sleep_until(timeout) => continue,
        }
        .map_err(map_warn!("Failed to send request"))?;

        let mut buf = Box::new([0u8; STUN_BUF_SIZE]);
        let mut left = 0usize;
        loop {
            let mut read = tokio::select! {
                res = socket.read(&mut buf[left..]) => res,
                _ = sleep_until(timeout) => continue 'resend,
            }
            .map_err(map_warn!("Failed to receive from socket"))?;
            is_idle = false;
            read += left;

            let consumed = decoder
                .decode(&buf[..read], bytecodec::Eos::new(false))
                .map_err(map_warn!("Failed to decode server response"))?;

            buf.copy_within(consumed..read, 0);
            left = read - consumed;

            if decoder.is_idle() {
                break 'resend;
            }
        }
    }

    if is_idle {
        warn!("Request timed out");
        return Err(());
    }

    let decoded = decoder
        .finish_decoding()
        .map_err(map_warn!("Failed to decode server response"))?
        .map_err(|err| warn!("Failed to decode server response {}", err.error()))?;

    let attrs = decoded;
    if let Some(attr) = attrs.get_attribute::<attributes::XorMappedAddress>() {
        return Ok(attr.address());
    }
    if let Some(attr) = attrs.get_attribute::<attributes::XorMappedAddress2>() {
        return Ok(attr.address());
    }
    if let Some(attr) = attrs.get_attribute::<attributes::MappedAddress>() {
        return Ok(attr.address());
    }

    warn!(
        "Unable to find address attribute in server response: {:#?}",
        attrs
    );
    Err(())
}
