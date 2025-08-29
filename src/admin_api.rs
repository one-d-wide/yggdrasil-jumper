use std::{net::Ipv6Addr, str::FromStr, time::Duration};
use tokio::{net::TcpStream, sync::watch, time::sleep};
use tracing::{info, instrument, warn};
use yggdrasilctl::{Endpoint, PeerEntry, RouterVersion, SessionEntry};

use crate::{admin_api, bridge::PeeringProtocol, map_error, utils, Config, SilentResult, State};

pub struct RouterState {
    pub supported_protocols: Vec<PeeringProtocol>,
    pub server_available: Vec<PeeringProtocol>,
    pub version: RouterVersion,
    pub address: Ipv6Addr,
    pub admin_api: Endpoint<Box<dyn utils::RwStream>>,
}

async fn connect_endpoint(
    config: &Config,
    uri: &str,
    socket: Box<dyn utils::RwStream>,
) -> SilentResult<RouterState> {
    info!("Connected to {uri}");
    let mut endpoint = Endpoint::attach(socket).await;

    // Check router info
    let version = endpoint.get_version();
    let info = endpoint
        .get_self()
        .await
        .map_err(map_error!("Failed to query admin api response"))?
        .map_err(map_error!("Command 'getself' failed"))?;

    // If router version is lower then v0.4.5
    if matches!(version, RouterVersion::__v0_4_4) && config.yggdrasil_listen.is_empty() {
        warn!("Direct bridges can't be established with the router at {uri}");
        warn!("Routers prior to v0.4.5 (Oct 2022) don't support addpeer/removepeer commands");
        warn!("Hint: Specify `yggdrasil_addresses` in the config file or update your router");
    }

    // If router version is lower then v0.5.0 and quic protocol is specified
    if config
        .yggdrasil_protocols
        .iter()
        .any(|p| *p == PeeringProtocol::Quic)
        && matches!(
            version,
            RouterVersion::__v0_4_4 | RouterVersion::v0_4_5__v0_4_7
        )
    {
        warn!("Transport protocol Quic is not supported by the router at {uri}");
    }

    // Report if any enabled client-server peering protocol doesn't have `listen` peer listed
    for protocol in config
        .yggdrasil_protocols
        .iter()
        .filter(|p| **p != PeeringProtocol::Tcp)
    {
        if config
            .yggdrasil_listen
            .iter()
            .filter_map(|a| {
                a.split_once("://")
                    .and_then(|(scheme, _)| PeeringProtocol::from_str(scheme).ok())
            })
            .all(|p| p != *protocol)
        {
            warn!("Transport protocol {protocol:?} is client-server only and it is unable to create peering");
            warn!("If both peering nodes have no appropriate `yggdrasil_listen` URI set in the config");
        }
    }

    // Select available router protocols, so we don't have to recompute it later
    let enabled_protocols: Vec<_> = config
        .yggdrasil_protocols
        .iter()
        .cloned()
        .filter(|prot| prot.is_supported_by_router(&version))
        .collect();
    let server_available: Vec<_> = enabled_protocols
        .iter()
        .cloned()
        .filter(|prot| {
            config
                .yggdrasil_listen
                .iter()
                .any(|a| a.split("://").next() == Some(prot.scheme()))
        })
        .collect();

    Ok(RouterState {
        supported_protocols: enabled_protocols,
        server_available,
        version,
        address: info.address,
        admin_api: endpoint,
    })
}

#[instrument(parent = None, name = "Admin API", skip_all)]
pub async fn connect(config: &Config, silent: bool) -> SilentResult<RouterState> {
    use std::io::{Error, ErrorKind};
    let error = |t| Error::new(ErrorKind::InvalidInput, t);

    let mut errs: Vec<(_, _)> = Vec::new();

    for uri in &config.yggdrasil_admin_listen {
        let Some((protocol, address)) = uri.split_once("://") else {
            warn!("Can't parse yggdrasil admin socket address {uri}");
            continue;
        };
        let socket = match protocol {
            #[cfg(unix)]
            "unix" => tokio::net::UnixStream::connect(address)
                .await
                .map(|s| -> Box<dyn utils::RwStream> { Box::new(s) }),
            #[cfg(not(unix))]
            "unix" => Err(error(format!(
                "Unix sockets are not supported on this platform"
            ))),
            "tcp" => TcpStream::connect(address)
                .await
                .map(|s| -> Box<dyn utils::RwStream> { Box::new(s) }),
            _ => Err(error(format!("Invalid protocol {protocol:?}"))),
        };
        let socket = match socket {
            Err(err) => {
                errs.push((uri, err));
                continue;
            }
            Ok(socket) => socket,
        };

        return connect_endpoint(config, uri, socket).await;
    }

    if !silent {
        for (uri, err) in errs {
            warn!("Failed to connect to {uri}: {err}");
        }
    }
    Err(())
}

pub async fn reconnect(config: &Config, reconnect: bool) -> SilentResult<RouterState> {
    let mut silent = false;
    loop {
        if let Ok(router) = connect(config, silent).await {
            return Ok(router);
        }

        if !reconnect {
            return Err(());
        }

        silent = true;
        sleep(Duration::from_secs(5)).await;
    }
}

#[instrument(parent = None, name = "Admin API watcher", skip_all)]
pub async fn monitor(
    config: Config,
    state: State,
    watch_sessions: watch::Sender<Vec<SessionEntry>>,
    watch_peers: watch::Sender<Vec<PeerEntry>>,
    reconnect: bool,
) -> SilentResult<()> {
    let err_io = map_error!("Failed to query admin api");
    let err_api = map_error!("Admin api returned error");
    fn err_silent<T>(_: T) {}

    loop {
        loop {
            {
                let endpoint = &mut state.router.write().await.admin_api;

                let Ok(sessions) = endpoint.get_sessions().await.map_err(err_io) else {
                    break;
                };
                watch_sessions.send(sessions.map_err(err_api)?).unwrap();

                let Ok(peers) = endpoint.get_peers().await.map_err(err_io) else {
                    break;
                };
                watch_peers.send(peers.map_err(err_api)?).unwrap();
            }

            sleep(config.yggdrasilctl_query_delay).await;
        }

        if !reconnect {
            return Err(());
        }

        if !watch_sessions.borrow().is_empty() {
            watch_sessions.send(Vec::new()).map_err(err_silent)?;
        }

        if !watch_peers.borrow().is_empty() {
            watch_peers.send(Vec::new()).map_err(err_silent)?;
        }

        *state.router.write().await = admin_api::reconnect(&config, reconnect).await?;
    }
}
