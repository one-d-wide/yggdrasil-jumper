use super::*;

pub struct RouterState {
    pub version: [u64; 3],
    pub address: Ipv6Addr,
    pub admin_api: Endpoint<utils::RWSocket>,
}

#[instrument(parent = None, name = "Admin API", skip_all)]
pub async fn connect(config: Config) -> Result<RouterState, ()> {
    use std::io::{Error, ErrorKind};
    let error = |t| Error::new(ErrorKind::InvalidInput, t);

    let mut errs: Vec<(_, _)> = Vec::new();

    for uri in &config.yggdrasil_admin_listen {
        if let Some((protocol, address)) = uri.split_once("://") {
            let socket = match protocol {
                #[cfg(unix)]
                "unix" => tokio::net::UnixStream::connect(address)
                    .await
                    .map(|s| -> utils::RWSocket { Box::new(s) }),
                #[cfg(not(unix))]
                "unix" => Err(error(format!(
                    "Unix socket is not supported on this platform"
                ))),
                "tcp" => TcpStream::connect(address)
                    .await
                    .map(|s| -> utils::RWSocket { Box::new(s) }),
                _ => Err(error(format!("Invalid protocol '{protocol}'"))),
            };
            match socket {
                Err(err) => errs.push((uri, err)),
                Ok(socket) => {
                    info!("Connected to {uri}");
                    let mut endpoint = Endpoint::attach(socket).await;

                    // Check router version
                    let info = endpoint
                        .get_self()
                        .await
                        .map_err(map_error!("Failed to query admin api response"))?
                        .map_err(map_error!("Command 'getself' failed"))?;
                    let build_version = info.build_version;
                    let version: Vec<u64> = build_version
                        .as_str()
                        .split(['.', '-'].as_slice())
                        .take(3)
                        .filter_map(|v| v.parse().ok())
                        .collect();

                    let version: [u64; 3] = match version.try_into() {
                        Ok(version) => version,
                        Err(_) => {
                            error!("Failed to parse router version '{build_version}'");
                            continue;
                        }
                    };

                    // If router version is lower then v0.4.5
                    if version[0] == 0
                        && version[1] <= 4
                        && (version[1] < 4 || version[2] < 5)
                        && config.yggdrasil_listen.is_empty()
                    {
                        warn!("Direct bridges can't be connected to the router of version {build_version} at {uri}");
                        warn!("Routers prior to v0.4.5 (Oct 2022) don't support addpeer/removepeer commands");
                        warn!("Help: Specify `yggdrasil_addresses` in the config or update your router");
                    }

                    // If router version is lower then v0.5.0 and quic protocol is specified
                    if config
                        .yggdrasil_protocols
                        .iter()
                        .any(|p| *p == PeeringProtocol::Quic)
                    {
                        if version[0] == 0 && version[1] < 5 {
                            warn!("Transport protocol Quic is not supported by the router of version {build_version} at {uri}");
                        }
                    }

                    // If any client-server peering protocol doesn't have `listen` peer listed
                    for protocol in config
                        .yggdrasil_protocols
                        .iter()
                        .filter(|p| **p != PeeringProtocol::Tcp)
                    {
                        if !config
                            .yggdrasil_listen
                            .iter()
                            .filter_map(|a| {
                                a.split("://")
                                    .next()
                                    .and_then(|p| PeeringProtocol::from_str(p).ok())
                            })
                            .any(|p| p == *protocol)
                        {
                            warn!("Transport protocol {protocol:?} is client-server only and it is unable to create peering");
                            warn!("If both peering nodes have no appropriate `yggdrasil_listen` URI set in the config");
                        }
                    }

                    return Ok(RouterState {
                        version,
                        address: info.address,
                        admin_api: endpoint,
                    });
                }
            }
        } else {
            warn!("Can't parse yggdrasil admin socket address {uri}");
            continue;
        }
    }
    for (uri, err) in errs {
        warn!("Failed to connect to {uri}: {err}");
    }
    Err(())
}

#[instrument(parent = None, name = "Admin API watcher", skip_all)]
pub async fn monitor(
    config: Config,
    state: State,
    watch_sessions: watch::Sender<Vec<yggdrasilctl::SessionEntry>>,
    watch_peers: watch::Sender<Vec<yggdrasilctl::PeerEntry>>,
) -> Result<(), ()> {
    let cancellation = state.cancellation.clone();

    loop {
        {
            let io_err = map_error!("Failed to query admin api");
            let api_err = map_error!("Admin api returned error");

            let endpoint = &mut state.router.write().await.admin_api;

            watch_sessions
                .send(
                    endpoint
                        .get_sessions()
                        .await
                        .map_err(io_err)?
                        .map_err(api_err)?,
                )
                .unwrap();
            watch_peers
                .send(
                    endpoint
                        .get_peers()
                        .await
                        .map_err(io_err)?
                        .map_err(api_err)?,
                )
                .unwrap();
        }
        select! {
            _ = sleep(config.yggdrasilctl_query_delay) => {},
            _ = cancellation.cancelled() => return Ok(()),
        }
    }
}
