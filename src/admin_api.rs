use super::*;

#[instrument(parent = None, name = "Admin API", skip_all)]
pub async fn connect(config: Config) -> Result<Endpoint<util::RWSocket>, ()> {
    use std::io::{Error, ErrorKind};
    let error = |t| Error::new(ErrorKind::InvalidInput, t);

    let mut errs: Vec<(_, _)> = Vec::new();

    for uri in &config.yggdrasil_admin_listen {
        if let Some((protocol, address)) = uri.split_once("://") {
            let socket = match protocol {
                #[cfg(unix)]
                "unix" => tokio::net::UnixStream::connect(address)
                    .await
                    .map(|s| -> util::RWSocket { Box::new(s) }),
                #[cfg(not(unix))]
                "unix" => Err(error(format!(
                    "Unix socket is not supported on this platform"
                ))),
                "tcp" => TcpStream::connect(address)
                    .await
                    .map(|s| -> util::RWSocket { Box::new(s) }),
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
                    let versions: Vec<u64> = build_version
                        .as_str()
                        .split(".")
                        .filter_map(|v| v.parse().ok())
                        .collect();
                    if versions.len() != 3 {
                        error!("Failed to parse router version {versions:?}");
                        continue;
                    }

                    // If router version is lower then v0.4.5
                    if versions[0] == 0 && versions[1] <= 4 && (versions[1] < 4 || versions[2] < 5)
                    {
                        if config.yggdrasil_listen.is_empty() {
                            warn!("Direct bridges can't be connected to the router of version {build_version} at {uri}");
                            warn!(
                                "Routers prior to v0.4.5 (Oct 2022) don't support addpeer/removepeer commands"
                            );
                            warn!("Help: Specify `ygdrasil_addresses` in the config or update your router");
                        }
                    }

                    return Ok(endpoint);
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
pub async fn watcher(
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
            let mut endpoint = state.admin.write().await;

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
