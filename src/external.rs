use super::*;

#[derive(Debug, PartialEq)]
pub struct ExternalAddress {
    pub external: SocketAddr,
    pub local: SocketAddr,
}

// Monitor external internet addresses
#[instrument(parent = None, name = "External address watcher", skip_all)]
pub async fn lookup(
    config: Config,
    state: State,
    local: Vec<SocketAddr>,
    watch_external: watch::Sender<Vec<ExternalAddress>>,
    mut external_required: watch::Receiver<Instant>,
) -> Result<(), ()> {
    use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

    let cancellation = state.cancellation.clone();
    let mut random = StdRng::from_entropy();
    let mut servers = config.stun_servers.clone();

    loop {
        // For each local address
        let mut external = Vec::<ExternalAddress>::new();
        for local in &local {
            if config.stun_randomize {
                servers.shuffle(&mut random);
            }
            // For each specified server
            let res = async {
                for server in &servers {
                    // Skip server if address range is not matched
                    if let Ok(false) = server
                        .parse::<SocketAddr>()
                        .map(|a| a.is_ipv4() == local.is_ipv4())
                    {
                        continue;
                    }
                    let res = async {
                        // Resolve server address
                        if let Ok(Ok(server_addr)) = lookup_host(server.as_str())
                            .await
                            .map_err(map_info!("Failed to lookup server address"))
                            .map(|addrs| {
                                addrs
                                    .filter(|addr| addr.is_ipv4() == local.is_ipv4())
                                    .next()
                                    .ok_or_else(|| info!("No suitable address resolved"))
                            })
                        {
                            // Try to connect to the server
                            if let Ok(stream) = util::new_socket_in_domain(local, local.port())?
                                .connect(server_addr)
                                .await
                                .map_err(map_info!("Failed to connect to {server_addr}"))
                            {
                                // Perform server request
                                let mut stream = BufReader::new(stream);
                                let external = stun::lookup_external_address(&mut stream).await;

                                // Unclean socket shutdown may cause an OS to temporarily disallow new reconnections
                                stream
                                    .shutdown()
                                    .await
                                    .map_err(map_info!("Failed to close connection"))
                                    .ok();

                                if let Ok(external) = external {
                                    info!("Resolved: {external}");
                                    return Ok(ExternalAddress {
                                        local: *local,
                                        external,
                                    });
                                }
                            }
                        }
                        Err(())
                    }
                    .instrument(info_span!(" ", server = %server))
                    .await;
                    if let Ok(external) = res {
                        return Ok(external);
                    }
                }
                Err(())
            }
            .instrument(info_span!(" Lookup ", local = %local))
            .await;
            if let Ok(address) = res {
                external.push(address)
            }
        }

        // Update watchers if externals changed
        if watch_external.borrow().as_slice() != external.as_slice() {
            watch_external.send(external).unwrap();
        }

        // Is external address unresolved or update required
        let required = watch_external.borrow().is_empty()
            || external_required.borrow_and_update().elapsed()
                < config.resolve_external_address_delay;

        if required {
            select! {
                // Delay next request
                _ = sleep(config.resolve_external_address_delay) => {},
                _ = cancellation.cancelled() => return Ok(()),
            };
        } else {
            info!("No update required, suspending");
            loop {
                // Wait untill new session is started
                select! {
                    (err, ()) = async {
                        join!(external_required.changed(), sleep(config.resolve_external_address_delay))
                    } => err.map_err(|_| ())?,
                    _ = cancellation.cancelled() => return Ok(()),
                };
                // Check if bridge is running
                if !state
                    .active_sessions
                    .read()
                    .await
                    .iter()
                    .any(|(_, v)| sessions::SessionType::is_bridge(v))
                {
                    break;
                }
            }
        }
    }
}
