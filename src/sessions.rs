use super::*;

#[derive(Debug)]
pub enum SessionType {
    Session,
    Bridge,
}

impl SessionType {
    pub fn is_bridge(&self) -> bool {
        match self {
            Self::Bridge => true,
            _ => false,
        }
    }
    pub fn is_session(&self) -> bool {
        match self {
            Self::Session => true,
            _ => false,
        }
    }
}

#[instrument(parent = None, name = "Session ", skip_all, fields(peer = %address))]
async fn connect_session(config: Config, state: State, address: SocketAddrV6) -> Result<(), ()> {
    let remote = SocketAddr::V6(address);
    debug!("Firewall traversal");

    let mut last_err: Option<std::io::Result<TcpStream>> = None;
    for _ in 0..config.nat_traversal_retry_count {
        {
            select! {
                err = util::new_socket_ipv6(config.listen_port)?.connect(remote) => { last_err = Some(err); },
                _ = sleep(config.nat_traversal_connection_timeout) => {},
            }
            if let Some(Ok(_)) = last_err {
                break;
            }
        }
        sleep(config.nat_traversal_connection_delay).await;
    }
    match last_err {
        Some(Ok(socket)) => return protocol::try_session(config, state, socket, address).await,
        Some(Err(err)) => debug!("Failed: {err}"),
        None => debug!("Failed: Timeout"),
    }
    Err(())
}

#[instrument(parent = None, name = "Session spawner", skip_all)]
pub async fn spawn_new_sessions(
    config: Config,
    state: State,
    external_required: watch::Sender<Instant>,
) -> Result<(), ()> {
    let cancellation = state.cancellation.clone();
    let mut watch_sessions = state.watch_sessions.clone();
    let mut watch_external = state.watch_external.clone();

    // Avoid warning on first launch
    if watch_external.borrow().is_empty() {
        watch_external.changed().await.map_err(|_| ())?;
    }

    loop {
        // Suspend if no external address found
        if watch_external.borrow_and_update().is_empty() {
            warn!("No external address found, suspending");
            select! {
                err = watch_external.changed() => { err.map_err(|_| ())? },
                _ = cancellation.cancelled() => return Ok(()),
            };
            continue;
        }

        {
            // For each connected session
            let mut is_new_session_spawned = false;
            let mut sessions = state.active_sessions.write().await;
            for (address, uptime) in watch_sessions
                .borrow_and_update()
                .iter()
                .map(|s| (s.address.clone(), s.uptime))
            {
                // Skip if address is not in the whitelist
                if let Some(false) = config.whitelist.as_ref().map(|w| w.contains(&address)) {
                    continue;
                }
                // Spawn handler if session is new
                if let None = sessions.get(&address) {
                    is_new_session_spawned = true;

                    // Add session record
                    sessions.insert(address.clone(), SessionType::Session);

                    // Spawn session handler
                    let (config, state) = (config.clone(), state.clone());
                    spawn(async move {
                        // Align connection time with session's uptime for firewall traversal effect
                        // Sleep untill uptime value is dividable by `protocol::ALIGN_UPTIME_TIMEOUT`
                        let delay = if uptime != 0.0 {
                            (uptime / protocol::ALIGN_UPTIME_TIMEOUT).ceil()
                                * protocol::ALIGN_UPTIME_TIMEOUT
                                - uptime
                        } else {
                            // Uptime unknown. Prevent request flood
                            protocol::ALIGN_UPTIME_TIMEOUT
                        };

                        sleep(Duration::from_secs_f64(delay)).await;

                        // Spawn handler
                        let _ = connect_session(
                            config.clone(),
                            state.clone(),
                            SocketAddrV6::new(address.clone(), config.listen_port, 0, 0),
                        )
                        .await;

                        // Remove handler record
                        let mut sessions = state.active_sessions.write().await;
                        if let Some(SessionType::Session) = sessions.get(&address) {
                            sessions.remove(&address);
                        }
                    });
                }
            }
            // Refresh watchdog
            if is_new_session_spawned {
                external_required.send(Instant::now()).map_err(|_| ())?;
            }
        }
        select! {
            err = watch_sessions.changed() => err.map_err(|_| ())?,
            _ = cancellation.cancelled() => return Ok(()),
        }
    }
}
