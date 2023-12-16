use super::*;

#[derive(Debug)]
pub enum SessionType {
    Session,
    Bridge,
}

impl SessionType {
    pub fn is_bridge(&self) -> bool {
        matches!(self, Self::Bridge)
    }
    pub fn is_session(&self) -> bool {
        matches!(self, Self::Session)
    }
}

#[instrument(parent = None, name = "Session ", skip_all, fields(peer = %address))]
async fn connect_session(
    config: Config,
    state: State,
    address: SocketAddrV6,
    uptime: Option<f64>,
) -> Result<(), ()> {
    // Return if inactivity delay is enacted
    if let Some(uptime) = uptime {
        if uptime > protocol::INACTIVITY_DELAY_PERIOD
            && uptime % protocol::INACTIVITY_DELAY_PERIOD < protocol::INACTIVITY_DELAY
        {
            if Duration::from_secs_f64(uptime % protocol::INACTIVITY_DELAY_PERIOD)
                < config.yggdrasilctl_query_delay
            {
                debug!("Enacting inactivity delay");
            }
            return Ok(());
        }
    }

    // Align connection time with session's uptime for firewall traversal effect
    // Sleep until uptime value is dividable by `protocol::ALIGN_UPTIME_TIMEOUT`
    let delay = match uptime {
        Some(uptime) => protocol::ALIGN_UPTIME_TIMEOUT - (uptime % protocol::ALIGN_UPTIME_TIMEOUT),
        // Uptime unknown. Prevent request flood
        None => protocol::ALIGN_UPTIME_TIMEOUT,
    };

    debug!("Delay: {delay:.2}s");

    select! {
        _ = sleep(Duration::from_secs_f64(delay)) => {},
        _ = state.cancellation.cancelled() => { return Ok(()); },
    }

    if let Ok(socket) = network::traverse(
        config.clone(),
        state.clone(),
        PeeringProtocol::Tcp,
        config.listen_port,
        address.into(),
        *address.ip(),
        None,
        None,
    )
    .await
    .map_err(map_debug!("NAT traversal failed"))
    {
        let socket = match socket {
            RouterStream::Tcp(socket) => socket,
            _ => unreachable!(),
        };
        return protocol::try_session(config, state, socket, address).await;
    }
    Err(())
}

#[instrument(parent = None, name = "Session spawner", skip_all)]
pub async fn spawn_new_sessions(
    config: Config,
    state: State,
    external_required: watch::Sender<Instant>,
) -> Result<(), ()> {
    let whitelist_contains = config.whitelist.as_ref().map(|whitelist| {
        const ADDRESS_PREFIX: u8 = 0x02;
        const SUBNET_PREFIX: u8 = 0x03;
        const SUBNET_BYTES: usize = 8;

        let get_subnet_id = |address: &Ipv6Addr| {
            u64::from_ne_bytes(address.octets()[..SUBNET_BYTES].try_into().unwrap())
        };

        let mut addresses = HashSet::new();
        let mut subnets = HashSet::new();
        for address in whitelist {
            if address.octets()[0] == SUBNET_PREFIX {
                let mut subnet = get_subnet_id(address).to_ne_bytes();
                subnet[0] = ADDRESS_PREFIX;
                let subnet = u64::from_ne_bytes(subnet);

                subnets.insert(subnet);
            } else {
                addresses.insert(*address);
            }
        }

        move |address: &Ipv6Addr| {
            addresses.contains(address) || subnets.contains(&get_subnet_id(address))
        }
    });

    let cancellation = state.cancellation.clone();
    let watch_peers = state.watch_peers.clone();
    let mut watch_sessions = state.watch_sessions.clone();
    let mut watch_external = state.watch_external.clone();

    // Avoid warning on startup
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
            let mut reload_external = false;
            let mut sessions = state.active_sessions.write().await;
            let peers = config.avoid_redundant_peering.then(|| watch_peers.borrow());
            for session in watch_sessions.borrow_and_update().iter() {
                let address = session.address;
                let uptime = session.uptime;

                // Skip if address is not in the whitelist
                if let Some(ref whitelist_contains) = whitelist_contains {
                    if !whitelist_contains(&address) {
                        continue;
                    }
                }

                // Skip if peer is already has direct connection
                if let Some(ref peers) = peers {
                    if peers.iter().any(|p| p.address.as_ref() == Some(&address)) {
                        continue;
                    }
                }

                // Spawn handler if session is new
                if sessions.get(&address).is_none() {
                    // Refresh watchdog
                    if reload_external == false {
                        external_required.send(Instant::now()).ok();
                        reload_external = true;
                    }

                    // Add session record
                    sessions.insert(address, SessionType::Session);

                    // Spawn session handler
                    let config = config.clone();
                    let state = state.clone();
                    spawn(async move {
                        // Spawn handler
                        let _ = connect_session(
                            config.clone(),
                            state.clone(),
                            SocketAddrV6::new(address, config.listen_port, 0, 0),
                            uptime,
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
        }

        select! {
            err = watch_sessions.changed() => err.map_err(|_| ())?,
            _ = cancellation.cancelled() => return Ok(()),
        }
    }
}
