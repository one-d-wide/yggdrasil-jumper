use super::*;

#[instrument(parent = None, name = "Bridge ", skip_all, fields(peer = ?address, remote = %peer_addr, uri = %uri))]
async fn bridge(
    config: Config,
    state: State,
    mut address: Option<Ipv6Addr>,
    peer_addr: SocketAddr,
    peer: TcpStream,
    ygg: TcpStream,
    uri: String,
) -> Result<(), ()> {
    let cancellation = state.cancellation.clone();
    let address = &mut address;
    info!("Connected");

    let mut recorded = false;
    let res = async {
        let (mut peer, mut ygg) = (BufReader::new(peer), BufReader::new(ygg));
        let mut watch_peers = state.watch_peers.clone();
        let mut watch_sessions = state.watch_sessions.clone();
        let mut delay_shutdown = Some(Instant::now());

        loop {
            if ! recorded {
                if let Some(ref addr) = address {
                    use sessions::SessionType;
                    let old = state.active_sessions.write().await.insert(*addr, SessionType::Bridge);
                    if let Some(SessionType::Bridge) = old {
                        // Multiple connections with the same identifiers are not allowed by the OS.
                        warn!("Bridge already exists. Implementation bug");
                        return Err(());
                    }
                    recorded = true;
                }
            }
            select! {
                // Send data from `peer` to `ygg`
                err = peer.fill_buf() => {
                    let buf = err.map_err(map_info!("Failed to read bridge socket"))?;
                    let len = buf.len();
                    if len == 0 {
                        info!("Peer closed connection");
                        return Err(())
                    }
                    ygg.get_mut()
                        .write_all(buf)
                        .await
                        .map_err(map_info!("Failed to write to yggdrasil socket"))?;
                    // trace!("Received {len} byte(s)");
                    peer.consume(len);
                },
                // Send data from `ygg` to `peer`
                err = ygg.fill_buf() => {
                    let buf = err.map_err(map_info!("Failed to read yggdrasil socket"))?;
                    let len = buf.len();
                    if len == 0 {
                        info!("Yggdrasil socket closed");
                        return Err(())
                    }
                    peer.get_mut()
                        .write_all(buf)
                        .await
                        .map_err(map_info!("Failed to write to bridge socket"))?;
                    // trace!("Sent {len} byte(s)");
                    ygg.consume(len);
                },
                // Return if per is not connected
                err = watch_peers.changed() => {
                    err.map_err(|_| ())?;
                    let peers = watch_peers.borrow();
                    // Check if shutdown is delayed
                    if let Some(ref timer) = delay_shutdown {
                       if timer.elapsed() > config.peer_unconnected_check_delay {
                            delay_shutdown = None;
                       }
                    }

                    // Return if peer is not connected
                    if delay_shutdown.is_none() && !peers.iter().filter_map(|peer| peer.remote.as_ref()).any(|remote| remote == &uri) {
                        return Err(info!("Bridge is not connected as peer"));
                    }
                    // Retrieve address
                    if address.is_none() {
                        for peer in peers.iter() {
                            if peer.remote.as_deref() == Some(&uri) {
                                if let Some(addr) = peer.address {
                                    *address = Some(addr);
                                    info!("Peer address instantiated");
                                    if let Some(false) = config.whitelist.as_ref().map(|w| w.contains(&addr)) {
                                        info!("Peer misses whitelist");
                                        return Ok(())
                                    }
                                    break;
                                }
                            }
                        }
                    }
                },
                // Return if session is closed
                err = watch_sessions.changed(), if address.is_some()  => {
                    err.map_err(|_| ())?;
                    if ! watch_sessions.borrow().iter().any(|session| &session.address == address.as_ref().unwrap()) {
                        return Err(info!("Session closed"));
                    }
                },
                // Return if cancelled
                _ = cancellation.cancelled() => return Ok(()),
            }
        }
    }.await;
    if recorded {
        state
            .active_sessions
            .write()
            .await
            .remove(address.as_ref().unwrap());
    }
    res
}

#[instrument(parent = None, name = "Connect bridge ", skip_all, fields(peer = ?address, remote = %peer_addr))]
pub async fn run_bridge(
    config: Config,
    state: State,
    peer_addr: SocketAddr,
    address: Option<Ipv6Addr>,
    socket: TcpStream,
) -> Result<(), ()> {
    let _cancellation = state.cancellation.clone();
    let uri = |local_addr: std::io::Result<SocketAddr>| -> Result<String, ()> {
        Ok(format!(
            "tcp://{}",
            local_addr.map_err(map_warn!("Failed to retrieve local inbound socket address"))?
        ))
    };

    // Try connect self to yggdrasil listen addresses directly
    for addr in &config.yggdrasil_listen {
        if let Ok(ygg) = TcpStream::connect(addr).await.map_err(map_warn!(
            "Failed to connect to yggdrasil listen socket at {addr}"
        )) {
            if let Ok(uri) = uri(ygg.local_addr()) {
                return bridge(config, state, address, peer_addr, socket, ygg, uri).await;
            }
        }
    }

    // Fallback. Try connect yggdrasil to self
    let socket_address = socket
        .local_addr()
        .map_err(map_warn!("Failed to retrieve local socket address"))?;
    let ygg = util::new_socket_in_domain(&socket_address, 0)?
        .listen(1)
        .map_err(map_warn!("Failed to create local inbound socket"))?;

    let uri = uri(ygg.local_addr())?;

    async {
        // Add peer
        state
            .admin
            .write()
            .await
            .add_peer(uri.clone(), None)
            .await
            .map_err(map_warn!("Failed to query admin api"))?
            .map_err(map_warn!("Failed to add local socket as peer"))?;

        // Run bridge
        let res = bridge(
            config,
            state.clone(),
            address,
            peer_addr,
            socket,
            ygg.accept()
                .await
                .map_err(map_warn!("Failed to accept yggdrasil connection"))
                .map(|(s, _)| s)?,
            uri.clone(),
        )
        .await;

        // Remove peer
        state
            .admin
            .write()
            .await
            .remove_peer(uri.clone(), None)
            .await
            .map_err(map_warn!("Failed to query admin api"))?
            .map_err(map_warn!("Failed to remove local socket from peer list"))?;

        res
    }
    .instrument(info_span!(" ", uri))
    .await
}
