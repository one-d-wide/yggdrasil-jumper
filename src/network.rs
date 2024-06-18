use super::*;

pub const NAT_TRAVERSAL_HELLO: &str = "nat-traversal-hello";

pub fn create_listener_sockets(
    config: Config,
    _state: State,
) -> Result<(Vec<TcpListener>, Vec<SocketAddr>), ()> {
    // Create socket pool
    let mut sockets = Vec::<TcpSocket>::new();
    if config.allow_ipv6 {
        sockets
            .push(utils::create_tcp_socket_ipv6(0).map_err(|_| warn!("Can't create IPv6 socket"))?);
    }
    if config.allow_ipv4 {
        sockets
            .push(utils::create_tcp_socket_ipv4(0).map_err(|_| warn!("Can't create IPv4 socket"))?);
    }

    if sockets.is_empty() {
        error!("Have no socket to listen");
        return Err(());
    }

    // Convert sockets to listeners
    let mut listeners = Vec::<TcpListener>::new();
    for socket in sockets {
        let listener = socket
            .listen(128)
            .map_err(map_error!("Failed to set listen socket up"))?;
        listeners.push(listener);
    }

    // Retrieve socket addresses
    let mut local_addresses = Vec::new();
    for listener in &listeners {
        local_addresses.push(
            listener
                .local_addr()
                .map_err(map_error!("Failed to retrieve local listen socket address"))?,
        );
    }

    Ok((listeners, local_addresses))
}

// Listen for incoming internet connections
#[instrument(parent = None, name = "Internet listener ", skip_all)]
pub async fn setup_listeners(
    config: Config,
    state: State,
    listeners: Vec<TcpListener>,
) -> Result<(), ()> {
    pub async fn handle_active_tcp_socket(
        config: &Config,
        state: &State,
        socket: TcpStream,
        address: SocketAddr,
    ) {
        // Set timer to automatically remove connected socket from the list
        let delay = config.socket_inactivity_cleanup_delay;
        let abort_handle = spawn({
            let state = state.clone();
            async move {
                sleep(delay).await;
                state.active_sockets_tcp.write().await.remove(&address);
            }
        })
        .abort_handle();
        let abort_guard = defer_arg(abort_handle, |h| h.abort());

        // Add connected socket to the list
        state
            .active_sockets_tcp
            .write()
            .await
            .insert(address, (socket, abort_guard));
    }

    let mut tasks = JoinSet::new();

    // Spawn internet listeners
    for listener in listeners {
        let config = config.clone();
        let state = state.clone();
        tasks.spawn(async move {
            loop {
                // Accept connection
                let (socket, address) = listener
                    .accept()
                    .await
                    .map_err(map_error!("Failed to accept incoming connection"))?;

                debug!("Incoming connection received from: {address}");

                // Save connection to the list
                handle_active_tcp_socket(&config, &state, socket, address).await;
            }
        });
    }

    // Spawn yggdrasil listener
    let socket = utils::create_tcp_socket_ipv6(config.listen_port)?;
    let socket = socket
        .listen(128)
        .map_err(map_error!("Failed to set listener socket up"))?;

    tasks.spawn(async move {
        loop {
            // Accept every incoming connection
            let (socket, address) = socket
                .accept()
                .await
                .map_err(map_error!("Failed to accept incoming connection"))?;

            debug!("Incoming connection received from: {address} (yggdrasil)");

            // Skip if connection isn't ipv6
            if !address.is_ipv6() {
                continue;
            }

            // Check if remote isn't on known port
            if address.port() != config.listen_port {
                continue;
            }

            handle_active_tcp_socket(&config, &state, socket, address).await;
        }
    });

    tasks.join_next().await.unwrap().unwrap()
}

/// Try NAT traversal
#[instrument(name = "NAT traversal", skip_all, fields(protocol = ?protocol, remote = %remote))]
pub async fn traverse(
    config: Config,
    state: State,
    protocol: PeeringProtocol,
    local_port: u16,
    remote: SocketAddr,
    _monitor_addr: Ipv6Addr,
    mut notify_traversed: Option<oneshot::Sender<()>>,
    mut check_traversed: Option<oneshot::Receiver<()>>,
) -> IoResult<IoResult<RouterStream>> {
    debug!("Started");

    match protocol {
        // Use TCP
        PeeringProtocol::Tcp | PeeringProtocol::Tls => {
            let mut last_result = None;
            for _ in 0..config.nat_traversal_tcp_retry_count {
                let delay = sleep(config.nat_traversal_tcp_cycle);

                // Check if TCP stream was already received
                if state.active_sockets_tcp.read().await.contains_key(&remote) {
                    let (_, (socket, _)) = state
                        .active_sockets_tcp
                        .write()
                        .await
                        .remove_entry(&remote)
                        .unwrap();

                    last_result = Some(Ok(socket));
                    break;
                } else {
                    // Try start new connection
                    let socket = utils::create_tcp_socket_in_domain(&remote, local_port)
                        .map_err(|_| IoError::last_os_error())?;

                    #[cfg(target_os = "linux")]
                    {
                        SockRef::from(&socket)
                            .set_tcp_user_timeout(Some(config.nat_traversal_tcp_timeout))?;

                        last_result = Some(socket.connect(remote).await);
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        select! {
                            _ = sleep(config.nat_traversal_tcp_timeout) => {
                                last_result = Some(Err(IoErrorKind::TimedOut.into()));
                            },
                            res = socket.connect(remote) => {
                                last_result = Some(res);
                            }
                        };
                    }
                    if let Some(Ok(_)) = last_result {
                        break;
                    }
                }
                delay.await;
            }
            match last_result {
                Some(res) => Ok(res.map(|s| {
                    #[cfg(target_os = "linux")]
                    SockRef::from(&s).set_tcp_user_timeout(None).ok();
                    s.into()
                })),
                None => Ok(Err(IoError::new(IoErrorKind::TimedOut, "Timeout"))),
            }
        }
        // Use UDP
        PeeringProtocol::Quic => {
            let socket = utils::create_udp_socket_in_domain(&remote, local_port)
                .map_err(|_| IoError::last_os_error())?;

            socket
                .connect(&remote)
                .await
                .map_err(|_| IoError::last_os_error())?;

            let mut last_result = None;
            for _ in 0..config.nat_traversal_udp_retry_count {
                let delay = sleep(config.nat_traversal_udp_cycle);

                socket.send(NAT_TRAVERSAL_HELLO.as_bytes()).await?;

                select! {
                    err = async {
                        let mut buf = [0u8; NAT_TRAVERSAL_HELLO.as_bytes().len()];

                        loop {
                            let received = socket.recv(&mut buf).await?;

                            if &buf[..received] == NAT_TRAVERSAL_HELLO.as_bytes() {
                                if let Some(tx) = notify_traversed.take() {
                                    tx.send(()).ok();
                                }
                            }
                        }
                    } => { last_result = Some(err); },
                    _ = sleep(config.nat_traversal_udp_timeout) => {},
                }

                if notify_traversed.is_none()
                    && check_traversed
                        .as_mut()
                        .map(|c| c.try_recv().is_ok())
                        .unwrap_or(false)
                {
                    last_result = Some(Ok(()));
                }

                if let Some(Ok(_)) = last_result {
                    break;
                }

                delay.await;
            }

            match last_result {
                Some(res) => Ok(res.map(|_| socket.into())),
                None => Ok(Err(IoError::new(IoErrorKind::TimedOut, "Timeout"))),
            }
        }
    }
}
