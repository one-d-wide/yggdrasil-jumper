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
        state: State,
        socket: TcpStream,
        address: SocketAddr,
    ) {
        // Add connected socket to the list
        state
            .active_sockets_tcp
            .write()
            .await
            .insert(address, socket);

        // Set timer to automatically remove connected socket from the list
        let delay = config.socket_inactivity_cleanup_delay;
        spawn(async move {
            select! {
                _ = sleep(delay) => {},
                _ = state.cancellation.cancelled() => { return; },
            }
            state.active_sockets_tcp.write().await.remove(&address);
        });
    }

    let mut tasks = JoinSet::new();

    // Spawn internet listeners
    for listener in listeners {
        let config = config.clone();
        let state = state.clone();
        tasks.spawn(async move {
            loop {
                // Accept connection
                let (socket, address) = select! {
                    result = listener.accept() => result,
                    _ = state.cancellation.cancelled() => return Ok(()),
                }
                .map_err(map_error!("Failed to accept incoming connection"))?;

                // Save connection to the list
                handle_active_tcp_socket(&config, state.clone(), socket, address).await;
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
            let (socket, address) = select! {
                result = socket.accept() => result,
                _ = state.cancellation.cancelled() => return Ok(()),
            }
            .map_err(map_error!("Failed to accept incoming connection"))?;

            // Skip if connection isn't ipv6
            if !address.is_ipv6() {
                continue;
            }

            // Check if remote isn't on known port
            if address.port() != config.listen_port {
                continue;
            }

            handle_active_tcp_socket(&config, state.clone(), socket, address).await;
        }
    });

    tasks.join_next().await.unwrap().unwrap()
}

/// Try NAT traversal
#[instrument(name = " NAT traversal", skip_all, fields(protocol = ?protocol, remote = %remote))]
pub async fn traverse(
    config: Config,
    state: State,
    protocol: PeeringProtocol,
    local_port: u16,
    remote: SocketAddr,
    _monitor_addr: Ipv6Addr,
    mut notify_traversed: Option<oneshot::Sender<()>>,
    mut check_traversed: Option<oneshot::Receiver<()>>,
) -> IoResult<RouterStream> {
    debug!("Started");

    let cancellation = state.cancellation.clone();

    match protocol {
        // Use TCP
        PeeringProtocol::Tcp | PeeringProtocol::Tls => {
            let mut last_err = None;
            for _ in 0..config.nat_traversal_tcp_retry_count {
                // Check if TCP stream was already received
                if state.active_sockets_tcp.read().await.contains_key(&remote) {
                    let entry = state
                        .active_sockets_tcp
                        .write()
                        .await
                        .remove_entry(&remote)
                        .unwrap();

                    last_err = Some(Ok(entry.1));
                    break;
                } else {
                    // Try start new connection
                    let socket = utils::create_tcp_socket_in_domain(&remote, local_port)
                        .map_err(|_| IoError::last_os_error())?;

                    if let Ok(err) =
                        timeout(config.nat_traversal_tcp_timeout, socket.connect(remote)).await
                    {
                        last_err = Some(err);
                        break;
                    }
                }
                if cancellation.is_cancelled() {
                    break;
                }
                sleep(config.nat_traversal_tcp_delay).await;
            }
            match last_err {
                Some(res) => res.map(|s| s.into()),
                None => Err(IoError::new(IoErrorKind::TimedOut, "Timeout")),
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

            let mut last_err = None;
            for _ in 0..config.nat_traversal_udp_retry_count {
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
                    } => { last_err = Some(err); },
                    _ = sleep(config.nat_traversal_udp_timeout) => {},
                }

                if notify_traversed.is_none()
                    && check_traversed
                        .as_mut()
                        .map(|c| c.try_recv().is_ok())
                        .unwrap_or(false)
                {
                    last_err = Some(Ok(()));
                }

                if let Some(Ok(_)) = last_err {
                    break;
                }
                if cancellation.is_cancelled() {
                    break;
                }

                sleep(config.nat_traversal_udp_delay).await;
            }

            match last_err {
                Some(res) => res.map(|_| socket.into()),
                None => Err(IoError::new(IoErrorKind::TimedOut, "Timeout")),
            }
        }
    }
}
