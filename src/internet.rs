use super::*;

pub fn new_sockets(config: &Config) -> Result<(Vec<TcpListener>, Vec<SocketAddr>), ()> {
    // Create socket pool
    let mut sockets = Vec::<TcpSocket>::new();
    if config.allow_ipv6 {
        sockets.push(util::new_socket_ipv6(0).map_err(|_| warn!("Can't create IPv6 socket"))?);
    }
    if config.allow_ipv4 {
        sockets.push(util::new_socket_ipv4(0).map_err(|_| warn!("Can't create IPv4 socket"))?);
    }

    if sockets.is_empty() {
        error!("Have no socket to listen");
        return Err(());
    }

    // Convert sockets to listeners
    let mut listeners = Vec::<TcpListener>::new();
    for socket in sockets {
        let listener = socket
            .listen(1024)
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
#[instrument(parent = None, name = "Internet listener", skip_all)]
pub async fn listen(config: Config, state: State, listeners: Vec<TcpListener>) -> Result<(), ()> {
    let cancellation = state.cancellation.clone();

    // A common funtion for async accept
    // Explicit function is used because async closure with arguments is currently unstable
    async fn listen(
        listener: TcpListener,
    ) -> (Result<(TcpStream, SocketAddr), std::io::Error>, TcpListener) {
        (listener.accept().await, listener)
    }

    // Create await pool
    let mut pool: FuturesUnordered<_> = listeners.into_iter().map(|l| listen(l)).collect();

    loop {
        // Accept every incoming connection
        let (connection, listener) = select! {
            result = pool.next() => result.unwrap(),
            _ = cancellation.cancelled() => return Ok(()),
        };
        // Reset listener
        pool.push(listen(listener));

        // Spawn handler
        let (socket, addr) =
            connection.map_err(map_error!("Failed to accept incoming connection"))?;
        spawn(bridge::run_bridge(
            config.clone(),
            state.clone(),
            addr,
            None,
            socket,
        ));
    }
}
