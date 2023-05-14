use super::*;

// Listen for incoming connections in overlay network
#[instrument(parent = None, name = "Yggdrasil listener", skip_all)]
pub async fn listen(config: Config, state: State) -> Result<(), ()> {
    let cancellation = state.cancellation.clone();

    let socket = util::new_socket_ipv6(config.listen_port)?;
    let socket = socket
        .listen(1024)
        .map_err(map_error!("Failed to set listen socket up"))?;

    loop {
        // Accept every incoming connection
        let connection = select! {
            _ = cancellation.cancelled() => return Ok(()),
            err = socket.accept() => err.map_err(map_error!("Failed to accept incoming connection"))?,
        };
        // Check whether connection is ipv6
        if let (socket, SocketAddr::V6(addr)) = connection {
            // Check if remote is on known port
            if addr.port() != config.listen_port {
                continue;
            }
            // Check whitelist
            if let Some(false) = config.whitelist.as_ref().map(|w| w.contains(addr.ip())) {
                continue;
            }
            // Spawn handler
            spawn(protocol::try_session(
                config.clone(),
                state.clone(),
                socket,
                addr,
            ));
        }
    }
}
