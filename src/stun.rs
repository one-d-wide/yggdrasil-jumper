use super::*;

use {
    bytecodec::{Decode, EncodeExt},
    rand::{rngs::StdRng, seq::SliceRandom, SeedableRng},
    stun_codec::{
        rfc5389::{attributes, methods::BINDING, Attribute},
        Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId,
    },
};

#[derive(Debug, PartialEq)]
pub struct ExternalAddress {
    pub external: SocketAddr,
    pub local: SocketAddr,
    pub protocol: NetworkProtocol,
}

/// Monitor external internet addresses
#[instrument(parent = None, name = "External address watcher", skip_all)]
pub async fn monitor(
    config: Config,
    state: State,
    local: Vec<SocketAddr>,
    watch_external: watch::Sender<Vec<ExternalAddress>>,
    mut external_required: watch::Receiver<Instant>,
) -> Result<(), ()> {
    let mut random = StdRng::from_entropy();
    struct Server<'a> {
        server: &'a str,
        tcp_status: bool,
        udp_status: bool,
    }
    impl<'a> Server<'a> {
        fn set(&self, protocol: NetworkProtocol) -> bool {
            match protocol {
                NetworkProtocol::Tcp => self.tcp_status,
                NetworkProtocol::Udp => self.udp_status,
            }
        }
        fn reset(&mut self, protocol: NetworkProtocol, value: bool) {
            match protocol {
                NetworkProtocol::Tcp => self.tcp_status = value,
                NetworkProtocol::Udp => self.udp_status = value,
            }
        }
    }
    let mut servers: Vec<Server> = config
        .stun_servers
        .iter()
        .map(|s| Server {
            server: s.as_str(),
            tcp_status: true,
            udp_status: true,
        })
        .collect();

    let protocols: Vec<NetworkProtocol> = config
        .yggdrasil_protocols
        .iter()
        .map(|p| (*p).into())
        .unique()
        .collect();

    loop {
        let mut external = Vec::<ExternalAddress>::new();

        for local in local.iter().map(Clone::clone) {
            for protocol in protocols.iter().map(Clone::clone) {
                // Reset protocol status for every known server if they all were rendered unaccessible
                if servers.iter().all(|s| !s.set(protocol)) {
                    for server in servers.iter_mut() {
                        server.reset(protocol, true);
                    }
                }

                if config.stun_randomize {
                    servers.shuffle(&mut random);
                }

                for server in servers.iter_mut().filter(|s| s.set(protocol)) {
                    match lookup(config.clone(), protocol, local, server.server).await {
                        Ok(address) => {
                            external.push(address);
                            break;
                        }
                        Err(()) => server.reset(protocol, false),
                    }
                }
            }
        }

        // Update watchers if externals changed
        if watch_external.borrow().as_slice() != external.as_slice() {
            watch_external.send(external).unwrap();
        }

        // Check is external address unresolved or update required
        let required = watch_external.borrow().is_empty()
            || external_required.borrow_and_update().elapsed()
                < config.resolve_external_address_delay;

        if required {
            // Delay next request
            sleep(config.resolve_external_address_delay).await;
        } else {
            debug!("No update required, suspending");
            loop {
                // Wait until any new session is started
                let (err, _) = join!(
                    external_required.changed(),
                    sleep(config.resolve_external_address_delay)
                );
                err.map_err(|_| ())?;

                // Check if any bridge is running
                if !state
                    .active_sessions
                    .read()
                    .await
                    .iter()
                    .any(|(_, v)| session::SessionType::is_bridge(v))
                {
                    break;
                }
            }
        }
    }
}

/// Lookup external internet address
#[instrument(parent = None, name = "Lookup ", skip_all, fields(protocol = ?protocol, local = %local, server = %server))]
pub async fn lookup(
    config: Config,
    protocol: NetworkProtocol,
    local: SocketAddr,
    server: &str,
) -> Result<ExternalAddress, ()> {
    // Resolve server address
    let server_address = lookup_host(server)
        .await
        .map_err(map_info!("Failed to lookup server address"))
        .map(|addrs| {
            addrs
                .filter(|addr| addr.is_ipv4() == local.is_ipv4())
                .next()
                .ok_or_else(|| info!("No suitable address resolved"))
        })??;

    // Create server connection
    let mut stream = match protocol {
        NetworkProtocol::Tcp => {
            let socket = utils::create_tcp_socket_in_domain(&local, local.port())?;
            let socket = timeout(
                config.stun_tcp_response_timeout,
                socket.connect(server_address),
            )
            .await
            .map_err(|_| info!("Failed to connect to {server_address}: Timeout"))?
            .map_err(map_info!("Failed to connect to {server_address}"))?;
            socket.into()
        }
        NetworkProtocol::Udp => {
            let socket = utils::create_udp_socket_in_domain(&local, local.port())?;
            socket
                .connect(server_address)
                .await
                .map_err(map_info!("Failed to connect to {server_address}"))?;
            socket.into()
        }
    };

    // Perform stun request
    let external_address = stun::lookup_external_address(config.clone(), &mut stream).await?;

    // Unclean socket shutdown may cause an OS to temporarily disallow new reconnection
    if let RouterStream::Tcp(ref mut stream) = stream {
        stream
            .shutdown()
            .await
            .map_err(map_info!("Failed to close connection"))
            .ok();
    }

    debug!("Resolved: {}", external_address);

    Ok(ExternalAddress {
        local,
        external: external_address,
        protocol,
    })
}

const MAXIMUM_EXPECTED_STUN_PACKET_SIZE: usize = 1024;

#[instrument(name = " STUN protocol", skip_all)]
pub async fn lookup_external_address(
    config: Config,
    stream: &mut RouterStream,
) -> Result<SocketAddr, ()> {
    // Encode request
    let request = MessageEncoder::<Attribute>::new()
        .encode_into_bytes(Message::new(
            MessageClass::Request,
            BINDING,
            TransactionId::new([0; 12]),
        ))
        .expect("Failed to encode STUN request");

    // Send request and decode response
    let mut decoder = MessageDecoder::<Attribute>::new();
    match stream {
        RouterStream::Tcp(stream) => {
            let mut stream = BufReader::with_capacity(MAXIMUM_EXPECTED_STUN_PACKET_SIZE, stream);

            stream
                .write_all(request.as_slice())
                .await
                .map_err(map_warn!("Failed to send request"))?;

            let mut last_len = 0usize;
            loop {
                let buf = timeout(config.stun_tcp_response_timeout, stream.fill_buf())
                    .await
                    .map_err(|_| warn!("Failed to read from socket: Timeout"))?
                    .map_err(map_warn!("Failed to read from socket"))?;
                if last_len == buf.len() {
                    return Err(warn!("Socket closed"));
                }
                last_len = buf.len();

                let consumed = decoder
                    .decode(buf, bytecodec::Eos::new(false))
                    .map_err(map_warn!("Failed to decode server response"))?;

                stream.consume(consumed);

                if decoder.is_idle() {
                    break;
                }
            }
        }
        RouterStream::Udp(stream) => {
            let mut is_timeout = true;
            for _ in 0..config.stun_udp_retry_count {
                stream
                    .send(request.as_slice())
                    .await
                    .map_err(map_warn!("Failed to send request"))?;

                let mut buf = [0u8; MAXIMUM_EXPECTED_STUN_PACKET_SIZE];
                let mut consumed = 0usize;
                loop {
                    let written = timeout(
                        config.stun_udp_response_timeout,
                        stream.recv(&mut buf[consumed..]),
                    )
                    .await;
                    let written = match written {
                        Ok(written) => {
                            is_timeout = false;
                            written.map_err(map_warn!("Failed to receive from socket"))?
                        }
                        Err(_) => break,
                    };

                    let last_consumed = decoder
                        .decode(&buf[..consumed + written], bytecodec::Eos::new(false))
                        .map_err(map_warn!("Failed to decode server response"))?;

                    buf.copy_within(last_consumed..consumed + written, 0);
                    consumed = consumed + written - last_consumed;

                    if decoder.is_idle() {
                        break;
                    }
                }
            }
            if is_timeout {
                info!("Failed to receive from socket: Timeout");
                return Err(());
            }
        }
    };

    let decoded = decoder
        .finish_decoding()
        .map_err(map_warn!("Failed to decode server response"))?
        .map_err(|err| warn!("Failed to decode server response {}", err.error()))?;

    let attrs = decoded;
    if let Some(attr) = attrs.get_attribute::<attributes::XorMappedAddress>() {
        return Ok(attr.address());
    }
    if let Some(attr) = attrs.get_attribute::<attributes::XorMappedAddress2>() {
        return Ok(attr.address());
    }
    if let Some(attr) = attrs.get_attribute::<attributes::MappedAddress>() {
        return Ok(attr.address());
    }

    warn!(
        "Unable to find address attribute in server response: {:#?}",
        attrs
    );
    Err(())
}
