use super::*;

/* Protocol stages:
 *  0. Select available external IP address ranges
 *  1. Select available router protocols
 *  2. Send `header` to peer
 *  3. Receive remote `header` from peer
 *  4. Check if version is correct
 *  5. Check if protocol lists are intersected
 *  6. Check if address ranges are intersected
 *  7. Send self external address
 *  8. Receive peer's external address
 *  10. Validate external addresses
 *  11. Create message pipe for traversal process
 *  12. Select connection mode
 *  13. Try NAT traversal
 *   *. If failed, retry with the next common protocol starting from pt. 6
 *  14. Start router bridge
 *
 * All commination is in length-delimited JSON packets using `tokio_util::codec::LengthDelimitedCodec`.
*/

/// Align connection time with session's uptime to simultaneously start firewall traversal
pub const ALIGN_UPTIME_TIMEOUT: f64 = 20.0;

/// Time to wait for inactive session to close
pub const INACTIVITY_DELAY: f64 = 1.5 * 60.0;
pub const INACTIVITY_DELAY_PERIOD: f64 = 5.0 * 60.0;

pub const VERSION_PREFIX: &str = "yggdrasil-jumper-v";
pub const VERSION_NUMBER: &str = "0.1";

pub const TRAVERSAL_SUCCEED: &str = "traversal-succeed";

#[derive(Serialize, Deserialize)]
struct Header {
    version: String,
    ipv4: bool,
    ipv6: bool,
    protocols: Vec<HeaderRouterProtocol>,
    nonce: Option<String>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, EnumIter, IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
enum HeaderRouterProtocol {
    // The highest priority
    Tcp,
    Quic { server_available: bool },
    Tls { server_available: bool },
    // The lowest priority
}

impl From<HeaderRouterProtocol> for PeeringProtocol {
    fn from(value: HeaderRouterProtocol) -> Self {
        match value {
            HeaderRouterProtocol::Tcp => Self::Tcp,
            HeaderRouterProtocol::Tls { .. } => Self::Tls,
            HeaderRouterProtocol::Quic { .. } => Self::Quic,
        }
    }
}

impl HeaderRouterProtocol {
    pub fn server_available(self) -> bool {
        match self {
            HeaderRouterProtocol::Tcp => true,
            HeaderRouterProtocol::Tls { server_available } => server_available,
            HeaderRouterProtocol::Quic { server_available } => server_available,
        }
    }
    pub fn compatible(self, other: Self) -> bool {
        PeeringProtocol::from(self) == other.into()
            && (self.server_available() || other.server_available())
    }
    pub fn priority_ascending(&self) -> u64 {
        Self::iter()
            .find_position(|protocol| {
                PeeringProtocol::from(*self) == PeeringProtocol::from(*protocol)
            })
            .map(|(priority, _)| priority as u64)
            .unwrap()
    }
}

async fn receive_message<S, D, M>(stream: &mut S, message_description: &D) -> Result<M, ()>
where
    S: StreamExt<Item = IoResult<BytesMut>> + Unpin,
    D: Display,
    M: for<'a> Deserialize<'a>,
{
    serde_json::from_slice(
        &stream
            .next()
            .await
            .ok_or_else(|| info!("Failed to receive {message_description}: Connection closed"))?
            .map_err(map_info!("Failed to receive {message_description}"))?,
    )
    .map_err(map_info!("Failed to parse {message_description}"))
}

async fn send_message<S, D, M>(sink: &mut S, message: &M, message_description: &D) -> Result<(), ()>
where
    S: SinkExt<Bytes, Error = IoError> + Unpin,
    D: Display,
    M: Serialize,
{
    sink.send(Bytes::from(serde_json::to_vec(message).map_err(
        map_error!("Failed to serialize {message_description}"),
    )?))
    .await
    .map_err(map_info!("Failed to send {message_description}"))
}

#[instrument(parent = None, name = "Session ", skip_all, fields(peer = %address))]
pub async fn try_session(
    config: Config,
    state: State,
    socket: TcpStream,
    address: SocketAddrV6,
) -> Result<(), ()> {
    let (mut sink, mut stream) = Framed::new(socket, LengthDelimitedCodec::new()).split();

    // 0. Select available external IP address ranges
    let (ipv6, ipv4) = {
        let addresses = state.watch_external.borrow();
        (
            config.allow_ipv6 && addresses.iter().map(|a| a.external).any(|a| a.is_ipv6()),
            config.allow_ipv4 && addresses.iter().map(|a| a.external).any(|a| a.is_ipv4()),
        )
    };

    // 1. Select available router protocols
    let self_protocols: Vec<HeaderRouterProtocol> = {
        let addresses = state.watch_external.borrow();
        let server_available = |protocol: PeeringProtocol| {
            config
                .yggdrasil_listen
                .iter()
                .any(|a| a.split("://").next() == Some(protocol.id()))
        };

        config
            .yggdrasil_protocols
            .iter()
            .filter(|p| addresses.iter().any(|a| a.protocol == (**p).into()))
            .filter_map(|p| {
                p.is_supported_by_router(state.router.version.clone())
                    .then_some(*p)
            })
            .map(|protocol| match protocol {
                PeeringProtocol::Tcp => HeaderRouterProtocol::Tcp,
                PeeringProtocol::Tls => HeaderRouterProtocol::Tls {
                    server_available: server_available(protocol),
                },
                PeeringProtocol::Quic => HeaderRouterProtocol::Quic {
                    server_available: server_available(protocol),
                },
            })
            .collect()
    };

    // 2. Send `header` to peer
    let self_nonce = match state.router.version {
        _ if config.force_nonce_peering_password => true,
        RouterVersion::__v0_4_4 | RouterVersion::v0_4_5__v0_4_7 => false,
        _ => true,
    }
    .then(|| bridge::Nonce::new());
    send_message(
        &mut sink,
        &protocol::Header {
            version: protocol::VERSION_PREFIX.to_string() + protocol::VERSION_NUMBER,
            ipv4,
            ipv6,
            protocols: self_protocols.clone(),
            nonce: self_nonce.as_ref().map(|n| n.as_str().to_string()),
        },
        &"protocol header",
    )
    .await?;

    // 3. Receive remote `header` from peer
    let remote_header: protocol::Header = receive_message(&mut stream, &"incoming header").await?;

    // 4. Check if version is correct
    let remote_header_version = remote_header.version.strip_prefix(VERSION_PREFIX).map(|v| {
        v.split('.')
            .take(2)
            .filter_map(|i| str::parse(i).ok())
            .collect::<Vec<u32>>()
    });
    if let None = remote_header_version {
        return Err(info!(
            "Incompatible protocol version: self: {}{}, received: {:?}",
            protocol::VERSION_PREFIX,
            protocol::VERSION_NUMBER,
            remote_header.version,
        ));
    };

    // TODO: Consider enforcing the check by default for future versions
    let remote_nonce = match remote_header.nonce.map(bridge::Nonce::try_from) {
        Some(Ok(nonce)) => Some(nonce),
        Some(Err(())) => return Err(info!("Failed to parse remote `nonce`")),
        None if config.force_nonce_peering_password => {
            return Err(info!("Received remote header is missing `nonce`"))
        }
        None => None,
    };

    // 5. Check if protocol lists are intersected
    let mut common_protocols: Vec<(_, _)> = self_protocols
        .iter()
        .filter_map(|self_protocol| {
            remote_header
                .protocols
                .iter()
                .find(|remote_protocol| self_protocol.compatible(**remote_protocol))
                .map(|remote_protocol| (*self_protocol, *remote_protocol))
        })
        .collect();

    common_protocols.sort_unstable_by_key(|(self_protocol, _)| self_protocol.priority_ascending());

    let mut last_result = None;
    let mut last_received_externals = None;
    for (self_protocol, remote_protocol) in common_protocols {
        last_result = Some(async {
            // 6. Check if address ranges are intersected
            let external = {
                let externals = state
                    .watch_external
                    .borrow();
                let external = externals.iter()
                    .filter(|e| ipv6 && remote_header.ipv6 && e.external.is_ipv6())
                    .chain(externals.iter()
                        .filter(|e| ipv4 && remote_header.ipv4 && e.external.is_ipv4()))
                    .find(|e| e.protocol == PeeringProtocol::from(self_protocol).into());
                match external {
                    Some(external) => external.external.clone(),
                    None => {
                        warn!(
                            "Have no address to share with peer (self: v4={}, v6={}; remote: v4={}, v6={})",
                            ipv4, ipv6, remote_header.ipv4, remote_header.ipv6
                        );
                        return Err(());
                    },
                }
            };

            // 7. Send self external address
            send_message(&mut sink, &external, &"self external addresses").await?;

            // 8. Receive peer's external address
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum Message {
                External(SocketAddr),
                Status(String),
            }
            let remote_external =
                if let Some(external) = last_received_externals {
                    last_received_externals = None;
                    external
                } else {
                    loop {
                        if let Message::External(addr) = receive_message(&mut stream, &"remote external address or connection status").await? {
                            break addr;
                        }
                    }
                };

            // 10. Validate external addresses
            match (external, remote_external) {
                (SocketAddr::V6(_), SocketAddr::V6(_)) => (),
                (SocketAddr::V4(_), SocketAddr::V4(_)) => (),
                _ => {
                    return Err(info!("External addresses have incompatible ranges: self {external:?}, remote {remote_external:?}"));
                }
            }

            // 12. Select connection mode
            let connection_mode = {
                match self_protocol.into() {
                    PeeringProtocol::Tcp => ConnectionMode::Any,
                    PeeringProtocol::Tls | PeeringProtocol::Quic => {
                        if self_protocol.server_available() == remote_protocol.server_available() {
                            if address.ip() < &state.router.address {
                                ConnectionMode::AsClient
                            } else {
                                ConnectionMode::AsServer
                            }
                        } else {
                            if self_protocol.server_available() {
                                ConnectionMode::AsClient
                            } else {
                                ConnectionMode::AsServer
                            }
                        }
                    }
                }
            };

            let local = state
                .watch_external
                .borrow()
                .iter()
                .find(|addr| addr.external == external)
                .ok_or_else(|| info!("Expected external address unavailable: {external}"))?
                .local;

            // 11. Create message pipe for traversal process
            let (notify_sender, notify_receiver) = oneshot::channel::<()>();
            let (check_sender, check_receiver) = oneshot::channel::<()>();
            let mut notify_receiver = Some(notify_receiver);
            let mut check_sender = Some(check_sender);

            // 13. Try NAT traversal
            let traversal = spawn(network::traverse(
                config.clone(),
                state.clone(),
                self_protocol.into(),
                local.port(),
                remote_external,
                *address.ip(),
                Some(notify_sender),
                Some(check_receiver),
            ));
            let mut traversal = defer_arg(traversal, |h| h.abort());

            let mut socket = None;
            while let None = socket {
                select!{
                    join = traversal.deref_mut() => {
                        if let Ok(result) = join {
                            socket = Some(result.map_err(map_debug!("NAT traversal failed"))?
                                .map_err(map_debug!("NAT traversal unsuccessful"))?);
                        }
                        break;
                    },
                    err = async { notify_receiver.as_mut().unwrap().await }, if notify_receiver.is_some() => {
                        notify_receiver = None;
                        if let Ok(_) = err {
                            send_message(&mut sink, &TRAVERSAL_SUCCEED, &"self external addresses").await?;
                        }
                    },
                    message = receive_message(&mut stream, &"remote external address or connection status") => {
                        match message? {
                            Message::Status(status) => {
                                if status == TRAVERSAL_SUCCEED {
                                    check_sender.take().map(|s| s.send(()).ok());
                                } else {
                                    info!("Received unknown peer connection status");
                                }
                            },
                            Message::External(external) => {
                                last_received_externals = Some(external)
                            },
                        }
                    },
                };
            }

            let server_password = matches!(connection_mode, ConnectionMode::Any)
                .then_some(())
                .and(self_nonce.as_ref())
                .zip(remote_nonce.as_ref())
                .map(|(s, r)| s.concat(r) );

            if let Some(socket) = socket {
                // 14. Start router bridge
                return Ok(bridge::start_bridge(
                    config.clone(),
                    state.clone(),
                    self_protocol.into(),
                    connection_mode,
                    remote_external,
                    *address.ip(),
                    socket,
                    server_password,
                ));
            }

            Err(())
        }.await);

        if let Some(Ok(_)) = last_result {
            break;
        }
    }

    match last_result {
        Some(Ok(result)) => {
            // Close connection in the Yggdrasil space
            stream.reunite(sink).ok();

            result.await
        },
        Some(Err(err)) => Err(err),
        None => {
            Err(debug!(
                "Can't find common router transmit protocols with remote:\n self {self_protocols:#?}, remote: {:#?}",
                remote_header.protocols
            ))
        }
    }
}
