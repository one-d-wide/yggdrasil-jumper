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
 *  13. Try NAT traversal.
 *  14. Start router bridge
 *
 * All commination is in length-delimited JSON packets using `tokio_util::codec::LengthDelimitedCodec`.
*/

/// Align connection time with session's uptime to simultaneously start firewall traversal
pub const ALIGN_UPTIME_TIMEOUT: f64 = 20.0;

/// Time to wait for inactive session to close
pub const INACTIVITY_DELAY: f64 = 1.5 * 60.0;
pub const INACTIVITY_DELAY_PERIOD: f64 = 5.0 * 60.0;

pub const VERSION: &str = "yggdrasil-jumper-v0.1";

pub const TRAVERSAL_SUCCEED: &str = "traversal-succeed";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: String,
    ipv4: bool,
    ipv6: bool,
    protocols: Vec<HeaderRouterProtocol>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, EnumString, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
enum HeaderRouterProtocol {
    // The highest priority
    Tcp,
    Tls { server_available: bool },
    Quic { server_available: bool },
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
    pub fn choose_with_highest_priority(
        iter: impl Iterator<Item = (Self, Self)>,
    ) -> Option<(Self, Self)> {
        let get_priority = |protocol| {
            Self::iter()
                .rev()
                .enumerate()
                .find_map(|(priority, p)| {
                    (PeeringProtocol::from(p) == PeeringProtocol::from(protocol))
                        .then_some(priority as u64)
                })
                .unwrap()
        };
        iter.max_by_key(|(p, _)| get_priority(*p))
    }
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
        let router_version = state.router.read().await.version;
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
            .filter_map(|p| p.is_supported_by_router(router_version).then_some(*p))
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
    sink.send(bytes::Bytes::from(
        serde_json::to_vec(&protocol::Header {
            version: protocol::VERSION.to_string(),
            ipv4: ipv4,
            ipv6: ipv6,
            protocols: self_protocols.clone(),
        })
        .expect("Protocol request header can't be serialized"),
    ))
    .await
    .map_err(map_info!("Failed to send protocol header to peer"))?;

    // 3. Receive remote `header` from peer
    let remote_header: protocol::Header = serde_json::from_reader(std::io::Cursor::new(
        stream
            .next()
            .await
            .ok_or_else(|| info!("Failed to receive header: Connection closed"))?
            .map_err(map_info!("Failed to receive incoming header"))?,
    ))
    .map_err(map_info!("Failed to parse incoming header"))?;

    // 4. Check if version is correct
    if remote_header.version != protocol::VERSION {
        return Err(info!(
            "Protocol version mismatch: expected: {:?}, received: {:?}",
            remote_header.version,
            protocol::VERSION
        ));
    }

    // 5. Check if protocol lists are intersected
    let protocols = self_protocols.iter().filter_map(|self_protocol| {
        remote_header
            .protocols
            .iter()
            .find(|remote_protocol| (*self_protocol).compatible(**remote_protocol))
            .map(|remote_protocol| (*self_protocol, *remote_protocol))
    });
    let (self_protocol, remote_protocol) = HeaderRouterProtocol::choose_with_highest_priority(protocols)
        .ok_or(())
        .map_err(|_| info!(
            "Can't find common router transmit protocols with remote:\n self {self_protocols:#?}, remote: {:#?}",
            remote_header.protocols
        ))?;

    // 6. Check if address ranges are intersected
    let external = (|| {
        if ipv6 && remote_header.ipv6 {
            if let Some(external) = state
                .watch_external
                .borrow()
                .iter()
                .filter(|e| e.external.is_ipv6())
                .filter(|e| e.protocol == PeeringProtocol::from(self_protocol).into())
                .next()
            {
                return Ok(external.external);
            }
        }
        if ipv4 && remote_header.ipv4 {
            if let Some(external) = state
                .watch_external
                .borrow()
                .iter()
                .filter(|e| e.external.is_ipv4())
                .filter(|e| e.protocol == PeeringProtocol::from(self_protocol).into())
                .next()
            {
                return Ok(external.external);
            }
        }
        warn!(
            "Have no address to share with peer (self: v4={}, v6={}; remote: v4={}, v6={})",
            ipv4, ipv6, remote_header.ipv4, remote_header.ipv6
        );
        Err(())
    })()?;

    // 7. Send self external address
    sink.send(
        serde_json::to_vec(&external)
            .expect("Self external addresses can't be serialized")
            .into(),
    )
    .await
    .map_err(map_info!("Failed to send self external addresses to peer"))?;

    // 8. Receive peer's external address
    let remote_external: SocketAddr = serde_json::from_slice(
        &stream
            .next()
            .await
            .ok_or_else(|| info!("Failed to receive peer's external addresses: Connection closed"))?
            .map_err(map_info!("Failed to receive peer's external addresses"))?,
    )
    .map_err(map_info!("Failed to parse peer's external addresses"))?;

    // 10. Validate external addresses
    match (external, remote_external) {
        (SocketAddr::V6(_), SocketAddr::V6(_)) => (),
        (SocketAddr::V4(_), SocketAddr::V4(_)) => (),
        _ => {
            info!("External addresses have incompatible ranges: self {external:?}, remote {remote_external:?}");
            return Err(());
        }
    }

    // 11. Create message pipe for traversal process
    let local = state
        .watch_external
        .borrow()
        .iter()
        .find(|addr| addr.external == external)
        .ok_or_else(|| info!("Expected external address unavailable: {external}"))?
        .local;
    let remote = remote_external;

    let notify_traversed = oneshot::channel::<()>();
    spawn(async move {
        if let Ok(_) = notify_traversed.1.await {
            sink.send(
                serde_json::to_vec(TRAVERSAL_SUCCEED)
                    .expect("String can't be serialized")
                    .into(),
            )
            .await
            .map_err(map_info!("Failed to send self external addresses to peer"))?;
        }

        Result::<(), ()>::Ok(())
    });

    let mut check_traversed = oneshot::channel::<()>();
    spawn(async move {
        let response = select! {
            response = stream.next() => {
                response.ok_or_else(|| {
                    info!("Failed to receive peer's connection status: Connection closed")
                })?
                .map_err(map_info!("Failed to receive peer's connection status"))?
            }
            _ = check_traversed.0.closed() => return Err(()),
        };

        let status: String = serde_json::from_slice(&response)
            .map_err(map_info!("Failed to parse peer's connection status"))?;

        if status == TRAVERSAL_SUCCEED {
            check_traversed.0.send(()).ok();

            Result::<(), ()>::Ok(())
        } else {
            info!("Received unknown peer's connection status");

            Result::<(), ()>::Err(())
        }
    });

    // 12. Select connection mode
    let connection_mode = {
        match self_protocol.into() {
            PeeringProtocol::Tcp => ConnectionMode::Any,
            PeeringProtocol::Tls | PeeringProtocol::Quic => {
                if self_protocol.server_available() == remote_protocol.server_available() {
                    if address.ip() < &state.router.read().await.address {
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

    // 13. Try NAT traversal.
    let socket = network::traverse(
        config.clone(),
        state.clone(),
        self_protocol.into(),
        local.port(),
        remote,
        *address.ip(),
        Some(notify_traversed.0),
        Some(check_traversed.1),
    )
    .await
    .map_err(map_debug!("NAT traversal failed"))?;

    // 14. Start router bridge
    bridge::start_bridge(
        config,
        state,
        self_protocol.into(),
        connection_mode,
        remote,
        *address.ip(),
        socket,
    )
    .await
}
