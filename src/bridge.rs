use super::*;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionMode {
    Any,
    AsClient,
    AsServer,
}

impl ConnectionMode {
    pub fn as_client(self) -> bool {
        matches!(self, Self::Any | Self::AsClient)
    }
    pub fn as_server(self) -> bool {
        matches!(self, Self::Any | Self::AsServer)
    }
}

#[derive(Debug)]
pub enum RouterStream {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl From<TcpStream> for RouterStream {
    fn from(value: TcpStream) -> Self {
        Self::Tcp(value)
    }
}

impl From<UdpSocket> for RouterStream {
    fn from(value: UdpSocket) -> Self {
        Self::Udp(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

impl From<PeeringProtocol> for NetworkProtocol {
    fn from(value: PeeringProtocol) -> Self {
        match value {
            PeeringProtocol::Tcp | PeeringProtocol::Tls => Self::Tcp,
            PeeringProtocol::Quic => Self::Udp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(EnumString, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum PeeringProtocol {
    Tcp,
    Tls,
    Quic,
}

impl PeeringProtocol {
    pub fn is_supported_by_router(&self, version: RouterVersion) -> bool {
        match self {
            Self::Tcp | Self::Tls => true,
            Self::Quic => !matches!(
                version,
                RouterVersion::__v0_4_4 | RouterVersion::v0_4_5__v0_4_7
            ),
        }
    }

    pub fn id(&self) -> &'static str {
        self.into()
    }
}

pub struct Nonce {
    nonce: String,
}
impl Nonce {
    pub fn new() -> Self {
        let nonce: u64 = rand::random();
        format!("{nonce:016x}").try_into().unwrap()
    }
    pub fn concat(&self, other: &Nonce) -> String {
        if self.nonce > other.nonce {
            self.nonce.clone() + &other.nonce
        } else {
            other.nonce.clone() + &self.nonce
        }
    }
    pub fn as_str(&self) -> &str {
        self.nonce.as_str()
    }
}
impl TryFrom<String> for Nonce {
    type Error = ();
    fn try_from(nonce: String) -> Result<Self, Self::Error> {
        (nonce.len() == 16
            && nonce.as_bytes().iter().all(|b| {
                let b = *b;
                (b >= b'0' && b <= b'9') | (b >= b'a' && b <= b'z') | (b >= b'A' && b <= b'Z')
            }))
        .then_some(Self { nonce })
        .ok_or(())
    }
}

pub const QUIC_MAXIMUM_PACKET_SIZE: usize = 1500;

#[instrument(parent = None, name = "Bridge ", skip_all, fields(peer = ?monitor_address, remote = %peer_addr, uri = %uri))]
async fn bridge(
    config: Config,
    state: State,
    monitor_address: Ipv6Addr,
    peer_addr: SocketAddr,
    peer: RouterStream,
    ygg: RouterStream,
    uri: String,
) -> Result<(), ()> {
    info!("Connected");

    let mut relays = JoinSet::new();

    match (peer, ygg) {
        // Relay UDP traffic
        (RouterStream::Tcp(peer), RouterStream::Tcp(ygg)) => {
            let (peer_read, peer_write) = peer.into_split();
            let (ygg_read, ygg_write) = ygg.into_split();

            use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
            let tcp_relay = |reader: OwnedReadHalf, mut writer: OwnedWriteHalf| async move {
                let mut reader = BufReader::new(reader);
                loop {
                    let buf = reader
                        .fill_buf()
                        .await
                        .map_err(map_debug!("Failed to read"))?;
                    let len = buf.len();
                    if len == 0 {
                        debug!("Connection closed");
                        return Result::<(), ()>::Ok(());
                    }
                    writer
                        .write_all(buf)
                        .await
                        .map_err(map_debug!("Failed to write"))?;
                    trace!("Sent {} byte(s)", len);
                    reader.consume(len);
                }
            };

            relays.spawn(
                tcp_relay(ygg_read, peer_write)
                    .instrument(error_span!(" Router -> Peer TCP relay")),
            );
            relays.spawn(
                tcp_relay(peer_read, ygg_write)
                    .instrument(error_span!(" Peer -> Router TCP relay")),
            );
        }
        // Relay UDP traffic
        (RouterStream::Udp(peer), RouterStream::Udp(ygg)) => {
            let peer_read = Arc::new(peer);
            let peer_write = peer_read.clone();
            let ygg_read = Arc::new(ygg);
            let ygg_write = ygg_read.clone();

            let udp_relay = |reader: Arc<UdpSocket>, writer: Arc<UdpSocket>| async move {
                let mut buf = Box::new([0u8; QUIC_MAXIMUM_PACKET_SIZE]);
                loop {
                    let received = reader
                        .recv(&mut buf[..])
                        .await
                        .map_err(map_debug!("Failed to recv"))?;

                    writer
                        .send(&buf[..received])
                        .await
                        .map_err(map_debug!("Failed to send"))?;
                    trace!("Sent {} byte(s)", &buf[..received].len());
                }
            };

            relays.spawn(
                udp_relay(peer_read, ygg_write)
                    .instrument(error_span!(" Peer -> Router UDP relay")),
            );
            relays.spawn(
                udp_relay(ygg_read, peer_write)
                    .instrument(error_span!(" Router -> Peer UDP relay")),
            );
        }

        _ => unreachable!(),
    };

    let mut watch_peers = state.watch_peers.clone();
    let mut watch_sessions = state.watch_sessions.clone();
    let mut delay_shutdown = Some(Instant::now());

    // Record the bridge
    let old = state
        .active_sessions
        .write()
        .await
        .insert(monitor_address, SessionType::Bridge);
    if let Some(SessionType::Bridge) = old {
        // Multiple connections with the same identifiers are not allowed by the OS.
        warn!("Bridge is already exist");
        return Err(());
    }

    // Remove record when bridge is closed
    let _bridge_record_guard = defer_async({
        let state = state.clone();
        async move {
            state.active_sessions.write().await.remove(&monitor_address);
        }
    });

    // Wait until bridge is unused
    loop {
        select! {
            // Return if relays are closed
            _ = relays.join_next() => {
                relays.abort_all();
                return Err(info!("Bridge is closed"));
            },

            // Return if peer is not connected or wrong node is peered
            err = watch_peers.changed() => {
                err.map_err(|_| ())?;
                let peers = watch_peers.borrow();

                if let Some(ref timer) = delay_shutdown {
                   if timer.elapsed() > config.peer_unconnected_check_delay {
                        delay_shutdown = None;
                   }
                }

                // Return if peer is not connected
                if delay_shutdown.is_none()
                    && !peers
                        .iter()
                        .filter(|peer| peer.up)
                        .any(|peer| peer.remote.as_ref() == Some(&uri))
                {
                    return Err(info!("Bridge is not connected as peer"));
                }

                // Return if peer is of unexpected address
                if let Some(connected_address) = peers.iter()
                        .filter(|peer| peer.remote.as_ref() == Some(&uri))
                        .filter_map(|peer| peer.address)
                        .find(|address| address != &monitor_address)
                {
                    return Err(warn!("Bridge had been connected to the wrong node: {connected_address}"));
                }
            },

            // Return if session is closed
            err = watch_sessions.changed()  => {
                err.map_err(|_| ())?;
                if ! watch_sessions.borrow().iter().any(|session| &session.address == &monitor_address) {
                    return Err(info!("Associated session is closed"));
                }
            },

            // Return if cancelled
            _ = state.cancellation.cancelled() => return Ok(()),
        }
    }
}

#[instrument(parent = None, name = "Connect bridge ", skip_all, fields(mode = ?connection_mode, peer = ?monitor_address, remote = %peer_addr))]
pub async fn start_bridge(
    config: Config,
    state: State,
    protocol: PeeringProtocol,
    connection_mode: ConnectionMode,
    peer_addr: SocketAddr,
    monitor_address: Ipv6Addr,
    socket: RouterStream,
    server_password: Option<String>,
) -> Result<(), ()> {
    debug!("Started");

    // Generate yggdrasil peer uri for given address and protocol
    let uri = |local_addr| {
        format!(
            "{}://{}:{}",
            protocol.id(),
            match local_addr {
                SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            },
            local_addr.port(),
        )
    };
    let map_addr_err = |err: IoResult<SocketAddr>| {
        err.map_err(map_warn!("Failed to retrieve local socket address"))
    };

    // Try connect self to the router listen address directly
    for url in config
        .yggdrasil_listen
        .iter()
        .filter(|_| connection_mode.as_client())
    {
        let mut iter = url.as_str().split("://");
        let prot = iter.next().map(PeeringProtocol::from_str);
        let addr = iter.next().map(|a| a.split('?').next());

        let ygg = match (prot, addr) {
            (Some(Ok(p)), Some(Some(addr))) if p == protocol => {
                if p != protocol {
                    continue;
                }
                match protocol {
                    PeeringProtocol::Tcp | PeeringProtocol::Tls => {
                        let ygg =
                            timeout(config.connect_as_client_timeout, TcpStream::connect(addr))
                                .await
                                .map_err(map_warn!(
                                    "Failed to connect to router listen socket at {addr}"
                                ))
                                .and_then(|e| {
                                    e.map_err(map_warn!(
                                        "Failed to connect to router listen socket at {addr}"
                                    ))
                                })
                                .ok();
                        let addr = ygg
                            .as_ref()
                            .and_then(|ygg| map_addr_err(ygg.local_addr()).ok());
                        ygg.map(|ygg| ygg.into()).zip(addr.map(uri))
                    }
                    PeeringProtocol::Quic => {
                        let addrs = tokio::net::lookup_host(addr)
                            .await
                            .map_err(map_warn!("Failed to lookup addr {addr}"))
                            .ok();

                        let addr = addrs.and_then(|mut a| a.next());

                        if let Some(addr) = addr {
                            let ygg = utils::create_udp_socket_in_domain(&addr, 0)?;
                            ygg.connect(addr)
                                .await
                                .map_err(map_warn!("Failed to connect UDP socket to {addr}"))
                                .ok();

                            let addr = map_addr_err(ygg.local_addr()).ok();

                            Some(ygg.into()).zip(addr.map(uri))
                        } else {
                            None
                        }
                    }
                }
            }
            _ => {
                debug!("Router address is unavailable: {}", url);
                continue;
            }
        };

        if let Some((ygg, uri)) = ygg {
            return bridge(config, state, monitor_address, peer_addr, socket, ygg, uri).await;
        }
    }

    // Fallback. Try connect router to self temporary socket
    if !connection_mode.as_server() {
        warn!("Failed to find suitable server socket");
        return Err(());
    }

    // Register peering socket as a server
    let remove_peer = {
        let state = state.clone();
        |uri: String| {
            // Create active cancellation token
            let cancellation = state.cancellation.get_active();
            async move {
                // Attach active cancellation token to the current scope
                let _cancellation = cancellation;
                state
                    .router
                    .admin_api
                    .write()
                    .await
                    .remove_peer(uri, None)
                    .await
                    .map_err(map_debug!("Failed to query admin api"))?
                    .map_err(map_debug!("Failed to remove local socket from peer list"))
            }
        }
    };
    let remove_peer_guard = &mut None;
    let add_peer = {
        let state = state.clone();
        |uri: String| async move {
            // Add peer now
            state
                .router
                .admin_api
                .write()
                .await
                .add_peer(
                    server_password
                        .map(|p| format!("{uri}?password={p}"))
                        .unwrap_or_else(|| uri.clone()),
                    None,
                )
                .await
                .map_err(map_warn!("Failed to query admin api"))?
                .map_err(map_warn!("Failed to add local socket as peer"))?;

            // Remove peer later
            *remove_peer_guard = Some(defer_async(remove_peer(uri)));
            Ok(())
        }
    };

    let (ygg, uri) = match protocol {
        PeeringProtocol::Tcp | PeeringProtocol::Tls => {
            // Create socket
            let ygg = utils::create_tcp_socket_in_domain(&peer_addr, 0)?
                .listen(1)
                .map_err(map_warn!("Failed to create local inbound socket"))?;

            // Register socket as a peer
            let uri = uri(map_addr_err(ygg.local_addr())?);
            add_peer(uri.clone()).await?;

            // Await incoming connection
            let (ygg, _) = timeout(config.connect_as_client_timeout, ygg.accept())
                .await
                .map_err(map_warn!("Failed to accept yggdrasil connection"))?
                .map_err(map_warn!("Failed to accept yggdrasil connection"))?;

            (RouterStream::Tcp(ygg), uri)
        }
        PeeringProtocol::Quic => {
            // Create socket
            let ygg = utils::create_udp_socket_in_domain(&peer_addr, 0)?;

            // Register socket as a peer
            let uri = uri(map_addr_err(ygg.local_addr())?);
            add_peer(uri.clone()).await?;

            // Await incoming packets
            let sender = timeout(config.connect_as_client_timeout, ygg.peek_sender())
                .await
                .map_err(map_warn!("Failed to peek yggdrasil connection"))?
                .map_err(map_warn!("Failed to peek yggdrasil connection"))?;

            // Connect socket to the sender of the first received packet
            ygg.connect(sender)
                .await
                .map_err(map_warn!("Failed to connect to yggdrasil socket"))?;

            (ygg.into(), uri)
        }
    };

    // Run bridge
    bridge(
        config,
        state.clone(),
        monitor_address,
        peer_addr,
        socket,
        ygg,
        uri.clone(),
    )
    .await
}
