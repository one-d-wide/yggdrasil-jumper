use super::*;

pub trait RW: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> RW for T {}
pub type RWSocket = Box<dyn RW>;

pub fn create_tcp_socket_ipv6(port: u16) -> Result<TcpSocket, ()> {
    create_tcp_socket(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
}

pub fn create_tcp_socket_ipv4(port: u16) -> Result<TcpSocket, ()> {
    create_tcp_socket(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
}

pub fn create_tcp_socket_in_domain(domain: &SocketAddr, port: u16) -> Result<TcpSocket, ()> {
    match domain {
        SocketAddr::V4(_) => create_tcp_socket_ipv4(port),
        SocketAddr::V6(_) => create_tcp_socket_ipv6(port),
    }
}

#[instrument(name = "New socket ", skip_all, fields(address = %address))]
pub fn create_tcp_socket(address: SocketAddr) -> Result<TcpSocket, ()> {
    let map_err = map_error!("Failed to create socket");

    let socket = Socket::new(
        match address {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        },
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .map_err(map_err)?;

    socket.set_nonblocking(true).map_err(map_err)?;
    socket.set_reuse_address(true).map_err(map_err)?;
    #[cfg(unix)]
    socket.set_reuse_port(true).map_err(map_err)?;

    socket
        .bind(&From::<SocketAddr>::from(address))
        .map_err(map_err)?;

    Ok(TcpSocket::from_std_stream(socket.into()))
}

pub fn create_udp_socket_ipv6(port: u16) -> Result<UdpSocket, ()> {
    create_udp_socket(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
}

pub fn create_udp_socket_ipv4(port: u16) -> Result<UdpSocket, ()> {
    create_udp_socket(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
}

pub fn create_udp_socket_in_domain(domain: &SocketAddr, port: u16) -> Result<UdpSocket, ()> {
    match domain {
        SocketAddr::V4(_) => create_udp_socket_ipv4(port),
        SocketAddr::V6(_) => create_udp_socket_ipv6(port),
    }
}

pub fn create_udp_socket(address: SocketAddr) -> Result<UdpSocket, ()> {
    let map_err = map_error!("Failed to crate socket");

    let socket = Socket::new(
        match address {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .map_err(map_err)?;

    socket.set_nonblocking(true).map_err(map_err)?;
    socket.set_reuse_address(true).map_err(map_err)?;
    #[cfg(unix)]
    socket.set_reuse_port(true).map_err(map_err)?;

    socket
        .bind(&From::<SocketAddr>::from(address))
        .map_err(map_err)?;

    UdpSocket::from_std(socket.into()).map_err(map_err)
}
