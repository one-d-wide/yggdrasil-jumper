use super::*;

pub trait RW: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> RW for T {}
pub type RWSocket = Box<dyn RW>;

pub fn new_socket_ipv6(port: u16) -> Result<TcpSocket, ()> {
    new_socket(SocketAddr::from(([0; 16], port)))
}

pub fn new_socket_ipv4(port: u16) -> Result<TcpSocket, ()> {
    new_socket(SocketAddr::from(([0; 4], port)))
}

pub fn new_socket_in_domain(domain: &SocketAddr, port: u16) -> Result<TcpSocket, ()> {
    match domain {
        SocketAddr::V4(_) => new_socket_ipv4(port),
        SocketAddr::V6(_) => new_socket_ipv6(port),
    }
}

#[instrument(name = " New socket ", skip_all, fields(address = %address))]
fn new_socket(address: SocketAddr) -> Result<TcpSocket, ()> {
    let map_err = map_error!("Failed to crate socket");

    let socket = Socket::new(
        match address {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        },
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .map_err(map_err)?;

    let timeout = Duration::from_secs(10);
    socket.set_read_timeout(Some(timeout)).map_err(map_err)?;
    socket.set_write_timeout(Some(timeout)).map_err(map_err)?;
    socket.set_nonblocking(true).map_err(map_err)?;
    socket.set_reuse_address(true).map_err(map_err)?;
    #[cfg(unix)]
    socket.set_reuse_port(true).map_err(map_err)?;
    socket
        .bind(&From::<SocketAddr>::from(address))
        .map_err(map_err)?;

    Ok(TcpSocket::from_std_stream(socket.into()))
}
