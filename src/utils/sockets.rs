use socket2::{Domain, Protocol, Socket, Type};
use std::{
    future::Future,
    io::ErrorKind,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket},
};

use crate::{map_error, IoResult, SilentResult};

/// Shorthand for read/write async stream
pub trait RwStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> RwStream for T {}

/// Common interface for UdpSocket and TcpStream
pub trait RwSocket {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = IoResult<()>>;
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = IoResult<usize>>;
    fn is_unreliable(&self) -> bool;
}

impl RwSocket for UdpSocket {
    async fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
        match self.send(buf).await {
            Ok(n) if n != buf.len() => Err(ErrorKind::UnexpectedEof.into()),
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }
    async fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.recv(buf).await
    }
    fn is_unreliable(&self) -> bool {
        true
    }
}

impl RwSocket for TcpStream {
    async fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
        AsyncWriteExt::write_all(self, buf).await
    }
    async fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        AsyncReadExt::read(self, buf).await
    }
    fn is_unreliable(&self) -> bool {
        false
    }
}

pub fn create_tcp_socket_ipv6(port: u16) -> SilentResult<TcpSocket> {
    create_tcp_socket((Ipv6Addr::UNSPECIFIED, port).into())
}

pub fn create_tcp_socket_ipv4(port: u16) -> SilentResult<TcpSocket> {
    create_tcp_socket((Ipv4Addr::UNSPECIFIED, port).into())
}

pub fn create_tcp_socket_in_domain(domain: &SocketAddr, port: u16) -> SilentResult<TcpSocket> {
    match domain {
        SocketAddr::V4(_) => create_tcp_socket_ipv4(port),
        SocketAddr::V6(_) => create_tcp_socket_ipv6(port),
    }
}

pub fn create_tcp_socket(bind_to: SocketAddr) -> SilentResult<TcpSocket> {
    let map_err = map_error!("Failed to create socket");

    let socket = Socket::new(
        match bind_to {
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

    socket.bind(&bind_to.into()).map_err(map_err)?;

    Ok(TcpSocket::from_std_stream(socket.into()))
}

pub fn create_udp_socket_ipv6(port: u16) -> SilentResult<UdpSocket> {
    create_udp_socket((Ipv6Addr::UNSPECIFIED, port).into())
}

pub fn create_udp_socket_ipv4(port: u16) -> SilentResult<UdpSocket> {
    create_udp_socket((Ipv4Addr::UNSPECIFIED, port).into())
}

pub fn create_udp_socket_in_domain(domain: &SocketAddr, port: u16) -> SilentResult<UdpSocket> {
    match domain {
        SocketAddr::V4(_) => create_udp_socket_ipv4(port),
        SocketAddr::V6(_) => create_udp_socket_ipv6(port),
    }
}

/// NOTE: Unconnected UDP socket steals all traffic from the global listener
pub fn create_udp_socket(bind_to: SocketAddr) -> SilentResult<UdpSocket> {
    let map_err = map_error!("Failed to crate socket");

    let socket = Socket::new(
        match bind_to {
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

    socket.bind(&bind_to.into()).map_err(map_err)?;

    UdpSocket::from_std(socket.into()).map_err(map_err)
}

pub fn into_std_tcp_socket(socket: TcpStream) -> SilentResult<std::net::TcpStream> {
    let map_err = map_error!("Failed to modify socket");

    let socket = socket.into_std().map_err(map_err)?;
    socket.set_nonblocking(false).map_err(map_err)?;
    Ok(socket)
}

pub fn into_std_udp_socket(socket: UdpSocket) -> SilentResult<std::net::UdpSocket> {
    let map_err = map_error!("Failed to modify socket");

    let socket = socket.into_std().map_err(map_err)?;
    socket.set_nonblocking(false).map_err(map_err)?;
    Ok(socket)
}
