use std::net::{Ipv6Addr, SocketAddrV6};

mod cancellation;
mod defer;
mod macros;
mod sockets;
mod timeout;

pub use cancellation::*;
pub use defer::*;
pub use sockets::*;
pub use timeout::*;

/// Yggdrasil IPv6 address appears a lot in the logs, so it should be short
pub fn pretty_ip(ip: Ipv6Addr) -> String {
    let [f1, f2, .., l1, l2] = ip.segments();
    format!("[{f1:x}:{f2:x}:…:{l1:x}:{l2:x}]")
}

pub fn pretty_addr(addr: SocketAddrV6) -> String {
    format!("{}:{}", pretty_ip(*addr.ip()), addr.port())
}
