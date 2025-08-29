#![allow(clippy::result_unit_err)]

use std::{
    collections::{HashMap, HashSet},
    io::{Error as IoError, Result as IoResult},
    net::Ipv6Addr,
    sync::Arc,
};
use tokio::sync::{watch, RwLock};
use yggdrasilctl::{PeerEntry, SessionEntry};

pub mod admin_api;
pub mod bridge;
pub mod config;
pub mod network;
pub mod protocol;
pub mod proxy_tcp;
pub mod proxy_udp;
pub mod session;
pub mod stun;
pub mod utils;
pub mod yggdrasil_dpi;

pub use admin_api::RouterState;
pub use bridge::{ConnectionMode, PeeringProtocol, RouterStream};
pub use config::Config;
pub use network::InetTraversalSession;
pub use session::{SessionCache, SessionStage};
pub use stun::Mapping;

/// Error is already logged where it received
pub type SilentResult<T> = Result<T, ()>;

pub type State = Arc<StateInner>;
pub struct StateInner {
    pub router: RwLock<RouterState>,
    pub watch_sessions: watch::Receiver<Vec<SessionEntry>>,
    pub watch_peers: watch::Receiver<Vec<PeerEntry>>,
    /// Remote ip -> session cache
    pub node_info_cache: RwLock<HashMap<Ipv6Addr, SessionCache>>,

    /// Resolved external addresses
    pub watch_external: watch::Receiver<Vec<Mapping>>,

    /// Remote yggdrasil address -> session stage
    pub active_sessions: RwLock<HashMap<Ipv6Addr, SessionStage>>,
    /// Remote id -> traversal session
    pub active_inet_traversal: RwLock<HashMap<u64, InetTraversalSession>>,

    pub active_proxies: RwLock<HashSet<std::thread::ThreadId>>,

    pub cancellation: utils::PassiveCancellationToken,
}
