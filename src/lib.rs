pub use {
    futures::{stream::FuturesUnordered, FutureExt, SinkExt, StreamExt},
    serde::{Deserialize, Serialize},
    socket2::{Domain, Protocol, Socket, Type},
    std::{
        collections::{HashMap, HashSet},
        mem::drop,
        net::{Ipv6Addr, SocketAddr, SocketAddrV6},
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, Instant},
    },
    tokio::{
        io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
        join,
        net::{lookup_host, TcpListener, TcpSocket, TcpStream},
        select, spawn,
        sync::{watch, RwLock},
        time::sleep,
    },
    tokio_util::{
        codec::{Framed, LengthDelimitedCodec},
        sync::CancellationToken,
    },
    tracing::{
        debug, error, error_span, event, info, info_span, instrument, level_filters::LevelFilter,
        warn, Instrument, Level,
    },
    yggdrasilctl::{Endpoint, PeerEntry, SessionEntry},
};

#[macro_use]
pub mod macros;

pub mod admin_api;
pub mod bridge;
pub mod config;
pub mod external;
pub mod internet;
pub mod overlay;
pub mod protocol;
pub mod sessions;
pub mod stun;
pub mod util;

pub use config::Config;
pub struct StateInner {
    pub admin: RwLock<Endpoint<util::RWSocket>>,
    pub watch_external: watch::Receiver<Vec<external::ExternalAddress>>,
    pub watch_sessions: watch::Receiver<Vec<SessionEntry>>,
    pub watch_peers: watch::Receiver<Vec<PeerEntry>>,
    pub active_sessions: RwLock<HashMap<Ipv6Addr, sessions::SessionType>>,
    pub cancellation: CancellationToken,
}
pub type State = Arc<StateInner>;
