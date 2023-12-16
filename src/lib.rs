pub use {
    futures::{stream::FuturesUnordered, FutureExt, SinkExt, StreamExt},
    itertools::Itertools,
    serde::{Deserialize, Serialize},
    socket2::{Domain, Protocol, Socket, Type},
    std::{
        cell::Cell,
        collections::{HashMap, HashSet},
        convert::Infallible,
        future::Future,
        io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
        mem::drop,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
        ops::Deref,
        path::{Path, PathBuf},
        rc::Rc,
        str::FromStr,
        sync::Arc,
        time::{Duration, Instant},
    },
    strum::IntoEnumIterator,
    strum_macros::{EnumIter, EnumString, IntoStaticStr},
    tokio::{
        io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
        join,
        net::{lookup_host, TcpListener, TcpSocket, TcpStream, UdpSocket},
        select, spawn,
        sync::{oneshot, watch, RwLock},
        task::JoinSet,
        time::{sleep, timeout},
    },
    tokio_util::{
        codec::{Framed, LengthDelimitedCodec},
        sync::CancellationToken,
    },
    tracing::{
        debug, error, error_span, event, info, info_span, instrument, level_filters::LevelFilter,
        trace, warn, Instrument, Level,
    },
    yggdrasilctl::{Endpoint, PeerEntry, SessionEntry},
};

pub mod admin_api;
pub mod bridge;
pub mod config;
pub mod network;
pub mod protocol;
pub mod session;
pub mod stun;
pub mod utils;

pub use admin_api::RouterState;
pub use bridge::{ConnectionMode, NetworkProtocol, PeeringProtocol, RouterStream};
pub use config::Config;
pub use session::SessionType;
pub use stun::ExternalAddress;
pub use utils::{defer, defer_async, CancellationUnit};

pub struct StateInner {
    pub router: RwLock<RouterState>,
    pub watch_external: watch::Receiver<Vec<ExternalAddress>>,
    pub watch_sessions: watch::Receiver<Vec<SessionEntry>>,
    pub watch_peers: watch::Receiver<Vec<PeerEntry>>,
    pub active_sessions: RwLock<HashMap<Ipv6Addr, SessionType>>,
    pub active_sockets_tcp: RwLock<HashMap<SocketAddr, TcpStream>>,
    pub cancellation: CancellationUnit,
}
pub type State = Arc<StateInner>;
