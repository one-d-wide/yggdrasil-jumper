use bytecodec::{DecodeExt, EncodeExt};
use std::{
    collections::hash_map::Entry,
    io::ErrorKind,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use stun_codec::{
    rfc5389::{
        attributes::{MessageIntegrity, XorMappedAddress},
        methods::BINDING,
        Attribute,
    },
    Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId,
};
use tokio::{net::UdpSocket, select, task::JoinSet, time::sleep};
use tracing::{debug, info, instrument, warn};

use crate::{
    map_error, protocol::JUMPER_PREFIX, utils, Config, IoError, IoResult, SilentResult, State,
};

#[derive(Debug, Clone)]
pub struct InetTraversal {
    pub session_id: u64,
    /// Authentication for traversal messages
    pub shared_secret: String,
}

#[derive(Debug, Clone)]
pub struct InetTraversalSession {
    pub inet: InetTraversal,
    pub chan: tokio::sync::mpsc::UnboundedSender<(SocketAddr, MessageClass)>,
}

pub fn new_stun_transaction(session_id: u64) -> TransactionId {
    let mut buf = [0u8; 12];
    let pref = JUMPER_PREFIX;
    buf[..pref.len()].copy_from_slice(pref);
    buf[pref.len()..].copy_from_slice(&session_id.to_le_bytes());
    TransactionId::new(buf)
}

fn extract_session_id(id: TransactionId) -> Option<u64> {
    let id: &[u8; 12] = id.as_bytes();
    if !id.starts_with(JUMPER_PREFIX) {
        return None;
    }
    Some(u64::from_le_bytes(
        id[JUMPER_PREFIX.len()..].try_into().unwrap(),
    ))
}
pub fn setup_inet_listeners(
    config: Config,
    state: State,
) -> SilentResult<(Vec<SocketAddr>, JoinSet<SilentResult<()>>)> {
    let mut listeners = JoinSet::new();
    let mut locals = Vec::new();

    let mut setup = |addr| {
        let socket = utils::create_udp_socket(addr)?;
        let addr = socket
            .local_addr()
            .map_err(map_error!("Can't get socket address"))?;
        locals.push(addr);
        listeners.spawn(inet_listener(config.clone(), state.clone(), socket));
        Ok(())
    };

    if config.allow_ipv4 {
        setup((Ipv4Addr::UNSPECIFIED, 0).into())?;
    }
    if config.allow_ipv6 {
        setup((Ipv6Addr::UNSPECIFIED, 0).into())?;
    }

    Ok((locals, listeners))
}

// Listen for traversal requests from the internet
#[instrument(parent = None, name = "Global listener ", skip_all)]
pub async fn inet_listener(_config: Config, state: State, socket: UdpSocket) -> SilentResult<()> {
    let mut buf = Box::new([0u8; 1 << 10]);
    loop {
        let (buf, addr) = match socket.recv_from(&mut buf[..]).await {
            Ok((read, addr)) => (&buf[..read], addr),
            Err(err) => {
                info!("Received error: {err}");
                continue;
            }
        };

        debug!(
            "Received {} bytes from {addr}: {:?}...",
            buf.len(),
            String::from_utf8_lossy(&buf[..buf.len().min(8)])
        );

        let Some((message, session_id)) = parse_stun_message(buf) else {
            continue;
        };

        let lock = state.active_inet_traversal.read().await;
        let Some(session) = lock.get(&session_id) else {
            debug!("No traversal session from {session_id}");
            continue;
        };

        let inet = &session.inet;
        if !verify_stun_message_integrity(&message, session_id, inet) {
            continue;
        }

        if session.chan.send((addr, message.class())).is_err() {
            warn!("Traversal session is dead, but still in the list {addr:?}");
        }
    }
}

fn parse_stun_message(buf: &[u8]) -> Option<(Message<Attribute>, u64)> {
    let mut decoder = MessageDecoder::<Attribute>::new();
    let message = match decoder.decode_from_bytes(buf) {
        Ok(Ok(message)) => message,
        Ok(Err(err)) => {
            debug!("Can't decode as STUN: {err:?}");
            return None;
        }
        Err(err) => {
            debug!("Can't decode: {err}");
            return None;
        }
    };

    if message.method() != BINDING {
        debug!("Not coming from jumper");
        return None;
    }

    let Some(session_id) = extract_session_id(message.transaction_id()) else {
        debug!("Not coming from jumper");
        return None;
    };

    Some((message, session_id))
}

#[must_use]
fn verify_stun_message_integrity(
    message: &Message<Attribute>,
    session_id: u64,
    inet: &InetTraversal,
) -> bool {
    if session_id != inet.session_id {
        debug!(
            "Received STUN message has different session id {} (expected {})",
            session_id, inet.session_id
        );
        return false;
    }

    let Some(int) = message.get_attribute::<MessageIntegrity>() else {
        debug!("Received STUN message not authenticated");
        return false;
    };

    if let Err(err) = int.check_short_term_credential(&inet.shared_secret) {
        debug!(
            "Invalid authentication of STUN message session id {}: {}",
            inet.session_id,
            err.reason_phrase()
        );
        return false;
    }
    true
}

#[derive(Debug, Clone)]
pub struct TraversalParams {
    pub retry_count: u32,
    pub cycle: Duration,
}

/// Attempt NAT traversal
#[instrument(name = " NAT traversal", skip_all, fields(remote = %remote))]
pub async fn traverse_udp(
    state: &State,
    params: &TraversalParams,
    local: &SocketAddr,
    remote: &SocketAddr,
    inet: Option<&InetTraversal>, // Always set for internet traversal
) -> IoResult<IoResult<UdpSocket>> {
    debug!("Started");

    let mut _drop_guard = None;
    let mut conn = None;
    let mut remote = *remote;
    if let Some(inet) = inet {
        debug!("session_id {}", inet.session_id);

        let (conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel();
        conn = Some(conn_rx);
        _drop_guard = Some(utils::defer_async({
            let state = state.clone();
            let session_id = inet.session_id;
            async move {
                state
                    .active_inet_traversal
                    .write()
                    .await
                    .remove(&session_id);
            }
        }));
        let mut lock = state.active_inet_traversal.write().await;
        let Entry::Vacant(entry) = lock.entry(inet.session_id) else {
            warn!("Oops, remote session with this session id already exists");
            _drop_guard.unwrap().forget();
            return Err(ErrorKind::AlreadyExists.into());
        };
        entry.insert(InetTraversalSession {
            inet: inet.clone(),
            chan: conn_tx,
        });
    }

    let socket = utils::create_udp_socket(*local).map_err(|_| IoError::last_os_error())?;
    socket.connect(&remote).await?;
    debug!("Socket connected to {remote}");

    let session_id = inet.map(|i| i.session_id).unwrap_or(0);

    let mut buf = Box::new([0u8; 256]);

    let mut send_ack = false;
    let mut got_remote_ack = false;

    let mut last_error = None;
    let mut counter = params.retry_count;
    while counter > 0 {
        counter -= 1;
        let delay = sleep(params.cycle);

        let mut message: Message<Attribute> = if send_ack {
            debug!("Send ACK");
            let mut message = Message::new(
                MessageClass::SuccessResponse,
                BINDING,
                new_stun_transaction(session_id),
            );
            // Socket is connected to remote, therefore request may come only from this ip:port
            message.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(remote)));
            message
        } else {
            debug!("Sending probing");
            Message::new(
                MessageClass::Request,
                BINDING,
                new_stun_transaction(session_id),
            )
        };

        if let Some(inet) = inet {
            let int =
                MessageIntegrity::new_short_term_credential(&message, &inet.shared_secret).unwrap();
            message.add_attribute(int);
        }

        let message = MessageEncoder::new()
            .encode_into_bytes(message)
            .expect("Failed to encode STUN request");

        if let Err(err) = socket.send(&message).await {
            debug!("Send error: {err}");
            last_error = Some(err);
        }

        let recv_routine = async {
            loop {
                let buf = match socket.recv(&mut buf[..]).await {
                    Err(err) => {
                        debug!("Recv error: {err:?}");
                        last_error = Some(err);
                        continue;
                    }
                    Ok(read) => &buf[..read],
                };

                debug!("Recv {:?}", String::from_utf8_lossy(buf));

                if buf.starts_with(JUMPER_PREFIX) {
                    // Peer already passed traversal stage
                    return (None, MessageClass::Indication);
                }

                let Some((message, session_id)) = parse_stun_message(buf) else {
                    continue;
                };

                if let Some(inet) = inet {
                    if !verify_stun_message_integrity(&message, session_id, inet) {
                        continue;
                    }
                }

                match message.class() {
                    MessageClass::Request if send_ack => continue,
                    message => return (None, message),
                }
            }
        };

        let conn_routine = async {
            loop {
                let (addr, message) = conn.as_mut().unwrap().recv().await.unwrap();
                match message {
                    MessageClass::Request if send_ack => continue,
                    message => return (Some(addr), message),
                }
            }
        };

        let (addr, message) = select! {
            res = conn_routine, if inet.is_some() => res,
            res = recv_routine => res,
            _ = delay => continue,
        };

        if let Some(addr) = addr {
            if remote != addr {
                debug!("Switching remote from {remote} to {addr}");
                socket.connect(addr).await.ok();
                remote = addr;
            }
        }

        match message {
            MessageClass::Request if !send_ack => {
                counter += params.retry_count / 2;
                send_ack = true;
            }
            MessageClass::SuccessResponse if !got_remote_ack => {
                send_ack = true;
                got_remote_ack = true;
                counter = 2;
            }
            // Peer already passed traversal stage
            MessageClass::Indication => {
                break;
            }
            _ => {}
        }
    }

    debug!("Terminating traversal");

    if got_remote_ack {
        return Ok(Ok(socket));
    } else {
        match last_error {
            Some(err) => Ok(Err(err)),
            None => Ok(Err(ErrorKind::TimedOut.into())),
        }
    }
}
