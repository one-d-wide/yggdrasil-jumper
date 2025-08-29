use std::{io::ErrorKind, sync::Arc};
use tokio::net::UdpSocket;
use tracing::{debug, debug_span};

use crate::{utils, Config, SilentResult, State};

// Quic mtu is <1500
pub const BUF_SIZE: usize = 1500;

const STACK_SIZE: usize = 32 * 1024;

/// `peer` socket have to be already connected
pub async fn setup_proxy_udp(
    _config: &Config,
    state: &State,
    ygg: UdpSocket,
    peer: UdpSocket,
) -> SilentResult<(tokio::sync::mpsc::Receiver<()>, Box<dyn Send>)> {
    let peer = Arc::new(utils::into_std_udp_socket(peer)?);
    let ygg = Arc::new(utils::into_std_udp_socket(ygg)?);

    let (term_tx, term_rx) = tokio::sync::mpsc::channel::<()>(1);

    setup_proxy(state, &ygg, &peer, "UDP -> UDP", &term_tx).await;
    setup_proxy(state, &peer, &ygg, "UDP <- UDP", &term_tx).await;

    Ok((
        term_rx,
        Box::new(utils::defer_async({
            async move {
                debug!("Dropping proxy");
                // Std UdpSocket doesn't have a shutdown option, and just .set_read_timeout()
                // doesn't work reliably, so...
                term_tx.closed().await;
                let shutdown = |sock: &std::net::UdpSocket| {
                    sock.connect(sock.local_addr().unwrap()).unwrap();
                    sock.send(&[0]).unwrap();
                };

                shutdown(&ygg);
                shutdown(&peer);
            }
        })),
    ))
}

async fn setup_proxy(
    state: &State,
    from: &Arc<std::net::UdpSocket>,
    to: &Arc<std::net::UdpSocket>,
    direction: &'static str,
    term_tx: &tokio::sync::mpsc::Sender<()>,
) {
    let thread = std::thread::Builder::new()
        .name(direction.into())
        .stack_size(STACK_SIZE)
        .spawn({
            let from = from.clone();
            let to = to.clone();
            let state = state.clone();
            let term_tx = term_tx.clone();
            move || {
                let _guard = utils::defer(|| {
                    term_tx.try_send(()).unwrap_or(());
                    state
                        .active_proxies
                        .blocking_write()
                        .remove(&std::thread::current().id());
                });
                let _span = debug_span!("", direction);
                let _span = _span.enter();
                let mut buf = Box::new([0u8; BUF_SIZE]);
                loop {
                    let read = match from.recv(&mut buf[..]) {
                        Ok(read) => read,
                        Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                        Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                        Err(err) if err.kind() == ErrorKind::TimedOut => break,
                        Err(err) => {
                            debug!("Error receiving: {err}");
                            break;
                        }
                    };
                    if term_tx.is_closed() {
                        break;
                    }
                    debug!("Forwarding {read} bytes");
                    match to.send(&buf[..read]) {
                        Ok(_) => {}
                        Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                        Err(err) => {
                            debug!("Error sending: {err}");
                            break;
                        }
                    };
                }
                debug!("Done");
            }
        })
        .unwrap()
        .thread()
        .id();

    state.active_proxies.write().await.insert(thread);
}
