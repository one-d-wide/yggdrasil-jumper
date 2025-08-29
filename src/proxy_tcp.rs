use kcp::Error as KcpError;
use std::{
    io::{ErrorKind, Read, Write},
    net::Shutdown,
    ops::BitAnd,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, debug_span};

use crate::{
    bridge::BridgeParams, map_warn, utils, yggdrasil_dpi, Config, IoResult, SilentResult, State,
};

const STACK_SIZE: usize = 128 * 1024;

const BUF_SIZE: usize = 1 << 14;

struct KcpWriter<F: FnMut(usize)>(Arc<std::net::UdpSocket>, Option<F>);

impl<F> std::io::Write for KcpWriter<F>
where
    F: FnMut(usize),
{
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if let Some(callback) = &mut self.1 {
            callback(buf.len());
        }
        self.0.send(buf)
    }
    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

/// `peer` socket have to be already connected
/// `peer_conv` is some value shared between peers
pub async fn setup_proxy_tcp(
    config: &Config,
    state: &State,
    ygg: TcpStream,
    peer: UdpSocket,
    params: &BridgeParams,
) -> SilentResult<(tokio::sync::mpsc::Receiver<()>, Box<dyn Send>)> {
    let ygg = utils::into_std_tcp_socket(ygg)?;
    let peer = Arc::new(utils::into_std_udp_socket(peer)?);

    let time_now = {
        let start = Instant::now();
        move || start.elapsed().as_millis().bitand(u32::MAX as u128) as u32
    };

    let peer_conv = params.peer_conv;

    let mut kcp = kcp::Kcp::new_stream(
        peer_conv,
        KcpWriter::<_>(peer.clone(), {
            Some(|len| debug!("Sending {} bytes to peer", len))
        }),
    );

    // Maximum interval at which .update() should be polled
    // KCP uses it in calculating flush time, so we can't make it too high
    let interval: u32 = 100;

    // TCP socket on the yggdrasil side is probably already uses buffering,
    // so we should avoid introducing even more delay
    let nodelay = true;

    let congestion_control = true;

    kcp.set_nodelay(nodelay, interval as i32, 0, congestion_control);

    let lossy = params.yggdrasil_dpi;
    let udp_mtu = config.yggdrasil_dpi_udp_mtu;
    let fallback_to_reliable = config.yggdrasil_dpi_fallback_to_reliable;

    let kcp = Arc::new(std::sync::Mutex::new(kcp));
    let (term_tx, term_rx) = tokio::sync::mpsc::channel::<()>(1);

    let err_kcp_sending = map_warn!("Error sending to kcp");
    let err_sending = map_warn!("Error sending");
    let err_writing = map_warn!("Error writing");
    let err_set_timeout = map_warn!("Error setting read timeout");
    let err_dup = map_warn!("Error duplicating socket");
    let err_spawn_thread = map_warn!("Error spawning new thread");

    let direction = "TCP -> UDP";
    let tx = std::thread::Builder::new()
        .name(direction.into())
        .stack_size(STACK_SIZE)
        .spawn({
            let state = state.clone();
            let term_tx = term_tx.clone();
            let kcp = kcp.clone();
            let mut ygg = ygg.try_clone().map_err(err_dup)?;
            let peer = peer.clone();

            let mut last_timeout_ms: u32 = 10;
            ygg.set_read_timeout(Some(Duration::from_millis(last_timeout_ms as u64)))
                .map_err(err_set_timeout)?;

            move || {
                let _guard = utils::defer(|| {
                    let _ = term_tx.try_send(());
                    state
                        .active_proxies
                        .blocking_write()
                        .remove(&std::thread::current().id());
                });
                let _span = debug_span!("", direction);
                let _span = _span.enter();
                let mut buf = Box::new([0u8; BUF_SIZE]);
                let mut left = 0;
                let mut send_lossy = yggdrasil_dpi::SendLossy {
                    udp_mtu,
                    fallback_to_reliable,
                    ..Default::default()
                };
                loop {
                    let read = match ygg.read(&mut buf[left..]) {
                        Ok(0) => {
                            debug!("Received EOF");
                            break;
                        }
                        Ok(mut read) => {
                            debug!("Received {read} bytes from yggdrasil");
                            read += left;
                            left = 0;
                            Some(read)
                        }
                        Err(err) if err.kind() == ErrorKind::WouldBlock => None,
                        Err(err) if err.kind() == ErrorKind::TimedOut => None,
                        Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                        Err(err) => {
                            debug!("Error reading: {err}");
                            break;
                        }
                    };

                    let mut k = kcp.lock().unwrap();

                    if let Some(read) = read {
                        if !lossy {
                            k.send(&buf[..read]).map_err(err_kcp_sending)?;
                        }

                        if lossy {
                            assert_eq!(left, 0);
                            left = send_lossy
                                .send(&mut buf[..read], &peer, &mut k)
                                .map_err(err_sending)?;
                        }
                    }

                    let mut now = time_now();

                    // Simulate backpressure if buffer is full
                    while k.wait_snd() > k.snd_wnd() as usize {
                        if term_tx.is_closed() {
                            break;
                        }
                        debug!("Send queue is full {}", k.wait_snd());
                        let next = k.check(now);
                        if next != 0 {
                            drop(k);
                            std::thread::sleep(Duration::from_millis(next as u64));
                            k = kcp.lock().unwrap();
                            now = time_now()
                        }
                        k.update(now).map_err(err_kcp_sending)?;
                        k.flush().map_err(err_kcp_sending)?;
                    }

                    let mut next_update = 0;
                    while next_update == 0 {
                        k.update(time_now()).map_err(err_kcp_sending)?;
                        k.flush().map_err(err_kcp_sending)?;
                        next_update = k.check(time_now());
                    }

                    let send_queue = k.wait_snd();
                    drop(k);

                    if send_queue == 0 && next_update + interval / 16 > interval {
                        if last_timeout_ms != 0 {
                            ygg.set_read_timeout(None).map_err(err_set_timeout)?;
                            last_timeout_ms = 0;
                        }
                        debug!("Next update is delayed");
                        continue;
                    }

                    // Avoid syscall if time difference is <6.25% (chosen arbitrary)
                    if last_timeout_ms.abs_diff(next_update) >= next_update / 16 {
                        let period = Duration::from_millis(next_update as u64);
                        ygg.set_read_timeout(Some(period))
                            .map_err(err_set_timeout)?;
                        last_timeout_ms = next_update;
                    }
                    debug!("Next update in {last_timeout_ms} ms");
                }
                debug!("Done");
                SilentResult::Ok(())
            }
        })
        .map_err(err_spawn_thread)?
        .thread()
        .id();

    let direction = "TCP <- UDP";
    let rx = std::thread::Builder::new()
        .name(direction.into())
        .stack_size(STACK_SIZE)
        .spawn({
            let state = state.clone();
            let term_tx = term_tx.clone();
            let kcp = kcp.clone();
            let mut ygg = ygg.try_clone().map_err(err_dup)?;
            let peer = peer.clone();
            let mut last_timeout_ms: u32 = 0;
            move || {
                let _guard = utils::defer(|| {
                    let _ = term_tx.try_send(());
                    state
                        .active_proxies
                        .blocking_write()
                        .remove(&std::thread::current().id());
                });
                let mut buf = Box::new([0u8; BUF_SIZE]);
                let _span = debug_span!("", direction);
                let _span = _span.enter();
                let mut recv_lossy = yggdrasil_dpi::ReceiveLossy {
                    peer_conv,
                    ..Default::default()
                };
                loop {
                    let read = match peer.recv(&mut buf[..]) {
                        Ok(read) => Some(read),
                        Err(err) if err.kind() == ErrorKind::WouldBlock => None,
                        Err(err) if err.kind() == ErrorKind::TimedOut => None,
                        Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                        Err(err) => {
                            debug!("Error receiving: {err}");
                            continue;
                        }
                    };

                    if lossy {
                        if let Some(read) = read {
                            if recv_lossy
                                .recv_lossy(&buf[..read], &mut ygg)
                                .map_err(err_sending)?
                            {
                                continue;
                            }
                        }
                    }

                    if term_tx.is_closed() {
                        break;
                    }

                    let mut k = kcp.lock().unwrap();
                    if let Some(read) = read {
                        debug!("Received {read} bytes from peer");
                        match k.input(&buf[..read]) {
                            Ok(read) => debug!("Consumed {read} bytes"),
                            Err(err) => debug!("Error consuming: {err}"),
                        }
                    }

                    let mut left = 0;
                    loop {
                        let read = match k.recv(&mut buf[left..]) {
                            Ok(0) => break,
                            Ok(mut read) => {
                                read += left;
                                left = 0;
                                read
                            }
                            Err(KcpError::RecvQueueEmpty) => break,
                            Err(err) => {
                                debug!("Error recv: {err}");
                                break;
                            }
                        };
                        debug!("Forwarding {read} bytes to yggdrasil");
                        drop(k);

                        if !lossy {
                            ygg.write_all(&buf[..read]).map_err(err_writing)?;
                        }

                        if lossy {
                            assert_eq!(left, 0);
                            left = recv_lossy
                                .read_reliable(&mut buf[..read], &mut ygg)
                                .map_err(err_writing)?;
                        }

                        k = kcp.lock().unwrap();
                    }

                    let mut next_update = 0;
                    while next_update == 0 {
                        k.update(time_now()).map_err(err_kcp_sending)?;
                        k.flush().map_err(err_kcp_sending)?;
                        next_update = k.check(time_now());
                    }

                    let send_queue = k.wait_snd();
                    drop(k);

                    if send_queue == 0 && next_update + interval / 16 > interval {
                        if last_timeout_ms != 0 {
                            peer.set_read_timeout(None).map_err(err_set_timeout)?;
                            last_timeout_ms = 0;
                        }
                        debug!("Next update is delayed");
                        continue;
                    }

                    // Avoid syscall if time difference is <6.25% (chosen arbitrary)
                    if last_timeout_ms.abs_diff(next_update) >= next_update / 16 {
                        let period = Duration::from_millis(next_update as u64);
                        peer.set_read_timeout(Some(period))
                            .map_err(err_set_timeout)?;
                        last_timeout_ms = next_update;
                    }
                    debug!("Next update in {next_update} ms");
                }
                debug!("Done");
                SilentResult::Ok(())
            }
        })
        .map_err(err_spawn_thread)?
        .thread()
        .id();

    {
        let mut lock = state.active_proxies.write().await;
        lock.insert(tx);
        lock.insert(rx);
    }

    Ok((
        term_rx,
        Box::new(utils::defer_async({
            let peer = peer.clone();
            async move {
                debug!("Dropping proxy");
                let _ = ygg.shutdown(Shutdown::Both);

                // Std UdpSocket doesn't have a shutdown option, and just .set_read_timeout()
                // doesn't work reliably, so...
                term_tx.closed().await;
                peer.connect(peer.local_addr().unwrap()).unwrap();
                peer.send(&[0]).unwrap();
            }
        })),
    ))
}
