use std::{
    collections::HashSet,
    future::Future,
    io::{BufRead, ErrorKind},
    net::{Ipv6Addr, SocketAddr},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::UdpSocket,
    select, spawn,
    task::JoinHandle,
    time::{sleep, sleep_until, Instant},
};
use tracing::{debug, error, event, info, instrument, warn, Level};

use crate::{
    config::ConfigInner,
    map_debug, map_error, map_warn,
    utils::{self, defer_async, CsvIter, FutureAttach},
    Config, SilentResult, State,
};

const WIREGUARD_KEEPALIVE_LEN: usize = 32;

pub fn wg_cmd(wg_type: &str) -> Option<&'static str> {
    match wg_type {
        "wireguard" => Some("wg"),
        "amneziawg" => Some("awg"),
        _ => None,
    }
}

pub async fn verify(config: &ConfigInner) -> SilentResult<()> {
    let mut res = Ok(());

    let mut spec = vec![
        ("ip link", "iproute2"),
        ("iptables --help", "iptables"),
        ("ip6tables --help", "iptables"),
        ("conntrack --help", "conntrack-tools"),
    ];

    for wg_type in Iterator::chain(
        config.wireguard_types.iter(),
        config.wireguard_device_params.keys(),
    ) {
        match wg_type.as_str() {
            "wireguard" => spec.push(("wg help", "wireguard-tools")),
            "amneziawg" => spec.push(("awg help", "amneziawg-tools")),
            _ => {
                error!("Wireguard type {wg_type:?} is not supported");
                return Err(());
            }
        }
    }

    for (cmd, pkg) in spec {
        if run(cmd).await.is_err() {
            error!(
                "Command {:?} not available. Consider installing {pkg:?}",
                cmd.split(" ").next().unwrap()
            );
            res = Err(());
        }
    }

    res
}

async fn run(line: impl AsRef<str>) -> SilentResult<Vec<u8>> {
    run_stdin(line, &[]).await
}

async fn run_stdin(line: impl AsRef<str>, stdin: impl AsRef<[u8]>) -> SilentResult<Vec<u8>> {
    run_stdin_args(line.as_ref().split(" "), stdin).await
}

async fn run_stdin_args<S: AsRef<str>>(
    args: impl IntoIterator<Item = S>,
    stdin: impl AsRef<[u8]>,
) -> SilentResult<Vec<u8>> {
    let stdin = stdin.as_ref();

    let mut args = args.into_iter();
    let command = args.next().unwrap();
    let command = command.as_ref();

    let mut line = command.to_string();
    let mut cmd = tokio::process::Command::new(command);
    for arg in args {
        cmd.arg(arg.as_ref());
        line.push_str(" ");
        line.push_str(arg.as_ref());
    }

    debug!("Running {line:?}");

    let mut proc = cmd
        .stdin(if !stdin.is_empty() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_warn!("Failed to spawn {command:?}"))?;

    if !stdin.is_empty() {
        let _ = proc.stdin.as_mut().unwrap().write_all(stdin).await;
    }

    let res = proc
        .wait_with_output()
        .await
        .map_err(map_warn!("Failed to execute {command:?}"))?;

    if !res.stderr.is_empty() {
        macro_rules! dump_stderr {
            ($level:expr) => {
                event!($level, "While executing {line:?}");
                for line in res.stderr.lines() {
                    event!($level, "> {}", line.unwrap());
                }
            };
        }

        if res.status.success() {
            dump_stderr!(Level::DEBUG);
        } else {
            dump_stderr!(Level::WARN);
        }
    }

    if res.status.success() {
        Ok(res.stdout)
    } else {
        warn!("Command returned error {line:?}");
        Err(())
    }
}

#[derive(Debug, Clone, Default)]
struct WgDev {
    listen_port: u16,
}

#[derive(Debug, Clone, Default)]
struct WgLink {
    /// Default is 0 (not connected)
    latest_handshake: u64,
    transfer_rx: u64,
    transfer_tx: u64,
}

async fn wg_dump(wg_cmd: &str, dev: &str) -> SilentResult<WgDev> {
    let lines = run(format!("{wg_cmd} show {dev} dump")).await?;
    let Some(Ok(line)) = lines.lines().next() else {
        warn!("Can't get wireguard device");
        return Err(());
    };

    let mut i = CsvIter(line.split("\t"));
    i.skip("private-key");
    i.skip("public-key");
    let listen_port = i.parse("listen-port")?;
    i.skip("fwmark");

    Ok(WgDev { listen_port })
}

async fn wg_dump_peer(wg_cmd: &str, dev: &str, pub_key: &str) -> SilentResult<WgLink> {
    let lines = run(format!("{wg_cmd} show {dev} dump")).await?;
    let Some(line) = lines
        .lines()
        .skip(1)
        .map_while(Result::ok)
        .find(|l| l.starts_with(pub_key))
    else {
        warn!("Can't find wireguard peer {pub_key:?}");
        return Err(());
    };

    let mut i = utils::CsvIter(line.split("\t"));

    i.skip("public-key");
    i.skip("preshared-key");
    i.skip("endpoint");
    i.skip("allowed-ips");
    let latest_handshake = i.parse("latest-handshake")?;
    let transfer_rx = i.parse("transfer-rx")?;
    let transfer_tx = i.parse("transfer-tx")?;
    i.skip("persistent-keepalive");

    Ok(WgLink {
        latest_handshake,
        transfer_rx,
        transfer_tx,
    })
}

pub async fn wg_genkeys(config: &Config) -> SilentResult<(String, String)> {
    let wg_cmd = wg_cmd(config.wireguard_types.first().unwrap()).unwrap();
    let trim = |key: Vec<u8>| {
        String::from_utf8(key.trim_ascii().into()).map_err(map_error!("Invalid key encoding"))
    };
    let priv_key = trim(run(format!("{wg_cmd} genkey")).await?)?;

    let pub_key = trim(run_stdin(format!("{wg_cmd} pubkey"), &priv_key).await?)?;

    Ok((pub_key, priv_key))
}

pub fn verify_pub_key(key: &[u8]) -> bool {
    // Check that remote pub_key matches "^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$"
    // Taken from https://lists.zx2c4.com/pipermail/wireguard/2020-December/006222.html
    key.len() == 44
        && key[0..42]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"+/".contains(c))
        && b"AEIMQUYcgkosw480".contains(&key[42])
        && key[43] == b'='
}

async fn allocate_wg_device(config: &Config) -> SilentResult<String> {
    let devices: HashSet<_> = run("ip link")
        .await?
        .lines()
        .map_while(Result::ok)
        .filter(|l| l.starts_with(|l: char| l.is_ascii_digit()))
        .filter_map(|l| l.split(": ").nth(1).map(|l| l.to_string()))
        .filter(|l| l.starts_with(&config.wireguard_device_prefix))
        .collect();
    for _ in 0..config.wireguard_device_rounds {
        let rand: u16 = rand::random();
        let dev = format!("{}{rand:04x}", config.wireguard_device_prefix);
        if !devices.contains(&dev) {
            return Ok(dev);
        }
    }
    warn!("Couldn't allocate wireguard device");
    Err(())
}

/// Clear existing UDP association in firewall state
async fn flush_firewall(dest: SocketAddr) {
    let _ = run(format!(
        "conntrack -D -p udp -d {} --dport {}",
        dest.ip(),
        dest.port(),
    ))
    .await;
}

/// Extend timeout of existing UDP association
/// Note that netfilter may shorten a timeout that is too long
async fn set_firewall_timeout(dest: SocketAddr, timeout: u64) {
    let _ = run(format!(
        "conntrack -U -p udp -d {} --dport {} -t {timeout}",
        dest.ip(),
        dest.port(),
    ))
    .await;
}

fn setup_firewall(method: &str, wg_port: u16, params: &WgBridgeParams) -> impl Future<Output = ()> {
    let iptables = if params.peer_addr.is_ipv4() {
        "iptables"
    } else {
        "ip6tables"
    };
    let local_port = params.local_addr.port();
    let remote_ip = params.peer_addr.ip();
    let remote_port = params.peer_addr.port();

    let cmds = [
        // Forward outbound
        format!("{iptables} -v -t nat {method} POSTROUTING -p udp -m udp --sport {wg_port} -d {remote_ip} --dport {remote_port} -j MASQUERADE --to-ports {local_port}"),

        // // Forward inbound
        // format!("{iptables} -v -t nat {method} PREROUTING -p udp -m udp -s {remote_ip} --sport {remote_port} --dport {local_port} -j REDIRECT --to-port {wg_port}"),
        // // Open wireguard listen port
        // format!("{iptables} -v {method} INPUT -p udp -m udp -s {remote_ip} --sport {remote_port} --dport {wg_port} -j ACCEPT"),
    ];

    async move {
        for cmd in cmds {
            let _ = run(&cmd).await;
        }
    }
}

#[instrument(parent = None, name = "Wireguard bridge yggdrasil keepalive", skip_all,
    fields(peer = utils::pretty_ip(monitor_address)))]
async fn keepalive(
    bound_sock: UdpSocket,
    interval: Duration,
    monitor_address: Ipv6Addr,
) -> SilentResult<()> {
    let mut buf = Box::new([0u8; 32]);
    let mut next_keepalive = Instant::now();
    loop {
        select! {
            _ = sleep_until(next_keepalive) => {},
            res = bound_sock.recv(&mut buf[..]) => {
                let buf = match res {
                    Ok(read) => &buf[..read],
                    Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
                    Err(err) => {
                        debug!("Received error: {err}. Stopping");
                        break;
                    },
                };
                debug!("Received: {:?}...", String::from_utf8_lossy(&buf[..buf.len().min(8)]));
                continue;
            },
        }
        debug!("Sending keepalive");
        bound_sock
            .send(b"keepalive")
            .await
            .map_err(map_warn!("Error seding keepalive"))
            .ok();
        next_keepalive = Instant::now() + interval;
    }
    Ok(())
}

async fn spawn_keepalive(
    config: &Config,
    tun_name: &Option<String>,
    monitor_address: Ipv6Addr,
) -> SilentResult<JoinHandle<SilentResult<()>>> {
    let tun = tun_name.as_ref().ok_or(())?;

    let bound_sock = utils::create_udp_socket_ipv6(config.listen_port)?;
    bound_sock
        .bind_device(Some(tun.as_bytes()))
        .map_err(map_warn!("Failed to bind socket to device"))?;

    bound_sock
        .connect((monitor_address, config.listen_port))
        .await
        .map_err(map_warn!("Error connecting"))?;

    let config = config.clone();
    Ok(spawn(keepalive(
        bound_sock,
        config.wireguard_yggdrasil_keepalive_interval,
        monitor_address,
    )))
}

pub struct WgBridgeParams {
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub peer_pub: String,
    pub self_priv: String,
    pub local_ygg_addr: Ipv6Addr,
    pub monitor_address: Ipv6Addr,
    pub inet_socket: UdpSocket,
    pub yggdrasil_socket: UdpSocket,
    pub shared_secret: u64,
    pub wg_type: String,
}

#[instrument(parent = None, name = "Wireguard bridge ", skip_all,
    fields(peer = utils::pretty_ip(params.monitor_address), remote = %params.peer_addr))]
pub async fn start_bridge(
    config: Config,
    state: State,
    params: WgBridgeParams,
) -> SilentResult<()> {
    debug!("Started");

    let tun = state.router.read().await.tun_name.clone();

    let _guard = if config.wireguard_yggdrasil_keepalive {
        spawn_keepalive(&config, &tun, params.monitor_address)
            .await
            .ok()
            .map(|handle| utils::defer(move || handle.abort()))
    } else {
        None
    };

    let cancellation = state.cancellation.clone();

    let remote_ygg: SocketAddr = (params.monitor_address, config.listen_port).into();
    let remote_ygg_addr = params.monitor_address;

    let local_ygg_addr = &params.local_ygg_addr;
    let remote_pub = &params.peer_pub;
    let self_priv = &params.self_priv;

    let dev = &allocate_wg_device(&config).await?;

    let remote = &params.peer_addr;

    let wg_type = &params.wg_type;
    let wg_cmd = wg_cmd(wg_type).unwrap();

    // Remove previous association of traversal socket
    flush_firewall(*remote).await;
    let _guard = defer_async(flush_firewall(*remote));

    // Extend previous association timeout of yggdrasil socket
    set_firewall_timeout(remote_ygg, 120).await;
    let _guard = defer_async(flush_firewall(remote_ygg));

    // TODO: Multiplex on a single wireguard device
    // TODO: add a queue?
    run(format!("ip link add dev {dev} type {wg_type}")).await?;
    // Associated routing entries are removed automatically
    let _guard =
        defer_async(run(format!("ip link del dev {dev}")).attach(cancellation.get_active()));

    run(format!("ip link set dev {dev} up")).await?;

    let wg_port = wg_dump(wg_cmd, dev).await?.listen_port;

    let mut wg_dev_args: Vec<_> =
        format!("{wg_cmd} set {dev} listen-port {wg_port} private-key /dev/stdin")
            .split(" ")
            .map(|s| s.to_string())
            .collect();

    if wg_type == "amneziawg" {
        use rand::{Rng, SeedableRng};
        let mut seed = params.shared_secret;
        let mut rand_param = |name: &str, range| {
            seed = seed.wrapping_add(1);
            let value = rand_chacha::ChaCha12Rng::seed_from_u64(seed).random_range(range);
            wg_dev_args.push(name.into());
            wg_dev_args.push(format!("{value}"));
        };

        rand_param("jc", 4..=12);
        rand_param("jmin", 8..=8);
        rand_param("jmax", 80..=80);
        for s in ["s1", "s2"] {
            rand_param(s, 15..=150);
        }
        for h in ["h1", "h2", "h3", "h4"] {
            rand_param(h, 5..=2147483647);
        }
    }

    if let Some(params) = config.wireguard_device_params.get(wg_type) {
        for (k, v) in params {
            wg_dev_args.push(k.clone());
            wg_dev_args.push(v.clone());
        }
    }

    run_stdin_args(wg_dev_args, &self_priv).await?;

    setup_firewall("-I", wg_port, &params).await;
    let _guard =
        defer_async(setup_firewall("-D", wg_port, &params).attach(cancellation.get_active()));

    let _ = params
        .yggdrasil_socket
        .bind_device(Some(dev.as_bytes()))
        .map_err(map_warn!("Can't bind socket to device"));

    run(format!(
        "{wg_cmd} set {dev} peer {remote_pub} persistent-keepalive 20 endpoint {remote} allowed-ips {remote_ygg_addr}/128"
    ))
    .await?;

    let init_time = Instant::now();

    let mut last_tx = 0;
    let mut last_rx = 0;
    let mut tx_changed = 0;
    let mut rx_changed = 0;

    let mut ygg_buf = Box::new([0u8; 32]);
    let mut inet_buf = Box::new([0u8; 32]);

    let mut next_ping = Instant::now();
    let mut ping_count = None;

    let mut next_set_firewall_timeout = Instant::now();

    let mut next_query = Instant::now();

    let mut notify_shutdown = false;

    let mut started = false;
    loop {
        select! {
            _ = sleep_until(next_query) => {
                next_query = Instant::now() + (if started {
                    config.wireguard_query_delay
                } else {
                    Duration::from_secs(1)
                });
            },
            _ = sleep_until(next_ping), if ping_count.is_some() => {
                debug!("Sending ping");
                let _ = params.yggdrasil_socket.send(b"ping").await
                    .map_err(map_debug!("Error sending ping"));
                next_ping = Instant::now() + config.wireguard_echo_delay;

                let count = ping_count.as_mut().unwrap();
                *count += 1;

                if *count > config.wireguard_echo_count {
                    info!("Stopping. Peer unresponsive");
                    break;
                }
                continue;
            }
            _ = sleep_until(next_set_firewall_timeout) => {
                let next = 100; // Netfilter resets to 120s on any activity
                let _ = set_firewall_timeout(remote_ygg, next + 10).await;
                next_set_firewall_timeout = Instant::now() + Duration::from_secs(next);
            }
            res = params.yggdrasil_socket.recv(&mut ygg_buf[..]) => {
                debug!("Received on {}", params.local_ygg_addr);
                let buf = match res {
                    Ok(read) => &ygg_buf[..read],
                    Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
                    Err(err) => {
                        debug!("Received error: {err}");
                        continue;
                    },
                };

                debug!("Received: {:?}...", String::from_utf8_lossy(&buf[..buf.len().min(8)]));
                match buf {
                    b"ping" => {
                        let _ = params.yggdrasil_socket.send(b"pong").await
                            .map_err(map_debug!("Error sending pong"));
                    },
                    b"pong" => ping_count = None,
                    b"shutdown" => {
                        info!("Received shutdown notification");
                        break;
                    },
                    _ => {}
                }
                continue;
            },
            res = params.inet_socket.recv(&mut inet_buf[..]) => {
                warn!("Received on {}, firewall might be misconfigured", params.local_addr);
                match res {
                    Ok(read) => debug!("Received: {:?}..", String::from_utf8_lossy(&inet_buf[..read.min(8)])),
                    Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
                    Err(err) => debug!("Received error: {err}"),
                }
                continue;
            },
            _ = cancellation.cancelled() => {
                notify_shutdown = true;
                break
            },
        }

        let dump = wg_dump_peer(wg_cmd, dev, &params.peer_pub).await?;

        if !started {
            if dump.latest_handshake != 0 {
                info!("Connection alive");

                // Redirecting traffic too early would cause connectivity to stall
                run(format!("ip addr add {local_ygg_addr}/128 dev {dev}")).await?;
                run(format!("ip route add {remote_ygg_addr} dev {dev}")).await?;
                started = true;
            } else if init_time.elapsed() > config.wireguard_negotiations_timeout {
                info!("Wireguard connection wasn't established in time");
                return Err(());
            }
            continue;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if dump.transfer_rx != last_rx {
            if dump.transfer_rx - last_rx > WIREGUARD_KEEPALIVE_LEN as u64 {
                debug!("Rx changed {}", dump.transfer_rx - last_rx);
                rx_changed = now;
            }
            last_rx = dump.transfer_rx;
        }

        if dump.transfer_tx != last_tx {
            if dump.transfer_tx - last_tx > WIREGUARD_KEEPALIVE_LEN as u64 {
                debug!("Tx changed {}", dump.transfer_tx - last_tx);
                tx_changed = now;
            }
            last_tx = dump.transfer_tx;
        }

        let last_active = rx_changed.max(tx_changed);
        if last_active != 0 && last_active.abs_diff(now) > config.wireguard_inactivity_timeout {
            notify_shutdown = true;
            info!("Session inactive");
            break;
        }

        if ping_count.is_none()
            && tx_changed > rx_changed
            && tx_changed - rx_changed > config.wireguard_echo_start
        {
            ping_count = Some(0);
        }

        if dump.latest_handshake + config.wireguard_handshake_renew_timeout < now {
            info!("Wireguard connection timed out");
            break;
        }
    }

    if started && notify_shutdown {
        debug!("Sending shutdown notifications");

        if let Some(tun) = &tun {
            // Minimize disruption to connectivity by immediately prioritizing the tun interface,
            // while sending shutdown notifications in the background
            let _guard = run(format!(
                "ip route add {remote_ygg_addr} dev {tun} metric 10"
            ))
            .await
            .ok()
            .map(|_| defer_async(run(format!("ip route del {remote_ygg_addr} dev {tun}"))));
        }

        for i in 0..config.wireguard_shutdown_notification_count {
            if i != 0 {
                sleep(config.wireguard_shutdown_notification_delay).await;
            }

            // Socket is specifically bound to wireguard interface
            let _ = params
                .yggdrasil_socket
                .send(b"shutdown")
                .await
                .map_err(map_debug!("Error sending shutdown notification"));
        }
    }

    Ok(())
}
