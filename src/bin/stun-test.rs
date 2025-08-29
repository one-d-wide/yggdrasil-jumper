use bytecodec::{Decode, DecodeExt, EncodeExt};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use stun_codec::{
    rfc5389::{attributes::XorMappedAddress, methods::BINDING, Attribute},
    Message, MessageClass, MessageDecoder, MessageEncoder,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket},
};
use tracing::{debug, error, error_span, info, instrument, level_filters::LevelFilter};

use yggdrasil_jumper::{config, map_error, map_info, stun, utils, SilentResult};

#[derive(Debug, clap::Parser)]
#[command(name = "stun-test", version)]
pub struct CliArgs {
    #[arg(required_unless_present_any = [ "config", "default", "serve" ])]
    pub servers: Vec<String>,
    #[arg(long, help = "Read servers from specified config file")]
    pub config: Option<PathBuf>,
    #[arg(long, help = "Take default servers")]
    pub default: bool,
    #[arg(long, help = "Set log verbosity level", default_value = "INFO")]
    pub loglevel: LevelFilter,
    #[arg(long = "no-color", help = "Whether to disable auto coloring", action = clap::ArgAction::SetFalse)]
    pub use_color: bool,
    #[arg(short = '6', long, help = "Use only IPv6")]
    #[arg(conflicts_with = "ipv4")]
    pub ipv6: bool,
    #[arg(short = '4', long, help = "Use only IPv4")]
    #[arg(conflicts_with = "ipv6")]
    pub ipv4: bool,
    #[arg(short = 'u', long, help = "Use only UDP")]
    #[arg(conflicts_with = "tcp")]
    pub udp: bool,
    #[arg(short = 't', long, help = "Use only TCP")]
    #[arg(conflicts_with = "udp")]
    pub tcp: bool,
    #[arg(long, help = "Print server for every resolved address")]
    pub print_servers: bool,
    #[arg(long = "no-check", help = "Skip all address consistency checks", action = clap::ArgAction::SetFalse)]
    pub check: bool,
    #[arg(long, help = "Serve as STUN server")]
    pub serve: bool,
    #[arg(long, help = "Bind socket to a specific port")]
    pub port: Option<u16>,
    #[arg(long = "fail-fast", help = "Exit immediately if resolution fails")]
    pub fail_fast: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(()) = start().await {
        std::process::exit(1);
    }
}

async fn start() -> Result<(), ()> {
    // Parse CLI arguments
    let mut cli_args: CliArgs = clap::Parser::try_parse().map_err(|e| e.exit())?;

    // Init logger
    tracing_subscriber::fmt()
        .with_target(false)
        .with_file(false)
        .with_thread_names(false)
        .with_ansi(
            cli_args.use_color
                && std::io::IsTerminal::is_terminal(&std::io::stdout())
                && std::env::var_os("TERM").is_some(),
        )
        .with_max_level(cli_args.loglevel)
        .without_time()
        .log_internal_errors(false)
        .with_writer(std::io::stderr)
        .init();

    if !cli_args.ipv6 && !cli_args.ipv4 {
        cli_args.ipv4 = true;
    }

    if !cli_args.udp && !cli_args.tcp {
        cli_args.udp = true;
    }

    // Allocate socket port
    let ip_domain: IpAddr = if cli_args.ipv6 {
        Ipv6Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::UNSPECIFIED.into()
    };

    let local_addr = SocketAddr::from((ip_domain, 0));
    let local_addr = if let Some(port) = cli_args.port {
        Ok((ip_domain, port).into())
    } else if cli_args.udp {
        utils::create_udp_socket(local_addr)?.local_addr()
    } else {
        utils::create_tcp_socket(local_addr)?.local_addr()
    }
    .map_err(map_error!("Failed to retrieve local socket address"))?;

    if cli_args.serve {
        if cli_args.udp {
            info!("Serving at port {} (UDP)", local_addr.port());
            let socket = utils::create_udp_socket(local_addr)?;
            serve_udp(socket).await?;
        } else {
            info!("Serving at port {} (TCP)", local_addr.port());
            let socket = utils::create_tcp_socket(local_addr)?;
            serve_tcp(socket).await?;
        }
        return Ok(());
    }

    // Load config
    let config = Arc::new(match cli_args.config {
        Some(ref path) => config::ConfigInner::read(path.as_path())?,
        None => config::ConfigInner::default(),
    });

    // Load server list
    if cli_args.config.is_some() {
        cli_args.servers.extend(config.stun_servers.iter().cloned());
    }

    if cli_args.default {
        cli_args
            .servers
            .extend(config::ConfigInner::default().stun_servers.iter().cloned());
    }

    let mut last_address = None;
    for server in &cli_args.servers {
        let result = async {
            let _span = error_span!("While resolving ", server = %server);
            let _span = _span.enter();

            let external_address = if cli_args.udp {
                let mut socket = utils::create_udp_socket(local_addr)?;
                socket
                    .connect(server)
                    .await
                    .map_err(map_error!("Can't connect to {server}"))?;

                stun::lookup_external_address(&config, &mut socket).await?
            } else {
                let server_addr = tokio::net::lookup_host(server)
                    .await
                    .map_err(map_error!("Failed to lookup address information"))?
                    .find(|a| a.is_ipv6() == local_addr.is_ipv6())
                    .ok_or_else(|| error!("Can't lookup suitable address"))?;

                let socket = utils::create_tcp_socket(local_addr)?;
                let mut socket = utils::timeout(
                    config.stun_tcp_response_timeout,
                    socket.connect(server_addr),
                )
                .await
                .map_err(map_error!("Can't connect to {server}"))?;

                stun::lookup_external_address(&config, &mut socket).await?
            };

            // Check address consistency
            if cli_args.check {
                let _span = error_span!(" ", received = %external_address);
                let _span = _span.enter();

                if external_address.is_ipv4() != local_addr.is_ipv4() {
                    error!("Resolved address has wrong range");
                    return Err(());
                }

                if let Some(ref last_address) = last_address {
                    if last_address != &external_address {
                        error!("Previously resolved addresses don't match");
                        return Err(());
                    }
                } else {
                    last_address = Some(external_address);
                }
            }

            // Print resolved address
            if cli_args.print_servers {
                print!("{server} ");
            }
            println!("{external_address}");

            Ok(())
        }
        .await;
        if result.is_err() && cli_args.fail_fast {
            return Err(());
        }
    }

    Ok(())
}

#[instrument(name = "UDP listener", skip_all)]
async fn serve_udp(socket: UdpSocket) -> SilentResult<()> {
    let mut buf = Box::new([0u8; 256]);
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

        let mut decoder = MessageDecoder::<Attribute>::new();
        let message = match decoder.decode_from_bytes(buf) {
            Ok(Ok(message)) => message,
            Ok(Err(err)) => {
                debug!("Can't decode as STUN: {err:?}");
                continue;
            }
            Err(err) => {
                debug!("Can't decode: {err}");
                continue;
            }
        };

        let mut message: Message<Attribute> = Message::new(
            MessageClass::SuccessResponse,
            BINDING,
            message.transaction_id(),
        );
        message.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(addr)));

        let buf = MessageEncoder::<Attribute>::new()
            .encode_into_bytes(message)
            .unwrap();

        if let Err(err) = socket.send_to(&buf, addr).await {
            info!("Failed to send response to {addr}: {err}");
        }
    }
}

#[instrument(name = "Session", skip_all, fields(addr = %addr))]
async fn handle_tcp(mut socket: TcpStream, addr: SocketAddr) -> SilentResult<()> {
    let mut buf = Box::new([0u8; 256]);

    let mut decoder = MessageDecoder::<Attribute>::new();

    let mut left = 0usize;
    loop {
        let mut read = socket
            .read(&mut buf[left..])
            .await
            .map_err(map_info!("Failed to receive from socket"))?;

        debug!(
            "Received {read} bytes: {:?}...",
            String::from_utf8_lossy(&buf[..buf.len().min(8)])
        );

        read += left;

        let consumed = decoder
            .decode(&buf[..read], bytecodec::Eos::new(false))
            .map_err(map_info!("Failed to decode server response"))?;

        buf.copy_within(consumed..read, 0);
        left = read - consumed;

        if decoder.is_idle() {
            break;
        }
    }

    let message = decoder
        .finish_decoding()
        .map_err(map_info!("Failed to decode server response"))?
        .map_err(|err| info!("Failed to decode server response {}", err.error()))?;

    let mut message: Message<Attribute> = Message::new(
        MessageClass::SuccessResponse,
        BINDING,
        message.transaction_id(),
    );
    message.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(addr)));

    let buf = MessageEncoder::<Attribute>::new()
        .encode_into_bytes(message)
        .unwrap();

    if let Err(err) = socket.write_all(&buf).await {
        info!("Failed to send response to {addr}: {err}");
    }

    Ok(())
}

#[instrument(name = "TCP listener", skip_all)]
async fn serve_tcp(socket: TcpSocket) -> SilentResult<()> {
    let listener = socket
        .listen(128)
        .map_err(map_error!("Failed to setup listen socket"))?;

    loop {
        let (socket, addr) = match listener.accept().await {
            Ok(res) => res,
            Err(err) => {
                info!("Accept error: {err}");
                continue;
            }
        };

        info!("New connection from {addr}");
        tokio::spawn(handle_tcp(socket, addr));
    }
}
