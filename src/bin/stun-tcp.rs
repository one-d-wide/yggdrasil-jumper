use yggdrasil_jumper::*;

#[derive(clap::Parser)]
#[command(name = "stun-tcp", version)]
pub struct CliArgs {
    #[arg(required_unless_present_any = [ "config", "default" ])]
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
    pub ipv6: bool,
    #[arg(short = '4', long, help = "Use only IPv4")]
    pub ipv4: bool,
    #[arg(long, help = "Print server for every resolved address")]
    pub print_server: bool,
    #[arg(long = "no-check", help = "Skip all address consistency checks", action = clap::ArgAction::SetFalse)]
    pub check: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    start().await.map_err(|_| std::process::exit(1)).ok();
}

async fn start() -> Result<(), ()> {
    // Parse CLI arguments
    let mut cli_args: CliArgs = clap::Parser::try_parse().map_err(|e| e.exit())?;

    if cli_args.ipv6 == cli_args.ipv4 {
        cli_args.ipv6 = true;
        cli_args.ipv4 = true;
    }

    // Init logger
    tracing_subscriber::fmt()
        .with_target(false)
        .with_file(false)
        .with_thread_names(false)
        .with_ansi(
            cli_args.use_color
                && atty::is(atty::Stream::Stdout)
                && std::env::var_os("TERM").is_some(),
        )
        .with_max_level(cli_args.loglevel)
        .without_time()
        .log_internal_errors(false)
        .with_writer(std::io::stderr)
        .init();

    // Find availible ports
    let (mut port_v4, mut port_v6) = (0, 0);
    {
        let port_of = |socket: TcpSocket| {
            let port = socket
                .local_addr()
                .map_err(map_error!("Failed to retreive local socket address"))?
                .port();
            Ok(port)
        };
        if cli_args.ipv6 {
            port_v6 = port_of(util::new_socket_ipv6(0)?)?;
        }
        if cli_args.ipv4 {
            port_v4 = port_of(util::new_socket_ipv4(0)?)?;
        }
    }

    // Load server list
    if let Some(path) = cli_args.config {
        cli_args
            .servers
            .append(&mut config::ConfigInner::read(path.as_path())?.stun_servers);
    }

    if cli_args.default {
        cli_args
            .servers
            .append(&mut config::ConfigInner::default().stun_servers);
    }

    let mut last_address_v4 = None;
    let mut last_address_v6 = None;

    for server in cli_args.servers {
        let _span = error_span!("While resolving ", server = %server);
        let _span = _span.enter();

        // Lookup server address
        let address = lookup_host(server.as_str())
            .await
            .map_err(map_error!("Failed to lookup host"))?
            .find(|a| (a.is_ipv4() && cli_args.ipv4) || (a.is_ipv6() && cli_args.ipv6))
            .ok_or_else(|| error!("No address resolved"))?;

        // Connect to server
        let port = match &address {
            SocketAddr::V6(_) => port_v6,
            SocketAddr::V4(_) => port_v4,
        };
        let socket = util::new_socket_in_domain(&address, port)?;
        let stream = select! {
            stream = socket.connect(address) => stream.map_err(map_error!("Failed to connect"))?,
            _ = sleep(Duration::from_secs(10)) => { error!("Timeout"); return Err(()); },
        };
        let mut stream = BufReader::new(stream);

        // Request external address
        let external_address = stun::lookup_external_address(&mut stream).await?;

        // Check address consistency
        if cli_args.check {
            let _span = error_span!(" ", received = %external_address);
            let _span = _span.enter();

            if external_address.is_ipv4() != address.is_ipv4() {
                error!("Resolved address has wrong range");
                return Err(());
            }

            let last_address = match &address {
                SocketAddr::V6(_) => &mut last_address_v6,
                SocketAddr::V4(_) => &mut last_address_v4,
            };

            if let Some(ref last_address) = last_address {
                if last_address != &external_address {
                    error!("Previously resolved addresses do not match");
                    return Err(());
                }
            } else {
                *last_address = Some(external_address);
            }
        }

        // Print resolved address
        if cli_args.print_server {
            print!("{server} ");
        }
        println!("{external_address}");
    }
    Ok(())
}
