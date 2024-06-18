use yggdrasil_jumper::*;

#[derive(Debug, clap::Parser)]
#[command(name = "stun-test", version)]
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
    #[arg(short = '6', long, help = "Use only IPv6", conflicts_with = "ipv4")]
    pub ipv6: bool,
    #[arg(short = '4', long, help = "Use only IPv4")]
    #[arg(conflicts_with = "ipv6", default_value = "true")]
    pub ipv4: bool,
    #[arg(short = 't', long, help = "Use only TCP")]
    #[arg(required_unless_present = "udp", conflicts_with = "udp")]
    pub tcp: bool,
    #[arg(short = 'u', long, help = "Use only UDP")]
    #[arg(required_unless_present = "tcp", conflicts_with = "tcp")]
    pub udp: bool,
    #[arg(long, help = "Print server for every resolved address")]
    pub print_servers: bool,
    #[arg(long = "no-check", help = "Skip all address consistency checks", action = clap::ArgAction::SetFalse)]
    pub check: bool,
    #[arg(long = "fail-fast", help = "Exit immediately if resolution fails")]
    pub fail_fast: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    start().await.map_err(|_| std::process::exit(1)).ok();
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

    // Allocate socket port
    if cli_args.ipv6 {
        cli_args.ipv4 = false;
    }
    let ip_domain: IpAddr = if cli_args.ipv6 {
        Ipv6Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::UNSPECIFIED.into()
    };

    let local_address = SocketAddr::from((ip_domain, 0));
    let local_address = if cli_args.tcp {
        utils::create_tcp_socket(local_address)?.local_addr()
    } else {
        utils::create_udp_socket(local_address)?.local_addr()
    }
    .map_err(map_error!("Failed to retrieve local socket address"))?;

    // Load config
    let config = Arc::new(match cli_args.config {
        Some(ref path) => config::ConfigInner::read(path.as_path())?,
        None => config::ConfigInner::default(),
    });

    // Load server list
    if cli_args.config.is_some() {
        cli_args
            .servers
            .clone_from_slice(config.stun_servers.as_slice());
    }

    if cli_args.default {
        cli_args
            .servers
            .append(&mut config::ConfigInner::default().stun_servers);
    }

    let mut last_address = None;
    for server in cli_args.servers {
        let result = async {
            let _span = error_span!("While resolving ", server = %server);
            let _span = _span.enter();

            // Connect to server
            let protocol = if cli_args.tcp {
                NetworkProtocol::Tcp
            } else {
                NetworkProtocol::Udp
            };
            let external_address = stun::lookup(config.clone(), protocol, local_address, &server)
                .await?
                .external;

            // Check address consistency
            if cli_args.check {
                let _span = error_span!(" ", received = %external_address);
                let _span = _span.enter();

                if external_address.is_ipv4() != local_address.is_ipv4() {
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
