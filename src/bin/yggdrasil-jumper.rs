use yggdrasil_jumper::*;

#[derive(Debug, clap::Parser)]
#[command(version)]
pub struct CliArgs {
    #[arg(long, help = "Read config from specified file")]
    pub config: Option<PathBuf>,
    #[arg(long, help = "Print default config and exit")]
    pub print_default: bool,
    #[arg(long, help = "Validate config and exit")]
    pub validate: bool,
    #[arg(long, help = "Set log verbosity level", default_value = "INFO")]
    pub loglevel: LevelFilter,
    #[arg(long = "no-color", help = "Whether to disable auto coloring", action = clap::ArgAction::SetFalse)]
    pub use_color: bool,
}

#[tokio::main]
async fn main() {
    let cancellation = CancellationToken::new();
    let err = start(cancellation.clone()).await;
    cancellation.cancel();
    err.map_err(|_| std::process::exit(1)).ok();
}

pub async fn start(cancellation: CancellationToken) -> Result<(), ()> {
    // Read CLI arguments
    let cli_args: CliArgs = clap::Parser::try_parse().unwrap_or_else(|err| err.exit());

    if cli_args.print_default {
        print!("{}", config::ConfigInner::default_str());
        return Ok(());
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
        .init();

    // Read config file
    let config = Arc::new(match cli_args.config {
        Some(ref path) => config::ConfigInner::read(path)?,
        None => config::ConfigInner::default(),
    });

    if cli_args.validate {
        return cli_args
            .config
            .map(|_| ())
            .ok_or_else(|| error!("Config file is not specified"));
    }

    // Construct state
    let admin_endpoint = admin_api::connect(config.clone())
        .await
        .map_err(|_| error!("Failed to connect to admin socket"))?;
    let watch_sessions = watch::channel(Vec::new());
    let watch_peers = watch::channel(Vec::new());
    let watch_external = watch::channel(Vec::new());

    let state = State::new(StateInner {
        admin: RwLock::new(admin_endpoint),
        watch_external: watch_external.1,
        watch_sessions: watch_sessions.1,
        watch_peers: watch_peers.1,
        active_sessions: RwLock::new(HashMap::new()),
        cancellation: cancellation.clone(),
    });

    // Spawn & wait
    let external_required = watch::channel(Instant::now());
    let (external_listeners, external_addresses) = internet::new_sockets(&config)?;

    select! {
        _ = spawn(internet::listen(config.clone(), state.clone(), external_listeners)) => {},
        _ = spawn(external::lookup(config.clone(), state.clone(), external_addresses, watch_external.0, external_required.1)) => {},
        _ = spawn(overlay::listen(config.clone(), state.clone())) => {},
        _ = spawn(admin_api::watcher(
            config.clone(),
            state.clone(),
            watch_sessions.0,
            watch_peers.0
        )) => {},
        _ = spawn(sessions::spawn_new_sessions(config.clone(), state.clone(), external_required.0)) => {},

        _ = cancellation.cancelled() => {},
        _ = tokio::signal::ctrl_c() => {
            warn!("Stop signal received");
            return Ok(())
        },
    }
    Err(())
}
