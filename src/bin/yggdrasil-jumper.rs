use std::{io::IsTerminal, path::PathBuf, sync::Arc, time::Instant};
use tokio::{
    select, spawn,
    sync::{watch, RwLock},
    task::JoinSet,
};
use tracing::{error, info, level_filters::LevelFilter};

use yggdrasil_jumper::{
    admin_api, config, network, session, stun, utils, SilentResult, State, StateInner,
};

#[derive(Debug, clap::Parser)]
#[command(version)]
pub struct CliArgs {
    #[arg(long, help = "Read config from specified file")]
    pub config: Option<PathBuf>,
    #[arg(long, help = "Show default config and exit")]
    #[arg(aliases = [ "show-default", "print-defaults", "print-default" ])]
    pub show_defaults: bool,
    #[arg(long, help = "Validate config and exit")]
    pub validate: bool,
    #[arg(long, help = "Reconnect to admin api if router stops")]
    pub reconnect: bool,
    #[arg(long, help = "Set log verbosity level", default_value = "INFO")]
    pub loglevel: LevelFilter,
    #[arg(long = "no-color", help = "Disable auto coloring", action = clap::ArgAction::SetFalse)]
    pub use_color: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (mut cancellation_root, cancellation) = utils::cancellation();
    let res = start(cancellation).await;

    cancellation_root.cancel().await;
    if let Err(()) = res {
        std::process::exit(1);
    }
}

pub async fn start(cancellation: utils::PassiveCancellationToken) -> SilentResult<()> {
    // Read CLI arguments
    let cli_args: CliArgs = clap::Parser::try_parse().unwrap_or_else(|err| err.exit());

    if cli_args.show_defaults {
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
                && std::io::stdout().is_terminal()
                && std::env::var_os("TERM").is_some(),
        )
        .with_max_level(cli_args.loglevel)
        .without_time()
        .log_internal_errors(false)
        .init();

    // Read config file
    let config = match &cli_args.config {
        Some(path) => config::ConfigInner::read(path)?,
        None => config::ConfigInner::default(),
    };
    let config = Arc::new(config);

    if cli_args.validate {
        return cli_args
            .config
            .map(|_| ())
            .ok_or_else(|| error!("Config file is not specified"));
    }

    let reconnect = cli_args.reconnect || config.yggdrasil_admin_reconnect;

    // Construct state
    let router_state = admin_api::reconnect(&config, reconnect)
        .await
        .map_err(|_| error!("Failed to connect to admin socket"))?;
    let watch_sessions = watch::channel(Vec::new());
    let watch_peers = watch::channel(Vec::new());
    let watch_external = watch::channel(Vec::new());

    let state = State::new(StateInner {
        router: RwLock::new(router_state),
        watch_sessions: watch_sessions.1,
        watch_peers: watch_peers.1,
        node_info_cache: Default::default(),
        watch_external: watch_external.1,
        active_sessions: Default::default(),
        active_inet_traversal: Default::default(),
        active_proxies: Default::default(),
        cancellation: cancellation.clone(),
    });

    let external_required = watch::channel(Instant::now());

    let mut signals = signal_harness();

    let (locals, mut inet_listeners) =
        network::setup_inet_listeners(config.clone(), state.clone())?;

    #[cfg(debug_assertions)]
    spawn(debug_sanity_checker(state.clone()));

    // Spawn & wait
    select! {
        _ = inet_listeners.join_next() => {},

        _ = spawn(stun::monitor(
            config.clone(),
            state.clone(),
            watch_external.0,
            external_required.1,
            locals,
        )) => {},

        _ = spawn(admin_api::monitor(
            config.clone(),
            state.clone(),
            watch_sessions.0,
            watch_peers.0,
            reconnect,
        )) => {},

        _ = spawn(session::spawn_new_sessions(
            config.clone(),
            state.clone(),
            external_required.0,
        )) => {},

        _ = cancellation.cancelled() => {},
        _ = signals.join_next() => {
            info!("Stop signal received");
            return Ok(());
        },
    }

    Err(())
}

fn signal_harness() -> JoinSet<()> {
    let mut signals = JoinSet::<()>::new();

    signals.spawn(async move {
        tokio::signal::ctrl_c().await.ok();
    });

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut listen = |kind| {
            if let Ok(mut signal) = signal(kind) {
                signals.spawn(async move {
                    signal.recv().await;
                });
            };
        };

        listen(SignalKind::interrupt());
        listen(SignalKind::terminate());
        listen(SignalKind::hangup());
    }

    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};
        macro_rules! listen {
            ($signal:expr) => {
                if let Ok(mut signal) = $signal {
                    signals.spawn(async move {
                        signal.recv().await;
                    });
                }
            };
        }

        listen!(ctrl_break());
        listen!(ctrl_c());
        listen!(ctrl_close());
        listen!(ctrl_shutdown());
    }

    signals
}

#[cfg(debug_assertions)]
async fn debug_sanity_checker(state: State) {
    use tracing::warn;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        if !state.watch_sessions.borrow().is_empty() && !state.watch_peers.borrow().is_empty() {
            continue;
        }

        if !state.active_sessions.read().await.is_empty() {
            warn!("Some sessions are lingering");
        }

        if !state.active_inet_traversal.read().await.is_empty() {
            warn!("Some traversal sessions are lingering");
        }

        if !state.active_proxies.read().await.is_empty() {
            warn!("Some proxy threads are still running");
        }
    }
}
