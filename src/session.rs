use std::{
    collections::HashSet,
    net::{Ipv6Addr, SocketAddrV6},
    time::{Duration, Instant},
};
use tokio::{spawn, sync::watch, time::sleep};
use tracing::{debug, instrument, warn};

use crate::{map_debug, map_info, network, protocol, utils, Config, SilentResult, State};

#[derive(Debug)]
pub enum SessionStage {
    Session,
    Bridge,
}

impl SessionStage {
    pub fn is_bridge(&self) -> bool {
        matches!(self, Self::Bridge)
    }
    pub fn is_session(&self) -> bool {
        matches!(self, Self::Session)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionCache {
    jumper_supported: Option<bool>,
    failed_yggdrasil_traversal: u32,
}

#[instrument(parent = None, name = "Session ", skip_all, fields(peer = utils::pretty_addr(addr)))]
async fn connect_session(
    config: Config,
    state: State,
    peer_key: String,
    addr: SocketAddrV6,
    uptime: Option<f32>,
) -> SilentResult<()> {
    if !is_jumper_supported(&config, &state, addr.ip(), peer_key)
        .await
        .unwrap_or(false)
    {
        return Err(());
    }

    //
    //         inactivity delay period              inactivity delay period  \
    // |<----------------------------------->|<------------------------------/
    // |                                     |                               \
    // +-------------------------------------:xxxxxxxxxxxxxxxxxx:------------/
    // ^                                     |<---------------->|            \
    //  session initiated                      inactivity delay       time   /
    //                                                               ----->
    if let Some(uptime) = uptime {
        if uptime > config.inactivity_delay_period
            && uptime % config.inactivity_delay_period < config.inactivity_delay
        {
            if Duration::from_secs_f32(uptime % config.inactivity_delay_period)
                < config.yggdrasilctl_query_delay
            {
                debug!("Enacting inactivity delay");
            }
            return Ok(());
        }
    }

    //
    //   past     now          next
    //   attempt   \   delay   attempt
    //          \   \|<----->|/
    // +---------:---+-------:----> time
    //           |<--------->|
    //             alignment
    //
    // Align connection time with session's uptime for firewall traversal effect
    let delay = match uptime {
        Some(uptime) => config.align_uptime_timeout - (uptime % config.align_uptime_timeout),
        // Uptime unknown. Avoid request flood
        None => config.align_uptime_timeout,
    };

    debug!("Delay: {delay:.2}s");

    sleep(Duration::from_secs_f32(delay)).await;

    let params = network::TraversalParams {
        retry_count: config.yggdrasil_firewall_traversal_udp_retry_count,
        cycle: config.yggdrasil_firewall_traversal_udp_cycle,
    };

    let res = network::traverse_udp(
        &state,
        &params,
        &(Ipv6Addr::UNSPECIFIED, config.listen_port).into(),
        &addr.into(),
        None,
    )
    .await
    .map_err(map_debug!("NAT traversal failed"))?
    .map_err(map_debug!("NAT traversal unsuccessful"));

    {
        let mut cache = state.node_info_cache.write().await;
        let entry = cache.entry(*addr.ip()).or_insert_with(Default::default);

        if res.is_ok() {
            entry.failed_yggdrasil_traversal = 0;
        } else {
            entry.failed_yggdrasil_traversal += 1;
        }
    }

    if let Ok(socket) = res {
        return protocol::try_session(config, state, socket, addr).await;
    }

    Err(())
}

#[instrument(parent = None, name = "Session spawner", skip_all)]
pub async fn spawn_new_sessions(
    config: Config,
    state: State,
    external_required: watch::Sender<Instant>,
) -> SilentResult<()> {
    let whitelist_contains = config.whitelist.as_ref().map(|whitelist| {
        const ADDRESS_PREFIX: u8 = 0x02;
        const SUBNET_PREFIX: u8 = 0x03;
        const SUBNET_BYTES: usize = 8;

        let get_subnet_id = |address: &Ipv6Addr| {
            u64::from_ne_bytes(address.octets()[..SUBNET_BYTES].try_into().unwrap())
        };

        let mut addresses = HashSet::new();
        let mut subnets = HashSet::new();
        for address in whitelist {
            if address.octets()[0] == SUBNET_PREFIX {
                let mut subnet = get_subnet_id(address).to_ne_bytes();
                subnet[0] = ADDRESS_PREFIX;
                let subnet = u64::from_ne_bytes(subnet);

                subnets.insert(subnet);
            } else {
                addresses.insert(*address);
            }
        }

        move |address: &Ipv6Addr| {
            addresses.contains(address) || subnets.contains(&get_subnet_id(address))
        }
    });

    if config.only_peers_advertising_jumper {
        spawn(node_info_cache_cleaner(config.clone(), state.clone()));
    }

    let watch_peers = state.watch_peers.clone();
    let mut watch_sessions = state.watch_sessions.clone();
    let mut watch_external = state.watch_external.clone();

    // Avoid warning on startup
    if watch_external.borrow().is_empty() {
        watch_external.changed().await.map_err(|_| ())?;
    }

    loop {
        // Suspend if no external address found
        if watch_external.borrow_and_update().is_empty() {
            warn!("No external address found, suspending");
            watch_external.changed().await.map_err(|_| ())?;
            continue;
        }

        {
            // For each connected session
            let mut reload_external = false;
            let mut sessions = state.active_sessions.write().await;
            let peers = config.avoid_redundant_peering.then(|| watch_peers.borrow());
            for session in watch_sessions.borrow_and_update().iter() {
                let addr = session.address;
                let uptime = session.uptime;

                // Skip if address is not in the whitelist
                if let Some(ref whitelist_contains) = whitelist_contains {
                    if !whitelist_contains(&addr) {
                        continue;
                    }
                }

                // Skip if peer is already has direct connection
                if let Some(ref peers) = peers {
                    if peers.iter().any(|p| p.address.as_ref() == Some(&addr)) {
                        continue;
                    }
                }

                // Skip if session already tracked
                if sessions.get(&addr).is_some() {
                    continue;
                }

                // Refresh watchdog
                if !reload_external {
                    external_required.send(Instant::now()).ok();
                    reload_external = true;
                }

                // Add session record
                sessions.insert(addr, SessionStage::Session);

                // Spawn session handler
                let peer_key = session.key.clone();
                let config = config.clone();
                let state = state.clone();
                spawn(async move {
                    let _ = connect_session(
                        config.clone(),
                        state.clone(),
                        peer_key,
                        SocketAddrV6::new(addr, config.listen_port, 0, 0),
                        uptime.map(|u| u as f32),
                    )
                    .await;

                    state.active_sessions.write().await.remove(&addr);
                });
            }
        }

        watch_sessions.changed().await.map_err(|_| ())?;
    }
}

async fn is_jumper_supported(
    config: &Config,
    state: &State,
    addr: &Ipv6Addr,
    key: String,
) -> SilentResult<bool> {
    if let Some(cache) = state.node_info_cache.read().await.get(addr) {
        if let Some(limit) = config.failed_yggdrasil_traversal_limit {
            if cache.failed_yggdrasil_traversal >= limit.into() {
                debug!(
                    "Traversal limit reached at {}",
                    cache.failed_yggdrasil_traversal
                );
                return Ok(false);
            }
        }

        if let Some(cached) = cache.jumper_supported {
            return Ok(cached);
        }
    }

    if !config.only_peers_advertising_jumper {
        return Ok(true);
    }

    let is_supported = {
        let admin_api = &mut state.router.write().await.admin_api;
        let node_info = utils::timeout(
            config.peer_getnodeinfo_timeout,
            admin_api.get_node_info(key),
        )
        .await
        .map_err(map_info!("Can't query admin api"))?
        .map_err(map_info!("Can't get node info from {addr}"))?;
        node_info
            .get("jumper")
            .take_if(|val| {
                use serde_json::Value;
                match val {
                    Value::Bool(true) => true,
                    Value::Number(ver) => ver.as_u64() == Some(protocol::PROTOCOL_VERSION as u64),
                    _ => false,
                }
            })
            .is_some()
    };

    state
        .node_info_cache
        .write()
        .await
        .entry(*addr)
        .or_insert_with(Default::default)
        .jumper_supported = Some(is_supported);

    Ok(is_supported)
}

async fn node_info_cache_cleaner(config: Config, state: State) {
    loop {
        sleep(config.session_cache_invalidation_timeout).await;

        // Simply purging the caches is fine, since fetching the node info is relatively cheap
        state.node_info_cache.write().await.clear();
    }
}
