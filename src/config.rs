use serde::Deserialize;
use std::{
    collections::HashSet, net::Ipv6Addr, num::NonZero, path::Path, sync::Arc, time::Duration,
};
use tracing::error;

use crate::{bridge::PeeringProtocol, map_error};

pub type Config = Arc<ConfigInner>;

#[derive(PartialEq, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigInner {
    pub yggdrasil_listen: Vec<String>,
    pub yggdrasil_admin_listen: Vec<String>,
    pub yggdrasil_protocols: Vec<PeeringProtocol>,
    pub allow_ipv4: bool,
    pub allow_ipv6: bool,
    pub listen_port: u16,

    // Fields below are not listed in example config
    pub yggdrasil_firewall_traversal_udp_retry_count: u32,
    #[serde(deserialize_with = "parse_duration")]
    pub yggdrasil_firewall_traversal_udp_cycle: Duration,

    pub nat_traversal_udp_retry_count: u32,
    #[serde(deserialize_with = "parse_duration")]
    pub nat_traversal_udp_cycle: Duration,

    pub stun_servers: Vec<String>,
    pub stun_randomize: bool,

    pub stun_udp_retry_count: u32,
    #[serde(deserialize_with = "parse_duration")]
    pub stun_udp_response_timeout: Duration,
    pub stun_udp_exponential_timeout: bool,

    #[serde(deserialize_with = "parse_duration")]
    pub stun_tcp_response_timeout: Duration,

    pub whitelist: Option<HashSet<Ipv6Addr>>,
    pub only_peers_advertising_jumper: bool,
    pub failed_yggdrasil_traversal_limit: Option<NonZero<u32>>,

    pub yggdrasil_dpi: bool,
    pub yggdrasil_dpi_udp_mtu: usize,
    pub yggdrasil_dpi_fallback_to_reliable: bool,

    pub yggdrasil_admin_reconnect: bool,
    pub avoid_redundant_peering: bool,

    #[serde(deserialize_with = "parse_duration")]
    pub peer_unconnected_check_delay: Duration,
    #[serde(deserialize_with = "parse_duration")]
    pub resolve_external_address_delay: Duration,
    #[serde(deserialize_with = "parse_duration")]
    pub yggdrasilctl_query_delay: Duration,
    #[serde(deserialize_with = "parse_duration")]
    pub connect_as_client_timeout: Duration,
    #[serde(deserialize_with = "parse_duration")]
    pub peer_getnodeinfo_timeout: Duration,
    #[serde(deserialize_with = "parse_duration")]
    pub session_cache_invalidation_timeout: Duration,

    pub align_uptime_timeout: f32,
    pub inactivity_delay: f32,
    pub inactivity_delay_period: f32,
}

impl Default for ConfigInner {
    fn default() -> Self {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Defaults {
            yggdrasil_listen: Vec<String>,
            yggdrasil_admin_listen: Vec<String>,
            yggdrasil_protocols: Vec<PeeringProtocol>,
            allow_ipv4: bool,
            allow_ipv6: bool,
            listen_port: u16,
            stun_servers: Vec<String>,
            stun_randomize: bool,
        }
        let Defaults {
            yggdrasil_listen,
            yggdrasil_admin_listen,
            yggdrasil_protocols,
            allow_ipv4,
            allow_ipv6,
            listen_port,
            stun_servers,
            stun_randomize,
        } = toml::from_str(Self::default_str()).unwrap();

        ConfigInner {
            yggdrasil_listen,
            yggdrasil_admin_listen,
            yggdrasil_protocols,
            allow_ipv4,
            allow_ipv6,
            listen_port,

            yggdrasil_firewall_traversal_udp_retry_count: 5,
            yggdrasil_firewall_traversal_udp_cycle: Duration::from_secs_f64(1.0),

            nat_traversal_udp_retry_count: 15,
            nat_traversal_udp_cycle: Duration::from_secs_f64(0.5),

            stun_servers,
            stun_randomize,

            stun_udp_retry_count: 4,
            stun_udp_response_timeout: Duration::from_secs_f64(0.5),
            stun_udp_exponential_timeout: true,

            stun_tcp_response_timeout: Duration::from_secs_f64(4.0),

            whitelist: None,
            only_peers_advertising_jumper: false,
            failed_yggdrasil_traversal_limit: None,

            yggdrasil_dpi: false,
            yggdrasil_dpi_udp_mtu: 1452, // 1500 (baseline mtu) - 20 (ipv4) or 40 (ipv6) - 8 (udp)
            yggdrasil_dpi_fallback_to_reliable: true,

            yggdrasil_admin_reconnect: false,
            avoid_redundant_peering: true,

            peer_unconnected_check_delay: Duration::from_secs(15),
            resolve_external_address_delay: Duration::from_secs(25),
            yggdrasilctl_query_delay: Duration::from_secs(10),
            connect_as_client_timeout: Duration::from_secs(5),
            peer_getnodeinfo_timeout: Duration::from_secs(10),
            session_cache_invalidation_timeout: Duration::from_secs(3 * 3600), // Chosen arbitrarily

            align_uptime_timeout: 20.0, // Must be the same on both sides
            inactivity_delay: 1.5 * 60.0,
            inactivity_delay_period: 5.0 * 60.0,
        }
    }
}

impl ConfigInner {
    pub fn default_str() -> &'static str {
        include_str!("../config.toml")
    }

    pub fn read(path: &Path) -> Result<Self, ()> {
        let config = if path == Path::new("-") {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut buf)
                .map_err(map_error!("Failed to read config from stdin"))?;
            buf
        } else {
            std::fs::read_to_string(path).map_err(map_error!("Failed to read config file"))?
        };
        let config: Self =
            toml::from_str(config.as_str()).map_err(map_error!("Failed to parse config"))?;
        config.verify()
    }

    fn verify(self) -> Result<Self, ()> {
        if self.yggdrasil_admin_listen.is_empty() {
            error!("No yggdrasil admin socket specified");
            return Err(());
        }
        if !self.allow_ipv4 && !self.allow_ipv6 {
            error!("IPv4 and IPv6 connectivity disallowed by the configuration");
            return Err(());
        }
        Ok(self)
    }
}

fn parse_duration<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    use serde::de::Error;
    // TODO: interpret suffix
    Duration::try_from_secs_f64(Deserialize::deserialize(deserializer)?).map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        ConfigInner::default();
    }
}
