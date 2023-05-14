use super::*;

pub type Config = Arc<ConfigInner>;

#[derive(PartialEq, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigInner {
    pub allow_ipv4: bool,
    pub allow_ipv6: bool,
    pub listen_port: u16,
    pub yggdrasil_listen: Vec<String>,
    pub yggdrasil_admin_listen: Vec<String>,
    pub whitelist: Option<HashSet<Ipv6Addr>>,
    pub stun_randomize: bool,
    pub stun_servers: Vec<String>,

    // Fields below are not listed in example config
    pub nat_traversal_retry_count: u64,
    #[serde(deserialize_with = "parse_duration")]
    pub nat_traversal_connection_delay: Duration,
    #[serde(deserialize_with = "parse_duration")]
    pub nat_traversal_connection_timeout: Duration,
    #[serde(deserialize_with = "parse_duration")]
    pub peer_unconnected_check_delay: Duration,
    #[serde(deserialize_with = "parse_duration")]
    pub resolve_external_address_delay: Duration,
    #[serde(deserialize_with = "parse_duration")]
    pub yggdrasilctl_query_delay: Duration,
}

impl Default for ConfigInner {
    fn default() -> Self {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Defaults {
            allow_ipv4: bool,
            allow_ipv6: bool,
            listen_port: u16,
            yggdrasil_listen: Vec<String>,
            yggdrasil_admin_listen: Vec<String>,
            whitelist: Option<HashSet<Ipv6Addr>>,
            stun_randomize: bool,
            stun_servers: Vec<String>,
        }
        let Defaults {
            allow_ipv4,
            allow_ipv6,
            listen_port,
            yggdrasil_listen,
            yggdrasil_admin_listen,
            whitelist,
            stun_randomize,
            stun_servers,
        } = toml::from_str(Self::default_str()).unwrap();

        Self {
            allow_ipv4,
            allow_ipv6,
            listen_port,
            yggdrasil_listen,
            yggdrasil_admin_listen,
            whitelist,
            stun_randomize,
            stun_servers,

            nat_traversal_retry_count: 5,
            nat_traversal_connection_delay: Duration::from_secs_f64(1.0),
            nat_traversal_connection_timeout: Duration::from_secs_f64(10.0),
            peer_unconnected_check_delay: Duration::from_secs_f64(15.0),
            resolve_external_address_delay: Duration::from_secs_f64(30.0),
            yggdrasilctl_query_delay: Duration::from_secs_f64(10.0),
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
        Ok(config.verify()?)
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
    Duration::try_from_secs_f64(Deserialize::deserialize(deserializer)?)
        .map_err(|e| D::Error::custom(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        ConfigInner::default();
    }
}
