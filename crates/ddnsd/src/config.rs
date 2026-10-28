use std::{fs::File, os::unix::fs::PermissionsExt, path::Path};

use anyhow::{Result, bail};
use ddns_clients::resolve::{AnyResolver, HttpResolver, IpFamily};

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ProviderConfig {
    Cloudflare {
        api_token: String,
        zone: String,
    },
    NoIp {
        username: String,
        password: String,
        /// No-IP asks for `Company NameOfProgram/Version maintainer-contact@example.com`.
        user_agent: Option<String>,
    },
}

impl ProviderConfig {
    /// The zone that `<hostname>.<zone>` default domains belong to.
    fn zone(&self) -> Option<&str> {
        match self {
            ProviderConfig::Cloudflare { zone, .. } => Some(zone),
            ProviderConfig::NoIp { .. } => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ResolverConfig {
    Icanhazip,
    Ipify,
    Http {
        ipv4_url: Option<String>,
        ipv6_url: Option<String>,
    },
    #[cfg(target_os = "linux")]
    Local,
}

impl From<&ResolverConfig> for AnyResolver {
    fn from(config: &ResolverConfig) -> Self {
        match config {
            ResolverConfig::Icanhazip => HttpResolver::icanhazip().into(),
            ResolverConfig::Ipify => HttpResolver::ipify().into(),
            ResolverConfig::Http { ipv4_url, ipv6_url } => {
                HttpResolver::new(ipv4_url.clone(), ipv6_url.clone()).into()
            }
            #[cfg(target_os = "linux")]
            ResolverConfig::Local => ddns_clients::resolve::LocalResolver.into(),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub provider: ProviderConfig,
    /// Defaults to `<hostname>.<zone>`.
    pub domain: Option<String>,
    #[serde(default = "yes")]
    pub ipv4: bool,
    #[serde(default = "yes")]
    pub ipv6: bool,
    /// Check interval in seconds.
    #[serde(default = "default_check_interval")]
    pub interval: u64,
    /// 0 means the provider's default.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    /// Tried in order, per address family.
    #[serde(default = "default_resolvers")]
    pub resolvers: Vec<ResolverConfig>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Config> {
        // check config file permission, should not been readable by other user
        let mode = std::fs::metadata(&path)?.permissions().mode();
        if mode & 0o077 != 0 {
            bail!("config file is readable by others");
        }

        let mut config: Config = serde_yaml::from_reader(File::open(path)?)?;
        if config.resolvers.is_empty() {
            bail!("resolvers must not be empty");
        }
        if config.domain.is_none() {
            let Some(zone) = config.provider.zone() else {
                bail!("domain must be set for this provider");
            };
            log::info!("domain is not set, use <hostname>.<zone> as domain");
            config.domain = Some(format!("{}.{zone}", hostname::get()?.to_string_lossy()));
        }
        Ok(config)
    }

    /// The domain to update; always set after [`Config::load`].
    pub fn domain(&self) -> &str {
        self.domain.as_deref().unwrap_or_default()
    }

    pub fn ttl(&self) -> Option<u32> {
        (self.ttl != 0).then_some(self.ttl)
    }

    /// The enabled address families.
    pub fn families(&self) -> Vec<IpFamily> {
        let mut families = vec![];
        if self.ipv4 {
            families.push(IpFamily::V4);
        }
        if self.ipv6 {
            families.push(IpFamily::V6);
        }
        families
    }

    pub fn resolvers(&self) -> Vec<AnyResolver> {
        self.resolvers.iter().map(AnyResolver::from).collect()
    }
}

fn yes() -> bool {
    true
}

fn default_check_interval() -> u64 {
    300
}

fn default_ttl() -> u32 {
    600
}

fn default_max_records() -> usize {
    2
}

fn default_resolvers() -> Vec<ResolverConfig> {
    vec![
        ResolverConfig::Icanhazip,
        #[cfg(target_os = "linux")]
        ResolverConfig::Local,
    ]
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;

    fn write_config(name: &str, content: &str, mode: u32) -> PathBuf {
        let path = std::env::temp_dir().join(format!("ddnsd-test-{}-{name}", std::process::id()));
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    const MINIMAL: &str = "
provider:
  type: cloudflare
  api_token: secret
  zone: example.com
";

    #[test]
    fn full() {
        let path = write_config(
            "full",
            "
provider:
  type: cloudflare
  api_token: secret
  zone: example.com
domain: myhost.example.com
ipv4: false
interval: 60
ttl: 0
max_records: 4
resolvers:
  - type: ipify
  - type: http
    ipv4_url: https://ip4.example.com
",
            0o600,
        );
        let config = Config::load(&path).unwrap();
        fs::remove_file(path).unwrap();

        let ProviderConfig::Cloudflare { api_token, zone } = &config.provider else {
            panic!("unexpected provider {:?}", config.provider);
        };
        assert_eq!(api_token, "secret");
        assert_eq!(zone, "example.com");
        assert_eq!(config.domain(), "myhost.example.com");
        assert!(!config.ipv4);
        assert!(config.ipv6);
        assert_eq!(config.interval, 60);
        assert_eq!(config.ttl(), None);
        assert_eq!(config.max_records, 4);
        assert_eq!(config.families(), vec![IpFamily::V6]);
        assert_eq!(
            config.resolvers,
            vec![
                ResolverConfig::Ipify,
                ResolverConfig::Http {
                    ipv4_url: Some("https://ip4.example.com".into()),
                    ipv6_url: None,
                },
            ]
        );
    }

    #[test]
    fn defaults() {
        let path = write_config("defaults", MINIMAL, 0o600);
        let config = Config::load(&path).unwrap();
        fs::remove_file(path).unwrap();

        let hostname = hostname::get().unwrap();
        assert_eq!(
            config.domain(),
            format!("{}.example.com", hostname.to_string_lossy())
        );
        assert!(config.ipv4);
        assert!(config.ipv6);
        assert_eq!(config.interval, 300);
        assert_eq!(config.ttl(), Some(600));
        assert_eq!(config.max_records, 2);
        assert_eq!(config.families(), vec![IpFamily::V4, IpFamily::V6]);
        assert_eq!(config.resolvers, default_resolvers());
    }

    #[test]
    fn rejects_world_readable() {
        let path = write_config("perm", MINIMAL, 0o644);
        let err = Config::load(&path).unwrap_err();
        fs::remove_file(path).unwrap();
        assert!(err.to_string().contains("readable by others"));
    }

    #[test]
    fn rejects_empty_resolvers() {
        let path = write_config("noresolver", &format!("{MINIMAL}resolvers: []\n"), 0o600);
        let err = Config::load(&path).unwrap_err();
        fs::remove_file(path).unwrap();
        assert!(err.to_string().contains("resolvers"));
    }

    #[test]
    fn noip() {
        let provider = "
provider:
  type: noip
  username: me@example.com
  password: secret
";
        let path = write_config(
            "noip",
            &format!("{provider}domain: myhost.ddns.net\n"),
            0o600,
        );
        let config = Config::load(&path).unwrap();
        fs::remove_file(path).unwrap();
        let ProviderConfig::NoIp {
            username,
            password,
            user_agent,
        } = &config.provider
        else {
            panic!("unexpected provider {:?}", config.provider);
        };
        assert_eq!(username, "me@example.com");
        assert_eq!(password, "secret");
        assert_eq!(user_agent, &None);
        assert_eq!(config.domain(), "myhost.ddns.net");

        let path = write_config("noip-nodomain", provider, 0o600);
        let err = Config::load(&path).unwrap_err();
        fs::remove_file(path).unwrap();
        assert!(err.to_string().contains("domain must be set"), "{err}");
    }

    #[test]
    fn rejects_unknown_provider() {
        let path = write_config("unknown", "provider:\n  type: nope\n", 0o600);
        assert!(Config::load(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
