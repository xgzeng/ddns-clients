use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use ddns_clients::{
    DynDnsClient,
    resolve::{CompositeResolver, HttpResolver, IpResolver},
};

/// A `[provider.<name>]` entry: the provider parameters, passed on to
/// [`DynDnsClient::provider`] which checks which ones the provider needs, and
/// overrides of the top-level settings.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Provider type, e.g. `cloudflare` or `noip`; defaults to the entry's name.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub api_token: Option<String>,
    /// Also the zone of `<hostname>.<zone>` default domains.
    pub zone: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// No-IP asks for `Company NameOfProgram/Version maintainer-contact@example.com`.
    pub user_agent: Option<String>,
    /// PKARR secret key, 64 hex digits.
    #[cfg(feature = "pkarr")]
    pub secret_key: Option<String>,
    /// File holding `secret_key`, relative to the config file's directory;
    /// read by [`Config::load`] into `secret_key`.
    #[cfg(feature = "pkarr")]
    pub secret_file: Option<std::path::PathBuf>,
    /// PKARR relay URLs; empty for the DHT only, unset for the default relays.
    #[cfg(feature = "pkarr")]
    pub relays: Option<Vec<String>>,
    /// Whether PKARR keeps the key's other records.
    #[cfg(feature = "pkarr")]
    pub keep_other_records: Option<bool>,
    /// With `zone`, `<domain>.<zone>` unless it already ends with the zone, and
    /// the zone itself if empty; defaults to `<hostname>.<zone>`. For PKARR,
    /// the name below the key, which is the key itself if empty or unset.
    pub domain: Option<String>,
    pub ipv4: Option<bool>,
    pub ipv6: Option<bool>,
    pub ttl: Option<u32>,
    pub max_records: Option<usize>,
    pub replace_only: Option<bool>,
    #[serde(default, deserialize_with = "optional_seconds")]
    pub cache_expire: Option<Duration>,
}

#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ResolverConfig {
    Icanhazip,
    Ipify,
    #[serde(rename = "ifconfig.me")]
    IfconfigMe,
    /// Echo services, tried in turn: each family's own URLs, then `url`. Each
    /// is a URL or a list of them.
    Http {
        /// For both address families, after their own URLs below.
        #[serde(default, deserialize_with = "urls")]
        url: Vec<String>,
        #[serde(default, deserialize_with = "urls")]
        ipv4_url: Vec<String>,
        #[serde(default, deserialize_with = "urls")]
        ipv6_url: Vec<String>,
    },
    #[cfg(target_os = "linux")]
    Local {
        /// Only this interface's addresses; all interfaces if unset.
        interface: Option<String>,
    },
    /// The addresses all of `resolvers` found; fails if any fails.
    All {
        resolvers: Vec<ResolverConfig>,
    },
    /// The addresses any of `resolvers` found, skipping failed ones.
    Any {
        resolvers: Vec<ResolverConfig>,
    },
}

/// Reads a URL or a list of URLs.
fn urls<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(
        match <OneOrMany as serde::Deserialize>::deserialize(deserializer)? {
            OneOrMany::One(url) => vec![url],
            OneOrMany::Many(urls) => urls,
        },
    )
}

impl ResolverConfig {
    fn resolver(&self) -> Box<dyn IpResolver> {
        match self {
            ResolverConfig::Icanhazip => {
                Box::new(HttpResolver::new().with_url(HttpResolver::ICANHAZIP))
            }
            ResolverConfig::Ipify => Box::new(
                HttpResolver::new()
                    .with_url_v4(HttpResolver::IPIFY_IPV4)
                    .with_url_v6(HttpResolver::IPIFY_IPV6),
            ),
            ResolverConfig::IfconfigMe => {
                Box::new(HttpResolver::new().with_url(HttpResolver::IFCONFIG_ME))
            }
            ResolverConfig::Http {
                url,
                ipv4_url,
                ipv6_url,
            } => {
                let mut resolver = HttpResolver::new();
                for url in ipv4_url {
                    resolver = resolver.with_url_v4(url);
                }
                for url in ipv6_url {
                    resolver = resolver.with_url_v6(url);
                }
                for url in url {
                    resolver = resolver.with_url(url);
                }
                Box::new(resolver)
            }
            #[cfg(target_os = "linux")]
            ResolverConfig::Local { interface } => {
                let resolver = ddns_clients::resolve::LocalResolver::default();
                Box::new(match interface {
                    Some(name) => resolver.interface(name),
                    None => resolver,
                })
            }
            ResolverConfig::All { resolvers } => Box::new(CompositeResolver::all(
                resolvers.iter().map(Self::resolver).collect(),
            )),
            ResolverConfig::Any { resolvers } => Box::new(CompositeResolver::any(
                resolvers.iter().map(Self::resolver).collect(),
            )),
        }
    }

    fn check(&self) -> Result<()> {
        if let ResolverConfig::Http {
            url,
            ipv4_url,
            ipv6_url,
        } = self
        {
            if url.is_empty() && ipv4_url.is_empty() && ipv6_url.is_empty() {
                bail!("http resolver: set url, or ipv4_url and/or ipv6_url");
            }
        }
        #[cfg(target_os = "linux")]
        if let ResolverConfig::Local {
            interface: Some(name),
        } = self
        {
            if name.is_empty() {
                bail!("local resolver: interface must not be empty");
            }
        }
        if let ResolverConfig::All { resolvers } | ResolverConfig::Any { resolvers } = self {
            if resolvers.is_empty() {
                let kind = match self {
                    ResolverConfig::All { .. } => "all",
                    _ => "any",
                };
                bail!("{kind} resolver: resolvers must not be empty");
            }
            for resolver in resolvers {
                resolver.check()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Whether public IPv4 addresses are looked up; default for providers
    /// that don't set it, which can't enable it if this doesn't.
    #[serde(default = "yes")]
    pub ipv4: bool,
    /// Like `ipv4`, for IPv6.
    #[serde(default = "yes")]
    pub ipv6: bool,
    /// Time between lookups of the public addresses, configured in seconds.
    #[serde(default = "default_resolve_interval", deserialize_with = "seconds")]
    pub resolve_interval: Duration,
    /// Time between the daemon's checks, which retry failed updates and look
    /// up the addresses once `resolve_interval` has passed; in seconds.
    #[serde(default = "default_tick", deserialize_with = "seconds")]
    pub tick: Duration,
    /// Default for providers that don't set it: time after which they read
    /// their records again, to notice changes made outside ddnsd; in seconds,
    /// 0 never.
    #[serde(default = "default_cache_expire", deserialize_with = "seconds")]
    pub cache_expire: Duration,
    /// Default for providers that don't set it; 0 means the provider's default.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Default for providers that don't set it.
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    /// Default for providers that don't set it: only re-point existing
    /// records, never create or delete any.
    #[serde(default)]
    pub replace_only: bool,
    /// Their addresses are merged, per address family; failed ones are
    /// skipped.
    #[serde(default = "default_resolvers")]
    pub resolvers: Vec<ResolverConfig>,
    /// The interface whose address changes make the daemon look up the
    /// addresses at the next check; all interfaces if unset.
    #[cfg(target_os = "linux")]
    pub watch_interface: Option<String>,
    /// Providers to update, by name.
    #[serde(default)]
    pub provider: BTreeMap<String, ProviderConfig>,
}

impl ProviderConfig {
    /// The provider type: `type`, or else the entry's `name`.
    fn kind<'a>(&'a self, name: &'a str) -> &'a str {
        self.kind.as_deref().unwrap_or(name)
    }

    /// Whether this is a PKARR provider; built without PKARR, the type is
    /// rejected as unknown later.
    fn is_pkarr(&self, name: &str) -> bool {
        self.kind(name) == "pkarr"
    }

    /// Reads `secret_file`, relative to `base`, into `secret_key`.
    #[cfg(feature = "pkarr")]
    fn read_secret_file(&mut self, name: &str, base: &Path) -> Result<()> {
        let Some(file) = &self.secret_file else {
            return Ok(());
        };
        if !self.is_pkarr(name) {
            bail!("secret_file is not used");
        }
        if self.secret_key.is_some() {
            bail!("set secret_key or secret_file, not both");
        }
        let path = base.join(file);
        check_private(&path).context("secret_file")?;
        let key = fs::read_to_string(&path)
            .with_context(|| format!("reading secret_file {}", path.display()))?;
        self.secret_key = Some(key.trim().to_string());
        Ok(())
    }

    /// Checks `zone` and `domain`, and returns the full name of the domain;
    /// `None` for a PKARR key's own records.
    fn full_domain(&self, name: &str) -> Result<Option<String>> {
        if self.is_pkarr(name) {
            // relative to the key, which the provider appends
            return match self.domain.as_deref() {
                None | Some("" | "@") => Ok(None),
                Some(domain) => {
                    check_domain_name(domain, true)
                        .with_context(|| format!("invalid domain {domain:?}"))?;
                    Ok(Some(domain.to_string()))
                }
            };
        }
        self.dns_domain(name).map(Some)
    }

    /// [`full_domain`](Self::full_domain) of a provider of DNS names.
    fn dns_domain(&self, name: &str) -> Result<String> {
        let Some(zone) = &self.zone else {
            let Some(domain) = &self.domain else {
                bail!("domain must be set for this provider");
            };
            check_domain_name(domain, true)
                .with_context(|| format!("invalid domain {domain:?}"))?;
            if !domain.contains('.') {
                bail!("invalid domain {domain:?}: must be a full name without a zone");
            }
            return Ok(domain.clone());
        };

        check_domain_name(zone, false).with_context(|| format!("invalid zone {zone:?}"))?;
        if !zone.contains('.') {
            bail!("invalid zone {zone:?}: must have at least two labels");
        }
        let domain = match &self.domain {
            Some(domain) if domain.is_empty() => return Ok(zone.clone()),
            Some(domain) => domain.clone(),
            None => {
                let hostname = hostname::get()?.to_string_lossy().into_owned();
                log::info!("provider {name}: domain is not set, using hostname {hostname}");
                hostname
            }
        };
        check_domain_name(&domain, true).with_context(|| format!("invalid domain {domain:?}"))?;
        if in_zone(&domain, zone) {
            return Ok(domain);
        }
        let full = format!("{domain}.{zone}");
        check_domain_name(&full, true).with_context(|| format!("invalid domain {full:?}"))?;
        Ok(full)
    }
}

/// Fails if the file at `path`, which holds credentials, is missing or readable
/// by group or others.
fn check_private(path: &Path) -> Result<()> {
    let mode = fs::metadata(path)
        .with_context(|| path.display().to_string())?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!("{} is readable by others", path.display());
    }
    Ok(())
}

/// Whether `domain` is `zone` or below it; both must be valid names.
fn in_zone(domain: &str, zone: &str) -> bool {
    let (domain, zone) = (domain.to_ascii_lowercase(), zone.to_ascii_lowercase());
    domain == zone || domain.ends_with(&format!(".{zone}"))
}

/// Checks that `name` is only a DNS name, in ASCII (so internationalized names
/// are written in punycode) and without a trailing dot. With `wildcard`, the
/// first label may be `*`.
fn check_domain_name(name: &str, wildcard: bool) -> Result<()> {
    if name.len() > 253 {
        bail!("longer than 253 characters");
    }
    for (i, label) in name.split('.').enumerate() {
        if wildcard && i == 0 && label == "*" {
            continue;
        }
        if label.is_empty() {
            bail!("empty label");
        }
        if label.len() > 63 {
            bail!("label {label:?} is longer than 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("label {label:?} starts or ends with a hyphen");
        }
        if let Some(c) = label
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
        {
            bail!("label {label:?} contains {c:?}");
        }
    }
    Ok(())
}

/// A configured provider with the top-level defaults applied.
pub struct Target {
    pub name: String,
    pub client: DynDnsClient,
    /// How often the provider reads its records again; `None` never.
    pub cache_expire: Option<Duration>,
}

impl Config {
    /// Reads the config file at `path`; relative paths in it are relative to
    /// its directory.
    pub fn load(path: impl AsRef<Path>) -> Result<Config> {
        let path = path.as_ref();
        check_private(path).context("config file")?;

        let mut config: Config = toml::from_str(&fs::read_to_string(path)?)?;
        if config.tick.is_zero() {
            bail!("tick must not be 0");
        }
        if config.resolvers.is_empty() {
            bail!("resolvers must not be empty");
        }
        for resolver in &config.resolvers {
            resolver.check()?;
        }
        #[cfg(target_os = "linux")]
        if config.watch_interface.as_deref() == Some("") {
            bail!("watch_interface must not be empty");
        }
        if config.provider.is_empty() {
            bail!("no provider configured, add a [provider.<name>] table");
        }
        #[cfg(feature = "pkarr")]
        let base = path.parent().unwrap_or(Path::new(""));
        for (name, provider) in &mut config.provider {
            let domain = provider
                .full_domain(name)
                .map_err(|err| anyhow::anyhow!("provider {name}: {err:#}"))?;
            provider.domain = domain;
            #[cfg(feature = "pkarr")]
            provider
                .read_secret_file(name, base)
                .map_err(|err| anyhow::anyhow!("provider {name}: {err:#}"))?;
        }
        Ok(config)
    }

    /// Creates a client for each provider; fails if a provider type is
    /// unknown, its parameters are missing or unused, both address families
    /// are disabled, or it enables a family disabled at the top level.
    pub fn targets(&self) -> Result<Vec<Target>> {
        self.provider
            .iter()
            .map(|(name, provider)| {
                let cache_expire = self.cache_expire(provider);
                let client = self
                    .check_families(provider)
                    .and_then(|()| {
                        if provider.is_pkarr(name) && cache_expire.is_none() {
                            // the packet is republished when the cache expires
                            bail!("cache_expire must not be 0, or the records drop off the DHT");
                        }
                        self.client(name, provider)
                    })
                    .with_context(|| format!("provider {name}"))?;
                Ok(Target {
                    name: name.clone(),
                    client,
                    cache_expire,
                })
            })
            .collect()
    }

    fn client(&self, name: &str, provider: &ProviderConfig) -> Result<DynDnsClient> {
        let mut builder = DynDnsClient::provider(provider.kind(name))?;
        if let Some(api_token) = &provider.api_token {
            builder = builder.api_token(api_token);
        }
        if let Some(zone) = &provider.zone {
            builder = builder.zone(zone);
        }
        if let Some(username) = &provider.username {
            builder = builder.username(username);
        }
        if let Some(password) = &provider.password {
            builder = builder.password(password);
        }
        if let Some(user_agent) = &provider.user_agent {
            builder = builder.user_agent(user_agent);
        }
        #[cfg(feature = "pkarr")]
        {
            if let Some(secret_key) = &provider.secret_key {
                builder = builder.secret_key(secret_key);
            }
            if let Some(relays) = &provider.relays {
                builder = builder.relays(relays);
            }
            if let Some(keep) = provider.keep_other_records {
                builder = builder.keep_other_records(keep);
            }
        }
        if let Some(domain) = &provider.domain {
            builder = builder.domain(domain);
        }
        builder
            .ttl(self.ttl(provider))
            .enable_ipv4(provider.ipv4.unwrap_or(self.ipv4))
            .enable_ipv6(provider.ipv6.unwrap_or(self.ipv6))
            .max_records(Some(self.max_records(provider)))
            .replace_only(self.replace_only(provider))
            .build()
    }

    /// Fails if `provider` enables a family whose addresses aren't looked up,
    /// as its records would be removed.
    fn check_families(&self, provider: &ProviderConfig) -> Result<()> {
        let families = [
            ("ipv4", provider.ipv4, self.ipv4),
            ("ipv6", provider.ipv6, self.ipv6),
        ];
        for (family, enabled, looked_up) in families {
            if enabled == Some(true) && !looked_up {
                bail!("{family} is enabled, but disabled at the top level");
            }
        }
        Ok(())
    }

    /// The TTL for `provider`'s records; `None` (configured as 0) uses the
    /// provider's default.
    fn ttl(&self, provider: &ProviderConfig) -> Option<u32> {
        let ttl = provider.ttl.unwrap_or(self.ttl);
        (ttl != 0).then_some(ttl)
    }

    /// The maximum number of `provider`'s A/AAAA records.
    fn max_records(&self, provider: &ProviderConfig) -> usize {
        provider.max_records.unwrap_or(self.max_records)
    }

    /// Whether `provider` only re-points existing records.
    fn replace_only(&self, provider: &ProviderConfig) -> bool {
        provider.replace_only.unwrap_or(self.replace_only)
    }

    /// How often `provider` reads its records again; `None` (configured as 0)
    /// never.
    fn cache_expire(&self, provider: &ProviderConfig) -> Option<Duration> {
        let expire = provider.cache_expire.unwrap_or(self.cache_expire);
        (!expire.is_zero()).then_some(expire)
    }

    /// The `any` of `resolvers`.
    pub fn resolver(&self) -> CompositeResolver {
        CompositeResolver::any(
            self.resolvers
                .iter()
                .map(ResolverConfig::resolver)
                .collect(),
        )
    }
}

fn yes() -> bool {
    true
}

fn default_tick() -> Duration {
    Duration::from_secs(15)
}

fn default_resolve_interval() -> Duration {
    Duration::from_secs(300)
}

/// Deserializes a [`Duration`] from whole seconds.
fn seconds<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    <u64 as serde::Deserialize>::deserialize(deserializer).map(Duration::from_secs)
}

/// Like [`seconds`], for settings that may be unset.
fn optional_seconds<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Duration>, D::Error> {
    seconds(deserializer).map(Some)
}

fn default_cache_expire() -> Duration {
    Duration::from_secs(3600)
}

fn default_ttl() -> u32 {
    600
}

fn default_max_records() -> usize {
    2
}

/// Like [`ddns_clients::resolve::default_resolvers`]: local AND ipify,
/// falling back to ifconfig.me and icanhazip.
fn default_resolvers() -> Vec<ResolverConfig> {
    vec![ResolverConfig::All {
        resolvers: vec![
            #[cfg(target_os = "linux")]
            ResolverConfig::Local { interface: None },
            ResolverConfig::Http {
                url: vec![
                    HttpResolver::IFCONFIG_ME.into(),
                    HttpResolver::ICANHAZIP.into(),
                ],
                ipv4_url: vec![HttpResolver::IPIFY_IPV4.into()],
                ipv6_url: vec![HttpResolver::IPIFY_IPV6.into()],
            },
        ],
    }]
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn write_config(name: &str, content: &str, mode: u32) -> PathBuf {
        let path = std::env::temp_dir().join(format!("ddnsd-test-{}-{name}", std::process::id()));
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn load(name: &str, content: &str) -> Result<Config> {
        let path = write_config(name, content, 0o600);
        let config = Config::load(&path);
        fs::remove_file(path).unwrap();
        config
    }

    const MINIMAL: &str = r#"
[provider.cloudflare]
api_token = "secret"
zone = "example.com"
"#;

    #[test]
    fn full() {
        let config = load(
            "full",
            r#"
resolve_interval = 60
tick = 5
cache_expire = 0
ttl = 0
max_records = 4
replace_only = true
resolvers = [
  { type = "ipify" },
  { type = "ifconfig.me" },
  { type = "http", ipv4_url = "https://ip4.example.com" },
]

[provider.home]
type = "cloudflare"
api_token = "secret"
zone = "example.com"
domain = "myhost.example.com"
ipv4 = false

[provider.noip]
username = "me@example.com"
password = "secret"
user_agent = "Example ddnsd/1.0 admin@example.com"
domain = "myhost.ddns.net"
ipv6 = false
ttl = 60
max_records = 1
replace_only = false
cache_expire = 600
"#,
        )
        .unwrap();
        assert_eq!(config.resolve_interval, Duration::from_secs(60));
        assert_eq!(config.tick, Duration::from_secs(5));
        assert_eq!(
            config.resolvers,
            vec![
                ResolverConfig::Ipify,
                ResolverConfig::IfconfigMe,
                ResolverConfig::Http {
                    url: vec![],
                    ipv4_url: vec!["https://ip4.example.com".into()],
                    ipv6_url: vec![],
                },
            ]
        );

        let targets = config.targets().unwrap();
        let [home, noip] = targets.as_slice() else {
            panic!("expected two targets");
        };
        assert_eq!(home.name, "home");
        assert_eq!(home.client.domain(), "myhost.example.com");
        assert_eq!(config.ttl(&config.provider["home"]), None);
        assert!(!home.client.is_ipv4_enabled());
        assert!(home.client.is_ipv6_enabled());
        assert_eq!(config.max_records(&config.provider["home"]), 4);
        assert_eq!(home.cache_expire, None);
        assert!(config.replace_only(&config.provider["home"]));
        assert_eq!(noip.name, "noip");
        assert_eq!(noip.client.domain(), "myhost.ddns.net");
        assert_eq!(config.ttl(&config.provider["noip"]), Some(60));
        assert!(noip.client.is_ipv4_enabled());
        assert!(!noip.client.is_ipv6_enabled());
        assert_eq!(config.max_records(&config.provider["noip"]), 1);
        assert_eq!(noip.cache_expire, Some(Duration::from_secs(600)));
        assert!(!config.replace_only(&config.provider["noip"]));
    }

    #[test]
    fn defaults() {
        let config = load("defaults", MINIMAL).unwrap();
        assert_eq!(config.resolve_interval, Duration::from_secs(300));
        assert_eq!(config.tick, Duration::from_secs(15));
        assert_eq!(config.resolvers, default_resolvers());

        let targets = config.targets().unwrap();
        let [target] = targets.as_slice() else {
            panic!("expected one target");
        };
        let hostname = hostname::get().unwrap();
        assert_eq!(
            target.client.domain(),
            format!("{}.example.com", hostname.to_string_lossy())
        );
        assert_eq!(config.ttl(&config.provider["cloudflare"]), Some(600));
        assert!(target.client.is_ipv4_enabled());
        assert!(target.client.is_ipv6_enabled());
        assert_eq!(config.max_records(&config.provider["cloudflare"]), 2);
        assert_eq!(target.cache_expire, Some(Duration::from_secs(3600)));
        assert!(!config.replace_only(&config.provider["cloudflare"]));
    }

    #[test]
    fn example() {
        let config = load("example", include_str!("../ddnsd.example.toml")).unwrap();
        let targets = config.targets().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].client.domain(), "myhost.example.com");
        assert_eq!(config.resolvers, default_resolvers());
    }

    #[test]
    fn rejects_world_readable() {
        let path = write_config("perm", MINIMAL, 0o644);
        let err = Config::load(&path).unwrap_err();
        fs::remove_file(path).unwrap();
        assert!(format!("{err:#}").contains("readable by others"), "{err:#}");
    }

    #[test]
    fn rejects_empty_resolvers() {
        let err = load("noresolver", &format!("resolvers = []\n{MINIMAL}")).unwrap_err();
        assert!(err.to_string().contains("resolvers"));
    }

    #[test]
    fn http_resolver_with_single_url() {
        let config = load(
            "singleurl",
            &format!(
                "resolvers = [{{ type = \"http\", url = \"https://ip.example.com\" }}]\n{MINIMAL}"
            ),
        )
        .unwrap();
        assert_eq!(
            config.resolvers,
            vec![ResolverConfig::Http {
                url: vec!["https://ip.example.com".into()],
                ipv4_url: vec![],
                ipv6_url: vec![],
            }]
        );
    }

    #[test]
    fn http_resolver_url_lists() {
        let config = load(
            "urllists",
            &format!(
                r#"resolvers = [{{ type = "http", url = "https://both",
  ipv4_url = ["https://v4a", "https://v4b"], ipv6_url = [] }}]
{MINIMAL}"#
            ),
        )
        .unwrap();
        assert_eq!(
            config.resolvers,
            vec![ResolverConfig::Http {
                url: vec!["https://both".into()],
                ipv4_url: vec!["https://v4a".into(), "https://v4b".into()],
                ipv6_url: vec![],
            }]
        );
    }

    #[test]
    fn rejects_http_resolver_without_url() {
        let err = load(
            "nourl",
            &format!("resolvers = [{{ type = \"http\" }}]\n{MINIMAL}"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("set url"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_resolver_interface() {
        let config = load(
            "iface",
            &format!("resolvers = [{{ type = \"local\", interface = \"eth0\" }}]\n{MINIMAL}"),
        )
        .unwrap();
        assert_eq!(
            config.resolvers,
            vec![ResolverConfig::Local {
                interface: Some("eth0".into())
            }]
        );

        let err = load(
            "noiface",
            &format!("resolvers = [{{ type = \"local\", interface = \"\" }}]\n{MINIMAL}"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("interface"), "{err}");
    }

    #[test]
    fn nested_resolvers() {
        let config = load(
            "nested",
            &format!(
                "resolvers = [{{ type = \"all\", resolvers = [{{ type = \"icanhazip\" }}, {{ type = \"ipify\" }}] }}]\n{MINIMAL}"
            ),
        )
        .unwrap();
        assert_eq!(
            config.resolvers,
            vec![ResolverConfig::All {
                resolvers: vec![ResolverConfig::Icanhazip, ResolverConfig::Ipify]
            }]
        );

        let err = load(
            "nestedempty",
            &format!("resolvers = [{{ type = \"any\", resolvers = [] }}]\n{MINIMAL}"),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("any resolver: resolvers must not be empty"),
            "{err}"
        );
    }

    fn cloudflare(zone: &str, domain: &str) -> String {
        format!(
            "[provider.cloudflare]\napi_token = \"secret\"\nzone = {zone:?}\ndomain = {domain:?}\n"
        )
    }

    #[test]
    fn domain_is_completed_with_zone() {
        for (domain, expected) in [
            ("home", "home.example.com"),
            ("a.home", "a.home.example.com"),
            ("*", "*.example.com"),
            // already ends with the zone
            ("home.example.com", "home.example.com"),
            ("*.example.com", "*.example.com"),
            ("HOME.Example.COM", "HOME.Example.COM"),
            ("example.com", "example.com"),
            ("", "example.com"),
            // only whole labels match the zone
            ("notexample.com", "notexample.com.example.com"),
        ] {
            let config = load("complete", &cloudflare("example.com", domain)).unwrap();
            let targets = config.targets().unwrap();
            assert_eq!(targets[0].client.domain(), expected);
        }
    }

    #[test]
    fn rejects_invalid_domain() {
        let long_label = "a".repeat(64);
        let long_name = ["a".repeat(60).as_str(); 5].join(".");
        for domain in [
            "https://home.example.com/",
            "home.example.com:443",
            "home example",
            "home..example.com",
            "home.example.com.",
            ".home",
            "-home",
            "home-",
            "*.*",
            "a.*",
            "h\u{f6}me",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            let err = load("baddomain", &cloudflare("example.com", domain)).unwrap_err();
            assert!(
                err.to_string()
                    .starts_with("provider cloudflare: invalid domain"),
                "{domain}: {err}"
            );
        }
    }

    #[test]
    fn rejects_domain_too_long_with_zone() {
        let domain = ["a".repeat(60).as_str(); 4].join(".");
        let err = load("longdomain", &cloudflare("example.com", &domain)).unwrap_err();
        assert!(err.to_string().contains("longer than 253"), "{err}");
    }

    #[test]
    fn rejects_invalid_zone() {
        for zone in [
            "",
            "example",
            "https://example.com",
            "example.com.",
            "*.example.com",
        ] {
            let err = load("badzone", &cloudflare(zone, "home")).unwrap_err();
            assert!(
                err.to_string()
                    .starts_with("provider cloudflare: invalid zone"),
                "{zone}: {err}"
            );
        }
    }

    #[test]
    fn domain_without_zone_must_be_full() {
        let provider = |domain: &str| {
            format!(
                "[provider.noip]\nusername = \"me\"\npassword = \"secret\"\ndomain = {domain:?}\n"
            )
        };
        let config = load("noipfull", &provider("myhost.ddns.net")).unwrap();
        assert_eq!(
            config.targets().unwrap()[0].client.domain(),
            "myhost.ddns.net"
        );
        let err = load("noiplabel", &provider("myhost")).unwrap_err();
        assert!(err.to_string().contains("must be a full name"), "{err}");
        let err = load("noipempty", &provider("")).unwrap_err();
        assert!(err.to_string().contains("invalid domain"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn watch_interface() {
        let config = load("watch", &format!("watch_interface = \"wan\"\n{MINIMAL}")).unwrap();
        assert_eq!(config.watch_interface.as_deref(), Some("wan"));
        let config = load("nowatch", MINIMAL).unwrap();
        assert_eq!(config.watch_interface, None);
        let err = load("emptywatch", &format!("watch_interface = \"\"\n{MINIMAL}")).unwrap_err();
        assert_eq!(err.to_string(), "watch_interface must not be empty");
    }

    #[test]
    fn rejects_zero_tick() {
        let err = load("zerotick", &format!("tick = 0\n{MINIMAL}")).unwrap_err();
        assert_eq!(err.to_string(), "tick must not be 0");
    }

    #[test]
    fn rejects_no_provider() {
        let err = load("noprovider", "resolve_interval = 60\n").unwrap_err();
        assert!(err.to_string().contains("no provider configured"), "{err}");
    }

    #[test]
    fn rejects_no_family() {
        let config = load(
            "nofamily",
            &format!("ipv6 = false\n{MINIMAL}ipv4 = false\n"),
        )
        .unwrap();
        let err = config.targets().err().unwrap();
        assert_eq!(
            format!("{err:#}"),
            "provider cloudflare: cloudflare: ipv4 and ipv6 are both disabled"
        );
    }

    #[test]
    fn rejects_family_disabled_at_top_level() {
        let config = load("v6off", &format!("ipv6 = false\n{MINIMAL}ipv6 = true\n")).unwrap();
        assert!(config.ipv4 && !config.ipv6);
        let err = config.targets().err().unwrap();
        assert_eq!(
            format!("{err:#}"),
            "provider cloudflare: ipv6 is enabled, but disabled at the top level"
        );
    }

    #[test]
    fn rejects_top_level_key_after_provider_table() {
        // belongs to [provider.cloudflare] in TOML, not to the top level
        let err = load("keyorder", &format!("{MINIMAL}resolve_interval = 60\n")).unwrap_err();
        assert!(
            err.to_string().contains("unknown field `resolve_interval`"),
            "{err}"
        );
    }

    #[test]
    fn requires_domain_without_zone() {
        let err = load(
            "nodomain",
            "[provider.noip]\nusername = \"me\"\npassword = \"secret\"\n",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("provider noip: domain must be set"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unknown_provider() {
        let config = load(
            "unknown",
            "[provider.nope]\ndomain = \"myhost.example.com\"\n",
        )
        .unwrap();
        let err = config.targets().err().unwrap();
        assert!(
            format!("{err:#}").starts_with(
                r#"provider nope: unknown provider "nope", expected one of: cloudflare, noip"#
            ),
            "{err:#}"
        );
    }

    #[test]
    fn rejects_bad_provider_parameters() {
        let config = load(
            "badparams",
            r#"
[provider.home]
type = "cloudflare"
zone = "example.com"
username = "me"
"#,
        )
        .unwrap();
        let err = config.targets().err().unwrap();
        assert!(
            format!("{err:#}")
                .contains("provider home: cloudflare: missing api_token; username is not used"),
            "{err:#}"
        );
    }

    #[cfg(feature = "pkarr")]
    const PKARR_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[cfg(feature = "pkarr")]
    #[test]
    fn pkarr_names_are_below_the_key() {
        let config = load(
            "pkarr",
            &format!(
                r#"
[provider.pkarr]
secret_key = "{PKARR_KEY}"
relays = []

[provider.home]
type = "pkarr"
secret_key = "{PKARR_KEY}"
relays = ["https://relay.example.net"]
keep_other_records = false
domain = "home"
"#
            ),
        )
        .unwrap();
        let targets = config.targets().unwrap();
        let key = targets[1].client.domain();
        assert_eq!(targets[1].name, "pkarr");
        assert_eq!(key.len(), 52, "{key}");
        assert_eq!(targets[0].client.domain(), format!("home.{key}"));
    }

    #[cfg(feature = "pkarr")]
    #[test]
    fn pkarr_secret_file() {
        let dir = std::env::temp_dir().join(format!("ddnsd-test-{}-secret", std::process::id()));
        fs::create_dir_all(dir.join("keys")).unwrap();
        let key_file = dir.join("keys/pkarr.key");
        fs::write(&key_file, format!("{PKARR_KEY}\n")).unwrap();
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
        let config_file = dir.join("ddnsd.toml");
        let load_with = |settings: &str| {
            fs::write(&config_file, format!("[provider.pkarr]\n{settings}\n")).unwrap();
            fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();
            Config::load(&config_file)
        };

        // relative to the config file's directory, and absolute
        for file in ["keys/pkarr.key", key_file.to_str().unwrap()] {
            let config = load_with(&format!("secret_file = {file:?}")).unwrap();
            assert_eq!(
                config.provider["pkarr"].secret_key.as_deref(),
                Some(PKARR_KEY)
            );
            config.targets().unwrap();
        }

        let both = format!("secret_file = \"keys/pkarr.key\"\nsecret_key = \"{PKARR_KEY}\"");
        let err = load_with(&both).unwrap_err();
        assert!(format!("{err:#}").contains("not both"), "{err:#}");

        let err = load_with("secret_file = \"missing.key\"").unwrap_err();
        assert!(format!("{err:#}").contains("missing.key"), "{err:#}");

        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_with("secret_file = \"keys/pkarr.key\"").unwrap_err();
        assert!(format!("{err:#}").contains("readable by others"), "{err:#}");

        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "pkarr")]
    #[test]
    fn rejects_secret_file_of_other_providers() {
        let err = load(
            "secret-other",
            &format!("{MINIMAL}secret_file = \"pkarr.key\"\n"),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("provider cloudflare: secret_file is not used"),
            "{err:#}"
        );
    }

    #[cfg(feature = "pkarr")]
    #[test]
    fn pkarr_rejects_never_expiring_cache() {
        let config = load(
            "pkarr-expire",
            &format!(
                r#"
[provider.pkarr]
secret_key = "{PKARR_KEY}"
cache_expire = 0
"#
            ),
        )
        .unwrap();
        let err = config.targets().err().unwrap();
        assert!(
            format!("{err:#}").contains("provider pkarr: cache_expire must not be 0"),
            "{err:#}"
        );
    }

    #[cfg(feature = "pkarr")]
    #[test]
    fn pkarr_rejects_bad_secret_key() {
        let config = load(
            "pkarr-key",
            r#"
[provider.pkarr]
secret_key = "abc"
zone = "example.com"
"#,
        )
        .unwrap();
        let err = config.targets().err().unwrap();
        assert!(
            format!("{err:#}").contains("pkarr: zone is not used"),
            "{err:#}"
        );
        let config = load(
            "pkarr-key2",
            r#"
[provider.pkarr]
secret_key = "abc"
"#,
        )
        .unwrap();
        let err = config.targets().err().unwrap();
        assert!(format!("{err:#}").contains("64 hex digits"), "{err:#}");
    }
}
