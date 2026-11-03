use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use ddns_clients::{
    DynDnsClient,
    resolve::{AnyResolver, HttpResolver},
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
    /// With `zone`, `<domain>.<zone>` unless it already ends with the zone, and
    /// the zone itself if empty; defaults to `<hostname>.<zone>`.
    pub domain: Option<String>,
    pub ipv4: Option<bool>,
    pub ipv6: Option<bool>,
    pub ttl: Option<u32>,
    pub max_records: Option<usize>,
    pub replace_only: Option<bool>,
}

#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ResolverConfig {
    Icanhazip,
    Ipify,
    Http {
        /// For the address families without their own URL below.
        url: Option<String>,
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
            ResolverConfig::Http {
                url,
                ipv4_url,
                ipv6_url,
            } => HttpResolver::new(
                ipv4_url.as_ref().or(url.as_ref()).cloned(),
                ipv6_url.as_ref().or(url.as_ref()).cloned(),
            )
            .into(),
            #[cfg(target_os = "linux")]
            ResolverConfig::Local => ddns_clients::resolve::LocalResolver.into(),
        }
    }
}

impl ResolverConfig {
    fn check(&self) -> Result<()> {
        if let ResolverConfig::Http {
            url: None,
            ipv4_url: None,
            ipv6_url: None,
        } = self
        {
            bail!("http resolver: set url, or ipv4_url and/or ipv6_url");
        }
        Ok(())
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Default for providers that don't set it.
    #[serde(default = "yes")]
    pub ipv4: bool,
    /// Default for providers that don't set it.
    #[serde(default = "yes")]
    pub ipv6: bool,
    /// Check interval in seconds.
    #[serde(default = "default_check_interval")]
    pub interval: u64,
    /// Seconds after which providers read their records again, to notice
    /// changes made outside ddnsd; 0 never does.
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,
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
    /// Tried in order, per address family.
    #[serde(default = "default_resolvers")]
    pub resolvers: Vec<ResolverConfig>,
    /// Providers to update, by name.
    #[serde(default)]
    pub provider: BTreeMap<String, ProviderConfig>,
}

impl ProviderConfig {
    /// Checks `zone` and `domain`, and returns the full name of the domain.
    fn full_domain(&self, name: &str) -> Result<String> {
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
    pub max_records: usize,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Config> {
        // check config file permission, should not been readable by other user
        let mode = fs::metadata(&path)?.permissions().mode();
        if mode & 0o077 != 0 {
            bail!("config file is readable by others");
        }

        let mut config: Config = toml::from_str(&fs::read_to_string(path)?)?;
        if config.resolvers.is_empty() {
            bail!("resolvers must not be empty");
        }
        for resolver in &config.resolvers {
            resolver.check()?;
        }
        if config.provider.is_empty() {
            bail!("no provider configured, add a [provider.<name>] table");
        }
        for (name, provider) in &mut config.provider {
            let domain = provider
                .full_domain(name)
                .map_err(|err| anyhow::anyhow!("provider {name}: {err:#}"))?;
            provider.domain = Some(domain);
        }
        Ok(config)
    }

    /// Creates a client for each provider; fails if a provider type is
    /// unknown, its parameters are missing or unused, or both address
    /// families are disabled.
    pub fn targets(&self) -> Result<Vec<Target>> {
        self.provider
            .iter()
            .map(|(name, provider)| {
                let client = self
                    .client(name, provider)
                    .with_context(|| format!("provider {name}"))?;
                Ok(Target {
                    name: name.clone(),
                    client,
                    max_records: provider.max_records.unwrap_or(self.max_records),
                })
            })
            .collect()
    }

    fn client(&self, name: &str, provider: &ProviderConfig) -> Result<DynDnsClient> {
        let mut builder = DynDnsClient::provider(provider.kind.as_deref().unwrap_or(name))?;
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
        if let Some(domain) = &provider.domain {
            builder = builder.domain(domain);
        }
        builder
            .ttl(self.ttl(provider))
            .enable_ipv4(provider.ipv4.unwrap_or(self.ipv4))
            .enable_ipv6(provider.ipv6.unwrap_or(self.ipv6))
            .replace_only(provider.replace_only.unwrap_or(self.replace_only))
            .build()
    }

    /// The TTL for `provider`'s records; `None` (configured as 0) uses the
    /// provider's default.
    fn ttl(&self, provider: &ProviderConfig) -> Option<u32> {
        let ttl = provider.ttl.unwrap_or(self.ttl);
        (ttl != 0).then_some(ttl)
    }

    /// How often providers read their records again; `None` never.
    pub fn refresh_interval(&self) -> Option<Duration> {
        (self.refresh_interval != 0).then(|| Duration::from_secs(self.refresh_interval))
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

fn default_refresh_interval() -> u64 {
    3600
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
    use std::path::PathBuf;

    use ddns_clients::resolve::IpFamily;

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
ipv4 = false
interval = 60
refresh_interval = 0
ttl = 0
max_records = 4
replace_only = true
resolvers = [
  { type = "ipify" },
  { type = "http", ipv4_url = "https://ip4.example.com" },
]

[provider.home]
type = "cloudflare"
api_token = "secret"
zone = "example.com"
domain = "myhost.example.com"

[provider.noip]
username = "me@example.com"
password = "secret"
user_agent = "Example ddnsd/1.0 admin@example.com"
domain = "myhost.ddns.net"
ipv4 = true
ipv6 = false
ttl = 60
max_records = 1
replace_only = false
"#,
        )
        .unwrap();
        assert_eq!(config.interval, 60);
        assert_eq!(config.refresh_interval(), None);
        assert_eq!(
            config.resolvers,
            vec![
                ResolverConfig::Ipify,
                ResolverConfig::Http {
                    url: None,
                    ipv4_url: Some("https://ip4.example.com".into()),
                    ipv6_url: None,
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
        assert!(!home.client.is_enabled(IpFamily::V4));
        assert!(home.client.is_enabled(IpFamily::V6));
        assert_eq!(home.max_records, 4);
        assert!(format!("{:?}", home.client).contains("replace_only: true"));
        assert_eq!(noip.name, "noip");
        assert_eq!(noip.client.domain(), "myhost.ddns.net");
        assert_eq!(config.ttl(&config.provider["noip"]), Some(60));
        assert!(noip.client.is_enabled(IpFamily::V4));
        assert!(!noip.client.is_enabled(IpFamily::V6));
        assert_eq!(noip.max_records, 1);
        assert!(format!("{:?}", noip.client).contains("replace_only: false"));
    }

    #[test]
    fn defaults() {
        let config = load("defaults", MINIMAL).unwrap();
        assert_eq!(config.interval, 300);
        assert_eq!(config.refresh_interval(), Some(Duration::from_secs(3600)));
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
        assert!(target.client.is_enabled(IpFamily::V4));
        assert!(target.client.is_enabled(IpFamily::V6));
        assert_eq!(target.max_records, 2);
        assert!(format!("{:?}", target.client).contains("replace_only: false"));
    }

    #[test]
    fn example() {
        let config = load("example", include_str!("../ddnsd.example.toml")).unwrap();
        let targets = config.targets().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].client.domain(), "myhost.example.com");
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
                url: Some("https://ip.example.com".into()),
                ipv4_url: None,
                ipv6_url: None,
            }]
        );
        let debug = format!("{:?}", config.resolvers());
        assert_eq!(
            debug.matches("https://ip.example.com").count(),
            2,
            "{debug}"
        );
    }

    #[test]
    fn http_resolver_family_url_overrides_url() {
        // the debug output lists the IPv4 URL, then the IPv6 URL
        for (keys, expected) in [
            (
                r#"url = "https://a", ipv6_url = "https://b""#,
                ["https://a", "https://b"],
            ),
            (
                r#"url = "https://a", ipv4_url = "https://b""#,
                ["https://b", "https://a"],
            ),
        ] {
            let config = load(
                "override",
                &format!("resolvers = [{{ type = \"http\", {keys} }}]\n{MINIMAL}"),
            )
            .unwrap();
            let debug = format!("{:?}", config.resolvers());
            let v4 = debug.find(expected[0]).expect(&debug);
            let v6 = debug.rfind(expected[1]).expect(&debug);
            assert!(v4 < v6, "{debug}");
            assert_eq!(debug.matches("https://").count(), 2, "{debug}");
        }
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

    #[test]
    fn rejects_no_provider() {
        let err = load("noprovider", "interval = 60\n").unwrap_err();
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
    fn rejects_top_level_key_after_provider_table() {
        // belongs to [provider.cloudflare] in TOML, not to the top level
        let err = load("keyorder", &format!("{MINIMAL}interval = 60\n")).unwrap_err();
        assert!(
            err.to_string().contains("unknown field `interval`"),
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
        assert_eq!(
            format!("{err:#}"),
            r#"provider nope: unknown provider "nope", expected one of: cloudflare, noip"#
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
}
