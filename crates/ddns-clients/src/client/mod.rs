mod plan;

use std::{net::IpAddr, time::Instant};

use anyhow::{Result, bail};
use plan::Operation;

use crate::{
    CloudflareProvider, DynDnsProvider, NoIpProvider,
    providers::{CLOUDFLARE, NOIP},
};
#[cfg(feature = "pkarr")]
use crate::{PkarrProvider, providers::PKARR};

/// A dynamic DNS client managing the address records of one domain on one
/// provider.
///
/// Built with [`DynDnsClient::provider`] for a built-in provider, or
/// [`DynDnsClient::new`] for any other [`DynDnsProvider`]. The client decides
/// which records to add, re-point and delete; the provider only carries out
/// those operations.
///
/// ```no_run
/// # async fn example() -> anyhow::Result<()> {
/// use ddns_clients::{DynDnsClient, providers};
///
/// let mut client = DynDnsClient::provider(providers::CLOUDFLARE)?
///     .api_token("api-token")
///     .zone("example.com")
///     .domain("myhost.example.com")
///     .ttl(Some(300))
///     .build()?;
///
/// // the domain's records are now exactly these
/// client.update(["192.0.2.1".parse().unwrap()]).await?;
/// # Ok(())
/// # }
/// ```
pub struct DynDnsClient {
    provider: Box<dyn DynDnsProvider>,
    ttl: Option<u32>,
    /// Whether A (IPv4) records are managed.
    ipv4: bool,
    /// Whether AAAA (IPv6) records are managed.
    ipv6: bool,
    /// Maximum number of records of the enabled families; `None` for no
    /// limit.
    max_records: Option<usize>,
    /// Only re-point existing records, never add or delete any.
    replace_only: bool,
    /// Plan and log the operations, but don't carry them out.
    dry_run: bool,
}

impl DynDnsClient {
    /// Starts building a client for the built-in provider `name`, e.g.
    /// [`providers::CLOUDFLARE`](crate::providers::CLOUDFLARE).
    ///
    /// Fails if there is no such provider.
    pub fn provider(name: &str) -> Result<DynDnsClientBuilder> {
        DynDnsClientBuilder::new(name)
    }

    /// Creates a client for an existing provider, e.g. a custom
    /// [`DynDnsProvider`] implementation, with the provider's default TTL and
    /// both address families enabled.
    ///
    /// ```no_run
    /// # fn example() -> anyhow::Result<()> {
    /// use ddns_clients::{CloudflareProvider, DynDnsClient};
    ///
    /// let provider = CloudflareProvider::new("api-token", "example.com", "myhost.example.com")?;
    /// let client = DynDnsClient::new(provider)
    ///     .ttl(Some(300))
    ///     .enable_ipv6(false);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(provider: impl DynDnsProvider + 'static) -> Self {
        DynDnsClient {
            provider: Box::new(provider),
            ttl: None,
            ipv4: true,
            ipv6: true,
            max_records: None,
            replace_only: false,
            dry_run: false,
        }
    }

    /// TTL of added and changed records; see [`DynDnsClientBuilder::ttl`].
    pub fn ttl(mut self, ttl: Option<u32>) -> Self {
        self.ttl = ttl;
        self
    }

    /// Whether A records are managed; see [`DynDnsClientBuilder::enable_ipv4`].
    pub fn enable_ipv4(mut self, enabled: bool) -> Self {
        self.ipv4 = enabled;
        self
    }

    /// Whether AAAA records are managed; see [`DynDnsClientBuilder::enable_ipv6`].
    pub fn enable_ipv6(mut self, enabled: bool) -> Self {
        self.ipv6 = enabled;
        self
    }

    /// Maximum number of records; see [`DynDnsClientBuilder::max_records`].
    pub fn max_records(mut self, max: Option<usize>) -> Self {
        self.max_records = max;
        self
    }

    /// Only re-point existing records, so the number of records never
    /// changes; see [`DynDnsClientBuilder::replace_only`].
    pub fn replace_only(mut self, enabled: bool) -> Self {
        self.replace_only = enabled;
        self
    }

    /// In dry-run mode, updates plan and log their operations (`replace A
    /// with B`, `delete A`, `add A`) without making the provider carry them
    /// out. Listing records still reads them from the provider.
    pub fn set_dryrun(&mut self, enabled: bool) {
        self.dry_run = enabled;
    }

    /// Whether A (IPv4) records are managed.
    pub fn is_ipv4_enabled(&self) -> bool {
        self.ipv4
    }

    /// Whether AAAA (IPv6) records are managed.
    pub fn is_ipv6_enabled(&self) -> bool {
        self.ipv6
    }

    /// Whether records with `ip`'s family are managed.
    fn manages(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.ipv4,
            IpAddr::V6(_) => self.ipv6,
        }
    }

    /// The domain whose records this client manages.
    pub fn domain(&self) -> &str {
        self.provider.domain()
    }

    /// When the next [`update`](Self::update) may be sent, e.g. after the
    /// provider asked clients to back off; `None` means there is no
    /// restriction. The time may be in the past, or
    /// [`NEVER`](crate::providers::NEVER) away if no further update should be
    /// sent. Callers should wait until then; it isn't enforced.
    pub fn next_allowed_update(&self) -> Option<Instant> {
        self.provider.next_allowed_update()
    }

    /// Addresses of the domain's records of the enabled families. Providers
    /// may answer from a cache; see [`refresh_cache`](Self::refresh_cache).
    pub async fn list(&mut self) -> Result<Vec<IpAddr>> {
        let mut records = self.provider.list().await?;
        records.retain(|ip| self.manages(ip));
        Ok(records)
    }

    /// Makes the provider read the records again, e.g. after they were
    /// changed elsewhere.
    pub async fn refresh_cache(&mut self) -> Result<()> {
        self.provider.refresh_cache().await
    }

    /// Replaces the domain's records of the enabled families with `ips`:
    /// existing records not in `ips` are re-pointed or deleted, and missing
    /// ones added. Addresses and records of disabled families are left
    /// alone.
    ///
    /// A [`replace_only`](Self::replace_only) client only re-points records:
    /// surplus records keep their addresses, and addresses without a record
    /// to re-point are skipped (logged as a warning).
    ///
    /// With [`max_records`](Self::max_records), at most that many of `ips`
    /// are used: those that already have a record first, then the others in
    /// order.
    ///
    /// Nothing is changed if the records already equal `ips`. The records
    /// may come from the provider's cache; call [`refresh_cache`](Self::refresh_cache) to
    /// pick up changes made elsewhere.
    ///
    /// Empty `ips` remove all records of the enabled families.
    pub async fn update(&mut self, ips: impl IntoIterator<Item = IpAddr>) -> Result<UpdateSummary> {
        let existing = self.list().await?;
        let ops = self.plan(&existing, ips);
        self.execute(&ops).await?;
        Ok(plan::summary(existing.len(), &ops))
    }

    /// The operations that turn the `existing` records into `ips`, within
    /// the enabled families, `max_records` and `replace_only`.
    fn plan(&self, existing: &[IpAddr], ips: impl IntoIterator<Item = IpAddr>) -> Vec<Operation> {
        let mut desired: Vec<IpAddr> = vec![];
        for ip in ips {
            if !self.manages(&ip) {
                log::debug!("{}: ignoring {ip} of a disabled family", self.domain());
            } else if !desired.contains(&ip) {
                desired.push(ip);
            }
        }
        if let Some(max) = self.max_records.filter(|&max| desired.len() > max) {
            // a stable sort: addresses with a record first, each in order
            desired.sort_by_key(|ip| !existing.contains(ip));
            let ignored = desired.split_off(max);
            log::debug!(
                "{}: ignoring {ignored:?} beyond max_records = {max}",
                self.domain()
            );
        }
        let ops = plan::plan(existing, &desired, self.replace_only);

        let after = plan::apply(existing, &ops);
        let skipped: Vec<&IpAddr> = desired.iter().filter(|ip| !after.contains(ip)).collect();
        if !skipped.is_empty() {
            log::warn!(
                "{}: no record left to re-point at {skipped:?} (replace only)",
                self.domain()
            );
        }
        ops
    }

    /// Carries out `ops` in order, or only logs them in dry-run mode.
    async fn execute(&mut self, ops: &[Operation]) -> Result<()> {
        for op in ops {
            if self.dry_run {
                log::info!("{}: {op} (dry run, not carried out)", self.domain());
                continue;
            }
            match *op {
                Operation::Replace { old, new } => {
                    self.provider.replace(old, new, self.ttl).await?
                }
                Operation::Delete(ip) => self.provider.delete(ip).await?,
                Operation::Add(ip) => self.provider.add(ip, self.ttl).await?,
            }
            log::info!("{}: {op}", self.domain());
        }
        Ok(())
    }
}

/// What an update changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpdateSummary {
    /// Records that already matched and were left alone.
    pub kept: usize,
    /// Records re-pointed at a new address.
    pub updated: usize,
    /// Records removed.
    pub deleted: usize,
    /// Records newly added.
    pub created: usize,
}

impl UpdateSummary {
    /// Returns `true` if no record was changed.
    pub fn is_unchanged(&self) -> bool {
        self.updated == 0 && self.deleted == 0 && self.created == 0
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Cloudflare,
    NoIp,
    #[cfg(feature = "pkarr")]
    Pkarr,
}

impl Kind {
    const ALL: [Kind; if cfg!(feature = "pkarr") { 3 } else { 2 }] = [
        Kind::Cloudflare,
        Kind::NoIp,
        #[cfg(feature = "pkarr")]
        Kind::Pkarr,
    ];

    fn name(&self) -> &'static str {
        match self {
            Kind::Cloudflare => CLOUDFLARE,
            Kind::NoIp => NOIP,
            #[cfg(feature = "pkarr")]
            Kind::Pkarr => PKARR,
        }
    }

    /// Required and optional parameters, besides `ttl`.
    fn parameters(&self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            Kind::Cloudflare => (&["api_token", "zone", "domain"], &[]),
            Kind::NoIp => (&["username", "password", "domain"], &["user_agent"]),
            #[cfg(feature = "pkarr")]
            Kind::Pkarr => (&["secret_key"], &["domain", "relays", "keep_other_records"]),
        }
    }
}

/// Builds a [`DynDnsClient`]; see [`DynDnsClient::provider`].
///
/// | Provider | Required | Optional |
/// |---|---|---|
/// | `cloudflare` | `api_token`, `zone`, `domain` | `ttl`, `enable_ipv4`, `enable_ipv6`, `max_records`, `replace_only` |
/// | `noip` | `username`, `password`, `domain` | `user_agent`, `ttl`, `enable_ipv4`, `enable_ipv6`, `max_records`, `replace_only` |
/// | `pkarr` | `secret_key` | `domain`, `relays`, `keep_other_records`, `ttl`, `enable_ipv4`, `enable_ipv6`, `max_records`, `replace_only` |
///
/// [`build`](Self::build) rejects missing (or empty) required parameters,
/// parameters the provider doesn't use, and disabling both families.
#[must_use = "a builder does nothing until `build` is called"]
pub struct DynDnsClientBuilder {
    kind: Kind,
    api_token: Option<String>,
    zone: Option<String>,
    username: Option<String>,
    password: Option<String>,
    user_agent: Option<String>,
    #[cfg(feature = "pkarr")]
    secret_key: Option<String>,
    #[cfg(feature = "pkarr")]
    relays: Option<Vec<String>>,
    #[cfg(feature = "pkarr")]
    keep_other_records: Option<bool>,
    domain: Option<String>,
    ttl: Option<u32>,
    ipv4: bool,
    ipv6: bool,
    max_records: Option<usize>,
    replace_only: bool,
}

impl DynDnsClientBuilder {
    /// Starts building a client for the built-in provider `kind`, e.g.
    /// [`providers::CLOUDFLARE`](crate::providers::CLOUDFLARE); the same as
    /// [`DynDnsClient::provider`].
    ///
    /// Fails if there is no such provider.
    pub fn new(kind: &str) -> Result<Self> {
        let kind = match kind {
            CLOUDFLARE => Kind::Cloudflare,
            NOIP => Kind::NoIp,
            #[cfg(feature = "pkarr")]
            PKARR => Kind::Pkarr,
            _ => bail!(
                "unknown provider {kind:?}, expected one of: {}",
                Kind::ALL.map(|kind| kind.name()).join(", ")
            ),
        };
        Ok(DynDnsClientBuilder {
            kind,
            api_token: None,
            zone: None,
            username: None,
            password: None,
            user_agent: None,
            #[cfg(feature = "pkarr")]
            secret_key: None,
            #[cfg(feature = "pkarr")]
            relays: None,
            #[cfg(feature = "pkarr")]
            keep_other_records: None,
            domain: None,
            ttl: None,
            ipv4: true,
            ipv6: true,
            max_records: None,
            replace_only: false,
        })
    }

    /// Cloudflare API token, needing `Zone:Read` and `DNS:Edit`.
    pub fn api_token(mut self, api_token: impl Into<String>) -> Self {
        self.api_token = Some(api_token.into());
        self
    }

    /// Cloudflare zone containing the domain, e.g. `example.com`.
    pub fn zone(mut self, zone: impl Into<String>) -> Self {
        self.zone = Some(zone.into());
        self
    }

    /// No-IP account username, or a DDNS key's username.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// No-IP password.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// User agent sent to No-IP; see [`NoIpProvider::with_user_agent`].
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// PKARR secret key, 64 hex digits; see [`PkarrProvider::new`].
    #[cfg(feature = "pkarr")]
    pub fn secret_key(mut self, secret_key: impl Into<String>) -> Self {
        self.secret_key = Some(secret_key.into());
        self
    }

    /// PKARR relay URLs; an empty list only uses the DHT. Without this, the
    /// default relays are used.
    #[cfg(feature = "pkarr")]
    pub fn relays(mut self, relays: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.relays = Some(relays.into_iter().map(Into::into).collect());
        self
    }

    /// Whether PKARR keeps the other records of the key's packet (default
    /// `true`); see [`PkarrProvider::keep_other_records`].
    #[cfg(feature = "pkarr")]
    pub fn keep_other_records(mut self, keep: bool) -> Self {
        self.keep_other_records = Some(keep);
        self
    }

    /// The domain whose records the client manages. For PKARR, the name
    /// below the key, which is the key itself if empty or unset.
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// TTL of created and changed records; `None` (the default) uses the
    /// provider's default.
    pub fn ttl(mut self, ttl: Option<u32>) -> Self {
        self.ttl = ttl;
        self
    }

    /// Whether A records are managed (default `true`). If not, the client
    /// neither lists, changes nor removes them, and ignores IPv4 addresses.
    pub fn enable_ipv4(mut self, enabled: bool) -> Self {
        self.ipv4 = enabled;
        self
    }

    /// Whether AAAA records are managed (default `true`); see
    /// [`enable_ipv4`](Self::enable_ipv4).
    pub fn enable_ipv6(mut self, enabled: bool) -> Self {
        self.ipv6 = enabled;
        self
    }

    /// Maximum number of records of the enabled families; `None` (the
    /// default) for no limit. If an update has more addresses, those that
    /// already have a record are kept first, then the others are used in
    /// order; the rest are ignored.
    pub fn max_records(mut self, max: Option<usize>) -> Self {
        self.max_records = max;
        self
    }

    /// Only re-point existing records, never create or delete any, so the
    /// number of records on the provider never changes (default `false`).
    /// Useful when the records are set up by hand, e.g. with provider-side
    /// settings that should not be lost.
    pub fn replace_only(mut self, enabled: bool) -> Self {
        self.replace_only = enabled;
        self
    }

    /// Checks the parameters and creates the client.
    ///
    /// Makes no network requests, except that PKARR starts joining the DHT.
    pub fn build(self) -> Result<DynDnsClient> {
        self.check()?;
        let domain = self.domain.unwrap_or_default();
        let provider: Box<dyn DynDnsProvider> = match self.kind {
            Kind::Cloudflare => Box::new(CloudflareProvider::new(
                self.api_token.unwrap_or_default(),
                self.zone.unwrap_or_default(),
                domain,
            )?),
            Kind::NoIp => {
                let username = self.username.unwrap_or_default();
                let password = self.password.unwrap_or_default();
                Box::new(match &self.user_agent {
                    Some(user_agent) => {
                        NoIpProvider::with_user_agent(username, password, domain, user_agent)?
                    }
                    None => NoIpProvider::new(username, password, domain)?,
                })
            }
            #[cfg(feature = "pkarr")]
            Kind::Pkarr => Box::new(
                PkarrProvider::new(
                    self.secret_key.as_deref().unwrap_or_default(),
                    &domain,
                    self.relays.as_deref(),
                )?
                .keep_other_records(self.keep_other_records.unwrap_or(true)),
            ),
        };
        Ok(DynDnsClient {
            provider,
            ttl: self.ttl,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            max_records: self.max_records,
            replace_only: self.replace_only,
            dry_run: false,
        })
    }

    fn check(&self) -> Result<()> {
        // whether each parameter is set, and if so, not empty
        let string = |value: &Option<String>| value.as_ref().map(|value| !value.is_empty());
        let parameters = [
            ("api_token", string(&self.api_token)),
            ("zone", string(&self.zone)),
            ("username", string(&self.username)),
            ("password", string(&self.password)),
            ("user_agent", string(&self.user_agent)),
            #[cfg(feature = "pkarr")]
            ("secret_key", string(&self.secret_key)),
            #[cfg(feature = "pkarr")]
            ("relays", self.relays.as_ref().map(|_| true)),
            #[cfg(feature = "pkarr")]
            ("keep_other_records", self.keep_other_records.map(|_| true)),
            ("domain", string(&self.domain)),
        ];
        let (required, optional) = self.kind.parameters();
        let missing: Vec<&str> = parameters
            .iter()
            .filter(|(name, value)| required.contains(name) && *value != Some(true))
            .map(|(name, _)| *name)
            .collect();
        let unused: Vec<&str> = parameters
            .iter()
            .filter(|(name, value)| {
                !required.contains(name) && !optional.contains(name) && value.is_some()
            })
            .map(|(name, _)| *name)
            .collect();

        let mut problems = vec![];
        if !missing.is_empty() {
            problems.push(format!("missing {}", missing.join(", ")));
        }
        if !self.ipv4 && !self.ipv6 {
            problems.push("ipv4 and ipv6 are both disabled".to_string());
        }
        match unused.as_slice() {
            [] => {}
            [name] => problems.push(format!("{name} is not used")),
            names => problems.push(format!("{} are not used", names.join(", "))),
        }
        if problems.is_empty() {
            return Ok(());
        }
        bail!("{}: {}", self.kind.name(), problems.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use anyhow::anyhow;
    use async_trait::async_trait;

    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Op {
        Add(IpAddr, Option<u32>),
        Replace(IpAddr, IpAddr, Option<u32>),
        Delete(IpAddr),
    }

    #[derive(Default)]
    struct FakeState {
        records: Vec<IpAddr>,
        ops: Vec<Op>,
        refreshes: usize,
        fail_next: bool,
    }

    impl FakeState {
        fn check_fail(&mut self) -> Result<()> {
            if std::mem::take(&mut self.fail_next) {
                return Err(anyhow!("injected failure"));
            }
            Ok(())
        }

        fn position(&self, ip: IpAddr) -> Result<usize> {
            self.records
                .iter()
                .position(|r| *r == ip)
                .ok_or_else(|| anyhow!("{DOMAIN} has no record for {ip}"))
        }
    }

    const DOMAIN: &str = "myhost.example.com";

    /// Keeps the records of `DOMAIN` in memory, uncached, and logs the
    /// operations it carries out.
    #[derive(Default, Clone)]
    struct Fake(Arc<Mutex<FakeState>>);

    impl Fake {
        fn with(records: &[IpAddr]) -> Self {
            let fake = Fake::default();
            fake.state().records = records.to_vec();
            fake
        }

        fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.0.lock().unwrap()
        }
    }

    #[async_trait]
    impl DynDnsProvider for Fake {
        fn domain(&self) -> &str {
            DOMAIN
        }

        async fn list(&mut self) -> Result<Vec<IpAddr>> {
            Ok(self.state().records.clone())
        }

        async fn refresh_cache(&mut self) -> Result<()> {
            self.state().refreshes += 1;
            Ok(())
        }

        async fn add(&mut self, ip: IpAddr, ttl: Option<u32>) -> Result<()> {
            let mut state = self.state();
            state.check_fail()?;
            state.records.push(ip);
            state.ops.push(Op::Add(ip, ttl));
            Ok(())
        }

        async fn replace(&mut self, old: IpAddr, new: IpAddr, ttl: Option<u32>) -> Result<()> {
            let mut state = self.state();
            state.check_fail()?;
            let i = state.position(old)?;
            state.records[i] = new;
            state.ops.push(Op::Replace(old, new, ttl));
            Ok(())
        }

        async fn delete(&mut self, ip: IpAddr) -> Result<()> {
            let mut state = self.state();
            state.check_fail()?;
            let i = state.position(ip)?;
            state.records.remove(i);
            state.ops.push(Op::Delete(ip));
            Ok(())
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn invalid_config(result: Result<DynDnsClient>) -> String {
        let Err(err) = result else {
            panic!("expected an invalid config");
        };
        err.to_string()
    }

    #[test]
    fn unknown_provider() {
        let Err(err) = DynDnsClient::provider("nope") else {
            panic!("expected an unknown provider");
        };
        let expected = if cfg!(feature = "pkarr") {
            r#"unknown provider "nope", expected one of: cloudflare, noip, pkarr"#
        } else {
            r#"unknown provider "nope", expected one of: cloudflare, noip"#
        };
        assert_eq!(err.to_string(), expected);
    }

    #[test]
    fn cloudflare() {
        let client = DynDnsClient::provider(CLOUDFLARE)
            .unwrap()
            .api_token("token")
            .zone("example.com")
            .domain("myhost.example.com")
            .ttl(Some(300))
            .build()
            .unwrap();
        assert_eq!(client.domain(), "myhost.example.com");
    }

    #[test]
    fn cloudflare_missing() {
        let builder = DynDnsClient::provider(CLOUDFLARE).unwrap().api_token("");
        assert_eq!(
            invalid_config(builder.build()),
            "cloudflare: missing api_token, zone, domain"
        );
    }

    #[test]
    fn noip() {
        let builder = DynDnsClient::provider(NOIP)
            .unwrap()
            .username("me")
            .password("secret")
            .domain("myhost.ddns.net");
        builder.build().unwrap();

        DynDnsClient::provider(NOIP)
            .unwrap()
            .username("me")
            .password("secret")
            .user_agent("Example ddns/1.0 admin@example.com")
            .domain("myhost.ddns.net")
            .build()
            .unwrap();
    }

    #[test]
    fn noip_missing_and_unused() {
        let builder = DynDnsClient::provider(NOIP)
            .unwrap()
            .username("me")
            .zone("example.com")
            .api_token("token")
            .domain("myhost.ddns.net");
        assert_eq!(
            invalid_config(builder.build()),
            "noip: missing password; api_token, zone are not used"
        );
    }

    #[test]
    fn rejects_both_families_disabled() {
        let builder = DynDnsClient::provider(CLOUDFLARE)
            .unwrap()
            .api_token("token")
            .zone("example.com")
            .domain("myhost.example.com")
            .enable_ipv4(false)
            .enable_ipv6(false);
        assert_eq!(
            invalid_config(builder.build()),
            "cloudflare: ipv4 and ipv6 are both disabled"
        );
    }

    #[tokio::test]
    async fn update_replaces_all() {
        let fake = Fake::with(&[ip("192.0.2.9")]);
        let mut client = DynDnsClient::new(fake.clone()).ttl(Some(120));
        let ips = vec![ip("192.0.2.1"), ip("2001:db8::1")];

        let summary = client.update(ips.clone()).await.unwrap();
        assert_eq!(summary.updated, 1);
        assert_eq!(summary.created, 1);
        assert_eq!(fake.state().records, ips);
        // an empty set removes every record
        client.update([]).await.unwrap();
        assert!(fake.state().records.is_empty());

        assert_eq!(
            fake.state().ops,
            vec![
                Op::Replace(ip("192.0.2.9"), ip("192.0.2.1"), Some(120)),
                Op::Add(ip("2001:db8::1"), Some(120)),
                Op::Delete(ip("192.0.2.1")),
                Op::Delete(ip("2001:db8::1")),
            ]
        );
    }

    #[tokio::test]
    async fn disabled_family_is_left_alone() {
        let fake = Fake::with(&[ip("192.0.2.9"), ip("2001:db8::9")]);
        let mut client = DynDnsClient::new(fake.clone()).enable_ipv6(false);
        assert!(client.is_ipv4_enabled());
        assert!(!client.is_ipv6_enabled());

        assert_eq!(client.list().await.unwrap(), vec![ip("192.0.2.9")]);

        client
            .update([ip("192.0.2.1"), ip("2001:db8::1")])
            .await
            .unwrap();
        let state = fake.state();
        assert_eq!(
            state.ops,
            vec![Op::Replace(ip("192.0.2.9"), ip("192.0.2.1"), None)]
        );
        assert_eq!(state.records, vec![ip("192.0.2.1"), ip("2001:db8::9")]);
    }

    #[tokio::test]
    async fn replace_only_keeps_record_count() {
        let fake = Fake::with(&[ip("192.0.2.9"), ip("2001:db8::9")]);
        let mut client = DynDnsClient::new(fake.clone()).replace_only(true);

        let summary = client
            .update([ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3")])
            .await
            .unwrap();
        assert_eq!(summary.updated, 2);
        assert_eq!(summary.created + summary.deleted, 0);
        assert_eq!(fake.state().records, vec![ip("192.0.2.1"), ip("192.0.2.2")]);

        // nothing to remove either: both records stay
        let summary = client.update([ip("192.0.2.1")]).await.unwrap();
        assert!(summary.is_unchanged());
        assert_eq!(fake.state().records.len(), 2);
        assert_eq!(fake.state().ops.len(), 2);
    }

    #[tokio::test]
    async fn replace_only_without_records_changes_nothing() {
        let fake = Fake::default();
        let mut client = DynDnsClient::new(fake.clone()).replace_only(true);
        let summary = client.update([ip("192.0.2.1")]).await.unwrap();
        assert!(summary.is_unchanged());
        assert!(fake.state().ops.is_empty());
    }

    #[tokio::test]
    async fn max_records_prefers_existing() {
        let fake = Fake::with(&[ip("192.0.2.9"), ip("192.0.2.3")]);
        let mut client = DynDnsClient::new(fake.clone()).max_records(Some(2));

        // 192.0.2.3 keeps its record; 192.0.2.1 is first of the others
        let summary = client
            .update([ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3")])
            .await
            .unwrap();
        assert_eq!(summary.kept, 1);
        assert_eq!(summary.updated, 1);
        assert_eq!(fake.state().records, vec![ip("192.0.2.1"), ip("192.0.2.3")]);

        // within the limit, nothing is ignored
        let mut client = DynDnsClient::new(fake.clone()).max_records(Some(3));
        client
            .update([ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3")])
            .await
            .unwrap();
        assert_eq!(fake.state().records.len(), 3);
    }

    #[tokio::test]
    async fn dry_run_changes_nothing() {
        let ips = [ip("192.0.2.1"), ip("2001:db8::1")];
        let fake = Fake::with(&[ip("192.0.2.9")]);
        let mut client = DynDnsClient::new(fake.clone());
        client.set_dryrun(true);

        let planned = client.update(ips).await.unwrap();
        assert_eq!(planned.updated, 1);
        assert_eq!(planned.created, 1);
        assert!(fake.state().ops.is_empty());
        assert_eq!(fake.state().records, vec![ip("192.0.2.9")]);

        // the real update does what was planned
        client.set_dryrun(false);
        assert_eq!(client.update(ips).await.unwrap(), planned);
        assert_eq!(fake.state().records, ips);
    }

    #[tokio::test]
    async fn unchanged_update_changes_nothing() {
        let fake = Fake::with(&[ip("192.0.2.1")]);
        let mut client = DynDnsClient::new(fake.clone());
        let summary = client
            .update([ip("192.0.2.1"), ip("192.0.2.1")])
            .await
            .unwrap();
        assert_eq!(summary.kept, 1);
        assert!(summary.is_unchanged());
        assert!(fake.state().ops.is_empty());
    }

    #[tokio::test]
    async fn update_after_failure() {
        let fake = Fake::with(&[ip("192.0.2.1")]);
        let mut client = DynDnsClient::new(fake.clone());
        fake.state().fail_next = true;
        client.update([ip("192.0.2.2")]).await.unwrap_err();
        client.update([ip("192.0.2.2")]).await.unwrap();
        assert_eq!(fake.state().records, vec![ip("192.0.2.2")]);
    }

    #[tokio::test]
    async fn refresh_reaches_provider() {
        let fake = Fake::default();
        let mut client = DynDnsClient::new(fake.clone());
        assert_eq!(client.domain(), DOMAIN);
        client.refresh_cache().await.unwrap();
        assert_eq!(fake.state().refreshes, 1);
    }
}
