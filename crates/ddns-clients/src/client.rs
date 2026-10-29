mod plan;

use std::{fmt, net::IpAddr};

use crate::{
    CloudflareProvider, DynDnsProvider, Error, NoIpProvider, Result,
    providers::{CLOUDFLARE, NOIP},
    resolve::IpFamily,
};

/// A dynamic DNS client managing the address records of one domain on one
/// provider.
///
/// Built with [`DynDnsClient::provider`] for a built-in provider, or
/// [`DynDnsClient::new`] for any other [`DynDnsProvider`]. The client decides
/// which records to add, re-point and delete; the provider only carries out
/// those operations.
///
/// ```no_run
/// # async fn example() -> ddns_clients::Result<()> {
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
///
/// // re-point one record, keep the others
/// client
///     .update_request()
///     .remove("192.0.2.1".parse().unwrap())
///     .add("192.0.2.2".parse().unwrap())
///     .send()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct DynDnsClient {
    provider: Box<dyn DynDnsProvider>,
    ttl: Option<u32>,
    /// Whether A (IPv4) and AAAA (IPv6) records are managed.
    ipv4: bool,
    ipv6: bool,
    /// Only re-point existing records, never add or delete any.
    replace_only: bool,
}

impl DynDnsClient {
    /// Starts building a client for the built-in provider `name`, e.g.
    /// [`providers::CLOUDFLARE`](crate::providers::CLOUDFLARE).
    ///
    /// Fails with [`Error::InvalidConfig`] if there is no such provider.
    pub fn provider(name: &str) -> Result<DynDnsClientBuilder> {
        let kind = match name {
            CLOUDFLARE => Kind::Cloudflare,
            NOIP => Kind::NoIp,
            _ => {
                return Err(Error::InvalidConfig(format!(
                    "unknown provider {name:?}, expected one of: {CLOUDFLARE}, {NOIP}"
                )));
            }
        };
        Ok(DynDnsClientBuilder::new(kind))
    }

    /// Creates a client for an existing provider, e.g. a custom
    /// [`DynDnsProvider`] implementation, with the provider's default TTL and
    /// both address families enabled.
    ///
    /// ```no_run
    /// # fn example() -> ddns_clients::Result<()> {
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
            replace_only: false,
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

    /// Only re-point existing records, so the number of records never
    /// changes; see [`DynDnsClientBuilder::replace_only`].
    pub fn replace_only(mut self, enabled: bool) -> Self {
        self.replace_only = enabled;
        self
    }

    /// Whether records of `family` are managed.
    pub fn is_enabled(&self, family: IpFamily) -> bool {
        match family {
            IpFamily::V4 => self.ipv4,
            IpFamily::V6 => self.ipv6,
        }
    }

    /// The domain whose records this client manages.
    pub fn domain(&self) -> &str {
        self.provider.domain()
    }

    /// Addresses of the domain's records of the enabled families. Providers
    /// may answer from a cache; see [`refresh`](Self::refresh).
    pub async fn list(&mut self) -> Result<Vec<IpAddr>> {
        let mut records = self.provider.list().await?;
        records.retain(|ip| self.is_enabled(IpFamily::of(ip)));
        Ok(records)
    }

    /// Makes the provider read the records again, e.g. after they were
    /// changed elsewhere.
    pub async fn refresh(&mut self) -> Result<()> {
        self.provider.refresh().await
    }

    /// Starts a batched change of the domain's address records, with the
    /// client's TTL preset; [`UpdateRequestBuilder::ttl`] overrides it.
    /// Addresses of disabled families are ignored, and a
    /// [`replace_only`](Self::replace_only) client only re-points records.
    pub fn update_request(&mut self) -> UpdateRequestBuilder<'_> {
        let ttl = self.ttl;
        UpdateRequestBuilder {
            client: self,
            add: vec![],
            remove: vec![],
            ttl,
        }
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
    /// Nothing is changed if the records already equal `ips`. The records
    /// may come from the provider's cache; call [`refresh`](Self::refresh) to
    /// pick up changes made elsewhere.
    ///
    /// Empty `ips` remove all records of the enabled families.
    pub async fn update(&mut self, ips: impl IntoIterator<Item = IpAddr>) -> Result<UpdateSummary> {
        let existing = self.list().await?;
        let remove = existing.clone();
        let prepared = self.prepare(existing, ips.into_iter().collect(), remove);
        self.execute(prepared, self.ttl).await
    }

    /// What [`update`](Self::update) with `ips` would change, without
    /// changing anything.
    pub async fn preview_update(
        &mut self,
        ips: impl IntoIterator<Item = IpAddr>,
    ) -> Result<UpdatePreview> {
        let existing = self.list().await?;
        let remove = existing.clone();
        Ok(self
            .prepare(existing, ips.into_iter().collect(), remove)
            .preview)
    }

    /// Plans adding `add` and removing `remove` on the `existing` records,
    /// within the enabled families and `replace_only`.
    fn prepare(&self, existing: Vec<IpAddr>, add: Vec<IpAddr>, remove: Vec<IpAddr>) -> Prepared {
        let enabled = |ip: &IpAddr| self.is_enabled(IpFamily::of(ip));
        if !add.iter().chain(&remove).all(enabled) {
            log::debug!("{}: ignoring addresses of disabled families", self.domain());
        }
        let mut desired: Vec<IpAddr> = vec![];
        for ip in add {
            if enabled(&ip) && !desired.contains(&ip) {
                desired.push(ip);
            }
        }
        let request = plan::Request {
            add: desired,
            remove: remove.into_iter().filter(enabled).collect(),
            replace_only: self.replace_only,
        };
        let plan = plan::plan(&existing, &request);
        let after = plan.after(&existing);

        let skipped: Vec<&IpAddr> = request
            .add
            .iter()
            .filter(|ip| !after.contains(ip))
            .collect();
        if !skipped.is_empty() {
            log::warn!(
                "{}: no record left to re-point at {skipped:?} (replace only)",
                self.domain()
            );
        }
        Prepared {
            preview: UpdatePreview {
                before: existing,
                after,
                summary: plan.summary(),
            },
            plan,
        }
    }

    /// Carries out a plan: re-points, then deletes, then adds records.
    async fn execute(&mut self, prepared: Prepared, ttl: Option<u32>) -> Result<UpdateSummary> {
        let Prepared { plan, preview } = prepared;
        for (i, new) in &plan.replace {
            let old = preview.before[*i];
            self.provider.replace(old, *new, ttl).await?;
            log::debug!("{}: re-pointed {old} to {new}", self.domain());
        }
        for i in &plan.delete {
            let ip = preview.before[*i];
            self.provider.delete(ip).await?;
            log::debug!("{}: deleted {ip}", self.domain());
        }
        for ip in &plan.add {
            self.provider.add(*ip, ttl).await?;
            log::debug!("{}: added {ip}", self.domain());
        }
        Ok(preview.summary)
    }
}

/// Builds and sends a batched change of a [`DynDnsClient`]'s records; see
/// [`DynDnsClient::update_request`].
///
/// Afterwards the domain has exactly the addresses `add ∪ (existing − remove)`.
/// Removing an absent address and adding a present one are no-ops.
#[must_use = "an update does nothing until `send` is awaited"]
pub struct UpdateRequestBuilder<'a> {
    client: &'a mut DynDnsClient,
    add: Vec<IpAddr>,
    remove: Vec<IpAddr>,
    ttl: Option<u32>,
}

impl UpdateRequestBuilder<'_> {
    /// Ensures a record with `ip` exists.
    #[allow(clippy::should_implement_trait)] // a builder step, not arithmetic
    pub fn add(mut self, ip: IpAddr) -> Self {
        self.add.push(ip);
        self
    }

    /// Ensures records with each of `ips` exist.
    pub fn add_all(mut self, ips: impl IntoIterator<Item = IpAddr>) -> Self {
        self.add.extend(ips);
        self
    }

    /// Removes the record with `ip`, if any.
    pub fn remove(mut self, ip: IpAddr) -> Self {
        self.remove.push(ip);
        self
    }

    /// Removes the records with each of `ips`, if any.
    pub fn remove_all(mut self, ips: impl IntoIterator<Item = IpAddr>) -> Self {
        self.remove.extend(ips);
        self
    }

    /// Sets the TTL of added and changed records; `None` uses the provider's
    /// default.
    pub fn ttl(mut self, ttl: Option<u32>) -> Self {
        self.ttl = ttl;
        self
    }

    /// Applies the change.
    pub async fn send(self) -> Result<UpdateSummary> {
        if self.add.is_empty() && self.remove.is_empty() {
            return Ok(UpdateSummary::default());
        }
        let existing = self.client.list().await?;
        let prepared = self.client.prepare(existing, self.add, self.remove);
        self.client.execute(prepared, self.ttl).await
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

/// What a [`DynDnsClient::update`] would change; see
/// [`DynDnsClient::preview_update`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePreview {
    /// The domain's addresses now (enabled families only).
    pub before: Vec<IpAddr>,
    /// The domain's addresses after the update.
    pub after: Vec<IpAddr>,
    /// The record changes the update would make.
    pub summary: UpdateSummary,
}

struct Prepared {
    plan: plan::Plan,
    preview: UpdatePreview,
}

impl fmt::Debug for DynDnsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynDnsClient")
            .field("domain", &self.domain())
            .field("ttl", &self.ttl)
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .field("replace_only", &self.replace_only)
            .finish_non_exhaustive()
    }
}

enum Kind {
    Cloudflare,
    NoIp,
}

impl Kind {
    fn name(&self) -> &str {
        match self {
            Kind::Cloudflare => CLOUDFLARE,
            Kind::NoIp => NOIP,
        }
    }

    /// Required and optional parameters, besides `ttl`.
    fn parameters(&self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            Kind::Cloudflare => (&["api_token", "zone", "domain"], &[]),
            Kind::NoIp => (&["username", "password", "domain"], &["user_agent"]),
        }
    }
}

/// Builds a [`DynDnsClient`]; see [`DynDnsClient::provider`].
///
/// | Provider | Required | Optional |
/// |---|---|---|
/// | `cloudflare` | `api_token`, `zone`, `domain` | `ttl`, `enable_ipv4`, `enable_ipv6`, `replace_only` |
/// | `noip` | `username`, `password`, `domain` | `user_agent`, `ttl`, `enable_ipv4`, `enable_ipv6`, `replace_only` |
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
    domain: Option<String>,
    ttl: Option<u32>,
    ipv4: bool,
    ipv6: bool,
    replace_only: bool,
}

impl DynDnsClientBuilder {
    fn new(kind: Kind) -> Self {
        DynDnsClientBuilder {
            kind,
            api_token: None,
            zone: None,
            username: None,
            password: None,
            user_agent: None,
            domain: None,
            ttl: None,
            ipv4: true,
            ipv6: true,
            replace_only: false,
        }
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

    /// The domain whose records the client manages.
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
    /// Makes no network requests.
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
        };
        Ok(DynDnsClient {
            provider,
            ttl: self.ttl,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            replace_only: self.replace_only,
        })
    }

    fn check(&self) -> Result<()> {
        let parameters = [
            ("api_token", &self.api_token),
            ("zone", &self.zone),
            ("username", &self.username),
            ("password", &self.password),
            ("user_agent", &self.user_agent),
            ("domain", &self.domain),
        ];
        let (required, optional) = self.kind.parameters();
        let missing: Vec<&str> = parameters
            .iter()
            .filter(|(name, value)| {
                required.contains(name) && value.as_deref().is_none_or(str::is_empty)
            })
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
        Err(Error::InvalidConfig(format!(
            "{}: {}",
            self.kind.name(),
            problems.join("; ")
        )))
    }
}

impl fmt::Debug for DynDnsClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // credentials are left out
        f.debug_struct("DynDnsClientBuilder")
            .field("provider", &self.kind.name())
            .field("domain", &self.domain)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

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
                return Err(Error::provider("injected failure"));
            }
            Ok(())
        }

        fn position(&self, ip: IpAddr) -> Result<usize> {
            self.records
                .iter()
                .position(|r| *r == ip)
                .ok_or_else(|| Error::RecordNotFound {
                    domain: DOMAIN.to_string(),
                    ip,
                })
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

        async fn refresh(&mut self) -> Result<()> {
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
        match result {
            Err(Error::InvalidConfig(message)) => message,
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn unknown_provider() {
        let Err(Error::InvalidConfig(message)) = DynDnsClient::provider("nope") else {
            panic!("expected InvalidConfig");
        };
        assert_eq!(
            message,
            r#"unknown provider "nope", expected one of: cloudflare, noip"#
        );
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
    async fn update_request_presets_ttl() {
        let fake = Fake::default();
        let mut client = DynDnsClient::new(fake.clone()).ttl(Some(120));

        client
            .update_request()
            .add(ip("192.0.2.1"))
            .send()
            .await
            .unwrap();
        client
            .update_request()
            .add(ip("192.0.2.2"))
            .ttl(None)
            .send()
            .await
            .unwrap();

        assert_eq!(
            fake.state().ops,
            vec![
                Op::Add(ip("192.0.2.1"), Some(120)),
                Op::Add(ip("192.0.2.2"), None)
            ]
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
        assert!(client.is_enabled(IpFamily::V4));
        assert!(!client.is_enabled(IpFamily::V6));

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
    async fn update_request_ignores_disabled_family() {
        let fake = Fake::with(&[ip("2001:db8::2")]);
        let mut client = DynDnsClient::new(fake.clone()).enable_ipv6(false);

        let summary = client
            .update_request()
            .add(ip("2001:db8::1"))
            .send()
            .await
            .unwrap();
        assert!(summary.is_unchanged());
        assert!(fake.state().ops.is_empty());

        client
            .update_request()
            .add(ip("192.0.2.1"))
            .add(ip("2001:db8::1"))
            .remove(ip("2001:db8::2"))
            .send()
            .await
            .unwrap();
        let state = fake.state();
        assert_eq!(state.ops, vec![Op::Add(ip("192.0.2.1"), None)]);
        assert_eq!(state.records, vec![ip("2001:db8::2"), ip("192.0.2.1")]);
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

        // update requests are restricted too
        client
            .update_request()
            .add(ip("192.0.2.4"))
            .send()
            .await
            .unwrap();
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
    async fn preview_changes_nothing() {
        let fake = Fake::with(&[ip("192.0.2.9")]);
        let mut client = DynDnsClient::new(fake.clone());

        let preview = client
            .preview_update([ip("192.0.2.1"), ip("2001:db8::1")])
            .await
            .unwrap();
        assert_eq!(preview.before, vec![ip("192.0.2.9")]);
        assert_eq!(preview.after, vec![ip("192.0.2.1"), ip("2001:db8::1")]);
        assert_eq!(preview.summary.updated, 1);
        assert_eq!(preview.summary.created, 1);
        assert!(fake.state().ops.is_empty());

        // the update matches the preview
        let summary = client
            .update([ip("192.0.2.1"), ip("2001:db8::1")])
            .await
            .unwrap();
        assert_eq!(summary, preview.summary);
        assert_eq!(fake.state().records, preview.after);
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
        client.refresh().await.unwrap();
        assert_eq!(fake.state().refreshes, 1);
    }
}
