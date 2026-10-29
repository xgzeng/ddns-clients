use std::{fmt, net::IpAddr};

use crate::{
    CloudflareProvider, DynDnsProvider, Error, NoIpProvider, RecordUpdateRequest, Result,
    UpdateRequestBuilder, UpdateSummary,
    providers::{CLOUDFLARE, NOIP, plan_changes},
    resolve::IpFamily,
};

/// A dynamic DNS client managing the address records of one domain on one
/// provider.
///
/// Built with [`DynDnsClient::provider`] for a built-in provider, or
/// [`DynDnsClient::new`] for any other [`DynDnsProvider`].
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
    domain: String,
    ttl: Option<u32>,
    /// Whether A (IPv4) and AAAA (IPv6) records are managed.
    ipv4: bool,
    ipv6: bool,
    /// Only re-point existing records, never create or delete any.
    replace_only: bool,
    /// The domain's addresses after the last `list` or `update`; `None` when
    /// unknown, e.g. after a failure or an `update_request`.
    records: Option<Vec<IpAddr>>,
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

    /// Creates a client managing `domain` through an existing provider, e.g.
    /// a custom [`DynDnsProvider`] implementation, with the provider's default
    /// TTL and both address families enabled.
    ///
    /// ```no_run
    /// # fn example(provider: impl ddns_clients::DynDnsProvider + 'static) {
    /// use ddns_clients::DynDnsClient;
    ///
    /// let client = DynDnsClient::new(provider, "myhost.example.com")
    ///     .ttl(Some(300))
    ///     .enable_ipv6(false);
    /// # }
    /// ```
    pub fn new(provider: impl DynDnsProvider + 'static, domain: impl Into<String>) -> Self {
        DynDnsClient {
            provider: Box::new(provider),
            domain: domain.into(),
            ttl: None,
            ipv4: true,
            ipv6: true,
            replace_only: false,
            records: None,
        }
    }

    /// TTL of created and changed records; see [`DynDnsClientBuilder::ttl`].
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
        &self.domain
    }

    /// The domain's addresses as of the last [`list`](Self::list) or
    /// [`update`](Self::update), if known.
    pub fn cached_records(&self) -> Option<&[IpAddr]> {
        self.records.as_deref()
    }

    /// Addresses of the domain's records of the enabled families, fetched
    /// from the provider; also refreshes the addresses cached for
    /// [`update`](Self::update).
    pub async fn list(&mut self) -> Result<Vec<IpAddr>> {
        self.records = None;
        let mut records = self.provider.list(&self.domain).await?;
        records.retain(|ip| self.is_enabled(IpFamily::of(ip)));
        self.records = Some(records.clone());
        Ok(records)
    }

    /// Starts a batched change of the domain's address records, with the
    /// client's TTL preset; [`UpdateRequestBuilder::ttl`] overrides it.
    /// Addresses of disabled families are ignored when it is sent, and a
    /// replace-only client always sends it as
    /// [`replace_only`](UpdateRequestBuilder::replace_only).
    ///
    /// Clears the addresses cached for [`update`](Self::update).
    pub fn update_request(&mut self) -> UpdateRequestBuilder<'_> {
        self.records = None;
        self.provider
            .update_request(&self.domain)
            .ttl(self.ttl)
            .restrict(self.ipv4, self.ipv6, self.replace_only)
    }

    /// Replaces the domain's records of the enabled families with `ips`:
    /// existing records not in `ips` are re-pointed or removed, and missing
    /// ones created. Addresses and records of disabled families are left
    /// alone.
    ///
    /// A [`replace_only`](Self::replace_only) client only re-points records:
    /// surplus records keep their addresses, and addresses without a record
    /// to re-point are skipped (logged as a warning).
    ///
    /// The domain's addresses are cached: only the first update, and the
    /// first after a failure or an [`update_request`](Self::update_request),
    /// lists them, and no request is sent if they already equal `ips`. Call
    /// [`list`](Self::list) to pick up changes made elsewhere.
    ///
    /// Empty `ips` remove all records of the enabled families.
    pub async fn update(&mut self, ips: impl IntoIterator<Item = IpAddr>) -> Result<UpdateSummary> {
        let mut desired: Vec<IpAddr> = vec![];
        for ip in ips {
            if self.is_enabled(IpFamily::of(&ip)) && !desired.contains(&ip) {
                desired.push(ip);
            }
        }
        // taken out, so the cache stays empty if anything below fails
        let existing = match self.records.take() {
            Some(records) => records,
            None => self.list().await?,
        };

        // records of disabled families are neither removed nor added, so
        // the provider leaves them alone
        let request = RecordUpdateRequest {
            domain: self.domain.clone(),
            add: desired,
            remove: existing.clone(),
            ttl: self.ttl,
            replace_only: self.replace_only,
        };
        // predict the provider's plan, with the records' positions as ids
        let mut records: Vec<(usize, IpAddr)> = existing.into_iter().enumerate().collect();
        let plan = plan_changes(&records, &request);
        for (i, ip) in &plan.repoint {
            records[*i].1 = *ip;
        }
        records.retain(|(i, _)| !plan.delete.contains(i));
        let after: Vec<IpAddr> = records
            .into_iter()
            .map(|(_, ip)| ip)
            .chain(plan.create.iter().copied())
            .collect();

        let skipped: Vec<&IpAddr> = request
            .add
            .iter()
            .filter(|ip| !after.contains(ip))
            .collect();
        if !skipped.is_empty() {
            log::warn!(
                "{}: no record left to re-point at {skipped:?} (replace only)",
                self.domain
            );
        }
        if plan.summary().is_unchanged() {
            self.records = Some(after);
            return Ok(plan.summary());
        }

        let summary = self.provider.execute_request(request).await?;
        self.records = Some(after);
        Ok(summary)
    }
}

impl fmt::Debug for DynDnsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynDnsClient")
            .field("domain", &self.domain)
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
        let provider: Box<dyn DynDnsProvider> = match self.kind {
            Kind::Cloudflare => Box::new(CloudflareProvider::new(
                self.api_token.unwrap_or_default(),
                self.zone.unwrap_or_default(),
            )?),
            Kind::NoIp => {
                let username = self.username.unwrap_or_default();
                let password = self.password.unwrap_or_default();
                Box::new(match &self.user_agent {
                    Some(user_agent) => {
                        NoIpProvider::with_user_agent(username, password, user_agent)?
                    }
                    None => NoIpProvider::new(username, password)?,
                })
            }
        };
        Ok(DynDnsClient {
            provider,
            domain: self.domain.unwrap_or_default(),
            ttl: self.ttl,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            replace_only: self.replace_only,
            records: None,
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
    use crate::{RecordUpdateRequest, UpdateSummary};

    #[derive(Default)]
    struct FakeState {
        records: Vec<IpAddr>,
        requests: Vec<RecordUpdateRequest>,
        lists: usize,
        fail_next: bool,
    }

    /// Keeps records in memory and records the requests it executes.
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
        async fn list(&mut self, _domain: &str) -> Result<Vec<IpAddr>> {
            let mut state = self.state();
            state.lists += 1;
            Ok(state.records.clone())
        }

        fn update_request<'a>(&'a mut self, domain: &str) -> UpdateRequestBuilder<'a> {
            UpdateRequestBuilder::new(self, domain)
        }

        async fn execute_request(&mut self, request: RecordUpdateRequest) -> Result<UpdateSummary> {
            let mut state = self.state();
            if std::mem::take(&mut state.fail_next) {
                return Err(Error::provider("injected failure"));
            }
            let mut records: Vec<(usize, IpAddr)> =
                state.records.iter().copied().enumerate().collect();
            let plan = plan_changes(&records, &request);
            for (i, ip) in &plan.repoint {
                records[*i].1 = *ip;
            }
            records.retain(|(i, _)| !plan.delete.contains(i));
            state.records = records
                .into_iter()
                .map(|(_, ip)| ip)
                .chain(plan.create.iter().copied())
                .collect();
            state.requests.push(request);
            Ok(plan.summary())
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

    #[tokio::test]
    async fn update_request_presets_domain_and_ttl() {
        let fake = Fake::default();
        let mut client = DynDnsClient::new(fake.clone(), "myhost.example.com").ttl(Some(120));

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

        let state = fake.state();
        assert_eq!(state.requests[0].domain, "myhost.example.com");
        assert_eq!(state.requests[0].add, vec![ip("192.0.2.1")]);
        assert_eq!(state.requests[0].ttl, Some(120));
        assert_eq!(state.requests[1].ttl, None);
    }

    #[tokio::test]
    async fn update_replaces_all() {
        let fake = Fake::with(&[ip("192.0.2.9")]);
        let mut client = DynDnsClient::new(fake.clone(), "myhost.example.com").ttl(Some(120));
        let ips = vec![ip("192.0.2.1"), ip("2001:db8::1")];

        client.update(ips.clone()).await.unwrap();
        assert_eq!(fake.state().records, ips);
        // an empty set removes every record
        client.update([]).await.unwrap();
        assert!(fake.state().records.is_empty());

        let state = fake.state();
        assert_eq!(state.requests.len(), 2);
        assert_eq!(state.requests[0].domain, "myhost.example.com");
        assert_eq!(state.requests[0].add, ips);
        assert_eq!(state.requests[0].remove, vec![ip("192.0.2.9")]);
        assert_eq!(state.requests[0].ttl, Some(120));
        assert!(state.requests[1].add.is_empty());
        assert_eq!(state.requests[1].remove, ips);
    }

    #[tokio::test]
    async fn update_uses_cached_records() {
        let fake = Fake::with(&[ip("192.0.2.9")]);
        let mut client = DynDnsClient::new(fake.clone(), "myhost.example.com");

        client.update([ip("192.0.2.1")]).await.unwrap();
        assert_eq!(fake.state().lists, 1);

        // unchanged addresses: neither listed nor sent
        let summary = client
            .update([ip("192.0.2.1"), ip("192.0.2.1")])
            .await
            .unwrap();
        assert_eq!(summary.kept, 1);
        assert!(summary.is_unchanged());
        assert_eq!(fake.state().requests.len(), 1);

        // changed addresses: sent, but not listed
        client.update([ip("192.0.2.2")]).await.unwrap();
        let state = fake.state();
        assert_eq!(state.lists, 1);
        assert_eq!(state.requests.len(), 2);
        assert_eq!(state.requests[1].remove, vec![ip("192.0.2.1")]);
    }

    #[tokio::test]
    async fn update_relists_after_failure_and_update_request() {
        let fake = Fake::default();
        let mut client = DynDnsClient::new(fake.clone(), "myhost.example.com");
        client.update([ip("192.0.2.1")]).await.unwrap();

        fake.state().fail_next = true;
        client.update([ip("192.0.2.2")]).await.unwrap_err();
        client.update([ip("192.0.2.2")]).await.unwrap();
        assert_eq!(fake.state().lists, 2);

        client
            .update_request()
            .add(ip("192.0.2.3"))
            .send()
            .await
            .unwrap();
        client.update([ip("192.0.2.3")]).await.unwrap();
        let state = fake.state();
        assert_eq!(state.lists, 3);
        assert_eq!(state.records, vec![ip("192.0.2.3")]);
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
    async fn disabled_family_is_left_alone() {
        let fake = Fake::with(&[ip("192.0.2.9"), ip("2001:db8::9")]);
        let mut client = DynDnsClient::new(fake.clone(), "myhost.example.com").enable_ipv6(false);
        assert!(client.is_enabled(IpFamily::V4));
        assert!(!client.is_enabled(IpFamily::V6));

        assert_eq!(client.list().await.unwrap(), vec![ip("192.0.2.9")]);
        assert_eq!(client.cached_records(), Some(&[ip("192.0.2.9")][..]));

        client
            .update([ip("192.0.2.1"), ip("2001:db8::1")])
            .await
            .unwrap();
        let state = fake.state();
        assert_eq!(state.requests[0].add, vec![ip("192.0.2.1")]);
        assert_eq!(state.requests[0].remove, vec![ip("192.0.2.9")]);
        assert_eq!(state.records, vec![ip("192.0.2.1"), ip("2001:db8::9")]);
    }

    #[tokio::test]
    async fn update_request_ignores_disabled_family() {
        let fake = Fake::default();
        let mut client = DynDnsClient::new(fake.clone(), "myhost.example.com").enable_ipv6(false);

        // nothing left to send
        let summary = client
            .update_request()
            .add(ip("2001:db8::1"))
            .send()
            .await
            .unwrap();
        assert!(summary.is_unchanged());
        assert!(fake.state().requests.is_empty());

        client
            .update_request()
            .add(ip("192.0.2.1"))
            .add(ip("2001:db8::1"))
            .remove(ip("2001:db8::2"))
            .send()
            .await
            .unwrap();
        let state = fake.state();
        assert_eq!(state.requests.len(), 1);
        assert_eq!(state.requests[0].add, vec![ip("192.0.2.1")]);
        assert!(state.requests[0].remove.is_empty());
    }

    #[tokio::test]
    async fn replace_only_keeps_record_count() {
        let fake = Fake::with(&[ip("192.0.2.9"), ip("2001:db8::9")]);
        let mut client = DynDnsClient::new(fake.clone(), "myhost.example.com").replace_only(true);

        let summary = client
            .update([ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3")])
            .await
            .unwrap();
        assert_eq!(summary.updated, 2);
        assert_eq!(summary.created + summary.deleted, 0);
        let records = fake.state().records.clone();
        assert_eq!(records, vec![ip("192.0.2.1"), ip("192.0.2.2")]);
        assert_eq!(client.cached_records(), Some(&records[..]));

        // nothing to remove either: both records stay
        let summary = client.update([ip("192.0.2.1")]).await.unwrap();
        assert!(summary.is_unchanged());
        assert_eq!(fake.state().records.len(), 2);
        assert_eq!(fake.state().requests.len(), 1);
    }

    #[tokio::test]
    async fn replace_only_without_records_sends_nothing() {
        let fake = Fake::default();
        let mut client = DynDnsClient::new(fake.clone(), "myhost.example.com").replace_only(true);
        let summary = client.update([ip("192.0.2.1")]).await.unwrap();
        assert!(summary.is_unchanged());
        assert!(fake.state().requests.is_empty());
        assert_eq!(client.cached_records(), Some(&[][..]));
    }

    #[tokio::test]
    async fn replace_only_is_forced_on_update_request() {
        let fake = Fake::default();
        let mut client = DynDnsClient::new(fake.clone(), "myhost.example.com").replace_only(true);
        client
            .update_request()
            .add(ip("192.0.2.1"))
            .replace_only(false)
            .send()
            .await
            .unwrap();
        let state = fake.state();
        assert!(state.requests[0].replace_only);
        assert!(state.records.is_empty());
    }
}
