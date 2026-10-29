use std::{fmt, net::IpAddr};

use crate::{
    CloudflareProvider, DynDnsProvider, Error, NoIpProvider, Result, UpdateBuilder,
    providers::{CLOUDFLARE, NOIP},
};

/// A dynamic DNS client managing the address records of one domain on one
/// provider.
///
/// Built with [`DynDnsClient::provider`] for a built-in provider, or
/// [`DynDnsClient::custom`] for any other [`DynDnsProvider`].
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
/// let current = client.list().await?;
/// client
///     .update()
///     .remove_all(current)
///     .add("192.0.2.1".parse().unwrap())
///     .send()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct DynDnsClient {
    provider: Box<dyn DynDnsProvider>,
    domain: String,
    ttl: Option<u32>,
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

    /// Starts building a client around an existing provider, e.g. a custom
    /// [`DynDnsProvider`] implementation.
    pub fn custom(provider: impl DynDnsProvider + 'static) -> DynDnsClientBuilder {
        DynDnsClientBuilder::new(Kind::Custom(Box::new(provider)))
    }

    /// The domain whose records this client manages.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// TTL of created and changed records; `None` uses the provider's default.
    pub fn ttl(&self) -> Option<u32> {
        self.ttl
    }

    /// Addresses of all A and AAAA records of the domain.
    pub async fn list(&mut self) -> Result<Vec<IpAddr>> {
        self.provider.list(&self.domain).await
    }

    /// Starts a batched change of the domain's address records, with the
    /// client's TTL preset; [`UpdateBuilder::ttl`] overrides it.
    pub fn update(&mut self) -> UpdateBuilder<'_> {
        self.provider.update(&self.domain).ttl(self.ttl)
    }
}

impl fmt::Debug for DynDnsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynDnsClient")
            .field("domain", &self.domain)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

enum Kind {
    Cloudflare,
    NoIp,
    Custom(Box<dyn DynDnsProvider>),
}

impl Kind {
    fn name(&self) -> &str {
        match self {
            Kind::Cloudflare => CLOUDFLARE,
            Kind::NoIp => NOIP,
            Kind::Custom(_) => "custom",
        }
    }

    /// Required and optional parameters, besides `ttl`.
    fn parameters(&self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            Kind::Cloudflare => (&["api_token", "zone", "domain"], &[]),
            Kind::NoIp => (&["username", "password", "domain"], &["user_agent"]),
            Kind::Custom(_) => (&["domain"], &[]),
        }
    }
}

/// Builds a [`DynDnsClient`]; see [`DynDnsClient::provider`].
///
/// | Provider | Required | Optional |
/// |---|---|---|
/// | `cloudflare` | `api_token`, `zone`, `domain` | `ttl` |
/// | `noip` | `username`, `password`, `domain` | `user_agent`, `ttl` |
/// | custom | `domain` | `ttl` |
///
/// [`build`](Self::build) rejects missing (or empty) required parameters and
/// parameters the provider doesn't use.
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
            Kind::Custom(provider) => provider,
        };
        Ok(DynDnsClient {
            provider,
            domain: self.domain.unwrap_or_default(),
            ttl: self.ttl,
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
    use crate::{RecordUpdate, UpdateSummary};

    /// Records the updates it is asked to apply.
    #[derive(Default)]
    struct Recorder(Arc<Mutex<Vec<RecordUpdate>>>);

    #[async_trait]
    impl DynDnsProvider for Recorder {
        async fn list(&mut self, _domain: &str) -> Result<Vec<IpAddr>> {
            Ok(vec![])
        }

        fn update<'a>(&'a mut self, domain: &str) -> UpdateBuilder<'a> {
            UpdateBuilder::new(self, domain)
        }

        async fn apply_update(&mut self, update: RecordUpdate) -> Result<UpdateSummary> {
            self.0.lock().unwrap().push(update);
            Ok(UpdateSummary::default())
        }
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
        assert_eq!(client.ttl(), Some(300));
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

        let client = DynDnsClient::provider(NOIP)
            .unwrap()
            .username("me")
            .password("secret")
            .user_agent("Example ddns/1.0 admin@example.com")
            .domain("myhost.ddns.net")
            .build()
            .unwrap();
        assert_eq!(client.ttl(), None);
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
    fn custom_unused() {
        let builder = DynDnsClient::custom(Recorder::default())
            .domain("myhost.example.com")
            .user_agent("x");
        assert_eq!(
            invalid_config(builder.build()),
            "custom: user_agent is not used"
        );
    }

    #[tokio::test]
    async fn update_presets_domain_and_ttl() {
        let recorder = Recorder::default();
        let updates = recorder.0.clone();
        let mut client = DynDnsClient::custom(recorder)
            .domain("myhost.example.com")
            .ttl(Some(120))
            .build()
            .unwrap();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();

        client.update().add(ip).send().await.unwrap();
        client.update().add(ip).ttl(None).send().await.unwrap();

        let updates = updates.lock().unwrap();
        assert_eq!(updates[0].domain, "myhost.example.com");
        assert_eq!(updates[0].add, vec![ip]);
        assert_eq!(updates[0].ttl, Some(120));
        assert_eq!(updates[1].ttl, None);
    }
}
