use std::net::IpAddr;

use async_trait::async_trait;

use super::{IpFamily, IpResolver};
use crate::Result;

/// Resolves addresses by querying an online service that echoes the client's
/// IP as plain text, with one URL per family.
///
/// Each URL should only be reachable over its family (e.g. an IPv6-only
/// host for the IPv6 URL), so the echoed address has the right family.
#[derive(Debug, Clone)]
pub struct HttpResolver {
    client: reqwest::Client,
    ipv4_url: Option<String>,
    ipv6_url: Option<String>,
}

impl HttpResolver {
    /// Creates a resolver from per-family URLs; `None` disables that family.
    pub fn new(ipv4_url: Option<String>, ipv6_url: Option<String>) -> Self {
        HttpResolver {
            client: reqwest::Client::new(),
            ipv4_url,
            ipv6_url,
        }
    }

    /// Uses <https://icanhazip.com>.
    pub fn icanhazip() -> Self {
        Self::new(
            Some("https://ipv4.icanhazip.com".into()),
            Some("https://ipv6.icanhazip.com".into()),
        )
    }

    /// Uses <https://www.ipify.org>.
    pub fn ipify() -> Self {
        Self::new(
            Some("https://api.ipify.org".into()),
            Some("https://api6.ipify.org".into()),
        )
    }

    /// Replaces the HTTP client, e.g. to set timeouts or a proxy.
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }
}

#[async_trait]
impl IpResolver for HttpResolver {
    async fn resolve(&self, family: IpFamily) -> Result<Vec<IpAddr>> {
        let url = match family {
            IpFamily::V4 => &self.ipv4_url,
            IpFamily::V6 => &self.ipv6_url,
        };
        let Some(url) = url else {
            return Ok(vec![]);
        };

        let addr: IpAddr = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?
            .trim()
            .parse()?;
        if IpFamily::of(&addr) != family {
            log::warn!("{url} returned {addr}, expected an {family:?} address");
            return Ok(vec![]);
        }
        Ok(vec![addr])
    }
}
