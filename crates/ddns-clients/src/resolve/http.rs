use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use async_trait::async_trait;

use super::IpResolver;

/// Resolves addresses by querying an online service that echoes the client's
/// IP as plain text, with one URL for both families or one per family.
///
/// Each family's requests only connect over that family, so a URL shared by
/// both needs a host reachable over both.
#[derive(Debug, Clone)]
pub struct HttpResolver {
    ipv4: Option<Endpoint>,
    ipv6: Option<Endpoint>,
}

/// A family's URL, and the client to query it with.
#[derive(Debug, Clone)]
struct Endpoint {
    client: reqwest::Client,
    url: String,
}

impl Endpoint {
    /// The address the service echoes back.
    async fn fetch(&self) -> Result<IpAddr> {
        let url = &self.url;
        self.client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?
            .trim()
            .parse()
            .with_context(|| format!("{url} returned an invalid ip address"))
    }
}

impl HttpResolver {
    /// Creates a resolver using `url`, on a host reachable over both families.
    ///
    /// # Panics
    ///
    /// If the HTTP client can't be initialized, as [`reqwest::Client::new`].
    pub fn dual_stack(url: impl Into<String>) -> Self {
        let url = url.into();
        Self::new(Some(url.clone()), Some(url))
    }

    /// Creates a resolver from per-family URLs; `None` disables that family.
    ///
    /// # Panics
    ///
    /// If the HTTP client can't be initialized, as [`reqwest::Client::new`].
    pub fn new(ipv4_url: Option<String>, ipv6_url: Option<String>) -> Self {
        let endpoint = |local_address, url| Endpoint {
            client: family_client(reqwest::Client::builder(), local_address),
            url,
        };
        HttpResolver {
            ipv4: ipv4_url.map(|url| endpoint(Ipv4Addr::UNSPECIFIED.into(), url)),
            ipv6: ipv6_url.map(|url| endpoint(Ipv6Addr::UNSPECIFIED.into(), url)),
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
    ///
    /// Requests of both families then use `client`, which may connect over
    /// either, so each URL has to be reachable over its family only.
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        for endpoint in [&mut self.ipv4, &mut self.ipv6].into_iter().flatten() {
            endpoint.client = client.clone();
        }
        self
    }
}

/// Builds a client bound to `local_address`, a family's unspecified address,
/// so it only connects over that family and skips the host's addresses of the
/// other one. Being per family, it also can't reuse a connection of the other
/// family.
fn family_client(builder: reqwest::ClientBuilder, local_address: IpAddr) -> reqwest::Client {
    builder
        .local_address(local_address)
        .build()
        .expect("failed to initialize the HTTP client")
}

#[async_trait]
impl IpResolver for HttpResolver {
    async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
        let Some(endpoint) = &self.ipv4 else {
            return Ok(vec![]);
        };
        match endpoint.fetch().await? {
            IpAddr::V4(addr) => Ok(vec![addr]),
            addr => {
                log::warn!("{} returned {addr}, expected an IPv4 address", endpoint.url);
                Ok(vec![])
            }
        }
    }

    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
        let Some(endpoint) = &self.ipv6 else {
            return Ok(vec![]);
        };
        match endpoint.fetch().await? {
            IpAddr::V6(addr) => Ok(vec![addr]),
            addr => {
                log::warn!("{} returned {addr}, expected an IPv6 address", endpoint.url);
                Ok(vec![])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    const LOCALHOST_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const LOCALHOST_V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    /// Answers every HTTP request on `listener` with the client's IP.
    async fn echo_ip(listener: TcpListener) {
        loop {
            let (mut stream, peer) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await;
            let ip = peer.ip().to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{ip}",
                ip.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    }

    /// A resolver with the same URL for both families, on a host with the
    /// given addresses, tried in this order by a client that may use any.
    fn same_url_resolver(addrs: &[SocketAddr]) -> HttpResolver {
        let host = "dual-stack.test";
        let url = format!("http://{host}:{}", addrs[0].port());
        let endpoint = |local_address| Endpoint {
            client: family_client(
                reqwest::Client::builder().resolve_to_addrs(host, addrs),
                local_address,
            ),
            url: url.clone(),
        };
        HttpResolver {
            ipv4: Some(endpoint(Ipv4Addr::UNSPECIFIED.into())),
            ipv6: Some(endpoint(Ipv6Addr::UNSPECIFIED.into())),
        }
    }

    #[test]
    fn dual_stack_uses_url_for_both_families() {
        let url = "https://ip.example.net";
        let resolver = HttpResolver::dual_stack(url);
        assert_eq!(resolver.ipv4.unwrap().url, url);
        assert_eq!(resolver.ipv6.unwrap().url, url);
    }

    #[tokio::test]
    async fn same_url_for_both_families() {
        // the test host may have no IPv6, not even on the loopback interface
        let Ok(v6_listener) = TcpListener::bind((LOCALHOST_V6, 0)).await else {
            eprintln!("skipped: no IPv6 loopback address");
            return;
        };
        let port = v6_listener.local_addr().unwrap().port();
        let v4_listener = TcpListener::bind((LOCALHOST_V4, port)).await.unwrap();
        tokio::spawn(echo_ip(v4_listener));
        tokio::spawn(echo_ip(v6_listener));

        let addrs = [
            SocketAddr::new(LOCALHOST_V6, port),
            SocketAddr::new(LOCALHOST_V4, port),
        ];
        for addrs in [addrs, [addrs[1], addrs[0]]] {
            let resolver = same_url_resolver(&addrs);
            assert_eq!(resolver.resolve_a().await.unwrap(), [Ipv4Addr::LOCALHOST]);
            assert_eq!(
                resolver.resolve_aaaa().await.unwrap(),
                [Ipv6Addr::LOCALHOST]
            );
        }
    }

    #[tokio::test]
    async fn family_missing_on_host_fails() {
        let listener = TcpListener::bind((LOCALHOST_V4, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(echo_ip(listener));

        let resolver = same_url_resolver(&[addr]);
        assert_eq!(resolver.resolve_a().await.unwrap(), [Ipv4Addr::LOCALHOST]);
        resolver.resolve_aaaa().await.unwrap_err();
    }
}
