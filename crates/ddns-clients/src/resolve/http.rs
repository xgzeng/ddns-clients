use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicUsize, Ordering},
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;

use super::IpResolver;

/// Resolves addresses by querying online services that echo the client's IP
/// as plain text, with URLs for both families or per family.
///
/// Each family's URLs are fallbacks: the one that last answered is asked
/// first, and the others, in order, only if it fails. Each family's requests
/// only connect over that family, so a URL for both needs a host reachable
/// over both.
///
/// ```no_run
/// use ddns_clients::resolve::HttpResolver;
///
/// let resolver = HttpResolver::new()
///     .with_url_v4(HttpResolver::IPIFY_IPV4)
///     .with_url_v6(HttpResolver::IPIFY_IPV6)
///     .with_url(HttpResolver::ICANHAZIP);
/// ```
#[derive(Debug, Clone)]
pub struct HttpResolver {
    ipv4: Endpoints,
    ipv6: Endpoints,
}

/// A family's URLs, in fallback order, and the client to query them with.
#[derive(Debug)]
struct Endpoints {
    client: reqwest::Client,
    urls: Vec<String>,
    /// The index of the URL that last answered.
    current: AtomicUsize,
}

impl Endpoints {
    fn new(client: reqwest::Client) -> Self {
        Endpoints {
            client,
            urls: vec![],
            current: AtomicUsize::new(0),
        }
    }

    /// The address the service at `url` echoes back to `client`.
    async fn fetch(client: &reqwest::Client, url: &str) -> Result<IpAddr> {
        client
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

    /// The address of `family` ("IPv4" or "IPv6", which `pick` takes) that the
    /// first URL to answer echoes to `client`, starting with the one that last
    /// answered; none if there are no URLs.
    async fn resolve<T>(
        &self,
        client: &reqwest::Client,
        family: &str,
        pick: fn(IpAddr) -> Option<T>,
    ) -> Result<Vec<T>> {
        let count = self.urls.len();
        let start = self.current.load(Ordering::Relaxed);
        let mut last_err = None;
        for index in (0..count).map(|n| (start + n) % count) {
            let url = &self.urls[index];
            if let Some(err) = last_err.take() {
                log::warn!("{err:#}; trying {url}");
            }
            match Self::fetch(client, url).await {
                Ok(addr) => match pick(addr) {
                    Some(addr) => {
                        self.current.store(index, Ordering::Relaxed);
                        return Ok(vec![addr]);
                    }
                    None => {
                        last_err = Some(anyhow!(
                            "{url} returned {addr}, expected an {family} address"
                        ))
                    }
                },
                Err(err) => last_err = Some(err),
            }
        }
        match last_err {
            Some(err) => Err(err),
            None => Ok(vec![]),
        }
    }
}

impl Clone for Endpoints {
    fn clone(&self) -> Self {
        Endpoints {
            client: self.client.clone(),
            urls: self.urls.clone(),
            current: AtomicUsize::new(self.current.load(Ordering::Relaxed)),
        }
    }
}

impl HttpResolver {
    /// <https://icanhazip.com> over both families.
    pub const ICANHAZIP: &str = "https://icanhazip.com";
    /// <https://www.ipify.org> over IPv4.
    pub const IPIFY_IPV4: &str = "https://api.ipify.org";
    /// <https://www.ipify.org> over IPv6.
    pub const IPIFY_IPV6: &str = "https://api6.ipify.org";
    /// <https://ifconfig.me>, over both families.
    pub const IFCONFIG_ME: &str = "https://ifconfig.me/ip";

    /// Creates a resolver without URLs, which resolves no family until URLs
    /// are added.
    ///
    /// # Panics
    ///
    /// If the HTTP client can't be initialized, as [`reqwest::Client::new`].
    pub fn new() -> Self {
        let endpoints = |local_address: IpAddr| {
            Endpoints::new(family_client(reqwest::Client::builder(), local_address))
        };
        HttpResolver {
            ipv4: endpoints(Ipv4Addr::UNSPECIFIED.into()),
            ipv6: endpoints(Ipv6Addr::UNSPECIFIED.into()),
        }
    }

    /// Adds `url`, on a host reachable over both families, as the last
    /// fallback of both.
    pub fn with_url(self, url: impl Into<String>) -> Self {
        let url = url.into();
        self.with_url_v4(url.clone()).with_url_v6(url)
    }

    /// Adds `url` as the last IPv4 fallback.
    pub fn with_url_v4(mut self, url: impl Into<String>) -> Self {
        self.ipv4.urls.push(url.into());
        self
    }

    /// Adds `url` as the last IPv6 fallback.
    pub fn with_url_v6(mut self, url: impl Into<String>) -> Self {
        self.ipv6.urls.push(url.into());
        self
    }

    /// Replaces the HTTP client, e.g. to set timeouts or a proxy.
    ///
    /// Requests of both families then use `client`, which may connect over
    /// either, so each URL has to be reachable over its family only.
    /// [`check`](IpResolver::check) doesn't use it, as it needs a client bound
    /// to the address it checks.
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.ipv4.client = client.clone();
        self.ipv6.client = client;
        self
    }

    /// Removes `urls` from both families.
    pub(super) fn remove_urls(&mut self, urls: &[&str]) {
        for endpoints in [&mut self.ipv4, &mut self.ipv6] {
            endpoints.urls.retain(|url| !urls.contains(&url.as_str()));
            endpoints.current = AtomicUsize::new(0);
        }
    }

    /// The IPv4 and IPv6 URLs, in fallback order.
    #[cfg(test)]
    pub(super) fn urls(&self) -> (&[String], &[String]) {
        (&self.ipv4.urls, &self.ipv6.urls)
    }
}

impl Default for HttpResolver {
    fn default() -> Self {
        Self::new()
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
        self.ipv4
            .resolve(&self.ipv4.client, "IPv4", |addr| match addr {
                IpAddr::V4(addr) => Some(addr),
                IpAddr::V6(_) => None,
            })
            .await
    }

    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
        self.ipv6
            .resolve(&self.ipv6.client, "IPv6", |addr| match addr {
                IpAddr::V6(addr) => Some(addr),
                IpAddr::V4(_) => None,
            })
            .await
    }

    /// Whether the services, asked from `addr`, see `addr` itself, i.e. it's
    /// public and not behind NAT; false if its family has no URLs.
    async fn check(&self, addr: IpAddr) -> Result<bool> {
        let client = reqwest::Client::builder()
            .local_address(addr)
            .build()
            .context("failed to initialize the HTTP client")?;
        let seen = match addr {
            IpAddr::V4(_) => self
                .ipv4
                .resolve(&client, "IPv4", |seen| seen.is_ipv4().then_some(seen)),
            IpAddr::V6(_) => self
                .ipv6
                .resolve(&client, "IPv6", |seen| seen.is_ipv6().then_some(seen)),
        }
        .await
        .with_context(|| format!("check {addr}"))?;
        match seen.first() {
            Some(&seen) if seen != addr => {
                log::debug!("{addr} is seen as {seen}");
                Ok(false)
            }
            seen => Ok(seen.is_some()),
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
        let endpoints = |local_address| Endpoints {
            urls: vec![url.clone()],
            ..Endpoints::new(family_client(
                reqwest::Client::builder().resolve_to_addrs(host, addrs),
                local_address,
            ))
        };
        HttpResolver {
            ipv4: endpoints(Ipv4Addr::UNSPECIFIED.into()),
            ipv6: endpoints(Ipv6Addr::UNSPECIFIED.into()),
        }
    }

    #[tokio::test]
    async fn check_from_the_address() {
        let listener = TcpListener::bind((LOCALHOST_V4, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(echo_ip(listener));

        let resolver = HttpResolver::new().with_url_v4(local_url(port));
        assert!(resolver.check(LOCALHOST_V4).await.unwrap());
        // no IPv6 URL, so nothing can confirm an IPv6 address
        assert!(!resolver.check(LOCALHOST_V6).await.unwrap());
    }

    #[test]
    fn remove_urls_keeps_the_others() {
        let mut resolver = HttpResolver::new()
            .with_url("https://a")
            .with_url_v4("https://b")
            .with_url_v6("https://c");
        resolver.ipv4.current.store(1, Ordering::Relaxed);
        resolver.remove_urls(&["https://a"]);
        assert_eq!(
            resolver.urls(),
            (&["https://b".into()][..], &["https://c".into()][..])
        );
        assert_eq!(resolver.ipv4.current.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn with_url_adds_to_both_families() {
        let resolver = HttpResolver::new()
            .with_url_v4("https://v4")
            .with_url_v6("https://v6")
            .with_url("https://both");
        assert_eq!(resolver.ipv4.urls, ["https://v4", "https://both"]);
        assert_eq!(resolver.ipv6.urls, ["https://v6", "https://both"]);
    }

    /// A local port nothing listens on.
    async fn closed_port() -> u16 {
        let listener = TcpListener::bind((LOCALHOST_V4, 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    }

    fn local_url(port: u16) -> String {
        format!("http://{LOCALHOST_V4}:{port}")
    }

    #[tokio::test]
    async fn falls_back_and_keeps_the_url_that_answered() {
        let first_port = closed_port().await;
        let second = TcpListener::bind((LOCALHOST_V4, 0)).await.unwrap();
        let second_port = second.local_addr().unwrap().port();
        let second = tokio::spawn(echo_ip(second));
        let resolver = HttpResolver::new()
            .with_url_v4(local_url(first_port))
            .with_url_v4(local_url(second_port));
        let current = || resolver.ipv4.current.load(Ordering::Relaxed);

        assert_eq!(resolver.resolve_a().await.unwrap(), [Ipv4Addr::LOCALHOST]);
        assert_eq!(current(), 1);

        // the first answers again, but the second is kept while it answers
        let first = TcpListener::bind((LOCALHOST_V4, first_port)).await.unwrap();
        tokio::spawn(echo_ip(first));
        assert_eq!(resolver.resolve_a().await.unwrap(), [Ipv4Addr::LOCALHOST]);
        assert_eq!(current(), 1);

        // once the second fails, it wraps around to the first
        second.abort();
        let _ = second.await;
        assert_eq!(resolver.resolve_a().await.unwrap(), [Ipv4Addr::LOCALHOST]);
        assert_eq!(current(), 0);
    }

    #[tokio::test]
    async fn fails_if_all_urls_fail() {
        let resolver = HttpResolver::new()
            .with_url_v4(local_url(closed_port().await))
            .with_url_v4(local_url(closed_port().await));
        resolver.resolve_a().await.unwrap_err();
        // no URLs, nothing to resolve
        assert!(resolver.resolve_aaaa().await.unwrap().is_empty());
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
