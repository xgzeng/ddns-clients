//! Resolution of this host's public IP addresses.
//!
//! An [`IpResolver`] finds this host's public IPv4 and IPv6 addresses:
//!
//! - [`DefaultResolver`] checks each global address of local interfaces with
//!   online "what is my IP" services, or just asks them.
//! - [`HttpResolver`] asks such services, falling back from one to the next.
//! - [`LocalResolver`] (Linux only) reads the addresses of local interfaces.

mod http;
#[cfg(target_os = "linux")]
mod local;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};
use async_trait::async_trait;

pub use http::HttpResolver;
#[cfg(target_os = "linux")]
pub use local::{AddressMonitor, LocalResolver};

/// A source of this host's public IP addresses.
///
/// An empty list means the resolver found none of that family, or doesn't
/// support it.
#[async_trait]
pub trait IpResolver: Send + Sync {
    /// Resolves the public IPv4 addresses, for A records.
    async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>>;

    /// Resolves the public IPv6 addresses, for AAAA records.
    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>>;

    /// Whether `addr` is a public address of this host, according to this
    /// resolver; by default, whether it resolves `addr`'s family to it.
    async fn check(&self, addr: IpAddr) -> Result<bool> {
        Ok(match addr {
            IpAddr::V4(addr) => self.resolve_a().await?.contains(&addr),
            IpAddr::V6(addr) => self.resolve_aaaa().await?.contains(&addr),
        })
    }
}

/// The URLs of the services [`DefaultResolver`] uses unless
/// [`without_builtin_urls`](DefaultResolver::without_builtin_urls).
const BUILTIN_URLS: [&str; 4] = [
    HttpResolver::ICANHAZIP,
    HttpResolver::IFCONFIG_ME,
    HttpResolver::IPIFY_IPV4,
    HttpResolver::IPIFY_IPV6,
];

/// Finds every public address of this host: on Linux, each global address of
/// local interfaces that an echo service, asked from that address, sees as
/// itself, i.e. that isn't behind NAT; without the local check, the one
/// address the echo service sees.
///
/// The echo services are fallbacks, as in [`HttpResolver`]:
/// <https://icanhazip.com>, <https://ifconfig.me> and
/// <https://www.ipify.org>, then any added with [`with_url`](Self::with_url).
///
/// ```no_run
/// use ddns_clients::resolve::DefaultResolver;
///
/// let resolver = DefaultResolver::new()
///     .with_interface("eth0")
///     .with_url("https://ip.example.net");
/// ```
pub struct DefaultResolver {
    /// The addresses to check; `None` to publish what the services see.
    #[cfg(target_os = "linux")]
    local: Option<LocalResolver>,
    http: HttpResolver,
}

impl DefaultResolver {
    /// Checks the addresses of all local interfaces with the built-in
    /// services.
    ///
    /// # Panics
    ///
    /// If the HTTP client can't be initialized, as [`HttpResolver::new`].
    pub fn new() -> Self {
        DefaultResolver {
            #[cfg(target_os = "linux")]
            local: Some(LocalResolver::default()),
            http: HttpResolver::new()
                .with_url(HttpResolver::ICANHAZIP)
                .with_url(HttpResolver::IFCONFIG_ME)
                .with_url_v4(HttpResolver::IPIFY_IPV4)
                .with_url_v6(HttpResolver::IPIFY_IPV6),
        }
    }

    /// Checks only the addresses of the interface `name`, e.g. `eth0`.
    #[cfg(target_os = "linux")]
    pub fn with_interface(mut self, name: impl Into<String>) -> Self {
        self.local = Some(LocalResolver::default().interface(name));
        self
    }

    /// Skips the local check: resolves to the address the services see, e.g.
    /// behind NAT.
    #[cfg(target_os = "linux")]
    pub fn without_local(mut self) -> Self {
        self.local = None;
        self
    }

    /// Doesn't use the built-in services, only the added URLs.
    pub fn without_builtin_urls(mut self) -> Self {
        self.http.remove_urls(&BUILTIN_URLS);
        self
    }

    /// Adds a service on a host reachable over both families, as the last
    /// fallback of both; see [`HttpResolver::with_url`].
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.http = self.http.with_url(url);
        self
    }

    /// Adds an IPv4 service as the last IPv4 fallback.
    pub fn with_url_v4(mut self, url: impl Into<String>) -> Self {
        self.http = self.http.with_url_v4(url);
        self
    }

    /// Adds an IPv6 service as the last IPv6 fallback.
    pub fn with_url_v6(mut self, url: impl Into<String>) -> Self {
        self.http = self.http.with_url_v6(url);
        self
    }

    /// Resolves the public addresses of both families at once, IPv4 first.
    ///
    /// A family that fails is logged and contributes no addresses, so
    /// updating records with the result removes that family's records; use
    /// [`resolve_a`](IpResolver::resolve_a) and
    /// [`resolve_aaaa`](IpResolver::resolve_aaaa) to tell the cases apart.
    ///
    /// # Errors
    ///
    /// If both families failed, with the IPv4 error, or no address was found.
    pub async fn resolve(&self) -> Result<Vec<IpAddr>> {
        let (ipv4, ipv6) = futures_util::future::join(self.resolve_a(), self.resolve_aaaa()).await;
        combine(ipv4, ipv6)
    }
}

/// The addresses of both families; see [`DefaultResolver::resolve`].
fn combine(ipv4: Result<Vec<Ipv4Addr>>, ipv6: Result<Vec<Ipv6Addr>>) -> Result<Vec<IpAddr>> {
    let ipv4 = ipv4.map(|addrs| addrs.into_iter().map(IpAddr::from).collect::<Vec<_>>());
    let ipv6 = ipv6.map(|addrs| addrs.into_iter().map(IpAddr::from).collect::<Vec<_>>());
    let mut addrs = vec![];
    match (ipv4, ipv6) {
        (Err(err), Err(_)) => return Err(err),
        (ipv4, ipv6) => {
            for (family, result) in [("IPv4", ipv4), ("IPv6", ipv6)] {
                match result {
                    Ok(found) => addrs.extend(found),
                    Err(err) => log::warn!("resolve {family} address failed: {err:#}"),
                }
            }
        }
    }
    if addrs.is_empty() {
        bail!("no public ip address found");
    }
    Ok(addrs)
}

impl Default for DefaultResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IpResolver for DefaultResolver {
    async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
        #[cfg(target_os = "linux")]
        if let Some(local) = &self.local {
            let addrs = local.resolve_a().await?;
            return confirm(addrs, |addr| self.http.check(addr.into())).await;
        }
        self.http.resolve_a().await
    }

    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
        #[cfg(target_os = "linux")]
        if let Some(local) = &self.local {
            let addrs = local.resolve_aaaa().await?;
            return confirm(addrs, |addr| self.http.check(addr.into())).await;
        }
        self.http.resolve_aaaa().await
    }
}

/// The `addrs` that `check` confirms, checked at once, in their order. A
/// failed check skips its address, and fails only if all of them failed, with
/// the last error.
#[cfg(target_os = "linux")]
async fn confirm<T, F, Fut>(addrs: Vec<T>, check: F) -> Result<Vec<T>>
where
    T: Copy,
    F: Fn(T) -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let results = futures_util::future::join_all(addrs.iter().map(|&addr| check(addr))).await;
    let mut confirmed = vec![];
    let mut checked = false;
    let mut last_err = None;
    for (addr, result) in addrs.into_iter().zip(results) {
        match result {
            Ok(public) => {
                checked = true;
                if public {
                    confirmed.push(addr);
                }
            }
            // the last error is returned if all failed; log only the others,
            // so that each error is logged once
            Err(err) => {
                if let Some(skipped) = last_err.replace(err) {
                    log::warn!("{skipped:#}");
                }
            }
        }
    }
    match last_err {
        Some(err) if !checked => Err(err),
        Some(skipped) => {
            log::warn!("{skipped:#}");
            Ok(confirmed)
        }
        None => Ok(confirmed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_urls() {
        let resolver = DefaultResolver::new().with_url_v4("https://v4");
        let (v4, v6) = resolver.http.urls();
        assert_eq!(
            v4,
            [
                HttpResolver::ICANHAZIP,
                HttpResolver::IFCONFIG_ME,
                HttpResolver::IPIFY_IPV4,
                "https://v4"
            ]
        );
        assert_eq!(
            v6,
            [
                HttpResolver::ICANHAZIP,
                HttpResolver::IFCONFIG_ME,
                HttpResolver::IPIFY_IPV6
            ]
        );

        // whether before or after adding URLs
        for resolver in [
            DefaultResolver::new()
                .without_builtin_urls()
                .with_url("https://both"),
            DefaultResolver::new()
                .with_url("https://both")
                .without_builtin_urls(),
        ] {
            let (v4, v6) = resolver.http.urls();
            assert_eq!(v4, ["https://both"]);
            assert_eq!(v6, ["https://both"]);
        }
    }

    #[test]
    fn combine_families() {
        let v4 = || -> Result<Vec<Ipv4Addr>> { Ok(vec![Ipv4Addr::new(192, 0, 2, 1)]) };
        let v6 = || -> Result<Vec<Ipv6Addr>> { Ok(vec!["2001:db8::1".parse().unwrap()]) };
        let failed = || anyhow::anyhow!("failed");
        let addrs =
            |addrs: &[&str]| -> Vec<IpAddr> { addrs.iter().map(|a| a.parse().unwrap()).collect() };

        assert_eq!(
            combine(v4(), v6()).unwrap(),
            addrs(&["192.0.2.1", "2001:db8::1"])
        );
        // a failed family is skipped
        assert_eq!(combine(v4(), Err(failed())).unwrap(), addrs(&["192.0.2.1"]));
        assert_eq!(
            combine(Err(failed()), v6()).unwrap(),
            addrs(&["2001:db8::1"])
        );
        // both failed, or nothing found
        assert!(combine(Err(failed()), Err(failed())).is_err());
        let err = combine(Ok(vec![]), Ok(vec![])).unwrap_err();
        assert_eq!(err.to_string(), "no public ip address found");
    }

    /// Resolves to fixed addresses.
    struct Fixed(Vec<Ipv4Addr>);

    #[async_trait]
    impl IpResolver for Fixed {
        async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
            Ok(self.0.clone())
        }

        async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn default_check_resolves() {
        let resolver = Fixed(vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert!(resolver.check("192.0.2.1".parse().unwrap()).await.unwrap());
        assert!(!resolver.check("192.0.2.2".parse().unwrap()).await.unwrap());
        assert!(
            !resolver
                .check("2001:db8::1".parse().unwrap())
                .await
                .unwrap()
        );
    }

    #[cfg(target_os = "linux")]
    mod confirm {
        use anyhow::anyhow;

        use super::super::confirm;

        /// `check` for `confirm`: odd numbers are confirmed, even ones not,
        /// and those in `failing` fail.
        async fn check(addr: u8, failing: &[u8]) -> anyhow::Result<bool> {
            if failing.contains(&addr) {
                return Err(anyhow!("check {addr} failed"));
            }
            Ok(addr % 2 == 1)
        }

        #[tokio::test]
        async fn keeps_confirmed_in_order() {
            let confirmed = confirm(vec![5, 2, 1, 4, 3], |addr| check(addr, &[]))
                .await
                .unwrap();
            assert_eq!(confirmed, [5, 1, 3]);
        }

        #[tokio::test]
        async fn skips_failed_checks() {
            let confirmed = confirm(vec![1, 3, 5], |addr| check(addr, &[3]))
                .await
                .unwrap();
            assert_eq!(confirmed, [1, 5]);
        }

        #[tokio::test]
        async fn fails_if_all_checks_fail() {
            let err = confirm(vec![1, 2], |addr| check(addr, &[1, 2]))
                .await
                .unwrap_err();
            assert_eq!(err.to_string(), "check 2 failed");
        }

        #[tokio::test]
        async fn none_to_check() {
            let confirmed = confirm(vec![], |addr| check(addr, &[])).await.unwrap();
            assert!(confirmed.is_empty());
        }
    }
}
