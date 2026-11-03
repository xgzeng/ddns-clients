//! Resolution of this host's public IP addresses.
//!
//! An [`IpResolver`] finds this host's public IPv4 and IPv6 addresses:
//!
//! - [`HttpResolver`] asks an online "what is my IP" service.
//! - [`LocalResolver`] (Linux only) reads the addresses of local interfaces.
//!
//! A `Vec` of resolvers is itself a resolver that tries each one in order;
//! use [`AnyResolver`] to mix kinds.

mod http;
#[cfg(target_os = "linux")]
mod local;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use async_trait::async_trait;

pub use http::HttpResolver;
#[cfg(target_os = "linux")]
pub use local::LocalResolver;

/// An IP address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamily {
    /// IPv4 (A records).
    V4,
    /// IPv6 (AAAA records).
    V6,
}

impl IpFamily {
    /// The family of `ip`.
    pub fn of(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => IpFamily::V4,
            IpAddr::V6(_) => IpFamily::V6,
        }
    }
}

/// A source of this host's public IP addresses.
///
/// An empty list means the resolver found none of that family, or doesn't
/// support it; fallbacks then try the next resolver.
#[async_trait]
pub trait IpResolver: Send + Sync {
    /// Resolves the public IPv4 addresses, for A records.
    async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>>;

    /// Resolves the public IPv6 addresses, for AAAA records.
    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>>;
}

/// Tries each resolver in order and returns the first non-empty result.
///
/// Failures are logged and skipped; only if every resolver fails is the last
/// error returned.
#[async_trait]
impl<R: IpResolver> IpResolver for Vec<R> {
    async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
        first_found(self, IpFamily::V4, |resolver| resolver.resolve_a()).await
    }

    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
        first_found(self, IpFamily::V6, |resolver| resolver.resolve_aaaa()).await
    }
}

/// The first non-empty result of `resolve` on each of `resolvers`, which
/// resolve `family`; see the `Vec` impl of [`IpResolver`].
async fn first_found<'a, R, T, F, Fut>(
    resolvers: &'a [R],
    family: IpFamily,
    resolve: F,
) -> Result<Vec<T>>
where
    F: Fn(&'a R) -> Fut,
    Fut: Future<Output = Result<Vec<T>>>,
{
    let mut last_err = None;
    for resolver in resolvers {
        match resolve(resolver).await {
            Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
            Ok(_) => last_err = None,
            Err(err) => {
                log::warn!("resolve {family:?} address failed: {err:#}");
                last_err = Some(err);
            }
        }
    }
    match last_err {
        Some(err) => Err(err),
        None => Ok(vec![]),
    }
}

/// Any of the built-in resolvers, for building mixed fallback lists.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AnyResolver {
    /// See [`HttpResolver`].
    Http(HttpResolver),
    /// See [`LocalResolver`].
    #[cfg(target_os = "linux")]
    Local(LocalResolver),
}

#[async_trait]
impl IpResolver for AnyResolver {
    async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
        match self {
            AnyResolver::Http(resolver) => resolver.resolve_a().await,
            #[cfg(target_os = "linux")]
            AnyResolver::Local(resolver) => resolver.resolve_a().await,
        }
    }

    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
        match self {
            AnyResolver::Http(resolver) => resolver.resolve_aaaa().await,
            #[cfg(target_os = "linux")]
            AnyResolver::Local(resolver) => resolver.resolve_aaaa().await,
        }
    }
}

impl From<HttpResolver> for AnyResolver {
    fn from(resolver: HttpResolver) -> Self {
        AnyResolver::Http(resolver)
    }
}

#[cfg(target_os = "linux")]
impl From<LocalResolver> for AnyResolver {
    fn from(resolver: LocalResolver) -> Self {
        AnyResolver::Local(resolver)
    }
}

/// The default fallback list: <https://icanhazip.com>, then local interfaces
/// (Linux only).
pub fn default_resolvers() -> Vec<AnyResolver> {
    vec![
        HttpResolver::icanhazip().into(),
        #[cfg(target_os = "linux")]
        LocalResolver.into(),
    ]
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::*;

    /// Returns fixed results: `None` fails, `Some` returns the addresses.
    struct Fixed {
        v4: Option<Vec<Ipv4Addr>>,
        v6: Option<Vec<Ipv6Addr>>,
    }

    #[async_trait]
    impl IpResolver for Fixed {
        async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
            self.v4.clone().ok_or_else(|| anyhow!("fixed failure"))
        }

        async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
            self.v6.clone().ok_or_else(|| anyhow!("fixed failure"))
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn family_of() {
        assert_eq!(IpFamily::of(&ip("1.1.1.1")), IpFamily::V4);
        assert_eq!(IpFamily::of(&ip("::1")), IpFamily::V6);
    }

    #[test]
    fn fallback_per_family() {
        let resolvers = vec![
            // v4 works, v6 fails
            Fixed {
                v4: Some(vec![v4("1.1.1.1")]),
                v6: None,
            },
            Fixed {
                v4: Some(vec![v4("2.2.2.2")]),
                v6: Some(vec![v6("2001:4860::1")]),
            },
        ];
        // each family falls back separately
        assert_eq!(block_on(resolvers.resolve_a()).unwrap(), [v4("1.1.1.1")]);
        assert_eq!(
            block_on(resolvers.resolve_aaaa()).unwrap(),
            [v6("2001:4860::1")]
        );
    }

    #[test]
    fn fallback_skips_empty() {
        let resolvers = vec![
            Fixed {
                v4: Some(vec![]),
                v6: Some(vec![]),
            },
            Fixed {
                v4: Some(vec![v4("2.2.2.2")]),
                v6: Some(vec![]),
            },
        ];
        assert_eq!(
            block_on(resolvers.resolve_a()).unwrap(),
            vec![v4("2.2.2.2")]
        );
        assert!(block_on(resolvers.resolve_aaaa()).unwrap().is_empty());
    }

    #[test]
    fn fallback_all_failed() {
        let resolvers = vec![Fixed { v4: None, v6: None }];
        assert!(block_on(resolvers.resolve_a()).is_err());
        assert!(block_on(resolvers.resolve_aaaa()).is_err());
    }
}
