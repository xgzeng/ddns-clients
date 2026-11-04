//! Resolution of this host's public IP addresses.
//!
//! An [`IpResolver`] finds this host's public IPv4 and IPv6 addresses:
//!
//! - [`HttpResolver`] asks an online "what is my IP" service.
//! - [`LocalResolver`] (Linux only) reads the addresses of local interfaces.
//!
//! A [`CompositeResolver`] combines several resolvers: the union of their
//! addresses, skipping failed ones ([`any`](CompositeResolver::any)), or the
//! addresses all of them found ([`all`](CompositeResolver::all)).

mod http;
#[cfg(target_os = "linux")]
mod local;

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use async_trait::async_trait;
use futures_util::future::join_all;

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
}

/// Combines the addresses of several resolvers, which are all asked at once,
/// deduplicated and in the order of the resolvers.
///
/// [`any`](Self::any) is the union, skipping failed resolvers and logging their
/// errors; [`all`](Self::all) is the intersection, and fails if any of them
/// fails. Composites nest, e.g. an `all` of the local addresses and an `any` of
/// two echo services: the local addresses that an echo service also sees.
pub struct CompositeResolver {
    /// Intersection, every resolver must succeed; otherwise union, failed ones
    /// skipped.
    all: bool,
    resolvers: Vec<Box<dyn IpResolver>>,
}

impl CompositeResolver {
    /// OR: the addresses of the resolvers that succeed; fails only if every
    /// one failed, with the last error.
    pub fn any(resolvers: Vec<Box<dyn IpResolver>>) -> Self {
        CompositeResolver {
            all: false,
            resolvers,
        }
    }

    /// AND: the addresses that every resolver found, in the order of the first;
    /// fails if any one fails.
    pub fn all(resolvers: Vec<Box<dyn IpResolver>>) -> Self {
        CompositeResolver {
            all: true,
            resolvers,
        }
    }

    /// Combines the results of `resolve` on each resolver, which resolve
    /// `family` ("IPv4" or "IPv6", for logging).
    async fn combine<'a, T, F, Fut>(&'a self, family: &str, resolve: F) -> Result<Vec<T>>
    where
        T: PartialEq,
        F: Fn(&'a dyn IpResolver) -> Fut,
        Fut: Future<Output = Result<Vec<T>>>,
    {
        let results = join_all(self.resolvers.iter().map(|resolver| resolve(&**resolver))).await;
        // `None` until a resolver succeeded
        let mut addrs: Option<Vec<T>> = None;
        let mut last_err = None;
        for result in results {
            match result {
                Ok(found) => {
                    addrs = Some(match addrs.take() {
                        Some(mut addrs) if self.all => {
                            addrs.retain(|addr| found.contains(addr));
                            addrs
                        }
                        // the union, which for `all` starts with the first
                        addrs => {
                            let mut addrs = addrs.unwrap_or_default();
                            for addr in found {
                                if !addrs.contains(&addr) {
                                    addrs.push(addr);
                                }
                            }
                            addrs
                        }
                    });
                }
                Err(err) if self.all => return Err(err),
                // the last error is returned if all failed; log only the
                // skipped ones, so that each error is logged once when nested
                Err(err) => {
                    if let Some(skipped) = last_err.replace(err) {
                        log::warn!("resolve {family} address failed: {skipped:#}");
                    }
                }
            }
        }
        match (addrs, last_err) {
            (None, Some(err)) => Err(err),
            (addrs, skipped) => {
                if let Some(skipped) = skipped {
                    log::warn!("resolve {family} address failed: {skipped:#}");
                }
                Ok(addrs.unwrap_or_default())
            }
        }
    }
}

#[async_trait]
impl IpResolver for CompositeResolver {
    async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
        self.combine("IPv4", |resolver| resolver.resolve_a()).await
    }

    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
        self.combine("IPv6", |resolver| resolver.resolve_aaaa())
            .await
    }
}

/// The default resolver: the global addresses of local interfaces that an
/// echo service also sees, <https://icanhazip.com> with
/// <https://www.ipify.org> and <https://ifconfig.me> as fallbacks; on other
/// systems, just what the echo service sees.
pub fn default_resolvers() -> CompositeResolver {
    let echo = HttpResolver::new()
        .with_url_v4(HttpResolver::ICANHAZIP_IPV4)
        .with_url_v6(HttpResolver::ICANHAZIP_IPV6)
        .with_url_v4(HttpResolver::IPIFY_IPV4)
        .with_url_v6(HttpResolver::IPIFY_IPV6)
        .with_url(HttpResolver::IFCONFIG_ME);
    CompositeResolver::all(vec![
        #[cfg(target_os = "linux")]
        Box::new(LocalResolver::default()),
        Box::new(echo),
    ])
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

    fn fixed(v4s: Option<&[&str]>, v6s: Option<&[&str]>) -> Box<dyn IpResolver> {
        Box::new(Fixed {
            v4: v4s.map(|addrs| addrs.iter().map(|s| v4(s)).collect()),
            v6: v6s.map(|addrs| addrs.iter().map(|s| v6(s)).collect()),
        })
    }

    #[test]
    fn any_merges_in_order() {
        let resolver = CompositeResolver::any(vec![
            fixed(Some(&["2.2.2.2", "1.1.1.1"]), Some(&[])),
            fixed(Some(&["1.1.1.1", "3.3.3.3"]), Some(&["2001:4860::1"])),
        ]);
        assert_eq!(
            block_on(resolver.resolve_a()).unwrap(),
            [v4("2.2.2.2"), v4("1.1.1.1"), v4("3.3.3.3")]
        );
        assert_eq!(
            block_on(resolver.resolve_aaaa()).unwrap(),
            [v6("2001:4860::1")]
        );
    }

    #[test]
    fn any_skips_failures() {
        let resolver = CompositeResolver::any(vec![
            fixed(None, Some(&[])),
            fixed(Some(&["2.2.2.2"]), None),
        ]);
        // each family separately
        assert_eq!(block_on(resolver.resolve_a()).unwrap(), [v4("2.2.2.2")]);
        assert!(block_on(resolver.resolve_aaaa()).unwrap().is_empty());
    }

    #[test]
    fn any_fails_if_all_fail() {
        let resolver = CompositeResolver::any(vec![fixed(None, None), fixed(None, None)]);
        assert!(block_on(resolver.resolve_a()).is_err());
        assert!(block_on(resolver.resolve_aaaa()).is_err());
    }

    #[test]
    fn all_intersects_in_order() {
        let resolver = CompositeResolver::all(vec![
            fixed(Some(&["1.1.1.1", "2.2.2.2", "1.1.1.1"]), Some(&[])),
            fixed(
                Some(&["3.3.3.3", "2.2.2.2", "1.1.1.1"]),
                Some(&["2001:4860::1"]),
            ),
        ]);
        assert_eq!(
            block_on(resolver.resolve_a()).unwrap(),
            [v4("1.1.1.1"), v4("2.2.2.2")]
        );
        assert!(block_on(resolver.resolve_aaaa()).unwrap().is_empty());
    }

    #[test]
    fn all_of_disjoint_is_empty() {
        let resolver = CompositeResolver::all(vec![
            fixed(Some(&["1.1.1.1"]), Some(&["2001:4860::1"])),
            fixed(Some(&["2.2.2.2"]), Some(&["2001:4860::2"])),
        ]);
        assert!(block_on(resolver.resolve_a()).unwrap().is_empty());
        assert!(block_on(resolver.resolve_aaaa()).unwrap().is_empty());
    }

    #[test]
    fn all_fails_if_one_fails() {
        let resolver = CompositeResolver::all(vec![
            fixed(Some(&["1.1.1.1"]), Some(&[])),
            fixed(None, Some(&[])),
        ]);
        assert!(block_on(resolver.resolve_a()).is_err());
        assert!(block_on(resolver.resolve_aaaa()).is_ok());
    }

    #[test]
    fn nested() {
        // local AND (echo OR echo), as the default: the local addresses the
        // working echo service sees
        let resolver = CompositeResolver::all(vec![
            fixed(Some(&["1.1.1.1"]), Some(&["2001:4860::1", "2001:4860::2"])),
            Box::new(CompositeResolver::any(vec![
                fixed(None, None),
                fixed(Some(&["1.1.1.1"]), Some(&["2001:4860::2"])),
            ])),
        ]);
        assert_eq!(block_on(resolver.resolve_a()).unwrap(), [v4("1.1.1.1")]);
        assert_eq!(
            block_on(resolver.resolve_aaaa()).unwrap(),
            [v6("2001:4860::2")]
        );
    }
}
