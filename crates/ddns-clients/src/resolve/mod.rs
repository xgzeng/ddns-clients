//! Resolution of this host's public IP addresses.
//!
//! An [`IpResolver`] finds this host's public IPv4 and IPv6 addresses:
//!
//! - [`HttpResolver`] asks an online "what is my IP" service.
//! - [`LocalResolver`] (Linux only) reads the addresses of local interfaces.
//!
//! A [`CompositeResolver`] merges the addresses of several resolvers, skipping
//! failed ones ([`any`](CompositeResolver::any)) or requiring all to succeed
//! ([`all`](CompositeResolver::all)).

mod http;
#[cfg(target_os = "linux")]
mod local;

use std::{
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::Result;
use async_trait::async_trait;
use futures_util::future::join_all;

pub use http::HttpResolver;
#[cfg(target_os = "linux")]
pub use local::LocalResolver;

/// A source of this host's public IP addresses.
///
/// An empty list means the resolver found none of that family, or doesn't
/// support it.
#[async_trait]
pub trait IpResolver: Debug + Send + Sync {
    /// Resolves the public IPv4 addresses, for A records.
    async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>>;

    /// Resolves the public IPv6 addresses, for AAAA records.
    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>>;
}

/// Merges the addresses of several resolvers, deduplicated and in the order of
/// the resolvers, which are all asked at once.
///
/// [`any`](Self::any) skips failed resolvers, logging their errors;
/// [`all`](Self::all) fails if any of them fails. Composites nest, e.g. an
/// `all` of the local addresses and an `any` of two echo services.
#[derive(Debug)]
pub struct CompositeResolver {
    /// Whether every resolver must succeed; otherwise failed ones are skipped.
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

    /// AND: the addresses of all the resolvers; fails if any one fails.
    pub fn all(resolvers: Vec<Box<dyn IpResolver>>) -> Self {
        CompositeResolver {
            all: true,
            resolvers,
        }
    }

    /// Merges the results of `resolve` on each resolver, which resolve
    /// `family` ("IPv4" or "IPv6", for logging).
    async fn merge<'a, T, F, Fut>(&'a self, family: &str, resolve: F) -> Result<Vec<T>>
    where
        T: PartialEq,
        F: Fn(&'a dyn IpResolver) -> Fut,
        Fut: Future<Output = Result<Vec<T>>>,
    {
        let results = join_all(self.resolvers.iter().map(|resolver| resolve(&**resolver))).await;
        let mut addrs = vec![];
        let mut succeeded = false;
        let mut last_err = None;
        for result in results {
            match result {
                Ok(found) => {
                    succeeded = true;
                    for addr in found {
                        if !addrs.contains(&addr) {
                            addrs.push(addr);
                        }
                    }
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
        match last_err {
            Some(err) if !succeeded => Err(err),
            Some(skipped) => {
                log::warn!("resolve {family} address failed: {skipped:#}");
                Ok(addrs)
            }
            None => Ok(addrs),
        }
    }
}

#[async_trait]
impl IpResolver for CompositeResolver {
    async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
        self.merge("IPv4", |resolver| resolver.resolve_a()).await
    }

    async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
        self.merge("IPv6", |resolver| resolver.resolve_aaaa()).await
    }
}

/// The default resolver: the global addresses of local interfaces (Linux
/// only), and those <https://icanhazip.com> and <https://www.ipify.org> see.
pub fn default_resolvers() -> CompositeResolver {
    CompositeResolver::all(vec![
        #[cfg(target_os = "linux")]
        Box::new(LocalResolver::default()),
        Box::new(CompositeResolver::any(vec![
            Box::new(HttpResolver::icanhazip()),
            Box::new(HttpResolver::ipify()),
        ])),
    ])
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::*;

    /// Returns fixed results: `None` fails, `Some` returns the addresses.
    #[derive(Debug)]
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
    fn all_merges() {
        let resolver = CompositeResolver::all(vec![
            fixed(Some(&["1.1.1.1"]), Some(&[])),
            fixed(Some(&["2.2.2.2"]), Some(&[])),
        ]);
        assert_eq!(
            block_on(resolver.resolve_a()).unwrap(),
            [v4("1.1.1.1"), v4("2.2.2.2")]
        );
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
        // local AND (echo OR echo), as the default
        let resolver = CompositeResolver::all(vec![
            fixed(Some(&[]), Some(&["2001:4860::1"])),
            Box::new(CompositeResolver::any(vec![
                fixed(None, None),
                fixed(Some(&["1.1.1.1"]), Some(&["2001:4860::2"])),
            ])),
        ]);
        assert_eq!(block_on(resolver.resolve_a()).unwrap(), [v4("1.1.1.1")]);
        assert_eq!(
            block_on(resolver.resolve_aaaa()).unwrap(),
            [v6("2001:4860::1"), v6("2001:4860::2")]
        );
    }
}
