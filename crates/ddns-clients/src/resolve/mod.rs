//! Resolution of this host's public IP addresses.
//!
//! An [`IpResolver`] finds the public addresses of one [`IpFamily`]:
//!
//! - [`HttpResolver`] asks an online "what is my IP" service.
//! - [`LocalResolver`] (Linux only) reads the addresses of local interfaces.
//!
//! A `Vec` of resolvers is itself a resolver that tries each one in order;
//! use [`AnyResolver`] to mix kinds. [`resolve_public_ips`] resolves several
//! families at once.

mod http;
#[cfg(target_os = "linux")]
mod local;

use std::net::IpAddr;

use async_trait::async_trait;

use crate::Result;

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
#[async_trait]
pub trait IpResolver: Send + Sync {
    /// Resolves the public addresses of `family`.
    ///
    /// An empty list means this resolver found none (or does not support
    /// `family`); fallbacks then try the next resolver.
    async fn resolve(&self, family: IpFamily) -> Result<Vec<IpAddr>>;
}

/// Tries each resolver in order and returns the first non-empty result.
///
/// Failures are logged and skipped; only if every resolver fails is the last
/// error returned.
#[async_trait]
impl<R: IpResolver> IpResolver for Vec<R> {
    async fn resolve(&self, family: IpFamily) -> Result<Vec<IpAddr>> {
        let mut last_err = None;
        for resolver in self {
            match resolver.resolve(family).await {
                Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
                Ok(_) => last_err = None,
                Err(err) => {
                    log::warn!("resolve {family:?} address failed: {}", err.chain());
                    last_err = Some(err);
                }
            }
        }
        match last_err {
            Some(err) => Err(err),
            None => Ok(vec![]),
        }
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
    async fn resolve(&self, family: IpFamily) -> Result<Vec<IpAddr>> {
        match self {
            AnyResolver::Http(resolver) => resolver.resolve(family).await,
            #[cfg(target_os = "linux")]
            AnyResolver::Local(resolver) => resolver.resolve(family).await,
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

/// Resolves the public addresses of each of `families` with `resolver`.
///
/// Families are resolved independently, so one failing does not affect the
/// others. Failures are logged; an empty list means nothing was found.
pub async fn resolve_public_ips<R: IpResolver>(resolver: &R, families: &[IpFamily]) -> Vec<IpAddr> {
    let mut addrs = vec![];
    for &family in families {
        match resolver.resolve(family).await {
            Ok(found) => addrs.extend(found),
            Err(err) => log::warn!("no {family:?} address resolved: {}", err.chain()),
        }
    }
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    /// Returns fixed results: `None` fails, `Some` returns the addresses.
    struct Fixed {
        v4: Option<Vec<IpAddr>>,
        v6: Option<Vec<IpAddr>>,
    }

    #[async_trait]
    impl IpResolver for Fixed {
        async fn resolve(&self, family: IpFamily) -> Result<Vec<IpAddr>> {
            let addrs = match family {
                IpFamily::V4 => &self.v4,
                IpFamily::V6 => &self.v6,
            };
            addrs
                .clone()
                .ok_or_else(|| Error::provider("fixed failure"))
        }
    }

    fn ip(s: &str) -> IpAddr {
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
                v4: Some(vec![ip("1.1.1.1")]),
                v6: None,
            },
            Fixed {
                v4: Some(vec![ip("2.2.2.2")]),
                v6: Some(vec![ip("2001:4860::1")]),
            },
        ];
        let addrs = block_on(resolve_public_ips(
            &resolvers,
            &[IpFamily::V4, IpFamily::V6],
        ));
        assert_eq!(addrs, vec![ip("1.1.1.1"), ip("2001:4860::1")]);
    }

    #[test]
    fn fallback_skips_empty() {
        let resolvers = vec![
            Fixed {
                v4: Some(vec![]),
                v6: Some(vec![]),
            },
            Fixed {
                v4: Some(vec![ip("2.2.2.2")]),
                v6: Some(vec![]),
            },
        ];
        assert_eq!(
            block_on(resolvers.resolve(IpFamily::V4)).unwrap(),
            vec![ip("2.2.2.2")]
        );
        assert!(
            block_on(resolvers.resolve(IpFamily::V6))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn fallback_all_failed() {
        let resolvers = vec![Fixed { v4: None, v6: None }];
        assert!(block_on(resolvers.resolve(IpFamily::V4)).is_err());
        assert!(block_on(resolve_public_ips(&resolvers, &[IpFamily::V4])).is_empty());
    }
}
