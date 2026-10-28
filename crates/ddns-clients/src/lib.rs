//! A multi-provider dynamic DNS client library.
//!
//! - An [`IpResolver`] finds this host's public IP addresses, e.g.
//!   [`HttpResolver`](resolve::HttpResolver); see [`resolve`].
//! - A [`DynDnsProvider`] changes a domain's address records on a DNS
//!   service, e.g. [`CloudflareProvider`] or [`NoIpProvider`]; see
//!   [`providers`].
//!
//! ```no_run
//! # #[cfg(feature = "cloudflare")]
//! # async fn example() -> ddns_clients::Result<()> {
//! use ddns_clients::{CloudflareProvider, DynDnsProvider, resolve};
//!
//! let mut provider = CloudflareProvider::new("api-token", "example.com")?;
//! let resolvers = resolve::default_resolvers();
//! let ips = resolve::resolve_public_ips(&resolvers, &[resolve::IpFamily::V4]).await;
//!
//! // replace the domain's A records with the resolved addresses
//! let current = provider.list("myhost.example.com").await?;
//! let summary = provider
//!     .update("myhost.example.com")
//!     .remove_all(current.into_iter().filter(|ip| ip.is_ipv4()))
//!     .add_all(ips)
//!     .ttl(Some(300))
//!     .send()
//!     .await?;
//! println!("{summary:?}");
//! # Ok(())
//! # }
//! ```

mod error;
pub mod providers;
pub mod resolve;

pub use error::{Error, Result};
#[cfg(feature = "cloudflare")]
pub use providers::cloudflare::CloudflareProvider;
#[cfg(feature = "noip")]
pub use providers::noip::NoIpProvider;
pub use providers::{DynDnsProvider, RecordUpdate, UpdateBuilder, UpdateSummary};
pub use resolve::IpResolver;
