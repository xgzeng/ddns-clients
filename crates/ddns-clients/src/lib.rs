//! A multi-provider dynamic DNS client library.
//!
//! - An [`IpResolver`] finds this host's public IP addresses, e.g.
//!   [`HttpResolver`](resolve::HttpResolver); see [`resolve`].
//! - A [`DynDnsProvider`] changes a domain's address records on a DNS
//!   service, e.g. [`CloudflareProvider`] or [`NoIpProvider`]; see
//!   [`providers`].
//! - A [`DynDnsClient`] wraps a provider, chosen by name, for one domain.
//!
//! ```no_run
//! # async fn example() -> ddns_clients::Result<()> {
//! use ddns_clients::{DynDnsClient, providers, resolve};
//!
//! let mut client = DynDnsClient::provider(providers::CLOUDFLARE)?
//!     .api_token("api-token")
//!     .zone("example.com")
//!     .domain("myhost.example.com")
//!     .ttl(Some(300))
//!     .build()?;
//! let resolvers = resolve::default_resolvers();
//! let ips = resolve::resolve_public_ips(&resolvers, &[resolve::IpFamily::V4]).await;
//!
//! // replace the domain's A records with the resolved addresses
//! let current = client.list().await?;
//! let summary = client
//!     .update()
//!     .remove_all(current.into_iter().filter(|ip| ip.is_ipv4()))
//!     .add_all(ips)
//!     .send()
//!     .await?;
//! println!("{summary:?}");
//! # Ok(())
//! # }
//! ```

mod client;
mod error;
pub mod providers;
pub mod resolve;

pub use client::{DynDnsClient, DynDnsClientBuilder};
pub use error::{Error, Result};
pub use providers::cloudflare::CloudflareProvider;
pub use providers::noip::NoIpProvider;
pub use providers::{DynDnsProvider, RecordUpdate, UpdateBuilder, UpdateSummary};
pub use resolve::IpResolver;
