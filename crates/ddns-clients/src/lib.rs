//! A multi-provider dynamic DNS client library.
//!
//! - An [`IpResolver`] finds this host's public IP addresses, e.g.
//!   [`DefaultResolver`](resolve::DefaultResolver); see [`resolve`].
//! - A [`DynDnsProvider`] changes a domain's address records on a DNS
//!   service, e.g. [`CloudflareProvider`] or [`NoIpProvider`]; see
//!   [`providers`].
//!
//! The `pkarr` feature (on by default) adds the PKARR provider.
//! - A [`DynDnsClient`] wraps a provider, chosen by name, for one domain.
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! use ddns_clients::{DynDnsClient, providers, resolve::DefaultResolver};
//!
//! let mut client = DynDnsClient::provider(providers::CLOUDFLARE)?
//!     .api_token("api-token")
//!     .zone("example.com")
//!     .domain("myhost.example.com")
//!     .ttl(Some(300))
//!     .build()?;
//! let ips = DefaultResolver::new().resolve().await?;
//!
//! // replace the domain's A/AAAA records with the resolved addresses
//! let summary = client.update(ips).await?;
//! println!("{summary:?}");
//! # Ok(())
//! # }
//! ```

mod client;
pub mod providers;
pub mod resolve;

pub use client::{DynDnsClient, DynDnsClientBuilder, UpdateSummary};
pub use providers::DynDnsProvider;
pub use providers::cloudflare::CloudflareProvider;
pub use providers::noip::NoIpProvider;
#[cfg(feature = "pkarr")]
pub use providers::pkarr::PkarrProvider;
pub use resolve::IpResolver;
