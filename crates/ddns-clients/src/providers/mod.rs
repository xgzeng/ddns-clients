//! DNS providers that manage a domain's address records.
//!
//! A [`DynDnsProvider`] offers the primitive operations on the A/AAAA records
//! of a domain on one DNS service:
//!
//! - [`CloudflareProvider`](cloudflare::CloudflareProvider).
//! - [`NoIpProvider`](noip::NoIpProvider).
//!
//! Records are identified by their address; provider-internal record ids
//! never leave the implementation. Deciding which operations to run is up to
//! [`DynDnsClient`](crate::DynDnsClient).

pub mod cloudflare;
pub mod noip;

/// Name of the Cloudflare provider for [`DynDnsClient::provider`](crate::DynDnsClient::provider).
pub const CLOUDFLARE: &str = "cloudflare";
/// Name of the No-IP provider for [`DynDnsClient::provider`](crate::DynDnsClient::provider).
pub const NOIP: &str = "noip";

use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use anyhow::Result;
use async_trait::async_trait;

/// A wait of about 100 years. [`Instant`] has no infinite value, so
/// [`next_allowed_update`](DynDnsProvider::next_allowed_update) returns the
/// current time plus this when no further update should be sent, e.g. until
/// bad credentials are fixed.
pub const NEVER: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

/// The address records of one domain on a DNS service.
///
/// A provider is created for a single domain. Records are identified by
/// address; the domain may have several records with the same address, and
/// each operation acts on one of them.
///
/// Implementations may cache records between calls, so [`list`](Self::list)
/// may answer from the cache and [`refresh`](Self::refresh) reads them again.
/// The cache must follow the provider's own operations, and be dropped when
/// an operation fails.
///
/// Operations fail if the service cannot perform them, and
/// [`replace`](Self::replace) and [`delete`](Self::delete) fail if there is no
/// record with the address.
#[async_trait]
pub trait DynDnsProvider: Send {
    /// The domain whose records this provider manages.
    fn domain(&self) -> &str;

    /// When the next update may be sent, e.g. after the service asked clients
    /// to back off; `None` means there is no restriction. The time may be in
    /// the past, or [`NEVER`] away if no further update should be sent. Callers
    /// should wait until then; it isn't enforced.
    fn next_allowed_update(&self) -> Option<Instant> {
        None
    }

    /// Addresses of all A and AAAA records, one per record; possibly cached.
    async fn list(&mut self) -> Result<Vec<IpAddr>>;

    /// Drops cached records and reads them again from the service. The
    /// default does nothing, for providers that don't cache.
    async fn refresh(&mut self) -> Result<()> {
        Ok(())
    }

    /// Creates a record for `ip`; `ttl` of `None` uses the provider's
    /// default.
    async fn add(&mut self, ip: IpAddr, ttl: Option<u32>) -> Result<()>;

    /// Re-points a record from `old` to `new`, possibly changing its type
    /// (A ↔ AAAA), and keeping its other provider-side settings.
    async fn replace(&mut self, old: IpAddr, new: IpAddr, ttl: Option<u32>) -> Result<()>;

    /// Deletes a record with `ip`.
    async fn delete(&mut self, ip: IpAddr) -> Result<()>;
}
