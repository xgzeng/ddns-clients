//! DNS providers that manage a domain's address records.
//!
//! A [`DynDnsProvider`] changes the A/AAAA records of a domain on one DNS
//! service:
//!
//! - [`CloudflareProvider`](cloudflare::CloudflareProvider).
//! - [`NoIpProvider`](noip::NoIpProvider).
//!
//! Records are identified by their address; provider-internal record ids
//! never leave the implementation.

pub mod cloudflare;
pub mod noip;

/// Name of the Cloudflare provider for [`DynDnsClient::provider`](crate::DynDnsClient::provider).
pub const CLOUDFLARE: &str = "cloudflare";
/// Name of the No-IP provider for [`DynDnsClient::provider`](crate::DynDnsClient::provider).
pub const NOIP: &str = "noip";

use std::net::IpAddr;

use async_trait::async_trait;

use crate::Result;

/// A DNS service that can manage the address records of a domain.
#[async_trait]
pub trait DynDnsProvider: Send {
    /// Addresses of all A and AAAA records of `domain`.
    async fn list(&mut self, domain: &str) -> Result<Vec<IpAddr>>;

    /// Starts a batched change of `domain`'s address records.
    ///
    /// Implementations return `UpdateBuilder::new(self, domain)`.
    fn update<'a>(&'a mut self, domain: &str) -> UpdateBuilder<'a>;

    /// Performs `update`; called by [`UpdateBuilder::send`].
    ///
    /// Implementations must follow the semantics documented on
    /// [`RecordUpdate`]; [`plan_changes`] computes the required operations.
    async fn apply_update(&mut self, update: RecordUpdate) -> Result<UpdateSummary>;
}

/// A batched change of one domain's address records.
///
/// Afterwards the domain has exactly the addresses
/// `add ∪ (existing − remove)`, or just `add` if `clear` is set. Removing an
/// absent address and adding a present one are no-ops.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordUpdate {
    /// The domain whose records change.
    pub domain: String,
    /// Addresses that must exist afterwards.
    pub add: Vec<IpAddr>,
    /// Addresses that must not exist afterwards, unless also in `add`.
    pub remove: Vec<IpAddr>,
    /// Remove every existing address not in `add`.
    pub clear: bool,
    /// TTL of created and changed records; `None` uses the provider's default.
    pub ttl: Option<u32>,
}

impl RecordUpdate {
    /// Returns `true` if this update can never change anything.
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty() && !self.clear
    }
}

/// Builds and sends a [`RecordUpdate`]; see [`DynDnsProvider::update`].
///
/// ```no_run
/// # async fn example(provider: &mut dyn ddns_clients::DynDnsProvider) -> ddns_clients::Result<()> {
/// let old = "192.0.2.1".parse().unwrap();
/// let new = "192.0.2.2".parse().unwrap();
/// provider.update("myhost.example.com").remove(old).add(new).send().await?;
/// provider.update("myhost.example.com").clear().send().await?;
/// # Ok(())
/// # }
/// ```
#[must_use = "an update does nothing until `send` is awaited"]
pub struct UpdateBuilder<'a> {
    provider: &'a mut dyn DynDnsProvider,
    update: RecordUpdate,
}

impl<'a> UpdateBuilder<'a> {
    /// Starts an empty update of `domain` on `provider`.
    pub fn new(provider: &'a mut dyn DynDnsProvider, domain: &str) -> Self {
        UpdateBuilder {
            provider,
            update: RecordUpdate {
                domain: domain.to_string(),
                ..Default::default()
            },
        }
    }

    /// Ensures a record with `ip` exists.
    #[allow(clippy::should_implement_trait)] // a builder step, not arithmetic
    pub fn add(mut self, ip: IpAddr) -> Self {
        self.update.add.push(ip);
        self
    }

    /// Ensures records with each of `ips` exist.
    pub fn add_all(mut self, ips: impl IntoIterator<Item = IpAddr>) -> Self {
        self.update.add.extend(ips);
        self
    }

    /// Removes the record with `ip`, if any.
    pub fn remove(mut self, ip: IpAddr) -> Self {
        self.update.remove.push(ip);
        self
    }

    /// Removes the records with each of `ips`, if any.
    pub fn remove_all(mut self, ips: impl IntoIterator<Item = IpAddr>) -> Self {
        self.update.remove.extend(ips);
        self
    }

    /// Removes all existing records not added by this update.
    pub fn clear(mut self) -> Self {
        self.update.clear = true;
        self
    }

    /// Sets the TTL of created and changed records; `None` uses the
    /// provider's default.
    pub fn ttl(mut self, ttl: Option<u32>) -> Self {
        self.update.ttl = ttl;
        self
    }

    /// Applies the update.
    pub async fn send(self) -> Result<UpdateSummary> {
        if self.update.is_empty() {
            return Ok(UpdateSummary::default());
        }
        self.provider.apply_update(self.update).await
    }
}

/// What an update changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpdateSummary {
    /// Records that already matched and were left alone.
    pub kept: usize,
    /// Records re-pointed at a new address.
    pub updated: usize,
    /// Records removed.
    pub deleted: usize,
    /// Records newly created.
    pub created: usize,
}

impl UpdateSummary {
    /// Returns `true` if no record was changed.
    pub fn is_unchanged(&self) -> bool {
        self.updated == 0 && self.deleted == 0 && self.created == 0
    }
}

/// The record operations that carry out a [`RecordUpdate`]; see
/// [`plan_changes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePlan<Id> {
    /// Number of records left alone.
    pub keep: usize,
    /// Records to re-point at a new address (possibly changing A ↔ AAAA).
    pub repoint: Vec<(Id, IpAddr)>,
    /// Records to delete.
    pub delete: Vec<Id>,
    /// Addresses to create records for.
    pub create: Vec<IpAddr>,
}

impl<Id> ChangePlan<Id> {
    /// The summary of carrying out this plan.
    pub fn summary(&self) -> UpdateSummary {
        UpdateSummary {
            kept: self.keep,
            updated: self.repoint.len(),
            deleted: self.delete.len(),
            created: self.create.len(),
        }
    }
}

/// Computes the operations that turn the `existing` records (provider id and
/// address) into the state described by `update`.
///
/// Records that are no longer wanted are re-pointed at missing addresses
/// where possible (same family first), which keeps provider-side record
/// settings; the rest are deleted, and the remaining addresses are created.
/// Duplicate records of a wanted address are treated as unwanted.
pub fn plan_changes<Id: Clone>(existing: &[(Id, IpAddr)], update: &RecordUpdate) -> ChangePlan<Id> {
    let mut desired: Vec<IpAddr> = vec![];
    for ip in &update.add {
        if !desired.contains(ip) {
            desired.push(*ip);
        }
    }
    if !update.clear {
        for (_, ip) in existing {
            if !update.remove.contains(ip) && !desired.contains(ip) {
                desired.push(*ip);
            }
        }
    }

    let mut missing = desired;
    let mut keep = 0;
    let mut dropped = vec![];
    for (id, ip) in existing {
        if let Some(pos) = missing.iter().position(|d| d == ip) {
            missing.remove(pos);
            keep += 1;
        } else {
            dropped.push((id.clone(), *ip));
        }
    }

    let mut repoint = vec![];
    let mut unpaired = vec![];
    for (id, ip) in dropped {
        match missing.iter().position(|m| m.is_ipv4() == ip.is_ipv4()) {
            Some(pos) => repoint.push((id, missing.remove(pos))),
            None => unpaired.push(id),
        }
    }

    let mut delete = vec![];
    for id in unpaired {
        if missing.is_empty() {
            delete.push(id);
        } else {
            repoint.push((id, missing.remove(0)));
        }
    }

    ChangePlan {
        keep,
        repoint,
        delete,
        create: missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn update(add: &[&str], remove: &[&str], clear: bool) -> RecordUpdate {
        RecordUpdate {
            domain: "h.example.com".into(),
            add: add.iter().map(|s| ip(s)).collect(),
            remove: remove.iter().map(|s| ip(s)).collect(),
            clear,
            ttl: None,
        }
    }

    fn existing(records: &[(&'static str, &str)]) -> Vec<(&'static str, IpAddr)> {
        records.iter().map(|(id, s)| (*id, ip(s))).collect()
    }

    #[test]
    fn empty() {
        let plan = plan_changes(&existing(&[("a", "1.1.1.1")]), &update(&[], &[], false));
        assert_eq!(
            plan.summary(),
            UpdateSummary {
                kept: 1,
                ..Default::default()
            }
        );
        assert!(update(&[], &[], false).is_empty());
    }

    #[test]
    fn add_present_and_remove_absent_are_noops() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1")]),
            &update(&["1.1.1.1"], &["9.9.9.9"], false),
        );
        assert!(plan.summary().is_unchanged());
        assert_eq!(plan.keep, 1);
    }

    #[test]
    fn creates_missing() {
        let plan = plan_changes::<&str>(&[], &update(&["1.1.1.1", "2001:db8::1"], &[], false));
        assert_eq!(plan.create, vec![ip("1.1.1.1"), ip("2001:db8::1")]);
    }

    #[test]
    fn repoints_same_family_first() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1"), ("b", "2001:db8::1")]),
            &update(
                &["2001:db8::2", "2.2.2.2"],
                &["1.1.1.1", "2001:db8::1"],
                false,
            ),
        );
        assert_eq!(
            plan.repoint,
            vec![("a", ip("2.2.2.2")), ("b", ip("2001:db8::2"))]
        );
        assert!(plan.delete.is_empty() && plan.create.is_empty());
    }

    #[test]
    fn repoints_across_families() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1")]),
            &update(&["2001:db8::1"], &["1.1.1.1"], false),
        );
        assert_eq!(plan.repoint, vec![("a", ip("2001:db8::1"))]);
    }

    #[test]
    fn deletes_and_creates_leftovers() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1"), ("b", "2.2.2.2")]),
            &update(&["3.3.3.3"], &["1.1.1.1", "2.2.2.2"], false),
        );
        assert_eq!(plan.repoint, vec![("a", ip("3.3.3.3"))]);
        assert_eq!(plan.delete, vec!["b"]);

        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1")]),
            &update(&["2.2.2.2", "3.3.3.3"], &["1.1.1.1"], false),
        );
        assert_eq!(plan.repoint, vec![("a", ip("2.2.2.2"))]);
        assert_eq!(plan.create, vec![ip("3.3.3.3")]);
    }

    #[test]
    fn clear() {
        let records = existing(&[("a", "1.1.1.1"), ("b", "2.2.2.2")]);
        let plan = plan_changes(&records, &update(&[], &[], true));
        assert_eq!(plan.delete, vec!["a", "b"]);

        let plan = plan_changes(&records, &update(&["2.2.2.2"], &[], true));
        assert_eq!(plan.keep, 1);
        assert_eq!(plan.delete, vec!["a"]);
    }

    #[test]
    fn add_wins_over_remove() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1")]),
            &update(&["1.1.1.1"], &["1.1.1.1"], false),
        );
        assert_eq!(plan.keep, 1);
        assert!(plan.summary().is_unchanged());
    }

    #[test]
    fn duplicates() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1"), ("b", "1.1.1.1")]),
            &update(&["1.1.1.1", "1.1.1.1"], &[], false),
        );
        assert_eq!(plan.keep, 1);
        assert_eq!(plan.delete, vec!["b"]);
    }
}
