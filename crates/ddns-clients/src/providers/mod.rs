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
    /// Implementations return `UpdateRequestBuilder::new(self, domain)`.
    fn update_request<'a>(&'a mut self, domain: &str) -> UpdateRequestBuilder<'a>;

    /// Carries out `request`; called by [`UpdateRequestBuilder::send`].
    ///
    /// Implementations must follow the semantics documented on
    /// [`RecordUpdateRequest`]; [`plan_changes`] computes the required operations.
    async fn execute_request(&mut self, request: RecordUpdateRequest) -> Result<UpdateSummary>;
}

/// A batched change of one domain's address records.
///
/// Afterwards the domain has exactly the addresses `add ∪ (existing − remove)`.
/// Removing an absent address and adding a present one are no-ops.
///
/// With `replace_only`, the number of records never changes: existing records
/// are only re-pointed. Records with nothing to re-point to are kept, and
/// addresses without a record to re-point are not created.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordUpdateRequest {
    /// The domain whose records change.
    pub domain: String,
    /// Addresses that must exist afterwards.
    pub add: Vec<IpAddr>,
    /// Addresses that must not exist afterwards, unless also in `add`.
    pub remove: Vec<IpAddr>,
    /// TTL of created and changed records; `None` uses the provider's default.
    pub ttl: Option<u32>,
    /// Only re-point existing records, never create or delete any.
    pub replace_only: bool,
}

impl RecordUpdateRequest {
    /// Returns `true` if this update can never change anything.
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty()
    }
}

/// Builds and sends a [`RecordUpdateRequest`]; see [`DynDnsProvider::update_request`].
///
/// ```no_run
/// # async fn example(provider: &mut dyn ddns_clients::DynDnsProvider) -> ddns_clients::Result<()> {
/// let old = "192.0.2.1".parse().unwrap();
/// let new = "192.0.2.2".parse().unwrap();
/// provider.update_request("myhost.example.com").remove(old).add(new).send().await?;
/// # Ok(())
/// # }
/// ```
#[must_use = "an update does nothing until `send` is awaited"]
pub struct UpdateRequestBuilder<'a> {
    provider: &'a mut dyn DynDnsProvider,
    request: RecordUpdateRequest,
    /// Whether IPv4 and IPv6 addresses may be added or removed.
    families: (bool, bool),
    /// Sends the request as `replace_only` whatever the caller sets.
    force_replace_only: bool,
}

impl<'a> UpdateRequestBuilder<'a> {
    /// Starts an empty update of `domain` on `provider`.
    pub fn new(provider: &'a mut dyn DynDnsProvider, domain: &str) -> Self {
        UpdateRequestBuilder {
            provider,
            request: RecordUpdateRequest {
                domain: domain.to_string(),
                ..Default::default()
            },
            families: (true, true),
            force_replace_only: false,
        }
    }

    /// Drops addresses of disabled families when sending, and forces
    /// `replace_only` if set.
    pub(crate) fn restrict(mut self, ipv4: bool, ipv6: bool, replace_only: bool) -> Self {
        self.families = (ipv4, ipv6);
        self.force_replace_only = replace_only;
        self
    }

    /// Ensures a record with `ip` exists.
    #[allow(clippy::should_implement_trait)] // a builder step, not arithmetic
    pub fn add(mut self, ip: IpAddr) -> Self {
        self.request.add.push(ip);
        self
    }

    /// Ensures records with each of `ips` exist.
    pub fn add_all(mut self, ips: impl IntoIterator<Item = IpAddr>) -> Self {
        self.request.add.extend(ips);
        self
    }

    /// Removes the record with `ip`, if any.
    pub fn remove(mut self, ip: IpAddr) -> Self {
        self.request.remove.push(ip);
        self
    }

    /// Removes the records with each of `ips`, if any.
    pub fn remove_all(mut self, ips: impl IntoIterator<Item = IpAddr>) -> Self {
        self.request.remove.extend(ips);
        self
    }

    /// Sets the TTL of created and changed records; `None` uses the
    /// provider's default.
    pub fn ttl(mut self, ttl: Option<u32>) -> Self {
        self.request.ttl = ttl;
        self
    }

    /// Only re-points existing records, never creates or deletes any; see
    /// [`RecordUpdateRequest::replace_only`].
    pub fn replace_only(mut self, enabled: bool) -> Self {
        self.request.replace_only = enabled;
        self
    }

    /// Applies the update.
    pub async fn send(mut self) -> Result<UpdateSummary> {
        self.request.replace_only |= self.force_replace_only;
        let (ipv4, ipv6) = self.families;
        let allowed = |ip: &IpAddr| if ip.is_ipv4() { ipv4 } else { ipv6 };
        let request = &mut self.request;
        if !request.add.iter().chain(&request.remove).all(allowed) {
            log::debug!(
                "{}: ignoring addresses of disabled families in add={:?}, remove={:?}",
                request.domain,
                request.add,
                request.remove
            );
            request.add.retain(allowed);
            request.remove.retain(allowed);
        }
        if self.request.is_empty() {
            return Ok(UpdateSummary::default());
        }
        self.provider.execute_request(self.request).await
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

/// The record operations that carry out a [`RecordUpdateRequest`]; see
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
/// address) into the state described by `request`.
///
/// Records that are no longer wanted are re-pointed at missing addresses
/// where possible (same family first), which keeps provider-side record
/// settings; the rest are deleted, and the remaining addresses are created.
/// Duplicate records of a wanted address are treated as unwanted. With
/// [`replace_only`](RecordUpdateRequest::replace_only), nothing is deleted or
/// created: the rest are kept and the remaining addresses dropped.
pub fn plan_changes<Id: Clone>(
    existing: &[(Id, IpAddr)],
    request: &RecordUpdateRequest,
) -> ChangePlan<Id> {
    let mut desired: Vec<IpAddr> = vec![];
    for ip in &request.add {
        if !desired.contains(ip) {
            desired.push(*ip);
        }
    }
    for (_, ip) in existing {
        if !request.remove.contains(ip) && !desired.contains(ip) {
            desired.push(*ip);
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
        if !missing.is_empty() {
            repoint.push((id, missing.remove(0)));
        } else if request.replace_only {
            keep += 1;
        } else {
            delete.push(id);
        }
    }
    if request.replace_only {
        missing.clear();
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

    fn request(add: &[&str], remove: &[&str]) -> RecordUpdateRequest {
        RecordUpdateRequest {
            domain: "h.example.com".into(),
            add: add.iter().map(|s| ip(s)).collect(),
            remove: remove.iter().map(|s| ip(s)).collect(),
            ttl: None,
            replace_only: false,
        }
    }

    fn existing(records: &[(&'static str, &str)]) -> Vec<(&'static str, IpAddr)> {
        records.iter().map(|(id, s)| (*id, ip(s))).collect()
    }

    #[test]
    fn empty() {
        let plan = plan_changes(&existing(&[("a", "1.1.1.1")]), &request(&[], &[]));
        assert_eq!(
            plan.summary(),
            UpdateSummary {
                kept: 1,
                ..Default::default()
            }
        );
        assert!(request(&[], &[]).is_empty());
    }

    #[test]
    fn add_present_and_remove_absent_are_noops() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1")]),
            &request(&["1.1.1.1"], &["9.9.9.9"]),
        );
        assert!(plan.summary().is_unchanged());
        assert_eq!(plan.keep, 1);
    }

    #[test]
    fn creates_missing() {
        let plan = plan_changes::<&str>(&[], &request(&["1.1.1.1", "2001:db8::1"], &[]));
        assert_eq!(plan.create, vec![ip("1.1.1.1"), ip("2001:db8::1")]);
    }

    #[test]
    fn repoints_same_family_first() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1"), ("b", "2001:db8::1")]),
            &request(&["2001:db8::2", "2.2.2.2"], &["1.1.1.1", "2001:db8::1"]),
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
            &request(&["2001:db8::1"], &["1.1.1.1"]),
        );
        assert_eq!(plan.repoint, vec![("a", ip("2001:db8::1"))]);
    }

    #[test]
    fn deletes_and_creates_leftovers() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1"), ("b", "2.2.2.2")]),
            &request(&["3.3.3.3"], &["1.1.1.1", "2.2.2.2"]),
        );
        assert_eq!(plan.repoint, vec![("a", ip("3.3.3.3"))]);
        assert_eq!(plan.delete, vec!["b"]);

        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1")]),
            &request(&["2.2.2.2", "3.3.3.3"], &["1.1.1.1"]),
        );
        assert_eq!(plan.repoint, vec![("a", ip("2.2.2.2"))]);
        assert_eq!(plan.create, vec![ip("3.3.3.3")]);
    }

    #[test]
    fn removes_all() {
        let records = existing(&[("a", "1.1.1.1"), ("b", "2.2.2.2")]);
        let plan = plan_changes(&records, &request(&[], &["1.1.1.1", "2.2.2.2"]));
        assert_eq!(plan.delete, vec!["a", "b"]);
    }

    #[test]
    fn replace_only_keeps_unpaired_records() {
        let mut request = request(&["3.3.3.3"], &["1.1.1.1", "2.2.2.2"]);
        request.replace_only = true;
        let plan = plan_changes(&existing(&[("a", "1.1.1.1"), ("b", "2.2.2.2")]), &request);
        assert_eq!(plan.repoint, vec![("a", ip("3.3.3.3"))]);
        assert_eq!(plan.keep, 1);
        assert!(plan.delete.is_empty() && plan.create.is_empty());
    }

    #[test]
    fn replace_only_drops_extra_addresses() {
        let mut request = request(&["2.2.2.2", "2001:db8::1"], &["1.1.1.1"]);
        request.replace_only = true;
        let plan = plan_changes(&existing(&[("a", "1.1.1.1")]), &request);
        assert_eq!(plan.repoint, vec![("a", ip("2.2.2.2"))]);
        assert!(plan.delete.is_empty() && plan.create.is_empty());

        // nothing to re-point at all
        let plan = plan_changes::<&str>(&[], &request);
        assert!(plan.summary().is_unchanged());
    }

    #[test]
    fn replace_only_keeps_duplicates() {
        let mut request = request(&["1.1.1.1"], &[]);
        request.replace_only = true;
        let plan = plan_changes(&existing(&[("a", "1.1.1.1"), ("b", "1.1.1.1")]), &request);
        assert_eq!(plan.keep, 2);
        assert!(plan.summary().is_unchanged());
    }

    #[test]
    fn add_wins_over_remove() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1")]),
            &request(&["1.1.1.1"], &["1.1.1.1"]),
        );
        assert_eq!(plan.keep, 1);
        assert!(plan.summary().is_unchanged());
    }

    #[test]
    fn duplicates() {
        let plan = plan_changes(
            &existing(&[("a", "1.1.1.1"), ("b", "1.1.1.1")]),
            &request(&["1.1.1.1", "1.1.1.1"], &[]),
        );
        assert_eq!(plan.keep, 1);
        assert_eq!(plan.delete, vec!["b"]);
    }
}
