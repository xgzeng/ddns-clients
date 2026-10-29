//! Planning: the record operations that turn a domain's records into the
//! requested state.

use std::net::IpAddr;

use crate::UpdateSummary;

/// A change of one domain's address records.
///
/// Afterwards the domain has exactly the addresses `add ∪ (existing − remove)`.
/// Removing an absent address and adding a present one are no-ops.
///
/// With `replace_only`, the number of records never changes: existing records
/// are only re-pointed. Records with nothing to re-point to are kept, and
/// addresses without a record to re-point are not added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Request {
    /// Addresses that must exist afterwards.
    pub add: Vec<IpAddr>,
    /// Addresses that must not exist afterwards, unless also in `add`.
    pub remove: Vec<IpAddr>,
    /// Only re-point existing records, never add or delete any.
    pub replace_only: bool,
}

/// The operations that carry out a [`Request`], on records identified by
/// their position in the existing records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Plan {
    /// Number of records left alone.
    pub keep: usize,
    /// Records to re-point at a new address (possibly changing A ↔ AAAA).
    pub replace: Vec<(usize, IpAddr)>,
    /// Records to delete.
    pub delete: Vec<usize>,
    /// Addresses to add records for.
    pub add: Vec<IpAddr>,
}

impl Plan {
    /// The summary of carrying out this plan.
    pub fn summary(&self) -> UpdateSummary {
        UpdateSummary {
            kept: self.keep,
            updated: self.replace.len(),
            deleted: self.delete.len(),
            created: self.add.len(),
        }
    }

    /// The addresses after carrying out this plan on `existing`.
    pub fn after(&self, existing: &[IpAddr]) -> Vec<IpAddr> {
        let mut records: Vec<(usize, IpAddr)> = existing.iter().copied().enumerate().collect();
        for (i, ip) in &self.replace {
            records[*i].1 = *ip;
        }
        records.retain(|(i, _)| !self.delete.contains(i));
        records
            .into_iter()
            .map(|(_, ip)| ip)
            .chain(self.add.iter().copied())
            .collect()
    }
}

/// Computes the operations that turn the `existing` records (one address per
/// record) into the state described by `request`.
///
/// Records that are no longer wanted are re-pointed at missing addresses
/// where possible (same family first), which keeps provider-side record
/// settings; the rest are deleted, and the remaining addresses are added.
/// Duplicate records of a wanted address are treated as unwanted. With
/// `replace_only`, nothing is deleted or added: the rest are kept and the
/// remaining addresses dropped.
pub(super) fn plan(existing: &[IpAddr], request: &Request) -> Plan {
    let mut desired: Vec<IpAddr> = vec![];
    for ip in &request.add {
        if !desired.contains(ip) {
            desired.push(*ip);
        }
    }
    for ip in existing {
        if !request.remove.contains(ip) && !desired.contains(ip) {
            desired.push(*ip);
        }
    }

    let mut missing = desired;
    let mut keep = 0;
    let mut dropped = vec![];
    for (i, ip) in existing.iter().enumerate() {
        if let Some(pos) = missing.iter().position(|d| d == ip) {
            missing.remove(pos);
            keep += 1;
        } else {
            dropped.push((i, *ip));
        }
    }

    let mut replace = vec![];
    let mut unpaired = vec![];
    for (i, ip) in dropped {
        match missing.iter().position(|m| m.is_ipv4() == ip.is_ipv4()) {
            Some(pos) => replace.push((i, missing.remove(pos))),
            None => unpaired.push(i),
        }
    }

    let mut delete = vec![];
    for i in unpaired {
        if !missing.is_empty() {
            replace.push((i, missing.remove(0)));
        } else if request.replace_only {
            keep += 1;
        } else {
            delete.push(i);
        }
    }
    if request.replace_only {
        missing.clear();
    }

    Plan {
        keep,
        replace,
        delete,
        add: missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| ip(s)).collect()
    }

    fn request(add: &[&str], remove: &[&str]) -> Request {
        Request {
            add: ips(add),
            remove: ips(remove),
            replace_only: false,
        }
    }

    fn replace_only(add: &[&str], remove: &[&str]) -> Request {
        Request {
            replace_only: true,
            ..request(add, remove)
        }
    }

    #[test]
    fn empty() {
        let plan = plan(&ips(&["1.1.1.1"]), &request(&[], &[]));
        assert_eq!(
            plan.summary(),
            UpdateSummary {
                kept: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn add_present_and_remove_absent_are_noops() {
        let plan = plan(&ips(&["1.1.1.1"]), &request(&["1.1.1.1"], &["9.9.9.9"]));
        assert!(plan.summary().is_unchanged());
        assert_eq!(plan.keep, 1);
    }

    #[test]
    fn adds_missing() {
        let plan = plan(&[], &request(&["1.1.1.1", "2001:db8::1"], &[]));
        assert_eq!(plan.add, ips(&["1.1.1.1", "2001:db8::1"]));
    }

    #[test]
    fn replaces_same_family_first() {
        let existing = ips(&["1.1.1.1", "2001:db8::1"]);
        let plan = plan(
            &existing,
            &request(&["2001:db8::2", "2.2.2.2"], &["1.1.1.1", "2001:db8::1"]),
        );
        assert_eq!(
            plan.replace,
            vec![(0, ip("2.2.2.2")), (1, ip("2001:db8::2"))]
        );
        assert!(plan.delete.is_empty() && plan.add.is_empty());
        assert_eq!(plan.after(&existing), ips(&["2.2.2.2", "2001:db8::2"]));
    }

    #[test]
    fn replaces_across_families() {
        let plan = plan(&ips(&["1.1.1.1"]), &request(&["2001:db8::1"], &["1.1.1.1"]));
        assert_eq!(plan.replace, vec![(0, ip("2001:db8::1"))]);
    }

    #[test]
    fn deletes_and_adds_leftovers() {
        let existing = ips(&["1.1.1.1", "2.2.2.2"]);
        let plan1 = plan(&existing, &request(&["3.3.3.3"], &["1.1.1.1", "2.2.2.2"]));
        assert_eq!(plan1.replace, vec![(0, ip("3.3.3.3"))]);
        assert_eq!(plan1.delete, vec![1]);
        assert_eq!(plan1.after(&existing), ips(&["3.3.3.3"]));

        let existing = ips(&["1.1.1.1"]);
        let plan2 = plan(&existing, &request(&["2.2.2.2", "3.3.3.3"], &["1.1.1.1"]));
        assert_eq!(plan2.replace, vec![(0, ip("2.2.2.2"))]);
        assert_eq!(plan2.add, ips(&["3.3.3.3"]));
        assert_eq!(plan2.after(&existing), ips(&["2.2.2.2", "3.3.3.3"]));
    }

    #[test]
    fn removes_all() {
        let plan = plan(
            &ips(&["1.1.1.1", "2.2.2.2"]),
            &request(&[], &["1.1.1.1", "2.2.2.2"]),
        );
        assert_eq!(plan.delete, vec![0, 1]);
    }

    #[test]
    fn add_wins_over_remove() {
        let plan = plan(&ips(&["1.1.1.1"]), &request(&["1.1.1.1"], &["1.1.1.1"]));
        assert_eq!(plan.keep, 1);
        assert!(plan.summary().is_unchanged());
    }

    #[test]
    fn duplicates() {
        let existing = ips(&["1.1.1.1", "1.1.1.1"]);
        let plan = plan(&existing, &request(&["1.1.1.1", "1.1.1.1"], &[]));
        assert_eq!(plan.keep, 1);
        assert_eq!(plan.delete, vec![1]);
        assert_eq!(plan.after(&existing), ips(&["1.1.1.1"]));
    }

    #[test]
    fn replace_only_keeps_unpaired_records() {
        let plan = plan(
            &ips(&["1.1.1.1", "2.2.2.2"]),
            &replace_only(&["3.3.3.3"], &["1.1.1.1", "2.2.2.2"]),
        );
        assert_eq!(plan.replace, vec![(0, ip("3.3.3.3"))]);
        assert_eq!(plan.keep, 1);
        assert!(plan.delete.is_empty() && plan.add.is_empty());
    }

    #[test]
    fn replace_only_drops_extra_addresses() {
        let request = replace_only(&["2.2.2.2", "2001:db8::1"], &["1.1.1.1"]);
        let plan1 = plan(&ips(&["1.1.1.1"]), &request);
        assert_eq!(plan1.replace, vec![(0, ip("2.2.2.2"))]);
        assert!(plan1.delete.is_empty() && plan1.add.is_empty());

        // nothing to re-point at all
        assert!(plan(&[], &request).summary().is_unchanged());
    }

    #[test]
    fn replace_only_keeps_duplicates() {
        let plan = plan(
            &ips(&["1.1.1.1", "1.1.1.1"]),
            &replace_only(&["1.1.1.1"], &[]),
        );
        assert_eq!(plan.keep, 2);
        assert!(plan.summary().is_unchanged());
    }
}
