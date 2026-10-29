//! Planning: the provider operations that turn a domain's records into the
//! desired addresses.

use std::{fmt, net::IpAddr};

use crate::UpdateSummary;

/// One provider operation of an update; records are identified by address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Operation {
    /// Re-point a record at a new address (possibly changing A ↔ AAAA).
    Replace { old: IpAddr, new: IpAddr },
    /// Delete a record.
    Delete(IpAddr),
    /// Add a record.
    Add(IpAddr),
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Replace { old, new } => write!(f, "replace {old} with {new}"),
            Operation::Delete(ip) => write!(f, "delete {ip}"),
            Operation::Add(ip) => write!(f, "add {ip}"),
        }
    }
}

/// The operations that turn the `existing` records (one address each) into
/// exactly the `desired` addresses: replaces first, then deletes, then adds.
///
/// One record per desired address is kept. Records that are no longer wanted
/// (including duplicates) are re-pointed at missing addresses where possible,
/// same family first, which keeps provider-side record settings; the rest are
/// deleted, and the remaining addresses are added. With `replace_only`,
/// nothing is deleted or added: the rest are kept and the remaining addresses
/// dropped.
pub(super) fn plan(existing: &[IpAddr], desired: &[IpAddr], replace_only: bool) -> Vec<Operation> {
    let mut missing: Vec<IpAddr> = vec![];
    for ip in desired {
        if !missing.contains(ip) {
            missing.push(*ip);
        }
    }

    let mut dropped = vec![];
    for ip in existing {
        match missing.iter().position(|m| m == ip) {
            Some(pos) => {
                missing.remove(pos);
            }
            None => dropped.push(*ip),
        }
    }

    let mut ops = vec![];
    let mut unpaired = vec![];
    for old in dropped {
        match missing.iter().position(|m| m.is_ipv4() == old.is_ipv4()) {
            Some(pos) => ops.push(Operation::Replace {
                old,
                new: missing.remove(pos),
            }),
            None => unpaired.push(old),
        }
    }

    let mut deletes = vec![];
    for old in unpaired {
        if !missing.is_empty() {
            ops.push(Operation::Replace {
                old,
                new: missing.remove(0),
            });
        } else if !replace_only {
            deletes.push(Operation::Delete(old));
        }
    }
    ops.extend(deletes);
    if !replace_only {
        ops.extend(missing.into_iter().map(Operation::Add));
    }
    ops
}

/// The addresses after carrying out `ops` on `existing`; each operation acts
/// on the first record with its address.
pub(super) fn apply(existing: &[IpAddr], ops: &[Operation]) -> Vec<IpAddr> {
    let mut records = existing.to_vec();
    for op in ops {
        match *op {
            Operation::Replace { old, new } => {
                if let Some(record) = records.iter_mut().find(|r| **r == old) {
                    *record = new;
                }
            }
            Operation::Delete(ip) => {
                if let Some(pos) = records.iter().position(|r| *r == ip) {
                    records.remove(pos);
                }
            }
            Operation::Add(ip) => records.push(ip),
        }
    }
    records
}

/// What carrying out `ops` on `records` records changes.
pub(super) fn summary(records: usize, ops: &[Operation]) -> UpdateSummary {
    let count = |f: fn(&Operation) -> bool| ops.iter().filter(|op| f(op)).count();
    let updated = count(|op| matches!(op, Operation::Replace { .. }));
    let deleted = count(|op| matches!(op, Operation::Delete(_)));
    UpdateSummary {
        kept: records - updated - deleted,
        updated,
        deleted,
        created: count(|op| matches!(op, Operation::Add(_))),
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

    fn replace(old: &str, new: &str) -> Operation {
        Operation::Replace {
            old: ip(old),
            new: ip(new),
        }
    }

    fn delete(s: &str) -> Operation {
        Operation::Delete(ip(s))
    }

    fn add(s: &str) -> Operation {
        Operation::Add(ip(s))
    }

    #[test]
    fn unchanged() {
        let existing = ips(&["1.1.1.1", "2001:db8::1"]);
        assert!(plan(&existing, &ips(&["2001:db8::1", "1.1.1.1"]), false).is_empty());
    }

    #[test]
    fn adds_missing() {
        assert_eq!(
            plan(&[], &ips(&["1.1.1.1", "2001:db8::1"]), false),
            vec![add("1.1.1.1"), add("2001:db8::1")]
        );
    }

    #[test]
    fn replaces_same_family_first() {
        let existing = ips(&["1.1.1.1", "2001:db8::1"]);
        let ops = plan(&existing, &ips(&["2001:db8::2", "2.2.2.2"]), false);
        assert_eq!(
            ops,
            vec![
                replace("1.1.1.1", "2.2.2.2"),
                replace("2001:db8::1", "2001:db8::2")
            ]
        );
        assert_eq!(apply(&existing, &ops), ips(&["2.2.2.2", "2001:db8::2"]));
    }

    #[test]
    fn replaces_across_families() {
        assert_eq!(
            plan(&ips(&["1.1.1.1"]), &ips(&["2001:db8::1"]), false),
            vec![replace("1.1.1.1", "2001:db8::1")]
        );
    }

    #[test]
    fn deletes_and_adds_leftovers() {
        let existing = ips(&["1.1.1.1", "2.2.2.2"]);
        let ops = plan(&existing, &ips(&["3.3.3.3"]), false);
        assert_eq!(ops, vec![replace("1.1.1.1", "3.3.3.3"), delete("2.2.2.2")]);
        assert_eq!(apply(&existing, &ops), ips(&["3.3.3.3"]));

        let existing = ips(&["1.1.1.1"]);
        let ops = plan(&existing, &ips(&["2.2.2.2", "3.3.3.3"]), false);
        assert_eq!(ops, vec![replace("1.1.1.1", "2.2.2.2"), add("3.3.3.3")]);
        assert_eq!(apply(&existing, &ops), ips(&["2.2.2.2", "3.3.3.3"]));
    }

    #[test]
    fn empty_desired_deletes_all() {
        assert_eq!(
            plan(&ips(&["1.1.1.1", "2.2.2.2"]), &[], false),
            vec![delete("1.1.1.1"), delete("2.2.2.2")]
        );
    }

    #[test]
    fn duplicates() {
        let existing = ips(&["1.1.1.1", "1.1.1.1"]);
        let ops = plan(&existing, &ips(&["1.1.1.1", "1.1.1.1"]), false);
        assert_eq!(ops, vec![delete("1.1.1.1")]);
        assert_eq!(apply(&existing, &ops), ips(&["1.1.1.1"]));
    }

    #[test]
    fn replace_only_keeps_unpaired_records() {
        let existing = ips(&["1.1.1.1", "2.2.2.2"]);
        let ops = plan(&existing, &ips(&["3.3.3.3"]), true);
        assert_eq!(ops, vec![replace("1.1.1.1", "3.3.3.3")]);
        assert_eq!(apply(&existing, &ops), ips(&["3.3.3.3", "2.2.2.2"]));
    }

    #[test]
    fn replace_only_drops_extra_addresses() {
        let desired = ips(&["2.2.2.2", "2001:db8::1"]);
        assert_eq!(
            plan(&ips(&["1.1.1.1"]), &desired, true),
            vec![replace("1.1.1.1", "2.2.2.2")]
        );
        // nothing to re-point at all
        assert!(plan(&[], &desired, true).is_empty());
    }

    #[test]
    fn replace_only_keeps_duplicates() {
        assert!(plan(&ips(&["1.1.1.1", "1.1.1.1"]), &ips(&["1.1.1.1"]), true).is_empty());
    }

    #[test]
    fn apply_acts_on_first_match() {
        let existing = ips(&["1.1.1.1", "1.1.1.1"]);
        let ops = [replace("1.1.1.1", "2.2.2.2"), delete("1.1.1.1")];
        assert_eq!(apply(&existing, &ops), ips(&["2.2.2.2"]));
    }

    #[test]
    fn summarizes() {
        let ops = [
            replace("1.1.1.1", "2.2.2.2"),
            delete("3.3.3.3"),
            add("4.4.4.4"),
        ];
        assert_eq!(
            summary(4, &ops),
            UpdateSummary {
                kept: 2,
                updated: 1,
                deleted: 1,
                created: 1,
            }
        );
    }
}
