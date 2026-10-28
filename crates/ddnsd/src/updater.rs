use std::net::IpAddr;

use ddns_clients::{DynDnsProvider, Result, UpdateSummary};

/// Settings for an [`Updater`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdaterOptions {
    /// Manage A records.
    pub ipv4: bool,
    /// Manage AAAA records.
    pub ipv6: bool,
    /// TTL for created/updated records; `None` uses the provider's default.
    pub ttl: Option<u32>,
    /// Maximum number of address records kept for the domain.
    pub max_records: usize,
}

impl Default for UpdaterOptions {
    fn default() -> Self {
        UpdaterOptions {
            ipv4: true,
            ipv6: true,
            ttl: None,
            max_records: 2,
        }
    }
}

/// Keeps the address records of one domain in sync with a set of IPs.
///
/// Records are cached between calls and only re-fetched from the provider
/// after a failed update.
pub struct Updater<P> {
    provider: P,
    domain: String,
    options: UpdaterOptions,
    records: Vec<IpAddr>, // cache existing dns records
    records_dirty: bool,
}

impl<P: DynDnsProvider> Updater<P> {
    /// Creates an updater managing `domain` through `provider`.
    pub fn new(provider: P, domain: impl Into<String>, options: UpdaterOptions) -> Self {
        Updater {
            provider,
            domain: domain.into(),
            options,
            records: vec![],
            records_dirty: true,
        }
    }

    fn is_enabled(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.options.ipv4,
            IpAddr::V6(_) => self.options.ipv6,
        }
    }

    async fn refresh_records(&mut self) -> Result<()> {
        log::info!("refresh dns records");
        let mut records = self.provider.list(&self.domain).await?;
        records.retain(|ip| self.is_enabled(ip));
        log::info!("{} have {} records: ", self.domain, records.len());
        for ip in &records {
            log::info!("    {ip}");
        }
        self.records = records;
        Ok(())
    }

    /// Makes the domain's records point at `ips`.
    ///
    /// Addresses of disabled families are ignored. Stale records are replaced
    /// or removed, and new ones added up to [`UpdaterOptions::max_records`].
    pub async fn update_ips(&mut self, ips: &[IpAddr]) -> Result<UpdateSummary> {
        if self.records_dirty {
            self.refresh_records().await?;
            self.records_dirty = false;
        }

        let ips: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|ip| self.is_enabled(ip))
            .collect();
        let (keep, stale, mut add) = diff_records(&self.records, &ips);

        // we don't want to exceed the max count
        add.truncate(self.options.max_records.saturating_sub(keep.len()));

        if stale.is_empty() && add.is_empty() {
            log::debug!("no record changes");
            return Ok(UpdateSummary {
                kept: keep.len(),
                ..Default::default()
            });
        }

        log::info!(
            "record changes: keep={:?}, remove={:?}, add={:?}",
            keep,
            stale,
            add
        );

        // mark records dirty in case of failure
        self.records_dirty = true;
        let desired: Vec<IpAddr> = keep.into_iter().chain(add).collect();
        // re-adding the kept addresses drops duplicate records of them
        let summary = self
            .provider
            .update(&self.domain)
            .remove_all(stale)
            .add_all(desired.iter().copied())
            .ttl(self.options.ttl)
            .send()
            .await?;
        self.records = desired;
        self.records_dirty = false;
        Ok(summary)
    }
}

/// Splits `records` into those matching one of `ips` (kept) and the rest
/// (stale), and returns the `ips` not covered by any record (to add).
fn diff_records(records: &[IpAddr], ips: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>, Vec<IpAddr>) {
    let mut keep = vec![];
    let mut stale = vec![];
    let mut add = ips.to_vec();

    for ip in records {
        if let Some(pos) = add.iter().position(|a| a == ip) {
            add.remove(pos);
            keep.push(*ip);
        } else {
            stale.push(*ip);
        }
    }

    (keep, stale, add)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ddns_clients::{Error, RecordUpdate, UpdateBuilder, providers::plan_changes};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rec(id: &str, addr: &str) -> (String, IpAddr) {
        (id.to_string(), ip(addr))
    }

    #[derive(Default)]
    struct MockProvider {
        records: Vec<(String, IpAddr)>,
        next_id: usize,
        fail_next: bool,
        list_calls: usize,
    }

    impl MockProvider {
        fn with(records: Vec<(String, IpAddr)>) -> Self {
            MockProvider {
                records,
                ..Default::default()
            }
        }

        fn check_fail(&mut self) -> Result<()> {
            if std::mem::take(&mut self.fail_next) {
                return Err(Error::provider("injected failure"));
            }
            Ok(())
        }

        fn ips(&self) -> Vec<IpAddr> {
            let mut ips: Vec<_> = self.records.iter().map(|(_, ip)| *ip).collect();
            ips.sort();
            ips
        }
    }

    #[async_trait]
    impl DynDnsProvider for MockProvider {
        async fn list(&mut self, _domain: &str) -> Result<Vec<IpAddr>> {
            self.list_calls += 1;
            self.check_fail()?;
            Ok(self.records.iter().map(|(_, ip)| *ip).collect())
        }

        fn update<'a>(&'a mut self, domain: &str) -> UpdateBuilder<'a> {
            UpdateBuilder::new(self, domain)
        }

        async fn apply_update(&mut self, update: RecordUpdate) -> Result<UpdateSummary> {
            self.check_fail()?;
            let plan = plan_changes(&self.records, &update);
            for (id, ip) in &plan.repoint {
                self.records.iter_mut().find(|(i, _)| i == id).unwrap().1 = *ip;
            }
            self.records.retain(|(id, _)| !plan.delete.contains(id));
            for ip in &plan.create {
                self.next_id += 1;
                self.records.push((format!("new{}", self.next_id), *ip));
            }
            Ok(plan.summary())
        }
    }

    fn updater(provider: MockProvider, options: UpdaterOptions) -> Updater<MockProvider> {
        Updater::new(provider, "host.example.com", options)
    }

    #[test]
    fn diff() {
        let (keep, stale, add) = diff_records(
            &[ip("1.1.1.1"), ip("2.2.2.2")],
            &[ip("2.2.2.2"), ip("3.3.3.3")],
        );
        assert_eq!(keep, vec![ip("2.2.2.2")]);
        assert_eq!(stale, vec![ip("1.1.1.1")]);
        assert_eq!(add, vec![ip("3.3.3.3")]);
    }

    #[test]
    fn diff_duplicates() {
        let (keep, stale, add) = diff_records(&[ip("1.1.1.1"), ip("1.1.1.1")], &[ip("1.1.1.1")]);
        assert_eq!(keep, vec![ip("1.1.1.1")]);
        assert_eq!(stale, vec![ip("1.1.1.1")]);
        assert!(add.is_empty());
    }

    #[tokio::test]
    async fn unchanged() {
        let provider = MockProvider::with(vec![rec("a", "1.1.1.1")]);
        let mut u = updater(provider, UpdaterOptions::default());
        let summary = u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert!(summary.is_unchanged());
        assert_eq!(summary.kept, 1);
    }

    #[tokio::test]
    async fn creates_missing() {
        let mut u = updater(MockProvider::default(), UpdaterOptions::default());
        let summary = u
            .update_ips(&[ip("1.1.1.1"), ip("2001:4860::1")])
            .await
            .unwrap();
        assert_eq!(summary.created, 2);
        assert_eq!(u.provider.ips(), vec![ip("1.1.1.1"), ip("2001:4860::1")]);
        assert_eq!(u.records.len(), 2);
    }

    #[tokio::test]
    async fn replaces_via_update() {
        let provider = MockProvider::with(vec![rec("a", "1.1.1.1")]);
        let mut u = updater(provider, UpdaterOptions::default());
        let summary = u.update_ips(&[ip("2.2.2.2")]).await.unwrap();
        assert_eq!(
            summary,
            UpdateSummary {
                updated: 1,
                ..Default::default()
            }
        );
        assert_eq!(u.provider.records, vec![rec("a", "2.2.2.2")]);
    }

    #[tokio::test]
    async fn deletes_surplus() {
        let provider = MockProvider::with(vec![rec("a", "1.1.1.1"), rec("b", "2.2.2.2")]);
        let mut u = updater(provider, UpdaterOptions::default());
        let summary = u.update_ips(&[ip("2.2.2.2")]).await.unwrap();
        assert_eq!(summary.deleted, 1);
        assert_eq!(u.provider.records, vec![rec("b", "2.2.2.2")]);
    }

    #[tokio::test]
    async fn deletes_duplicates() {
        let provider = MockProvider::with(vec![rec("a", "1.1.1.1"), rec("b", "1.1.1.1")]);
        let mut u = updater(provider, UpdaterOptions::default());
        let summary = u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert_eq!(summary.deleted, 1);
        assert_eq!(u.provider.records, vec![rec("a", "1.1.1.1")]);
    }

    #[tokio::test]
    async fn caps_at_max_records() {
        let options = UpdaterOptions {
            max_records: 1,
            ..Default::default()
        };
        let mut u = updater(MockProvider::default(), options);
        let summary = u.update_ips(&[ip("1.1.1.1"), ip("2.2.2.2")]).await.unwrap();
        assert_eq!(summary.created, 1);
        assert_eq!(u.provider.records.len(), 1);
    }

    #[tokio::test]
    async fn ignores_disabled_family() {
        let provider = MockProvider::with(vec![rec("a", "1.1.1.1")]);
        let options = UpdaterOptions {
            ipv4: false,
            ..Default::default()
        };
        let mut u = updater(provider, options);
        let summary = u
            .update_ips(&[ip("2.2.2.2"), ip("2001:4860::1")])
            .await
            .unwrap();
        assert_eq!(summary.created, 1);
        assert_eq!(summary.deleted + summary.updated, 0);
        assert_eq!(u.provider.ips(), vec![ip("1.1.1.1"), ip("2001:4860::1")]);
    }

    #[tokio::test]
    async fn refreshes_after_failure() {
        let mut u = updater(MockProvider::default(), UpdaterOptions::default());
        u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert_eq!(u.provider.list_calls, 1);

        // cached records are reused while updates succeed
        u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert_eq!(u.provider.list_calls, 1);

        u.provider.fail_next = true;
        u.update_ips(&[ip("2.2.2.2")]).await.unwrap_err();

        u.update_ips(&[ip("2.2.2.2")]).await.unwrap();
        assert_eq!(u.provider.list_calls, 2);
        assert_eq!(u.provider.records, vec![rec("new1", "2.2.2.2")]);
    }
}
