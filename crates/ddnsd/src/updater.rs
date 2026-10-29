use std::net::IpAddr;

use ddns_clients::{DynDnsClient, Result, UpdateSummary, resolve::IpFamily};

/// Keeps the client's domain pointed at a set of IPs, with at most
/// `max_records` address records.
///
/// Only the client's enabled address families are touched. The client caches
/// the domain's records between updates; they are only listed again after a
/// failed update.
pub struct Updater {
    client: DynDnsClient,
    max_records: usize,
}

impl Updater {
    /// Creates an updater managing the domain of `client`.
    pub fn new(client: DynDnsClient, max_records: usize) -> Self {
        Updater {
            client,
            max_records,
        }
    }

    pub fn client(&self) -> &DynDnsClient {
        &self.client
    }

    async fn refresh_records(&mut self) -> Result<Vec<IpAddr>> {
        log::info!("{}: refresh dns records", self.client.domain());
        let records = self.client.list().await?;
        log::info!("{} have {} records: ", self.client.domain(), records.len());
        for ip in &records {
            log::info!("    {ip}");
        }
        Ok(records)
    }

    /// Makes the domain's records point at `ips`.
    ///
    /// Stale records are replaced or removed, and new ones added up to
    /// `max_records`.
    pub async fn update_ips(&mut self, ips: &[IpAddr]) -> Result<UpdateSummary> {
        let records = match self.client.cached_records() {
            Some(records) => records.to_vec(),
            None => self.refresh_records().await?,
        };
        let ips: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|ip| self.client.is_enabled(IpFamily::of(ip)))
            .collect();
        let (keep, stale, mut add) = diff_records(&records, &ips);

        // we don't want to exceed the max count
        add.truncate(self.max_records.saturating_sub(keep.len()));

        if stale.is_empty() && add.is_empty() {
            log::debug!("{}: no record changes", self.client.domain());
            return Ok(UpdateSummary {
                kept: keep.len(),
                ..Default::default()
            });
        }

        log::info!(
            "{}: record changes: keep={:?}, remove={:?}, add={:?}",
            self.client.domain(),
            keep,
            stale,
            add
        );
        self.client.update(keep.into_iter().chain(add)).await
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
    use std::sync::{Arc, Mutex};

    use super::*;
    use async_trait::async_trait;
    use ddns_clients::{
        DynDnsProvider, Error, RecordUpdateRequest, UpdateRequestBuilder, providers::plan_changes,
    };

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rec(id: &str, addr: &str) -> (String, IpAddr) {
        (id.to_string(), ip(addr))
    }

    #[derive(Default)]
    struct MockState {
        records: Vec<(String, IpAddr)>,
        next_id: usize,
        fail_next: bool,
        list_calls: usize,
    }

    impl MockState {
        fn with(records: Vec<(String, IpAddr)>) -> Self {
            MockState {
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

    /// The provider half of a mock; the test keeps the state to inspect it.
    struct MockProvider(Arc<Mutex<MockState>>);

    #[async_trait]
    impl DynDnsProvider for MockProvider {
        async fn list(&mut self, _domain: &str) -> Result<Vec<IpAddr>> {
            let mut state = self.0.lock().unwrap();
            state.list_calls += 1;
            state.check_fail()?;
            Ok(state.records.iter().map(|(_, ip)| *ip).collect())
        }

        fn update_request<'a>(&'a mut self, domain: &str) -> UpdateRequestBuilder<'a> {
            UpdateRequestBuilder::new(self, domain)
        }

        async fn execute_request(&mut self, request: RecordUpdateRequest) -> Result<UpdateSummary> {
            let state = &mut *self.0.lock().unwrap();
            state.check_fail()?;
            let plan = plan_changes(&state.records, &request);
            for (id, ip) in &plan.repoint {
                state.records.iter_mut().find(|(i, _)| i == id).unwrap().1 = *ip;
            }
            state.records.retain(|(id, _)| !plan.delete.contains(id));
            for ip in &plan.create {
                state.next_id += 1;
                state.records.push((format!("new{}", state.next_id), *ip));
            }
            Ok(plan.summary())
        }
    }

    /// An updater (both families, at most 2 records) on a mock provider
    /// starting with `state`, and the shared mock state.
    fn updater(state: MockState) -> (Updater, Arc<Mutex<MockState>>) {
        updater_with(state, true, 2)
    }

    fn updater_with(
        state: MockState,
        ipv4: bool,
        max_records: usize,
    ) -> (Updater, Arc<Mutex<MockState>>) {
        let state = Arc::new(Mutex::new(state));
        let client =
            DynDnsClient::new(MockProvider(state.clone()), "host.example.com").enable_ipv4(ipv4);
        (Updater::new(client, max_records), state)
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
        let state = MockState::with(vec![rec("a", "1.1.1.1")]);
        let (mut u, _) = updater(state);
        let summary = u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert!(summary.is_unchanged());
        assert_eq!(summary.kept, 1);
    }

    #[tokio::test]
    async fn creates_missing() {
        let (mut u, mock) = updater(MockState::default());
        let summary = u
            .update_ips(&[ip("1.1.1.1"), ip("2001:4860::1")])
            .await
            .unwrap();
        assert_eq!(summary.created, 2);
        assert_eq!(
            mock.lock().unwrap().ips(),
            vec![ip("1.1.1.1"), ip("2001:4860::1")]
        );
        assert_eq!(u.client.cached_records().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn replaces_via_update() {
        let state = MockState::with(vec![rec("a", "1.1.1.1")]);
        let (mut u, mock) = updater(state);
        let summary = u.update_ips(&[ip("2.2.2.2")]).await.unwrap();
        assert_eq!(
            summary,
            UpdateSummary {
                updated: 1,
                ..Default::default()
            }
        );
        assert_eq!(mock.lock().unwrap().records, vec![rec("a", "2.2.2.2")]);
    }

    #[tokio::test]
    async fn deletes_surplus() {
        let state = MockState::with(vec![rec("a", "1.1.1.1"), rec("b", "2.2.2.2")]);
        let (mut u, mock) = updater(state);
        let summary = u.update_ips(&[ip("2.2.2.2")]).await.unwrap();
        assert_eq!(summary.deleted, 1);
        assert_eq!(mock.lock().unwrap().records, vec![rec("b", "2.2.2.2")]);
    }

    #[tokio::test]
    async fn deletes_duplicates() {
        let state = MockState::with(vec![rec("a", "1.1.1.1"), rec("b", "1.1.1.1")]);
        let (mut u, mock) = updater(state);
        let summary = u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert_eq!(summary.deleted, 1);
        assert_eq!(mock.lock().unwrap().records, vec![rec("a", "1.1.1.1")]);
    }

    #[tokio::test]
    async fn caps_at_max_records() {
        let (mut u, mock) = updater_with(MockState::default(), true, 1);
        let summary = u.update_ips(&[ip("1.1.1.1"), ip("2.2.2.2")]).await.unwrap();
        assert_eq!(summary.created, 1);
        assert_eq!(mock.lock().unwrap().records.len(), 1);
    }

    #[tokio::test]
    async fn ignores_disabled_family() {
        let state = MockState::with(vec![rec("a", "1.1.1.1")]);
        let (mut u, mock) = updater_with(state, false, 2);
        let summary = u
            .update_ips(&[ip("2.2.2.2"), ip("2001:4860::1")])
            .await
            .unwrap();
        assert_eq!(summary.created, 1);
        assert_eq!(summary.deleted + summary.updated, 0);
        assert_eq!(
            mock.lock().unwrap().ips(),
            vec![ip("1.1.1.1"), ip("2001:4860::1")]
        );
    }

    #[tokio::test]
    async fn keeps_disabled_family_records() {
        let state = MockState::with(vec![rec("a", "1.1.1.1"), rec("b", "2001:4860::1")]);
        let (mut u, mock) = updater_with(state, false, 2);
        let summary = u.update_ips(&[ip("2001:4860::2")]).await.unwrap();
        assert_eq!(summary.updated, 1);
        assert_eq!(summary.deleted + summary.created, 0);
        assert_eq!(
            mock.lock().unwrap().records,
            vec![rec("a", "1.1.1.1"), rec("b", "2001:4860::2")]
        );
    }

    #[tokio::test]
    async fn refreshes_after_failure() {
        let (mut u, mock) = updater(MockState::default());
        u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert_eq!(mock.lock().unwrap().list_calls, 1);

        // cached records are reused while updates succeed
        u.update_ips(&[ip("1.1.1.1")]).await.unwrap();
        assert_eq!(mock.lock().unwrap().list_calls, 1);

        mock.lock().unwrap().fail_next = true;
        u.update_ips(&[ip("2.2.2.2")]).await.unwrap_err();

        u.update_ips(&[ip("2.2.2.2")]).await.unwrap();
        assert_eq!(mock.lock().unwrap().list_calls, 2);
        assert_eq!(mock.lock().unwrap().records, vec![rec("new1", "2.2.2.2")]);
    }
}
