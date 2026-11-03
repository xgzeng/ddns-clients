mod config;

use std::{
    net::IpAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ddns_clients::{
    DynDnsClient, IpResolver, UpdateSummary,
    providers::NEVER,
    resolve::{self, AnyResolver, IpFamily},
};

use config::{Config, Target};

/// Dynamic DNS daemon: keeps domains' A/AAAA records pointed at this host.
///
/// Without a command, runs the daemon.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML config file.
    #[arg(short, long, global = true, default_value = "/etc/ddnsd.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run one update pass without changing any records; the planned
    /// changes are logged.
    DryRun,
}

/// A configured provider and its update state.
struct Entry {
    name: String,
    client: DynDnsClient,
    /// Maximum number of address records kept for the domain.
    max_records: usize,
    /// When the provider last read its records from the service.
    refreshed_at: Instant,
}

impl Entry {
    fn new(name: String, client: DynDnsClient, max_records: usize) -> Self {
        Entry {
            name,
            client,
            max_records,
            refreshed_at: Instant::now(),
        }
    }

    fn is_due(&self, now: Instant) -> bool {
        self.client.next_allowed_update().is_none_or(|at| at <= now)
    }
}

/// Keeps the domains of all configured providers pointed at this host's
/// public addresses, found with `resolver`.
///
/// Only each client's enabled address families are touched, with at most
/// `max_records` records per domain. Providers may cache their records; they
/// read them again every `refresh_interval`.
struct Daemon<R> {
    entries: Vec<Entry>,
    resolver: R,
    /// Time between checks.
    interval: Duration,
    /// Time after which providers read their records again; `None` never.
    refresh_interval: Option<Duration>,
}

impl Daemon<Vec<AnyResolver>> {
    /// The daemon for the configured providers; with `dry_run`, their
    /// clients only log the changes they would make.
    fn from_config(config: &Config, targets: Vec<Target>, dry_run: bool) -> Self {
        let entries = targets
            .into_iter()
            .map(|mut target| {
                target.client.set_dryrun(dry_run);
                Entry::new(target.name, target.client, target.max_records)
            })
            .collect();
        Daemon::new(
            entries,
            config.resolvers(),
            Duration::from_secs(config.interval),
            config.refresh_interval(),
        )
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::load(&args.config)
        .with_context(|| format!("load {} failed", args.config.display()))?;
    let targets = config
        .targets()
        .with_context(|| format!("invalid provider in {}", args.config.display()))?;
    let dry_run = matches!(args.command, Some(Command::DryRun));
    let mut daemon = Daemon::from_config(&config, targets, dry_run);
    match args.command {
        None => daemon.run().await,
        Some(Command::DryRun) => daemon.dry_run().await,
    }
}

impl<R: IpResolver> Daemon<R> {
    fn new(
        entries: Vec<Entry>,
        resolver: R,
        interval: Duration,
        refresh_interval: Option<Duration>,
    ) -> Self {
        Daemon {
            entries,
            resolver,
            interval,
            refresh_interval,
        }
    }

    /// Updates all providers every `interval`.
    async fn run(&mut self) -> Result<()> {
        loop {
            self.update_all().await;
            tokio::time::sleep(self.interval).await;
        }
    }

    /// Runs one update pass; meant for clients in dry-run mode, which only
    /// log the changes they would make. Fails if any provider failed.
    async fn dry_run(&mut self) -> Result<()> {
        let count = self.entries.len();
        let failed = self.update_all().await;
        if failed > 0 {
            bail!("{failed} of {count} providers failed");
        }
        Ok(())
    }

    /// Resolves the public IPs once and updates every provider that is due,
    /// first making it read its records again if it hasn't for
    /// `refresh_interval`.
    ///
    /// Returns the number of providers that were due but failed, all of them
    /// if no public address was found.
    async fn update_all(&mut self) -> usize {
        let now = Instant::now();
        let due = self.entries.iter().filter(|entry| entry.is_due(now));
        let (count, families) = (due.clone().count(), families(due));
        if families.is_empty() {
            return 0;
        }
        let addrs = resolve::resolve_public_ips(&self.resolver, &families).await;
        if addrs.is_empty() {
            log::warn!("no public ip address found");
            return count;
        }

        let mut failed = 0;

        let refresh_interval = self.refresh_interval;
        for entry in self.entries.iter_mut().filter(|entry| entry.is_due(now)) {
            let refresh = refresh_interval
                .is_some_and(|interval| now.duration_since(entry.refreshed_at) >= interval);
            let result = async {
                if refresh {
                    Self::refresh_entry(entry).await?;
                    entry.refreshed_at = now;
                }
                Self::update_entry(entry, &addrs).await
            }
            .await;
            match result {
                Ok(summary) if !summary.is_unchanged() => log::info!(
                    "{}: update complete: kept={}, updated={}, deleted={}, created={}",
                    entry.name,
                    summary.kept,
                    summary.updated,
                    summary.deleted,
                    summary.created
                ),
                Ok(_) => {}
                Err(err) => {
                    failed += 1;
                    let wait = entry
                        .client
                        .next_allowed_update()
                        .and_then(|at| at.checked_duration_since(Instant::now()));
                    match wait {
                        // less than `NEVER` has remained since it was set
                        Some(wait) if wait > NEVER / 2 => log::error!(
                            "{}: {err:#}; not trying this provider again, fix the configuration and restart",
                            entry.name
                        ),
                        Some(wait) => log::warn!(
                            "{}: update dns record failed: {err:#}; next attempt in {} min",
                            entry.name,
                            wait.as_secs().div_ceil(60)
                        ),
                        None => log::warn!("{}: update dns record failed: {err:#}", entry.name),
                    }
                }
            }
        }
        failed
    }

    /// Makes `entry`'s provider read the records again, and warns if they
    /// differ from what it had cached, i.e. they were changed outside ddnsd.
    /// Returns whether they did.
    async fn refresh_entry(entry: &mut Entry) -> Result<bool> {
        let client = &mut entry.client;
        let mut before = client.list().await?;
        client.refresh().await?;
        let mut after = client.list().await?;
        log::debug!("{}: refreshed records {after:?}", client.domain());
        before.sort();
        after.sort();
        if before == after {
            return Ok(false);
        }
        log::warn!(
            "{}: records changed outside ddnsd: expected {before:?}, found {after:?}",
            client.domain()
        );
        Ok(true)
    }

    /// Makes `entry`'s domain point at `ips`: stale records are replaced or
    /// removed, and new ones added up to `max_records`.
    async fn update_entry(entry: &mut Entry, ips: &[IpAddr]) -> Result<UpdateSummary> {
        let (keep, stale, add) = Self::changes(entry, ips).await?;
        if stale.is_empty() && add.is_empty() {
            log::debug!("{}: no record changes", entry.client.domain());
            return Ok(UpdateSummary {
                kept: keep.len(),
                ..Default::default()
            });
        }

        log::info!(
            "{}: record changes: keep={:?}, remove={:?}, add={:?}",
            entry.client.domain(),
            keep,
            stale,
            add
        );
        entry.client.update(keep.into_iter().chain(add)).await
    }

    /// The records to keep and remove, and the addresses to add (within
    /// `max_records`), for pointing `entry`'s domain at `ips`.
    async fn changes(
        entry: &mut Entry,
        ips: &[IpAddr],
    ) -> Result<(Vec<IpAddr>, Vec<IpAddr>, Vec<IpAddr>)> {
        let records = entry.client.list().await?;
        let ips: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|ip| entry.client.is_enabled(IpFamily::of(ip)))
            .collect();
        let (keep, stale, mut add) = diff_records(&records, &ips);

        // we don't want to exceed the max count
        add.truncate(entry.max_records.saturating_sub(keep.len()));
        Ok((keep, stale, add))
    }
}

/// The address families enabled for any of `entries`.
fn families<'a>(entries: impl Iterator<Item = &'a Entry>) -> Vec<IpFamily> {
    let (mut ipv4, mut ipv6) = (false, false);
    for entry in entries {
        ipv4 |= entry.client.is_enabled(IpFamily::V4);
        ipv6 |= entry.client.is_enabled(IpFamily::V6);
    }
    [(ipv4, IpFamily::V4), (ipv6, IpFamily::V6)]
        .into_iter()
        .filter_map(|(enabled, family)| enabled.then_some(family))
        .collect()
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
    use std::{
        net::IpAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use std::sync::Mutex;

    use anyhow::anyhow;
    use async_trait::async_trait;
    use ddns_clients::DynDnsProvider;

    use super::*;

    type TestDaemon = Daemon<Fixed>;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn daemon(entries: Vec<Entry>, refresh_interval: Option<Duration>) -> TestDaemon {
        Daemon::new(entries, Fixed, Duration::from_secs(300), refresh_interval)
    }

    struct Fixed;

    #[async_trait]
    impl IpResolver for Fixed {
        async fn resolve(&self, family: IpFamily) -> Result<Vec<IpAddr>> {
            Ok(match family {
                IpFamily::V4 => vec!["192.0.2.1".parse().unwrap()],
                IpFamily::V6 => vec![],
            })
        }
    }

    /// What an `OutcomeMock` did, shared with the test.
    #[derive(Default)]
    struct Counters {
        updates: AtomicUsize,
        refreshes: AtomicUsize,
        next_update: Mutex<Option<Instant>>,
    }

    impl Counters {
        fn updates(&self) -> usize {
            self.updates.load(Ordering::SeqCst)
        }

        fn refreshes(&self) -> usize {
            self.refreshes.load(Ordering::SeqCst)
        }
    }

    /// Has no records, and counts the changes and refreshes. With `wait`,
    /// every change fails and asks to wait that long before the next one.
    struct OutcomeMock {
        domain: String,
        wait: Option<Duration>,
        counters: Arc<Counters>,
    }

    impl OutcomeMock {
        fn change(&self) -> Result<()> {
            self.counters.updates.fetch_add(1, Ordering::SeqCst);
            let Some(wait) = self.wait else {
                return Ok(());
            };
            *self.counters.next_update.lock().unwrap() = Some(Instant::now() + wait);
            Err(anyhow!("try later"))
        }
    }

    #[async_trait]
    impl DynDnsProvider for OutcomeMock {
        fn domain(&self) -> &str {
            &self.domain
        }

        fn next_allowed_update(&self) -> Option<Instant> {
            *self.counters.next_update.lock().unwrap()
        }

        async fn list(&mut self) -> Result<Vec<IpAddr>> {
            Ok(vec![])
        }

        async fn refresh(&mut self) -> Result<()> {
            self.counters.refreshes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn add(&mut self, _ip: IpAddr, _ttl: Option<u32>) -> Result<()> {
            self.change()
        }

        async fn replace(&mut self, _old: IpAddr, _new: IpAddr, _ttl: Option<u32>) -> Result<()> {
            self.change()
        }

        async fn delete(&mut self, _ip: IpAddr) -> Result<()> {
            self.change()
        }
    }

    /// An entry on an `OutcomeMock`, and its counters.
    fn entry(name: &str, wait: Option<Duration>) -> (Entry, Arc<Counters>) {
        let counters = Arc::new(Counters::default());
        let mock = OutcomeMock {
            domain: format!("{name}.example.com"),
            wait,
            counters: counters.clone(),
        };
        let client = DynDnsClient::new(mock);
        (Entry::new(name.to_string(), client, 2), counters)
    }

    #[tokio::test]
    async fn waiting_provider_does_not_hold_up_others() {
        let (good, good_counters) = entry("good", None);
        let (bad, bad_counters) = entry("bad", Some(NEVER));
        let mut daemon = daemon(vec![bad, good], None);

        assert_eq!(daemon.update_all().await, 1);
        assert_eq!(bad_counters.updates(), 1);
        assert_eq!(good_counters.updates(), 1);

        // the waiting provider stays configured, and isn't tried
        assert_eq!(daemon.update_all().await, 0);
        assert_eq!(daemon.entries.len(), 2);
        assert_eq!(bad_counters.updates(), 1);
        assert_eq!(good_counters.updates(), 2);
    }

    #[tokio::test]
    async fn provider_waits_until_next_allowed_update() {
        let (busy, counters) = entry("busy", Some(Duration::from_secs(1800)));
        let mut daemon = daemon(vec![busy], Some(Duration::ZERO));

        daemon.update_all().await;
        assert_eq!(counters.updates(), 1);
        assert_eq!(counters.refreshes(), 1);

        // still waiting: not even the records are refreshed
        daemon.update_all().await;
        assert_eq!(counters.updates(), 1);
        assert_eq!(counters.refreshes(), 1);

        *counters.next_update.lock().unwrap() = Some(Instant::now());
        daemon.update_all().await;
        assert_eq!(counters.updates(), 2);
        assert_eq!(counters.refreshes(), 2);
    }

    #[tokio::test]
    async fn refreshes_when_due() {
        let (entry, counters) = entry("home", None);
        let mut daemon = daemon(vec![entry], Some(Duration::from_secs(3600)));

        // refreshed at creation, so not due within the hour
        daemon.update_all().await;
        assert_eq!(counters.refreshes(), 0);
        assert_eq!(counters.updates(), 1);

        daemon.refresh_interval = Some(Duration::ZERO);
        daemon.update_all().await;
        assert_eq!(counters.refreshes(), 1);

        // disabled
        daemon.refresh_interval = None;
        daemon.update_all().await;
        assert_eq!(counters.refreshes(), 1);
    }

    fn rec(id: &str, addr: &str) -> (String, IpAddr) {
        (id.to_string(), ip(addr))
    }

    #[derive(Default)]
    struct RecordsState {
        records: Vec<(String, IpAddr)>,
        /// A stale cache, listed instead of `records` until `refresh`.
        stale: Option<Vec<IpAddr>>,
        next_id: usize,
        fail_next: bool,
        list_calls: usize,
    }

    impl RecordsState {
        fn with(records: Vec<(String, IpAddr)>) -> Self {
            RecordsState {
                records,
                ..Default::default()
            }
        }

        fn check_fail(&mut self) -> Result<()> {
            if std::mem::take(&mut self.fail_next) {
                return Err(anyhow!("injected failure"));
            }
            Ok(())
        }

        fn position(&self, ip: IpAddr) -> Result<usize> {
            self.records
                .iter()
                .position(|(_, r)| *r == ip)
                .ok_or_else(|| anyhow!("host.example.com has no record for {ip}"))
        }

        fn ips(&self) -> Vec<IpAddr> {
            let mut ips: Vec<_> = self.records.iter().map(|(_, ip)| *ip).collect();
            ips.sort();
            ips
        }
    }

    /// Keeps records with ids in shared state, which the test inspects.
    struct RecordsMock(Arc<Mutex<RecordsState>>);

    #[async_trait]
    impl DynDnsProvider for RecordsMock {
        fn domain(&self) -> &str {
            "host.example.com"
        }

        async fn list(&mut self) -> Result<Vec<IpAddr>> {
            let mut state = self.0.lock().unwrap();
            state.list_calls += 1;
            state.check_fail()?;
            if let Some(stale) = &state.stale {
                return Ok(stale.clone());
            }
            Ok(state.records.iter().map(|(_, ip)| *ip).collect())
        }

        async fn refresh(&mut self) -> Result<()> {
            self.0.lock().unwrap().stale = None;
            Ok(())
        }

        async fn add(&mut self, ip: IpAddr, _ttl: Option<u32>) -> Result<()> {
            let state = &mut *self.0.lock().unwrap();
            state.check_fail()?;
            state.next_id += 1;
            state.records.push((format!("new{}", state.next_id), ip));
            Ok(())
        }

        async fn replace(&mut self, old: IpAddr, new: IpAddr, _ttl: Option<u32>) -> Result<()> {
            let state = &mut *self.0.lock().unwrap();
            state.check_fail()?;
            let i = state.position(old)?;
            state.records[i].1 = new;
            Ok(())
        }

        async fn delete(&mut self, ip: IpAddr) -> Result<()> {
            let state = &mut *self.0.lock().unwrap();
            state.check_fail()?;
            let i = state.position(ip)?;
            state.records.remove(i);
            Ok(())
        }
    }

    /// An entry (both families, at most 2 records) on a `RecordsMock`
    /// starting with `state`, and the shared state.
    fn records_entry(state: RecordsState) -> (Entry, Arc<Mutex<RecordsState>>) {
        records_entry_with(state, true, 2)
    }

    fn records_entry_with(
        state: RecordsState,
        ipv4: bool,
        max_records: usize,
    ) -> (Entry, Arc<Mutex<RecordsState>>) {
        let state = Arc::new(Mutex::new(state));
        let client = DynDnsClient::new(RecordsMock(state.clone())).enable_ipv4(ipv4);
        (Entry::new("host".to_string(), client, max_records), state)
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
        let state = RecordsState::with(vec![rec("a", "1.1.1.1")]);
        let (mut e, _) = records_entry(state);
        let summary = TestDaemon::update_entry(&mut e, &[ip("1.1.1.1")])
            .await
            .unwrap();
        assert!(summary.is_unchanged());
        assert_eq!(summary.kept, 1);
    }

    #[tokio::test]
    async fn creates_missing() {
        let (mut e, mock) = records_entry(RecordsState::default());
        let summary = TestDaemon::update_entry(&mut e, &[ip("1.1.1.1"), ip("2001:4860::1")])
            .await
            .unwrap();
        assert_eq!(summary.created, 2);
        assert_eq!(
            mock.lock().unwrap().ips(),
            vec![ip("1.1.1.1"), ip("2001:4860::1")]
        );
    }

    #[tokio::test]
    async fn replaces_via_update() {
        let state = RecordsState::with(vec![rec("a", "1.1.1.1")]);
        let (mut e, mock) = records_entry(state);
        let summary = TestDaemon::update_entry(&mut e, &[ip("2.2.2.2")])
            .await
            .unwrap();
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
        let state = RecordsState::with(vec![rec("a", "1.1.1.1"), rec("b", "2.2.2.2")]);
        let (mut e, mock) = records_entry(state);
        let summary = TestDaemon::update_entry(&mut e, &[ip("2.2.2.2")])
            .await
            .unwrap();
        assert_eq!(summary.deleted, 1);
        assert_eq!(mock.lock().unwrap().records, vec![rec("b", "2.2.2.2")]);
    }

    #[tokio::test]
    async fn deletes_duplicates() {
        let state = RecordsState::with(vec![rec("a", "1.1.1.1"), rec("b", "1.1.1.1")]);
        let (mut e, mock) = records_entry(state);
        let summary = TestDaemon::update_entry(&mut e, &[ip("1.1.1.1")])
            .await
            .unwrap();
        assert_eq!(summary.deleted, 1);
        // records are identified by address, so either duplicate may go
        assert_eq!(mock.lock().unwrap().ips(), vec![ip("1.1.1.1")]);
    }

    #[tokio::test]
    async fn caps_at_max_records() {
        let (mut e, mock) = records_entry_with(RecordsState::default(), true, 1);
        let summary = TestDaemon::update_entry(&mut e, &[ip("1.1.1.1"), ip("2.2.2.2")])
            .await
            .unwrap();
        assert_eq!(summary.created, 1);
        assert_eq!(mock.lock().unwrap().records.len(), 1);
    }

    #[tokio::test]
    async fn ignores_disabled_family() {
        let state = RecordsState::with(vec![rec("a", "1.1.1.1")]);
        let (mut e, mock) = records_entry_with(state, false, 2);
        let summary = TestDaemon::update_entry(&mut e, &[ip("2.2.2.2"), ip("2001:4860::1")])
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
        let state = RecordsState::with(vec![rec("a", "1.1.1.1"), rec("b", "2001:4860::1")]);
        let (mut e, mock) = records_entry_with(state, false, 2);
        let summary = TestDaemon::update_entry(&mut e, &[ip("2001:4860::2")])
            .await
            .unwrap();
        assert_eq!(summary.updated, 1);
        assert_eq!(summary.deleted + summary.created, 0);
        assert_eq!(
            mock.lock().unwrap().records,
            vec![rec("a", "1.1.1.1"), rec("b", "2001:4860::2")]
        );
    }

    #[tokio::test]
    async fn recovers_after_failure() {
        let (mut e, mock) = records_entry(RecordsState::default());
        TestDaemon::update_entry(&mut e, &[ip("1.1.1.1")])
            .await
            .unwrap();

        mock.lock().unwrap().fail_next = true;
        TestDaemon::update_entry(&mut e, &[ip("2.2.2.2")])
            .await
            .unwrap_err();

        TestDaemon::update_entry(&mut e, &[ip("2.2.2.2")])
            .await
            .unwrap();
        assert_eq!(mock.lock().unwrap().records, vec![rec("new1", "2.2.2.2")]);
    }

    #[tokio::test]
    async fn dry_run_changes_nothing() {
        let state = RecordsState::with(vec![rec("a", "1.1.1.1")]);
        let (mut e, mock) = records_entry(state);
        e.client.set_dryrun(true);
        let mut daemon = daemon(vec![e], None);

        assert_eq!(daemon.update_all().await, 0);
        assert_eq!(mock.lock().unwrap().records, vec![rec("a", "1.1.1.1")]);
    }

    #[tokio::test]
    async fn refresh_detects_outside_changes() {
        let mut state = RecordsState::with(vec![rec("a", "2.2.2.2")]);
        state.stale = Some(vec![ip("1.1.1.1")]);
        let (mut e, _) = records_entry(state);
        assert!(TestDaemon::refresh_entry(&mut e).await.unwrap());
        // up to date now
        assert!(!TestDaemon::refresh_entry(&mut e).await.unwrap());
    }
}
