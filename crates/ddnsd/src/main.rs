mod config;

use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ddns_clients::{DynDnsClient, IpResolver, providers::NEVER};

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
struct ProviderInstance {
    name: String,
    client: DynDnsClient,
    /// Time after which the provider reads its records again; `None` never.
    cache_expire: Option<Duration>,
    /// When the provider last read its records from the service.
    cache_refreshed_at: Instant,
    /// The addresses the domain should point at; empty until some are found.
    addrs: Vec<IpAddr>,
    /// `addrs` haven't been pushed to the provider yet, or the last push
    /// failed.
    pending: bool,
}

impl ProviderInstance {
    fn new(target: Target) -> Self {
        ProviderInstance {
            name: target.name,
            client: target.client,
            cache_expire: target.cache_expire,
            cache_refreshed_at: Instant::now(),
            addrs: vec![],
            pending: false,
        }
    }

    fn is_due(&self, now: Instant) -> bool {
        self.client.next_allowed_update().is_none_or(|at| at <= now)
    }

    /// Sets the addresses the domain should point at; they are pushed by
    /// [`tick`](Self::tick).
    fn set_addrs(&mut self, addrs: &[IpAddr]) {
        if self.addrs != addrs {
            self.addrs = addrs.to_vec();
            self.pending = true;
        }
    }

    /// Unless the provider asked to wait: reads the records again if they are
    /// older than `cache_expire`, then pushes the addresses if they changed,
    /// the records were read again, or the last push failed. Failures are
    /// logged, and retried on the next tick.
    async fn tick(&mut self) {
        // nothing to push yet: an empty set would remove all records
        if self.addrs.is_empty() || !self.is_due(Instant::now()) {
            return;
        }
        let cache_expired = self
            .cache_expire
            .is_some_and(|interval| self.cache_refreshed_at.elapsed() >= interval);
        if cache_expired {
            if let Err(err) = self.client.refresh_cache().await {
                self.log_failure(&err);
                return;
            }
            self.cache_refreshed_at = Instant::now();
            // the records may have been changed elsewhere
            self.pending = true;
        }
        if !self.pending {
            return;
        }

        let summary = match self.client.update(self.addrs.iter().copied()).await {
            Ok(summary) => summary,
            Err(err) => {
                self.log_failure(&err);
                return;
            }
        };
        if !summary.is_unchanged() {
            log::info!(
                "{}: update complete: kept={}, updated={}, deleted={}, created={}",
                self.name,
                summary.kept,
                summary.updated,
                summary.deleted,
                summary.created
            );
        } else {
            log::info!("{}: {} is up to date", self.name, self.client.domain());
        }
        self.pending = false;
    }

    /// Logs that an update failed with `err`, and when the next one is.
    fn log_failure(&self, err: &anyhow::Error) {
        let wait = self
            .client
            .next_allowed_update()
            .and_then(|at| at.checked_duration_since(Instant::now()));
        match wait {
            // less than `NEVER` has remained since it was set
            Some(wait) if wait > NEVER / 2 => log::error!(
                "{}: {err:#}; not trying this provider again, fix the configuration and restart",
                self.name
            ),
            Some(wait) => log::warn!(
                "{}: update dns record failed: {err:#}; next attempt in {} min",
                self.name,
                wait.as_secs().div_ceil(60)
            ),
            None => log::warn!("{}: update dns record failed: {err:#}", self.name),
        }
    }
}

/// Keeps the domains of all configured providers pointed at this host's
/// public addresses, found with `resolver`.
///
/// The daemon checks every `tick_interval`: it looks up the addresses once
/// `resolve_interval` has passed, and updates the providers whose addresses
/// changed or whose last update failed, unless they asked to wait, e.g. after
/// a server error. Each client keeps to its address families and
/// `max_records`. Providers may cache their records; each reads them again
/// every `cache_expire` of its own.
struct Daemon {
    providers: Vec<ProviderInstance>,
    resolver: Box<dyn IpResolver>,
    /// Whether public IPv4 addresses are looked up.
    ipv4: bool,
    /// Whether public IPv6 addresses are looked up.
    ipv6: bool,
    /// Time between lookups of the public addresses.
    resolve_interval: Duration,
    /// Time between checks.
    tick_interval: Duration,
    /// When the last lookup started; `None` before the first one.
    resolved_at: Option<Instant>,
    /// The sorted public addresses of each family last found, which the
    /// providers are updated to; empty if none has been yet.
    public_ipv4: Vec<Ipv4Addr>,
    public_ipv6: Vec<Ipv6Addr>,
    /// Set when the local addresses changed, to look up the public ones at
    /// the next check.
    addresses_changed: Arc<AtomicBool>,
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
        None => {
            #[cfg(target_os = "linux")]
            watch_addresses(
                config.watch_interface.clone(),
                daemon.addresses_changed.clone(),
            );
            daemon.run().await
        }
        Some(Command::DryRun) => daemon.dry_run().await,
    }
}

/// Sets `changed` whenever the global addresses of `interface`, or of all
/// interfaces, change; in the background, until the netlink socket fails.
#[cfg(target_os = "linux")]
fn watch_addresses(interface: Option<String>, changed: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut monitor =
            match ddns_clients::resolve::AddressMonitor::new(interface.as_deref()).await {
                Ok(monitor) => monitor,
                Err(err) => {
                    log::warn!("not watching local addresses: {err:#}");
                    return;
                }
            };
        loop {
            if let Err(err) = monitor.changed().await {
                log::warn!("stopped watching local addresses: {err:#}");
                return;
            }
            log::info!("local addresses changed");
            changed.store(true, Ordering::Relaxed);
        }
    });
}

impl Daemon {
    /// The daemon for the configured providers; with `dry_run`, their
    /// clients only log the changes they would make.
    fn from_config(config: &Config, targets: Vec<Target>, dry_run: bool) -> Self {
        let providers = targets
            .into_iter()
            .map(|mut target| {
                target.client.set_dryrun(dry_run);
                ProviderInstance::new(target)
            })
            .collect();
        Daemon::new(
            providers,
            config.resolver(),
            config.ipv4,
            config.ipv6,
            config.resolve_interval,
            config.tick,
        )
    }

    fn new(
        providers: Vec<ProviderInstance>,
        resolver: impl IpResolver + 'static,
        ipv4: bool,
        ipv6: bool,
        resolve_interval: Duration,
        tick_interval: Duration,
    ) -> Self {
        Daemon {
            providers,
            resolver: Box::new(resolver),
            ipv4,
            ipv6,
            resolve_interval,
            tick_interval,
            resolved_at: None,
            public_ipv4: vec![],
            public_ipv6: vec![],
            addresses_changed: Arc::default(),
        }
    }

    /// Checks every `tick_interval`.
    async fn run(&mut self) -> Result<()> {
        loop {
            self.tick().await;
            tokio::time::sleep(self.tick_interval).await;
        }
    }

    /// Runs one check; meant for clients in dry-run mode, which only log the
    /// changes they would make. Fails if no address was found or any
    /// provider failed.
    async fn dry_run(&mut self) -> Result<()> {
        self.tick().await;
        if self.public_ipv4.is_empty() && self.public_ipv6.is_empty() {
            bail!("no public ip address found");
        }
        let count = self.providers.len();
        let failed = self.providers.iter().filter(|p| p.pending).count();
        if failed > 0 {
            bail!("{failed} of {count} providers failed");
        }
        Ok(())
    }

    /// Looks up the public addresses if `resolve_interval` has passed since
    /// the last lookup or the local addresses changed, passes them on to the
    /// providers, and lets each one update.
    async fn tick(&mut self) {
        if self.addresses_changed.swap(false, Ordering::Relaxed) {
            self.resolved_at = None;
        }
        if self
            .resolved_at
            .is_none_or(|at| at.elapsed() >= self.resolve_interval)
        {
            self.resolve().await;
            let ipv4 = self.public_ipv4.iter().copied().map(IpAddr::from);
            let ipv6 = self.public_ipv6.iter().copied().map(IpAddr::from);
            let addrs: Vec<IpAddr> = ipv4.chain(ipv6).collect();
            if !addrs.is_empty() {
                for provider in &mut self.providers {
                    provider.set_addrs(&addrs);
                }
            }
        }
        for provider in &mut self.providers {
            provider.tick().await;
        }
    }

    /// Looks up the public addresses of the configured families, whatever
    /// the providers' state, and logs them if they changed. A failed lookup or
    /// finding none keeps the previous ones, as the lookup may just have
    /// failed.
    async fn resolve(&mut self) {
        self.resolved_at = Some(Instant::now());
        let mut found = false;
        if self.ipv4 {
            let result = self.resolver.resolve_a().await;
            found |= update_known("IPv4", &mut self.public_ipv4, result);
        }
        if self.ipv6 {
            let result = self.resolver.resolve_aaaa().await;
            found |= update_known("IPv6", &mut self.public_ipv6, result);
        }
        if !found {
            log::warn!("no public ip address found");
        }
    }
}

/// Replaces the `known` addresses of `family` ("IPv4" or "IPv6") with the
/// sorted result of a lookup, logging them if they changed; keeps them if the
/// lookup failed or found none. Returns whether it found any.
fn update_known<T: Ord + Debug>(family: &str, known: &mut Vec<T>, result: Result<Vec<T>>) -> bool {
    match result {
        Ok(mut new) if !new.is_empty() => {
            new.sort();
            if known.is_empty() {
                log::info!("public {family} address: {new:?}");
            } else if *known != new {
                log::info!("public {family} address changed: {known:?} -> {new:?}");
            }
            *known = new;
            true
        }
        Ok(_) => false,
        Err(err) => {
            log::warn!("no {family} address resolved: {err:#}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const TICK: Duration = Duration::from_secs(10);

    fn daemon(providers: Vec<ProviderInstance>) -> Daemon {
        Daemon::new(providers, Fixed, true, true, Duration::from_secs(300), TICK)
    }

    /// A provider that never reads its records again.
    fn instance(name: &str, client: DynDnsClient) -> ProviderInstance {
        ProviderInstance::new(Target {
            name: name.to_string(),
            client,
            cache_expire: None,
        })
    }

    #[derive(Debug)]
    struct Fixed;

    #[async_trait]
    impl IpResolver for Fixed {
        async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
            Ok(vec![Ipv4Addr::new(192, 0, 2, 1)])
        }

        async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
            Ok(vec![])
        }
    }

    /// Answers IPv4 lookups with the shared addresses, or fails on `None`;
    /// finds no IPv6 address.
    #[derive(Debug)]
    struct Scripted(Arc<Mutex<Option<Vec<Ipv4Addr>>>>);

    #[async_trait]
    impl IpResolver for Scripted {
        async fn resolve_a(&self) -> Result<Vec<Ipv4Addr>> {
            let answer = self.0.lock().unwrap().clone();
            answer.ok_or_else(|| anyhow!("lookup failed"))
        }

        async fn resolve_aaaa(&self) -> Result<Vec<Ipv6Addr>> {
            Ok(vec![])
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

        async fn refresh_cache(&mut self) -> Result<()> {
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
    fn entry(name: &str, wait: Option<Duration>) -> (ProviderInstance, Arc<Counters>) {
        let counters = Arc::new(Counters::default());
        let mock = OutcomeMock {
            domain: format!("{name}.example.com"),
            wait,
            counters: counters.clone(),
        };
        let client = DynDnsClient::new(mock);
        (instance(name, client), counters)
    }

    #[tokio::test]
    async fn waiting_provider_does_not_hold_up_others() {
        let (good, good_counters) = entry("good", None);
        let (bad, bad_counters) = entry("bad", Some(NEVER));
        let mut daemon = daemon(vec![bad, good]);

        daemon.tick().await;
        assert_eq!(bad_counters.updates(), 1);
        assert_eq!(good_counters.updates(), 1);

        // the waiting provider stays configured, and isn't tried; the other
        // one is up to date, so isn't pushed to again
        daemon.tick().await;
        assert_eq!(daemon.providers.len(), 2);
        assert_eq!(bad_counters.updates(), 1);
        assert!(daemon.providers[0].pending);
        assert_eq!(good_counters.updates(), 1);
        assert!(!daemon.providers[1].pending);
    }

    #[tokio::test]
    async fn provider_waits_until_next_allowed_update() {
        let (mut busy, counters) = entry("busy", Some(Duration::from_secs(1800)));
        busy.cache_expire = Some(Duration::ZERO);
        let mut daemon = daemon(vec![busy]);

        daemon.tick().await;
        assert_eq!(counters.updates(), 1);
        assert_eq!(counters.refreshes(), 1);

        // still waiting: not even the records are refreshed
        daemon.tick().await;
        assert_eq!(counters.updates(), 1);
        assert_eq!(counters.refreshes(), 1);

        *counters.next_update.lock().unwrap() = Some(Instant::now());
        daemon.tick().await;
        assert_eq!(counters.updates(), 2);
        assert_eq!(counters.refreshes(), 2);
    }

    #[tokio::test]
    async fn refreshes_when_due() {
        let (mut hourly, counters) = entry("hourly", None);
        hourly.cache_expire = Some(Duration::from_secs(3600));
        let (mut always, always_counters) = entry("always", None);
        always.cache_expire = Some(Duration::ZERO);
        let (never, never_counters) = entry("never", None);
        let mut daemon = daemon(vec![hourly, always, never]);

        // each provider follows its own interval; the hourly one was
        // refreshed at creation, so isn't due within the hour
        daemon.tick().await;
        assert_eq!(counters.updates(), 1);
        assert_eq!(counters.refreshes(), 0);
        assert_eq!(always_counters.refreshes(), 1);
        assert_eq!(never_counters.refreshes(), 0);

        daemon.providers[0].cache_expire = Some(Duration::ZERO);
        daemon.tick().await;
        assert_eq!(counters.refreshes(), 1);
        assert_eq!(always_counters.refreshes(), 2);
        assert_eq!(never_counters.refreshes(), 0);
    }

    fn rec(id: &str, addr: &str) -> (String, IpAddr) {
        (id.to_string(), ip(addr))
    }

    #[derive(Default)]
    struct RecordsState {
        records: Vec<(String, IpAddr)>,
        next_id: usize,
    }

    impl RecordsState {
        fn with(records: Vec<(String, IpAddr)>) -> Self {
            RecordsState {
                records,
                ..Default::default()
            }
        }

        fn position(&self, ip: IpAddr) -> Result<usize> {
            self.records
                .iter()
                .position(|(_, r)| *r == ip)
                .ok_or_else(|| anyhow!("host.example.com has no record for {ip}"))
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
            let state = self.0.lock().unwrap();
            Ok(state.records.iter().map(|(_, ip)| *ip).collect())
        }

        async fn add(&mut self, ip: IpAddr, _ttl: Option<u32>) -> Result<()> {
            let state = &mut *self.0.lock().unwrap();
            state.next_id += 1;
            state.records.push((format!("new{}", state.next_id), ip));
            Ok(())
        }

        async fn replace(&mut self, old: IpAddr, new: IpAddr, _ttl: Option<u32>) -> Result<()> {
            let state = &mut *self.0.lock().unwrap();
            let i = state.position(old)?;
            state.records[i].1 = new;
            Ok(())
        }

        async fn delete(&mut self, ip: IpAddr) -> Result<()> {
            let state = &mut *self.0.lock().unwrap();
            let i = state.position(ip)?;
            state.records.remove(i);
            Ok(())
        }
    }

    /// An entry on a `RecordsMock` starting with `state`, and the shared
    /// state.
    fn records_entry(state: RecordsState) -> (ProviderInstance, Arc<Mutex<RecordsState>>) {
        let state = Arc::new(Mutex::new(state));
        let client = DynDnsClient::new(RecordsMock(state.clone()));
        (instance("host", client), state)
    }

    #[tokio::test]
    async fn dry_run_changes_nothing() {
        let state = RecordsState::with(vec![rec("a", "1.1.1.1")]);
        let (mut e, mock) = records_entry(state);
        e.client.set_dryrun(true);
        let mut daemon = daemon(vec![e]);

        daemon.dry_run().await.unwrap();
        assert_eq!(mock.lock().unwrap().records, vec![rec("a", "1.1.1.1")]);
    }

    #[tokio::test]
    async fn resolves_while_no_provider_is_due() {
        let (bad, counters) = entry("bad", Some(NEVER));
        let mut daemon = Daemon::new(vec![bad], Fixed, true, true, Duration::ZERO, TICK);

        daemon.tick().await;
        daemon.public_ipv4.clear();
        // the provider is waiting, but the addresses are looked up anyway
        daemon.tick().await;
        assert_eq!(daemon.public_ipv4, [Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(counters.updates(), 1);
    }

    #[tokio::test]
    async fn resolves_only_every_resolve_interval() {
        let (good, _) = entry("good", None);
        let mut daemon = daemon(vec![good]);

        daemon.tick().await;
        daemon.public_ipv4.clear();
        daemon.tick().await;
        assert!(daemon.public_ipv4.is_empty());
    }

    #[tokio::test]
    async fn resolves_after_addresses_changed() {
        let (good, _) = entry("good", None);
        let mut daemon = daemon(vec![good]);

        daemon.tick().await;
        daemon.public_ipv4.clear();
        daemon.addresses_changed.store(true, Ordering::Relaxed);
        daemon.tick().await;
        assert!(!daemon.public_ipv4.is_empty());
        assert!(!daemon.addresses_changed.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn retries_failed_update_every_tick() {
        // fails, without asking to wait
        let (bad, counters) = entry("bad", Some(Duration::ZERO));
        let mut daemon = daemon(vec![bad]);

        for _ in 0..3 {
            daemon.tick().await;
        }
        assert_eq!(counters.updates(), 3);
        assert!(daemon.providers[0].pending);
    }

    #[tokio::test]
    async fn updates_when_addresses_change() {
        let answer = Arc::new(Mutex::new(Some(vec![Ipv4Addr::new(192, 0, 2, 1)])));
        let (good, counters) = entry("good", None);
        let resolver = Scripted(answer.clone());
        let mut daemon = Daemon::new(vec![good], resolver, true, true, Duration::ZERO, TICK);

        daemon.tick().await;
        daemon.tick().await;
        assert_eq!(counters.updates(), 1);

        *answer.lock().unwrap() = Some(vec![Ipv4Addr::new(192, 0, 2, 2)]);
        daemon.tick().await;
        assert_eq!(counters.updates(), 2);
    }

    #[tokio::test]
    async fn waits_for_addresses() {
        let (mut good, counters) = entry("good", None);
        // without addresses, the records are left alone
        good.tick().await;
        assert_eq!(counters.updates(), 0);

        let addrs = [ip("192.0.2.1")];
        good.set_addrs(&addrs);
        assert!(good.pending);
        good.tick().await;
        assert!(!good.pending);
        // the same addresses again aren't a change
        good.set_addrs(&addrs);
        assert!(!good.pending);
        assert_eq!(counters.updates(), 1);
    }

    #[tokio::test]
    async fn tracks_public_ips() {
        let (a, b) = (Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2));
        let answer = Arc::new(Mutex::new(Some(vec![b])));
        let resolver = Scripted(answer.clone());
        let mut daemon = Daemon::new(vec![], resolver, true, true, Duration::ZERO, TICK);

        daemon.resolve().await;
        assert_eq!(daemon.public_ipv4, [b]);
        // kept sorted, so another order compares equal
        *answer.lock().unwrap() = Some(vec![b, a]);
        daemon.resolve().await;
        assert_eq!(daemon.public_ipv4, [a, b]);
        assert!(daemon.public_ipv6.is_empty());

        // a failed or empty lookup keeps the known addresses
        *answer.lock().unwrap() = Some(vec![]);
        daemon.resolve().await;
        *answer.lock().unwrap() = None;
        daemon.resolve().await;
        assert_eq!(daemon.public_ipv4, [a, b]);
    }
}
