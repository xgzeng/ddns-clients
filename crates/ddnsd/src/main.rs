mod config;
mod updater;

use std::{
    fmt::Write as _,
    net::IpAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ddns_clients::{
    Error, IpResolver, UpdatePreview,
    resolve::{self, IpFamily},
};

use config::{Config, Target};
use updater::Updater;

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
    /// Resolve the public IPs once and show what each provider's records
    /// would become, without changing them.
    DryRun,
}

/// A configured provider and its update state.
struct Entry {
    name: String,
    updater: Updater,
    /// Set after the provider asked to wait; no update before then.
    retry_at: Option<Instant>,
    /// The provider rejected an update; it is not tried again.
    rejected: bool,
    /// When the provider last read its records from the service.
    refreshed_at: Instant,
}

impl Entry {
    fn new(name: String, updater: Updater) -> Self {
        Entry {
            name,
            updater,
            retry_at: None,
            rejected: false,
            refreshed_at: Instant::now(),
        }
    }

    fn is_due(&self, now: Instant) -> bool {
        self.retry_at.is_none_or(|at| at <= now)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    // a dry run reports on stdout; only problems are logged
    let default_level = match args.command {
        None => "info",
        Some(Command::DryRun) => "warn",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_level))
        .init();

    let config = Config::load(&args.config)
        .with_context(|| format!("load {} failed", args.config.display()))?;
    let targets = config
        .targets()
        .with_context(|| format!("invalid provider in {}", args.config.display()))?;
    match args.command {
        None => run(&config, targets).await,
        Some(Command::DryRun) => dry_run(&config, targets).await,
    }
}

/// Runs the daemon: updates all providers every `interval`, until every
/// provider has rejected its updates.
async fn run(config: &Config, targets: Vec<Target>) -> Result<()> {
    let mut entries: Vec<Entry> = targets
        .into_iter()
        .map(|target| Entry::new(target.name, Updater::new(target.client, target.max_records)))
        .collect();
    let resolvers = config.resolvers();

    let interval = Duration::from_secs(config.interval);
    let refresh_interval = config.refresh_interval();
    loop {
        update_all(&resolvers, &mut entries, refresh_interval).await;
        if entries.is_empty() {
            bail!("all providers rejected their updates, fix the configuration and restart");
        }
        tokio::time::sleep(interval).await;
    }
}

/// Resolves the public IPs once and prints what each provider's records would
/// become. Only reads from the providers.
async fn dry_run(config: &Config, targets: Vec<Target>) -> Result<()> {
    let (mut ipv4, mut ipv6) = (false, false);
    for target in &targets {
        ipv4 |= target.client.is_enabled(IpFamily::V4);
        ipv6 |= target.client.is_enabled(IpFamily::V6);
    }
    let families: Vec<IpFamily> = [(ipv4, IpFamily::V4), (ipv6, IpFamily::V6)]
        .into_iter()
        .filter_map(|(enabled, family)| enabled.then_some(family))
        .collect();
    let addrs = resolve::resolve_public_ips(&config.resolvers(), &families).await;
    println!("public addresses: {}", addresses(&addrs));
    if addrs.is_empty() {
        bail!("no public ip address found");
    }

    let mut failed = 0;
    let count = targets.len();
    for target in targets {
        let domain = target.client.domain().to_string();
        let mut updater = Updater::new(target.client, target.max_records);
        match updater.preview_ips(&addrs).await {
            Ok(preview) => print!("{}", describe(&target.name, &domain, &preview)),
            Err(err) => {
                failed += 1;
                println!(
                    "\n[{}] {domain}\n  failed: {:#}",
                    target.name,
                    anyhow::Error::from(err)
                );
            }
        }
    }
    if failed > 0 {
        bail!("{failed} of {count} providers failed");
    }
    Ok(())
}

/// A dry run's report for one provider.
fn describe(name: &str, domain: &str, preview: &UpdatePreview) -> String {
    let mut out = format!("\n[{name}] {domain}\n");
    let _ = writeln!(out, "  current: {}", addresses(&preview.before));
    let summary = &preview.summary;
    if summary.is_unchanged() {
        out.push_str("  no changes\n");
        return out;
    }
    let _ = writeln!(out, "  after:   {}", addresses(&preview.after));
    let changes: Vec<String> = [
        (summary.updated, "re-pointed"),
        (summary.deleted, "deleted"),
        (summary.created, "created"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, what)| format!("{n} {what}"))
    .collect();
    let _ = writeln!(out, "  changes: {}", changes.join(", "));
    out
}

fn addresses(ips: &[IpAddr]) -> String {
    if ips.is_empty() {
        return "none".to_string();
    }
    ips.iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolves the public IPs once and updates every provider that is due,
/// first making it read its records again if it hasn't for
/// `refresh_interval`. Providers that reject an update are removed from
/// `entries`.
async fn update_all<R: IpResolver>(
    resolver: &R,
    entries: &mut Vec<Entry>,
    refresh_interval: Option<Duration>,
) {
    let now = Instant::now();
    let (mut ipv4, mut ipv6) = (false, false);
    for entry in entries.iter().filter(|entry| entry.is_due(now)) {
        ipv4 |= entry.updater.client().is_enabled(IpFamily::V4);
        ipv6 |= entry.updater.client().is_enabled(IpFamily::V6);
    }
    let families: Vec<IpFamily> = [(ipv4, IpFamily::V4), (ipv6, IpFamily::V6)]
        .into_iter()
        .filter_map(|(enabled, family)| enabled.then_some(family))
        .collect();
    if families.is_empty() {
        return;
    }

    let addrs = resolve::resolve_public_ips(resolver, &families).await;
    if addrs.is_empty() {
        log::warn!("no public ip address found");
        return;
    }

    for entry in entries.iter_mut().filter(|entry| entry.is_due(now)) {
        entry.retry_at = None;
        let refresh = refresh_interval
            .is_some_and(|interval| now.duration_since(entry.refreshed_at) >= interval);
        let result = async {
            if refresh {
                entry.updater.refresh().await?;
                entry.refreshed_at = now;
            }
            entry.updater.update_ips(&addrs).await
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
                match &err {
                    Error::Rejected(_) => entry.rejected = true,
                    Error::Unavailable { retry_after, .. } => {
                        entry.retry_at = Some(now + *retry_after);
                    }
                    _ => {}
                }
                let err = anyhow::Error::from(err);
                if entry.rejected {
                    log::error!(
                        "{}: {err:#}; giving up on this provider, fix the configuration and restart",
                        entry.name
                    );
                } else {
                    log::warn!("{}: update dns record failed: {err:#}", entry.name);
                }
            }
        }
    }
    entries.retain(|entry| !entry.rejected);
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

    use async_trait::async_trait;
    use ddns_clients::{DynDnsClient, DynDnsProvider, UpdateSummary};

    use super::*;

    struct Fixed;

    #[async_trait]
    impl IpResolver for Fixed {
        async fn resolve(&self, family: IpFamily) -> ddns_clients::Result<Vec<IpAddr>> {
            Ok(match family {
                IpFamily::V4 => vec!["192.0.2.1".parse().unwrap()],
                IpFamily::V6 => vec![],
            })
        }
    }

    #[derive(Clone, Copy)]
    enum Outcome {
        Succeed,
        Reject,
        Unavailable(Duration),
    }

    /// Has no records, answers every change with `outcome` and counts the
    /// changes and refreshes.
    struct Mock {
        domain: String,
        outcome: Outcome,
        updates: Arc<AtomicUsize>,
        refreshes: Arc<AtomicUsize>,
    }

    impl Mock {
        fn change(&self) -> ddns_clients::Result<()> {
            self.updates.fetch_add(1, Ordering::SeqCst);
            match self.outcome {
                Outcome::Succeed => Ok(()),
                Outcome::Reject => Err(Error::rejected("badauth")),
                Outcome::Unavailable(retry_after) => Err(Error::unavailable(retry_after, "911")),
            }
        }
    }

    #[async_trait]
    impl DynDnsProvider for Mock {
        fn domain(&self) -> &str {
            &self.domain
        }

        async fn list(&mut self) -> ddns_clients::Result<Vec<IpAddr>> {
            Ok(vec![])
        }

        async fn refresh(&mut self) -> ddns_clients::Result<()> {
            self.refreshes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn add(&mut self, _ip: IpAddr, _ttl: Option<u32>) -> ddns_clients::Result<()> {
            self.change()
        }

        async fn replace(
            &mut self,
            _old: IpAddr,
            _new: IpAddr,
            _ttl: Option<u32>,
        ) -> ddns_clients::Result<()> {
            self.change()
        }

        async fn delete(&mut self, _ip: IpAddr) -> ddns_clients::Result<()> {
            self.change()
        }
    }

    /// An entry on a `Mock`, and its counters of changes and refreshes.
    fn entry(name: &str, outcome: Outcome) -> (Entry, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let updates = Arc::new(AtomicUsize::new(0));
        let refreshes = Arc::new(AtomicUsize::new(0));
        let mock = Mock {
            domain: format!("{name}.example.com"),
            outcome,
            updates: updates.clone(),
            refreshes: refreshes.clone(),
        };
        let client = DynDnsClient::new(mock);
        let entry = Entry::new(name.to_string(), Updater::new(client, 2));
        (entry, updates, refreshes)
    }

    #[tokio::test]
    async fn rejected_provider_is_dropped() {
        let (good, good_updates, _) = entry("good", Outcome::Succeed);
        let (bad, bad_updates, _) = entry("bad", Outcome::Reject);
        let mut entries = vec![bad, good];

        update_all(&Fixed, &mut entries, None).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "good");
        assert_eq!(bad_updates.load(Ordering::SeqCst), 1);
        assert_eq!(good_updates.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unavailable_provider_waits() {
        let (busy, busy_updates, _) =
            entry("busy", Outcome::Unavailable(Duration::from_secs(1800)));
        let mut entries = vec![busy];

        update_all(&Fixed, &mut entries, None).await;
        assert_eq!(busy_updates.load(Ordering::SeqCst), 1);
        assert!(entries[0].retry_at.is_some());

        // still waiting: not even the records are refreshed
        update_all(&Fixed, &mut entries, None).await;
        assert_eq!(busy_updates.load(Ordering::SeqCst), 1);

        entries[0].retry_at = Some(Instant::now());
        update_all(&Fixed, &mut entries, None).await;
        assert_eq!(busy_updates.load(Ordering::SeqCst), 2);
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn refreshes_when_due() {
        let (entry, updates, refreshes) = entry("home", Outcome::Succeed);
        let mut entries = vec![entry];

        // refreshed at creation, so not due within the hour
        update_all(&Fixed, &mut entries, Some(Duration::from_secs(3600))).await;
        assert_eq!(refreshes.load(Ordering::SeqCst), 0);
        assert_eq!(updates.load(Ordering::SeqCst), 1);

        update_all(&Fixed, &mut entries, Some(Duration::ZERO)).await;
        assert_eq!(refreshes.load(Ordering::SeqCst), 1);

        // disabled
        update_all(&Fixed, &mut entries, None).await;
        assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn describes_preview() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let preview = UpdatePreview {
            before: vec![ip("192.0.2.9")],
            after: vec![ip("192.0.2.1"), ip("2001:db8::1")],
            summary: UpdateSummary {
                kept: 0,
                updated: 1,
                deleted: 0,
                created: 1,
            },
        };
        assert_eq!(
            describe("home", "home.example.com", &preview),
            "\n[home] home.example.com\n  current: 192.0.2.9\n  after:   192.0.2.1, 2001:db8::1\n  changes: 1 re-pointed, 1 created\n"
        );

        let unchanged = UpdatePreview {
            before: vec![],
            after: vec![],
            summary: UpdateSummary::default(),
        };
        assert_eq!(
            describe("noip", "myhost.ddns.net", &unchanged),
            "\n[noip] myhost.ddns.net\n  current: none\n  no changes\n"
        );
    }
}
