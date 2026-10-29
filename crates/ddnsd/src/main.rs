mod config;
mod updater;

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use ddns_clients::{
    Error, IpResolver,
    resolve::{self, IpFamily},
};

use config::Config;
use updater::Updater;

/// Dynamic DNS daemon: keeps domains' A/AAAA records pointed at this host.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "/etc/ddnsd.toml")]
    config: PathBuf,
}

/// A configured provider and its update state.
struct Entry {
    name: String,
    updater: Updater,
    /// Set after the provider asked to wait; no update before then.
    retry_at: Option<Instant>,
    /// The provider rejected an update; it is not tried again.
    rejected: bool,
}

impl Entry {
    fn is_due(&self, now: Instant) -> bool {
        self.retry_at.is_none_or(|at| at <= now)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let config = Config::load(&args.config)
        .with_context(|| format!("load {} failed", args.config.display()))?;
    let targets = config
        .targets()
        .with_context(|| format!("invalid provider in {}", args.config.display()))?;
    let mut entries: Vec<Entry> = targets
        .into_iter()
        .map(|target| Entry {
            name: target.name,
            updater: Updater::new(target.client, target.max_records),
            retry_at: None,
            rejected: false,
        })
        .collect();
    let resolvers = config.resolvers();

    let interval = Duration::from_secs(config.interval);
    loop {
        update_all(&resolvers, &mut entries).await;
        if entries.is_empty() {
            bail!("all providers rejected their updates, fix the configuration and restart");
        }
        tokio::time::sleep(interval).await;
    }
}

/// Resolves the public IPs once and updates every provider that is due.
/// Providers that reject an update are removed from `entries`.
async fn update_all<R: IpResolver>(resolver: &R, entries: &mut Vec<Entry>) {
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
        match entry.updater.update_ips(&addrs).await {
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
    use ddns_clients::{
        DynDnsClient, DynDnsProvider, RecordUpdateRequest, UpdateRequestBuilder, UpdateSummary,
    };

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

    /// Answers every update with `outcome` and counts the updates.
    struct Mock {
        outcome: Outcome,
        updates: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DynDnsProvider for Mock {
        async fn list(&mut self, _domain: &str) -> ddns_clients::Result<Vec<IpAddr>> {
            Ok(vec![])
        }

        fn update_request<'a>(&'a mut self, domain: &str) -> UpdateRequestBuilder<'a> {
            UpdateRequestBuilder::new(self, domain)
        }

        async fn execute_request(
            &mut self,
            _request: RecordUpdateRequest,
        ) -> ddns_clients::Result<UpdateSummary> {
            self.updates.fetch_add(1, Ordering::SeqCst);
            match self.outcome {
                Outcome::Succeed => Ok(UpdateSummary::default()),
                Outcome::Reject => Err(Error::rejected("badauth")),
                Outcome::Unavailable(retry_after) => Err(Error::unavailable(retry_after, "911")),
            }
        }
    }

    fn entry(name: &str, outcome: Outcome) -> (Entry, Arc<AtomicUsize>) {
        let updates = Arc::new(AtomicUsize::new(0));
        let mock = Mock {
            outcome,
            updates: updates.clone(),
        };
        let client = DynDnsClient::new(mock, format!("{name}.example.com"));
        let entry = Entry {
            name: name.to_string(),
            updater: Updater::new(client, 2),
            retry_at: None,
            rejected: false,
        };
        (entry, updates)
    }

    #[tokio::test]
    async fn rejected_provider_is_dropped() {
        let (good, good_updates) = entry("good", Outcome::Succeed);
        let (bad, bad_updates) = entry("bad", Outcome::Reject);
        let mut entries = vec![bad, good];

        update_all(&Fixed, &mut entries).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "good");
        assert_eq!(bad_updates.load(Ordering::SeqCst), 1);
        assert_eq!(good_updates.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unavailable_provider_waits() {
        let (busy, busy_updates) = entry("busy", Outcome::Unavailable(Duration::from_secs(1800)));
        let mut entries = vec![busy];

        update_all(&Fixed, &mut entries).await;
        assert_eq!(busy_updates.load(Ordering::SeqCst), 1);
        assert!(entries[0].retry_at.is_some());

        // still waiting: not even the records are refreshed
        update_all(&Fixed, &mut entries).await;
        assert_eq!(busy_updates.load(Ordering::SeqCst), 1);

        entries[0].retry_at = Some(Instant::now());
        update_all(&Fixed, &mut entries).await;
        assert_eq!(busy_updates.load(Ordering::SeqCst), 2);
        assert_eq!(entries.len(), 1);
    }
}
