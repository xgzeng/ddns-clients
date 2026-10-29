mod config;
mod updater;

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use ddns_clients::{
    Error, IpResolver,
    resolve::{self, IpFamily},
};

use config::Config;
use updater::{Updater, UpdaterOptions};

/// Dynamic DNS daemon: keeps a domain's A/AAAA records pointed at this host.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the YAML config file.
    #[arg(short, long, default_value = "/etc/ddnsd.yaml")]
    config: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let config = Config::load(&args.config)
        .with_context(|| format!("load {} failed", args.config.display()))?;

    let mut updater = Updater::new(
        config
            .client()
            .with_context(|| format!("invalid provider in {}", args.config.display()))?,
        UpdaterOptions {
            ipv4: config.ipv4,
            ipv6: config.ipv6,
            max_records: config.max_records,
        },
    );
    let resolvers = config.resolvers();
    let families = config.families();

    let interval = Duration::from_secs(config.interval);
    loop {
        let mut delay = interval;
        if let Err(err) = update_once(&resolvers, &families, &mut updater).await {
            match err.downcast_ref::<Error>() {
                Some(Error::Rejected(_)) => {
                    return Err(err.context("giving up, fix the configuration and restart"));
                }
                Some(Error::Unavailable { retry_after, .. }) => delay = delay.max(*retry_after),
                _ => {}
            }
            log::warn!("update dns record failed: {err:?}");
        }
        tokio::time::sleep(delay).await;
    }
}

async fn update_once<R: IpResolver>(
    resolver: &R,
    families: &[IpFamily],
    updater: &mut Updater,
) -> Result<()> {
    let addrs = resolve::resolve_public_ips(resolver, families).await;
    if addrs.is_empty() {
        log::warn!("no public ip address found");
        return Ok(());
    }
    let summary = updater.update_ips(&addrs).await?;
    if !summary.is_unchanged() {
        log::info!(
            "update complete: kept={}, updated={}, deleted={}, created={}",
            summary.kept,
            summary.updated,
            summary.deleted,
            summary.created
        );
    }
    Ok(())
}
