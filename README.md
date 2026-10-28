# DDNS clients

A multi-provider dynamic DNS client library and daemon written in Rust.

| Crate | Path | |
|---|---|---|
| `ddns-clients` | `crates/ddns-clients` | Library: `IpResolver` trait and resolvers, `DynDnsProvider` trait and providers |
| `ddnsd` | `crates/ddnsd` | Daemon that periodically syncs a domain's A/AAAA records (owns the record-reconciliation `Updater`) |

DNS providers (features on by default):

| Provider | Feature | Notes |
|---|---|---|
| Cloudflare | `cloudflare` | API token with `Zone:Read` and `DNS:Edit` |
| No-IP | `noip` | at most one A and one AAAA record per hostname, which can be re-pointed but not removed; TTL is ignored; current records are read via DNS |

IP resolvers: HTTP echo services (icanhazip, ipify, or custom URLs) and local
interfaces via netlink (Linux). A `Vec` of resolvers falls back in order, per
address family.

## Library

```rust
use ddns_clients::{CloudflareProvider, DynDnsProvider, resolve};

let mut provider = CloudflareProvider::new("api-token", "example.com")?;
let resolvers = resolve::default_resolvers(); // icanhazip, then local interfaces
let ips = resolve::resolve_public_ips(&resolvers, &[resolve::IpFamily::V4]).await;

// replace the domain's A records with the resolved addresses
let current = provider.list("myhost.example.com").await?;
let summary = provider
    .update("myhost.example.com")
    .remove_all(current.into_iter().filter(|ip| ip.is_ipv4()))
    .add_all(ips)
    .ttl(Some(300))
    .send()
    .await?;
```

Records are identified by address. One `update` can `add`/`add_all` and
`remove`/`remove_all` several addresses, or `clear` all existing ones; existing
records are re-pointed where possible, so provider-side settings survive.

To add a DNS provider, implement `ddns_clients::providers::DynDnsProvider` (`list`,
`update`, `apply_update`; `providers::plan_changes` computes the record operations);
to add an IP source, implement `ddns_clients::IpResolver`.

## Daemon

```sh
cargo run -p ddnsd -- -c /etc/ddnsd.yaml
```

The config file must not be readable by group/others (`chmod 600`).

```yaml
provider:
  type: cloudflare
  api_token: "..."
  zone: example.com
domain: myhost.example.com   # optional, default <hostname>.<zone>
ipv4: true                   # default true
ipv6: true                   # default true
interval: 300                # seconds between checks, default 300
ttl: 600                     # 0 = provider default; default 600
max_records: 2               # max A/AAAA records kept, default 2
resolvers:                   # tried in order per family; default: icanhazip, local
  - type: icanhazip
  - type: ipify
  - type: http               # any service echoing the client IP as plain text
    ipv4_url: https://ipv4.example.net
    ipv6_url: https://ipv6.example.net
  - type: local              # Linux only: global addresses of local interfaces
```

For No-IP, `domain` is required:

```yaml
provider:
  type: noip
  username: "..."            # account email/username, or a DDNS key's username
  password: "..."
  user_agent: "..."          # optional; No-IP asks for "Company Program/Version contact@example.com"
domain: myhost.ddns.net
```

The daemon exits when the provider rejects an update in a way only the user
can fix (e.g. No-IP's `badauth`, `nohost`, `abuse`), and waits as long as the
provider asks after server errors (30 minutes for No-IP).

Log level is controlled with `RUST_LOG` (default `info`).

## Debian package

`debian/` builds the `ddnsd` package with debhelper. It installs
`/usr/sbin/ddnsd`, a hardened `ddnsd.service` systemd unit, the `ddnsd(8)` man
page and an example config. On Debian 13 (trixie) or later:

```sh
sudo apt install build-essential debhelper cargo rustc
dpkg-buildpackage -us -uc     # cargo downloads the crates, so this needs network access
sudo apt install ../ddnsd_*.deb
```

Elsewhere, `mise run deb` builds it in a `debian:trixie` container (podman, or set
`CONTAINER_ENGINE=docker`; `DEBIAN_IMAGE` picks another release) and writes the
packages to `target/debian/`.

The service starts once `/etc/ddnsd.yaml` exists:

```sh
sudo install -m 600 /usr/share/doc/ddnsd/examples/ddnsd.example.yaml /etc/ddnsd.yaml
sudoedit /etc/ddnsd.yaml
sudo systemctl start ddnsd
```

It isn't restarted when ddnsd exits on a rejected update; fix the config and
start it again. Debian's packaged Rust sets the minimum supported Rust version:
`rust-version = "1.85"`, the version in trixie.

## Testing

```sh
cargo test --workspace
```

The tests in `crates/ddns-clients/tests/live.rs` talk to the real provider
APIs. They are `#[ignore]`d, so `cargo test` lists them as ignored; running them
needs network access, and each record test fails if its provider's variables are
missing (set them e.g. in an untracked `mise.local.toml` `[env]` section):

| Provider | Variable | |
|---|---|---|
| Cloudflare | `DDNS_CLOUDFLARE_API_TOKEN` | API token with `Zone:Read` and `DNS:Edit` |
| | `DDNS_CLOUDFLARE_ZONE` | zone to test in, e.g. `example.com` |
| | `DDNS_CLOUDFLARE_TEST_DOMAIN` | optional; default `ddns-clients-test-<unix-seconds>.<zone>` |
| No-IP | `DDNS_NOIP_USERNAME` | account username |
| | `DDNS_NOIP_PASSWORD` | account password |
| | `DDNS_NOIP_HOSTNAME` | existing hostname with exactly one A record, e.g. `myhost.ddns.net` |

```sh
mise run test-live
# or: cargo test -p ddns-clients --test live -- --include-ignored --nocapture
mise run test-live noip   # only one provider's tests
```

The Cloudflare record test creates, updates and deletes A/AAAA records on the
test domain and cleans up after itself, even on failure. The No-IP record test
points the hostname's A record at a documentation address (`192.0.2.10`) and
then restores it; if it fails in between, restore the address in the No-IP
dashboard.
