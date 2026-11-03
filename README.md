# DDNS clients

> [!WARNING]
> This project is in early development. The library API, the daemon's config
> format and the packaging may change incompatibly between releases.

A multi-provider dynamic DNS client library and daemon written in Rust:

- `ddns-clients`, a library that finds this host's public IP addresses and
  updates a domain's A/AAAA records on a DNS provider;
- `ddnsd`, a daemon that keeps the records of one or more domains, on one or
  more providers, pointed at this host.

DNS providers:

| Provider | Notes |
|---|---|
| Cloudflare | API token with `Zone:Read` and `DNS:Edit` |
| No-IP | at most one A and one AAAA record per hostname, which can be re-pointed but not removed; TTL is ignored; current records are read from No-IP's nameservers over DNS |
| [PKARR](https://pkdns.net) | records under an Ed25519 key, published on the Mainline DHT and PKARR relays and republished every `cache_expire`; the `pkarr` cargo feature, on by default |

IP resolvers: HTTP echo services (icanhazip, ipify, or custom URLs) and local
interfaces via netlink (Linux), whose addresses can be merged.

## Installation

Each [GitHub release](https://github.com/xgzeng/ddns-clients/releases) has:

- `ddnsd-<version>-x86_64-unknown-linux-musl` and
  `ddnsd-<version>-aarch64-unknown-linux-musl`: static binaries that run on any
  Linux distribution (`chmod +x` after downloading);
- `ddnsd_<version>_amd64.deb` and `ddnsd_<version>_arm64.deb`: packages for
  Debian 13 (trixie) and later;
- `ddnsd-<version>-r1_aarch64_generic.apk`: a package for OpenWrt 25.12 and
  later, on `aarch64_generic`;
- `SHA256SUMS`.

The Debian package installs `/usr/sbin/ddnsd`, a hardened `ddnsd.service`
systemd unit, the `ddnsd(8)` man page and an example config. The service starts
once `/etc/ddnsd.toml` exists:

```sh
sudo apt install ./ddnsd_<version>_amd64.deb
sudo install -m 600 /usr/share/doc/ddnsd/examples/ddnsd.example.toml /etc/ddnsd.toml
sudoedit /etc/ddnsd.toml
sudo systemctl start ddnsd
```

The OpenWrt package installs `/usr/sbin/ddnsd`, an enabled `ddnsd` procd service,
a minimal `/etc/ddnsd.toml` and a full example config, and takes 8-10 MiB of
storage before the filesystem's compression. It installs where
`cat /etc/apk/arch` lists `aarch64_generic`; it isn't signed, so `apk` needs
`--allow-untrusted`. The installed `/etc/ddnsd.toml` has every provider
commented out, so the service doesn't run until one is filled in. Upgrades keep
the edited config, leaving the packaged one as `/etc/ddnsd.toml.apk-new`, and so
does `sysupgrade`. The logs are in `logread -e ddnsd`.

```sh
apk add --allow-untrusted ./ddnsd-<version>-r1_aarch64_generic.apk
vi /etc/ddnsd.toml                 # uncomment and fill in a provider
/etc/init.d/ddnsd restart
```

To build from source, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Library

### Resolving the public IP

```rust
use ddns_clients::{IpResolver, resolve};

let resolver = resolve::default_resolvers();   // local addresses and icanhazip/ipify
let ipv4 = resolver.resolve_a().await?;        // Vec<Ipv4Addr>
let ipv6 = resolver.resolve_aaaa().await.unwrap_or_default(); // none without IPv6
```

### Updating DNS records

```rust
use std::net::IpAddr;

use ddns_clients::DynDnsClient;

let mut client = DynDnsClient::provider("cloudflare")?
    .api_token("api-token")
    .zone("example.com")
    .domain("myhost.example.com")
    .build()?;
let ips = ipv4.into_iter().map(IpAddr::from).chain(ipv6.into_iter().map(IpAddr::from));
client.update(ips).await?; // replaces the domain's A/AAAA records
```

## Daemon

```sh
ddnsd -c /etc/ddnsd.toml           # the default path
sudo ddnsd dry-run                 # one update pass that only logs the changes
```

`dry-run` runs one update pass without changing any records: the planned
changes are logged (e.g. `myhost.example.com: replace 192.0.2.1 with
192.0.2.2 (dry run, not carried out)`), the providers are only read from, and
it exits with an error if any of them failed.

The config file is TOML and must not be readable by group/others (`chmod 600`).
Each `[provider.<name>]` table is one domain on one provider, whose type is
taken from the name:

```toml
[provider.cloudflare]
api_token = "..."              # needs Zone:Read and DNS:Edit
zone = "example.com"
domain = "home"                # home.example.com
```

See [docs/configuration.md](docs/configuration.md) for all settings.

Failed updates are retried every `tick` (15 seconds by default). After server
errors or rate limiting the daemon waits as long as the provider asks (30
minutes for No-IP), and a provider that rejects the credentials isn't updated
again until ddnsd is restarted.

Log level is controlled with `RUST_LOG` (default `info`).
