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

IP resolvers: HTTP echo services (icanhazip, ipify, or custom URLs) and local
interfaces via netlink (Linux).

## Installation

Each [GitHub release](https://github.com/xgzeng/ddns-clients/releases) has:

- `ddnsd-<version>-x86_64-unknown-linux-musl` and
  `ddnsd-<version>-aarch64-unknown-linux-musl`: static binaries that run on any
  Linux distribution (`chmod +x` after downloading);
- `ddnsd_<version>_amd64.deb` and `ddnsd_<version>_arm64.deb`: packages for
  Debian 13 (trixie) and later;
- `ddnsd-<version>-r1_<arch>.apk`: packages for OpenWrt 25.12 and later, on
  `x86_64`, `aarch64_generic`, `aarch64_cortex-a53`, `aarch64_cortex-a72` and
  `aarch64_cortex-a76`;
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

The OpenWrt package installs `/usr/sbin/ddnsd`, an enabled `ddnsd` procd service
and an example config, and takes 8-10 MiB of storage before the filesystem's
compression. Pick the package matching `cat /etc/apk/arch`; it isn't signed, so
`apk` needs `--allow-untrusted`. As on Debian, the service starts once
`/etc/ddnsd.toml` exists. `sysupgrade` keeps the config, and the logs are in
`logread -e ddnsd`.

```sh
apk add --allow-untrusted ./ddnsd-<version>-r1_<arch>.apk
cp /usr/share/ddnsd/ddnsd.example.toml /etc/ddnsd.toml
chmod 600 /etc/ddnsd.toml
vi /etc/ddnsd.toml
/etc/init.d/ddnsd start
```

To build from source, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Library

### Resolving the public IP

```rust
use ddns_clients::resolve::{self, IpFamily};

let resolvers = resolve::default_resolvers(); // icanhazip, then local interfaces
let ips = resolve::resolve_public_ips(&resolvers, &[IpFamily::V4, IpFamily::V6]).await;
```

### Updating DNS records

```rust
use ddns_clients::DynDnsClient;

let mut client = DynDnsClient::provider("cloudflare")?
    .api_token("api-token")
    .zone("example.com")
    .domain("myhost.example.com")
    .build()?;
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
domain = "home.example.com"
```

See [docs/configuration.md](docs/configuration.md) for all settings.

After server errors the daemon waits as long as the provider asks (30 minutes
for No-IP) before updating that provider again.

Log level is controlled with `RUST_LOG` (default `info`).
