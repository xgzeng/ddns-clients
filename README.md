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

The service isn't restarted when ddnsd exits because every provider rejected
its updates; fix the config and start it again.

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

The config file is TOML and must not be readable by group/others
(`chmod 600`). Each `[provider.<name>]` table is one domain on one provider;
the public IPs are resolved once per check and pushed to all of them. `type`
defaults to the table's name. Top-level settings must come before the first
provider table; `ipv4`, `ipv6`, `ttl`, `max_records` and `replace_only` are
defaults that each provider can override.

```toml
interval = 300                 # seconds between checks, default 300
refresh_interval = 3600        # seconds after which records are read again from the
                               # provider, warning about changes made elsewhere; 0 = never;
                               # default 3600
resolvers = [                  # tried in order per family; default: icanhazip, local
  { type = "icanhazip" },
  { type = "ipify" },
  # any service echoing the client IP as plain text
  { type = "http", ipv4_url = "https://ipv4.example.net", ipv6_url = "https://ipv6.example.net" },
  { type = "local" },          # Linux only: global addresses of local interfaces
]
ipv4 = true                    # default true
ipv6 = true                    # default true
ttl = 600                      # 0 = provider default; default 600
max_records = 2                # max A/AAAA records kept, default 2
replace_only = false           # only re-point existing records, never create or
                               # delete any (e.g. records set up by hand); default false

[provider.home]
type = "cloudflare"
api_token = "..."              # needs Zone:Read and DNS:Edit
zone = "example.com"
domain = "home.example.com"    # optional, default <hostname>.<zone>

[provider.noip]                # type = "noip" from the name
username = "..."               # account email/username, or a DDNS key's username
password = "..."
user_agent = "..."             # optional; No-IP asks for "Company Program/Version contact@example.com"
domain = "myhost.ddns.net"     # required
ipv6 = false                   # overrides the default
```

The provider keys are passed to `DynDnsClient`, so the daemon rejects unknown
types and missing or unused keys at startup.

When a provider rejects an update in a way only the user can fix (e.g.
No-IP's `badauth`, `nohost`, `abuse`), the daemon logs an error and stops
updating that provider; it exits once every provider has been rejected. After
server errors it waits as long as the provider asks (30 minutes for No-IP)
before updating that provider again.

Log level is controlled with `RUST_LOG` (default `info`).
