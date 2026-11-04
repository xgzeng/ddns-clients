# ddnsd configuration

`ddnsd` reads a [TOML](https://toml.io) file, `/etc/ddnsd.toml` unless `-c`
gives another path. A commented example is in
[`crates/ddnsd/ddnsd.example.toml`](../crates/ddnsd/ddnsd.example.toml), which
the packages install:

| Package | Example config |
|---|---|
| Debian | `/usr/share/doc/ddnsd/examples/ddnsd.example.toml` |
| OpenWrt | `/usr/share/ddnsd/ddnsd.example.toml` |

The file holds credentials, so `ddnsd` refuses to start if group or others have
any access to it: use `chmod 600`.

The file is checked at startup: unknown settings and provider types, and missing
or unused provider settings, are errors. To try a config without changing any
records, run `ddnsd dry-run`.

## Example

```toml
resolve_interval = 300
ttl = 600
resolvers = [
  { type = "all", resolvers = [
    { type = "local" },
    { type = "http",
      ipv4_url = ["https://ipv4.icanhazip.com", "https://api.ipify.org"],
      ipv6_url = ["https://ipv6.icanhazip.com", "https://api6.ipify.org"],
      url = "https://ifconfig.me/ip" },
  ] },
]

[provider.home]
type = "cloudflare"
api_token = "..."
zone = "example.com"
domain = "home.example.com"

[provider.noip]
username = "..."
password = "..."
domain = "myhost.ddns.net"
ipv6 = false
```

## General settings

These must come before the first `[provider.<name>]` table, as TOML would
otherwise read them as part of that table.

| Setting | Default | |
|---|---|---|
| `tick` | `15` | Seconds between the daemon's checks. Each check looks up the public addresses once `resolve_interval` has passed, and updates the providers whose addresses changed or whose last update failed, unless the provider asked to wait; must not be `0` |
| `resolve_interval` | `300` | Seconds between lookups of the public addresses, which happen at the first check after it. On Linux they are also looked up at the next check after the global addresses of a local interface change, e.g. after a WAN reconnect |
| `watch_interface` | all | The interface whose address changes trigger a lookup, e.g. `pppoe-wan`; Linux only |
| `resolvers` | local and icanhazip, falling back to ipify and ifconfig.me | How to find the public addresses, see [Resolvers](#resolvers); must not be empty |
| `ipv4`, `ipv6` | `true` | Which public addresses are looked up, and defaults for all providers; a provider can't enable a family disabled here |
| `ttl`, `max_records`, `replace_only`, `cache_expire` | | Defaults for all providers, see [Record settings](#record-settings) |

## Resolvers

`resolvers` is a list of the ways to find this host's public addresses. All of
them are asked, separately for IPv4 and IPv6, and the addresses they find are
merged, without duplicates. A failed one is skipped, and the lookup fails only if
all of them failed. The addresses are resolved every `resolve_interval`, at the
next `tick`, and pushed to all providers. A family whose lookup finds nothing or
fails keeps its last known addresses.

| `type` | |
|---|---|
| `icanhazip` | [icanhazip.com](https://icanhazip.com) |
| `ipify` | [ipify.org](https://www.ipify.org) |
| `ifconfig.me` | [ifconfig.me](https://ifconfig.me) |
| `http` | Any service echoing the client's IP as plain text, see below |
| `local` | Global addresses of local network interfaces, or only of `interface`, e.g. `interface = "eth0"`; Linux only |
| `any` | The addresses any of its `resolvers` found, skipping failed ones, like the top-level list |
| `all` | The addresses all of its `resolvers` found, in the order of the first; fails if any of them fails |

`http` takes `ipv4_url` and `ipv6_url`, for their family, and `url`, for both
families if its host has both A and AAAA records. Each is a URL or a list of
them, and at least one URL is required; a family left without a URL isn't
resolved. A family's URLs are fallbacks: its own URLs, then `url`, in order.
The one that last answered is asked first, and the next ones only if it fails:

```toml
resolvers = [
  { type = "http", url = "https://ip.example.net" },
  { type = "http", ipv4_url = "https://ipv4.example.net", ipv6_url = "https://ipv6.example.net" },
  { type = "http", url = "https://ip.example.net", ipv6_url = "https://ipv6.example.net" },
  { type = "http", ipv4_url = ["https://ipv4.example.net", "https://ipv4.example.org"] },
]
```

The third one tries `https://ipv6.example.net` for IPv6 and falls back to
`https://ip.example.net`.

`any` and `all` nest, separately for IPv4 and IPv6. The default publishes the
local addresses that an echo service also sees, so a host behind NAT, or with a
private or CGNAT address, publishes no IPv4 address, and of several IPv6
addresses only the one it connects from:

```toml
resolvers = [
  { type = "all", resolvers = [
    { type = "local" },
    { type = "http",
      ipv4_url = ["https://ipv4.icanhazip.com", "https://api.ipify.org"],
      ipv6_url = ["https://ipv6.icanhazip.com", "https://api6.ipify.org"],
      url = "https://ifconfig.me/ip" },
  ] },
]
```

Behind a NAT router, publish what an echo service sees instead:

```toml
resolvers = [
  { type = "http",
    ipv4_url = ["https://ipv4.icanhazip.com", "https://api.ipify.org"],
    ipv6_url = ["https://ipv6.icanhazip.com", "https://api6.ipify.org"] },
]
```

With two uplinks, this publishes the addresses of both interfaces, skipping one
that can't be read:

```toml
resolvers = [
  { type = "local", interface = "wan1" },
  { type = "local", interface = "wan2" },
]
```

## Providers

Each `[provider.<name>]` table is one domain on one provider, so several domains
need several tables. The name is free and appears in the logs. `type` selects the
provider and defaults to the name, so several tables of one provider need
distinct names and an explicit `type`.

### Cloudflare

| Setting | |
|---|---|
| `type` | `cloudflare` |
| `api_token` | Required; API token with `Zone:Read` and `DNS:Edit` |
| `zone` | Required; the zone containing the domain, e.g. `example.com` |
| `domain` | The domain to update, see below; default `<hostname>` |

`zone` must be a full name, and a `domain` that doesn't end with the zone gets it
appended:

| `domain`, with `zone = "example.com"` | Updated records |
|---|---|
| `home` | `home.example.com` |
| `home.example.com` | `home.example.com` |
| `example.com` or empty (`""`) | `example.com`, the zone's root |
| `*` | `*.example.com` |
| `home.example.org` | `home.example.org.example.com` |

```toml
[provider.cloudflare]
api_token = "..."
zone = "example.com"
domain = "home"
```

### No-IP

| Setting | |
|---|---|
| `type` | `noip` |
| `username` | Required; account email or username, or a DDNS key's username |
| `password` | Required; the password of that account or key |
| `domain` | Required; the hostname to update, e.g. `myhost.ddns.net` |
| `user_agent` | Sent to No-IP, which asks for `Company Program/Version contact@example.com`; default `ddns-clients ddns-clients/<version>` |

A No-IP hostname has at most one A and one AAAA record, which can be re-pointed
but not removed. `ttl` has no effect.

```toml
[provider.noip]
username = "..."
password = "..."
domain = "myhost.ddns.net"
```

### PKARR

[PKARR](https://pkdns.net) (Public-Key Addressable Resource Records) publishes
DNS records signed with an Ed25519 key on the Mainline DHT and on PKARR relays.
The key's z-base32 public key is the domain, e.g.
`yg4gxe7z1r7mr6orids9fh95y7gxhdsxjqi6nngsxxtakqaxr5no`, and can be resolved
by PKARR-aware resolvers such as [pkdns](https://github.com/pubky/pkdns).
Packages built with `--no-default-features` leave PKARR out.

| Setting | |
|---|---|
| `type` | `pkarr` |
| `secret_key` | The key's secret, 64 hex digits, e.g. from `openssl rand -hex 32`; this or `secret_file` is required |
| `secret_file` | A file holding `secret_key`, as PKARR's key files do; a relative path is relative to the config file's directory. Like the config file, it must not be readable by group or others. The Debian service can't read files under `/home` |
| `domain` | The name below the key, e.g. `home` for `home.<public key>`; default the key itself, as do `""` and `@` |
| `relays` | PKARR relay URLs to publish to and read from besides the DHT; `[]` uses only the DHT; default pkarr's relays (`https://pkarr.pubky.app`, `https://pkarr.pubky.org`) |
| `keep_other_records` | Keep the key's other records, of other names or types, when publishing; if `false`, they are removed; default `true` |

All records of a key are one signed packet, which every change publishes again
in full. The DHT drops packets after a few hours, so every `cache_expire`
(default an hour) the packet is read and published again, re-signed; it can't
be `0`. The public key, and with it the domain, is in the logs, e.g. of
`ddnsd dry-run`.

```toml
[provider.pkarr]
secret_file = "pkarr.key"   # /etc/pkarr.key, next to /etc/ddnsd.toml
domain = "home"
```

```sh
(umask 077; openssl rand -hex 32 > /etc/pkarr.key)
```

### Domain names

`domain` and `zone` are checked at startup and must be only a DNS name, without a
scheme, port, path or trailing dot. Internationalized names are written in
punycode (`xn--...`). The first label of a `domain` may be the wildcard `*`.

## Record settings

Set at the top of the file they are defaults for all providers, and set in a
`[provider.<name>]` table they override the default for that provider.

| Setting | Default | |
|---|---|---|
| `ipv4` | `true` | Manage A records; if `false`, they are left alone |
| `ipv6` | `true` | Manage AAAA records; if `false`, they are left alone. A provider must have one of `ipv4` and `ipv6` enabled, and can't enable one that is disabled at the top of the file |
| `ttl` | `600` | TTL of created and changed records, in seconds; `0` uses the provider's default |
| `max_records` | `2` | Maximum number of A and AAAA records kept for the domain; if more addresses are found, those that already have a record are kept first, and the rest aren't added |
| `replace_only` | `false` | Only re-point existing records, never create or delete any, e.g. for records set up by hand |
| `cache_expire` | `3600` | Seconds after which the records are read again from the provider, warning about changes made elsewhere; `0` never does. PKARR also publishes its records again then, and doesn't allow `0` |
