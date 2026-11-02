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
interval = 300
ttl = 600
resolvers = [
  { type = "icanhazip" },
  { type = "local" },
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
| `interval` | `300` | Seconds between checks of the public addresses |
| `refresh_interval` | `3600` | Seconds after which records are read again from the provider, warning about changes made elsewhere; `0` never does |
| `resolvers` | icanhazip, then local | How to find the public addresses, see [Resolvers](#resolvers); must not be empty |
| `ipv4`, `ipv6`, `ttl`, `max_records`, `replace_only` | | Defaults for all providers, see [Record settings](#record-settings) |

## Resolvers

`resolvers` is a list of the ways to find this host's public addresses. They are
tried in order, separately for IPv4 and IPv6, until one finds an address. The
addresses are resolved once per check and pushed to all providers.

| `type` | |
|---|---|
| `icanhazip` | [icanhazip.com](https://icanhazip.com) |
| `ipify` | [ipify.org](https://www.ipify.org) |
| `http` | Any service echoing the client's IP as plain text, see below |
| `local` | Global addresses of local network interfaces; Linux only |

`http` takes `url`, used for both families if its host has both A and AAAA
records, and `ipv4_url` and `ipv6_url`, which override it for their family. At
least one is required, and a family left without a URL isn't resolved:

```toml
resolvers = [
  { type = "http", url = "https://ip.example.net" },
  { type = "http", ipv4_url = "https://ipv4.example.net", ipv6_url = "https://ipv6.example.net" },
  { type = "http", url = "https://ip.example.net", ipv6_url = "https://ipv6.example.net" },
  { type = "http", ipv4_url = "https://ipv4.example.net" },
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
| `example.com` | `example.com`, the zone's root |
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
| `ipv6` | `true` | Manage AAAA records; if `false`, they are left alone. A provider must have one of `ipv4` and `ipv6` enabled |
| `ttl` | `600` | TTL of created and changed records, in seconds; `0` uses the provider's default |
| `max_records` | `2` | Maximum number of A and AAAA records kept for the domain; the addresses beyond it aren't added |
| `replace_only` | `false` | Only re-point existing records, never create or delete any, e.g. for records set up by hand |
