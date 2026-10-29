# Development

## Layout

| Path | |
|---|---|
| `crates/ddns-clients` | Library: `IpResolver` trait and resolvers (`resolve/`), `DynDnsProvider` trait, providers and `plan_changes` (`providers/`), `DynDnsClient` with its record cache and address-family restriction, and its builder (`client.rs`) |
| `crates/ddnsd` | Daemon: TOML config (`config.rs`), the `Updater` that keeps a domain at the resolved IPs within `max_records` (`updater.rs`), and the per-provider update loop (`main.rs`) |
| `debian/` | Debian packaging of `ddnsd` |
| `scripts/` | Helper scripts, e.g. `build-deb.sh` |
| `.github/workflows/` | CI and releases |

## Building

```sh
cargo build --workspace
cargo run -p ddnsd -- -c config.toml   # untracked; the config must be mode 600
```

The minimum supported Rust version is `rust-version = "1.85"`, the rustc in
Debian 13 (trixie), which builds the Debian package. The workspace uses
resolver 3, so `cargo update` picks dependency versions that support it; CI
builds the package with trixie's toolchain and fails if a newer one is needed.

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
dashboard. Don't run the No-IP tests repeatedly with wrong credentials: No-IP
may block the client's IP.

## Adding a built-in provider

1. Implement `DynDnsProvider` in `crates/ddns-clients/src/providers/<name>.rs`,
   using `plan_changes` to turn a `RecordUpdateRequest` into record operations.
   Return `Error::Rejected` for errors that need a configuration fix and
   `Error::Unavailable` when the service asks clients to back off.
2. Add its name constant to `providers/mod.rs` and re-export the type in
   `lib.rs`.
3. Add a `Kind` variant to `client.rs`, with its required and optional
   parameters and how `build()` constructs it; add builder methods for new
   parameters.
4. Add new parameters to `ProviderConfig` in `crates/ddnsd/src/config.rs` and
   pass them on in `Config::client`.
5. Add a live test module to `tests/live.rs`, reading `DDNS_<PROVIDER>_*`
   variables.
6. Document it: the provider tables in `README.md`, the example config, the
   man page `debian/ddnsd.8` and the package description in `debian/control`.

## Debian package

`debian/` builds the `ddnsd` package with debhelper. On Debian 13 (trixie) or
later:

```sh
sudo apt build-dep ./
dpkg-buildpackage -us -uc     # cargo downloads the crates, so this needs network access
sudo apt install ../ddnsd_*.deb
```

Elsewhere, `mise run deb` (`scripts/build-deb.sh`) builds it in a `debian:trixie`
podman container (`DEBIAN_IMAGE` picks another release) and writes the packages
to `target/debian/`. The source tree is mounted as an overlay, so the build
leaves it untouched.

## CI and releases

GitHub Actions lints, tests and builds every push to `main` and every pull
request (`ci.yml`, using the shared jobs in `build.yml`). Pushing a
`v<version>` tag runs `release.yml`, which publishes a GitHub release with the
static musl binaries, the Debian packages and `SHA256SUMS`.

The tag must match the version in `Cargo.toml` and `debian/changelog`:

```sh
# bump `version` in Cargo.toml, run `cargo update --workspace` to update Cargo.lock, then:
dch -v 0.0.2 "Describe the changes."   # or add a debian/changelog entry by hand
git commit -am "Release 0.0.2"
git tag v0.0.2
git push origin main v0.0.2
```
