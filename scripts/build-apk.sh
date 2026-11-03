#!/bin/sh
# Builds a static ddnsd in an Alpine container and packages it for OpenWrt, into
# target/openwrt/, for the architecture of the container: x86_64 or aarch64.
#
# Needs podman, for the overlay mount (`:O`), see build-deb.sh.
#
#   APK_IMAGE     build image, default docker.io/library/rust:1-alpine3.24
#   APK_PLATFORM  container platform, e.g. linux/arm64 (emulated, so slow)
set -eu

if ! command -v podman >/dev/null 2>&1; then
  echo "error: podman not found; install it, or run openwrt/package.sh on Alpine" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
mkdir -p target/openwrt

podman run --rm -i \
  ${APK_PLATFORM:+--platform "$APK_PLATFORM"} \
  -v "$PWD":/build/ddns-clients:O \
  -v "$PWD/target/openwrt":/out \
  -w /build/ddns-clients \
  "${APK_IMAGE:-docker.io/library/rust:1-alpine3.24}" sh -eus <<'SCRIPT'
apk add --no-cache -q gcc musl-dev
export CARGO_PROFILE_RELEASE_STRIP=symbols
cargo build --release --locked -p ddnsd
case $(uname -m) in
  x86_64) arches=x86_64 ;;
  aarch64) arches="aarch64_generic aarch64_cortex-a53 aarch64_cortex-a72 aarch64_cortex-a76" ;;
  *) echo "error: no OpenWrt architectures known for $(uname -m)" >&2; exit 1 ;;
esac
openwrt/package.sh target/release/ddnsd /out $arches
SCRIPT

ls -l target/openwrt
