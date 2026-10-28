#!/bin/sh
# Builds the Debian packages in a Debian container and copies them to
# target/debian/, for hosts without Debian's build tools.
#
# Needs podman: the source tree is mounted as an overlay (`:O`), so the build
# can write into it, and into its parent as dpkg-buildpackage does, while the
# changes are discarded when the container exits. Docker has no overlay mounts.
#
#   DEBIAN_IMAGE  build image, default docker.io/library/debian:trixie
set -eu

if ! command -v podman >/dev/null 2>&1; then
  echo "error: podman not found; install it, or build on Debian with dpkg-buildpackage" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
mkdir -p target/debian

podman run --rm -i \
  -v "$PWD":/build/ddns-clients:O \
  -v "$PWD/target/debian":/out \
  -w /build/ddns-clients \
  "${DEBIAN_IMAGE:-docker.io/library/debian:trixie}" bash -eus <<'SCRIPT'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get build-dep -qq -y ./ >/dev/null
dpkg-buildpackage -us -uc
cp /build/*.deb /build/*.dsc /build/*.tar.xz /build/*.buildinfo /build/*.changes /out/
SCRIPT

ls -l target/debian
