#!/bin/sh
# Packages a static ddnsd binary as OpenWrt apk packages, one per OpenWrt
# architecture, the way OpenWrt's include/package-pack.mk does.
#
#   openwrt/package.sh BINARY OUTDIR ARCH...
#
# Needs apk-tools 3 (Alpine 3.23 or later) and root, as the packaged files
# keep their owner.
set -eu

if [ "$#" -lt 3 ]; then
  echo "usage: $0 BINARY OUTDIR ARCH..." >&2
  exit 2
fi
binary=$1
outdir=$2
shift 2

if [ "$(id -u)" != 0 ]; then
  echo "error: must run as root, the packaged files would belong to this user" >&2
  exit 1
fi

src=$(dirname "$0")/..
upstream=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$src/Cargo.toml")
version=$upstream-r1

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

root=$work/root
install -D -m 755 "$binary" "$root/usr/sbin/ddnsd"
install -D -m 755 "$src/openwrt/ddnsd.init" "$root/etc/init.d/ddnsd"
install -D -m 644 "$src/crates/ddnsd/ddnsd.example.toml" "$root/usr/share/ddnsd/ddnsd.example.toml"
# the config isn't packaged, so sysupgrade has to be told to keep it
install -d "$root/lib/upgrade/keep.d"
echo /etc/ddnsd.toml >"$root/lib/upgrade/keep.d/ddnsd"

# default_postinst and default_prerm read the package's files from this list
install -d "$root/lib/apk/packages"
(cd "$root" && find . -type f | sed 's/^\.//' | sort) >"$work/ddnsd.list"
mv "$work/ddnsd.list" "$root/lib/apk/packages/ddnsd.list"

# the scripts OpenWrt generates for every package: enable and start the
# service on install, restart it on upgrade if enabled, stop it on removal
cat >"$work/post-install" <<'SCRIPT'
#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s "${IPKG_INSTROOT}/lib/functions.sh" ] || exit 0
. "${IPKG_INSTROOT}/lib/functions.sh"
export root="${IPKG_INSTROOT}"
export pkgname="ddnsd"
add_group_and_user
default_postinst
SCRIPT
{
  echo '#!/bin/sh'
  echo 'export PKG_UPGRADE=1'
  sed '/^#!/d' "$work/post-install"
} >"$work/post-upgrade"
cat >"$work/pre-deinstall" <<'SCRIPT'
#!/bin/sh
[ -s "${IPKG_INSTROOT}/lib/functions.sh" ] || exit 0
. "${IPKG_INSTROOT}/lib/functions.sh"
export root="${IPKG_INSTROOT}"
export pkgname="ddnsd"
default_prerm
SCRIPT

mkdir -p "$outdir"
for arch in "$@"; do
  SOURCE_DATE_EPOCH=0 apk mkpkg \
    --info "name:ddnsd" \
    --info "version:$version" \
    --info "description:Dynamic DNS daemon for Cloudflare and No-IP" \
    --info "arch:$arch" \
    --info "license:MIT" \
    --info "origin:ddnsd" \
    --info "url:https://github.com/xgzeng/ddns-clients" \
    --info "maintainer:XiaoGuang Zeng <xgzeng@gmail.com>" \
    --info "depends:ca-bundle" \
    --script "post-install:$work/post-install" \
    --script "post-upgrade:$work/post-upgrade" \
    --script "pre-deinstall:$work/pre-deinstall" \
    --files "$root" \
    --output "$outdir/ddnsd-${version}_$arch.apk"
done
