#!/bin/sh
# Bring an AP's openUF dependencies up to date: the feed packages openUF
# installs (setup.sh's REQUIRED and OPTIONAL, the full wpad, the uhttpd
# family) and d-malinowski's rrb-unifi at the tag this tree pins.
#
#   sh tools/deps.sh --check <host>...   what is installed, what would change
#   sh tools/deps.sh <host>...           upgrade the packages, install the pinned rrb-unifi
#   OPENUF_SSH_PASS='secret' sh tools/deps.sh <host>   APs with a root password
#
# `make deps-update` moves the rrb-unifi pin first (tools/rrb-unifi-compat.sh
# --bump: only when both test suites pass against the new release), so
# `make deps-update deps-deploy HOST=...` is "the latest that is known to work".
#
# Feed packages: `apk update` / `opkg update` on the AP, then an upgrade of the
# INSTALLED members of the set only -- nothing new is pulled in. kmod-* stay
# out: they belong to the kernel the image was built with. A wpad upgrade
# restarts every radio (clients reconnect), and the uhttpd family goes as one:
# a feed rebuilt after the image left a 25.12.0 hAP ac with uhttpd-mod-ucode
# 2026.11.05 under uhttpd 2025.10.03, and uhttpd died at every start.
#
# rrb-unifi: the AP cannot be assumed to reach GitHub (the same hAP ac timed
# out on github.com:443 while downloads.openwrt.org worked), so the tag archive
# is fetched HERE, its plugin checked against setup.sh's sha256, and the tree
# copied over. Its own `rrb-unifi-setup install --yes` then updates the files;
# with the veth pair already present it does not touch the network. An AP
# without rrb-unifi is left without it: installing it is setup.sh's question.
#
# Runs from the repository root on the dev machine (POSIX sh).

set -u

SSH_COMMON="-o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR"
ASKPASS=""
WORK=""
cleanup() {
	[ -n "$ASKPASS" ] && rm -f "$ASKPASS"
	[ -n "$WORK" ] && rm -rf "$WORK"
	return 0
}
trap cleanup EXIT

if [ -n "${OPENUF_SSH_PASS:-}" ]; then
	ASKPASS=$(mktemp "${TMPDIR:-/tmp}/openuf-askpass.XXXXXX") || exit 1
	cat > "$ASKPASS" <<'HELPER'
#!/bin/sh
printf '%s\n' "$OPENUF_SSH_PASS"
HELPER
	chmod 700 "$ASKPASS"
	export OPENUF_SSH_PASS SSH_ASKPASS="$ASKPASS" SSH_ASKPASS_REQUIRE=force DISPLAY="${DISPLAY:-:0}"
	SSH=${OPENUF_SSH:-"ssh $SSH_COMMON -o NumberOfPasswordPrompts=1"}
else
	SSH=${OPENUF_SSH:-"ssh $SSH_COMMON -o BatchMode=yes"}
fi

CHECK=0
HOSTS=""
while [ $# -gt 0 ]; do
	case "$1" in
		--check)   CHECK=1 ;;
		-h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		-*)        echo "unknown option: $1" >&2; exit 2 ;;
		*)         HOSTS="$HOSTS $1" ;;
	esac
	shift
done
[ -n "$HOSTS" ] || { echo "usage: sh tools/deps.sh [--check] <host> [host...]" >&2; exit 2; }
[ -f setup.sh ] || { echo "run from the repository root" >&2; exit 2; }

remote() { # remote <host> <command...>
	_h=$1; shift
	# shellcheck disable=SC2086
	$SSH "root@$_h" "$@"
}

# setup.sh is the one place the lists and the pin live; read them, never copy.
setup_val() { sed -n "s/^$1=\${$1:-\"\{0,1\}\([^}\"]*\)\"\{0,1\}}\$/\1/p; s/^$1=\"\{0,1\}\([^\"\$]*\)\"\{0,1\}\$/\1/p" setup.sh | head -1; }
REQUIRED=$(setup_val REQUIRED)
OPTIONAL=$(setup_val OPTIONAL)
RRB_REPO=$(setup_val RRB_UNIFI_REPO)
RRB_TAG=$(setup_val RRB_UNIFI_PINNED_TAG)
RRB_SHA=$(setup_val RRB_UNIFI_PLUGIN_SHA256)
for v in REQUIRED OPTIONAL RRB_REPO RRB_TAG RRB_SHA; do
	eval "_v=\$$v"
	[ -n "$_v" ] || { echo "could not read $v from setup.sh" >&2; exit 2; }
done

PKGSET=""
for p in $REQUIRED $OPTIONAL; do
	case "$p" in kmod-*) ;; *) PKGSET="$PKGSET $p" ;; esac
done
PKGSET="$PKGSET wpad wpad-mbedtls wpad-wolfssl wpad-openssl hostapd-mbedtls hostapd-wolfssl hostapd-openssl"
PKGSET="$PKGSET uhttpd uhttpd-mod-ubus uhttpd-mod-ucode uhttpd-mod-lua"

# Run on the AP: refresh the index, list (and with "upgrade", apply) the
# upgradable installed members of the set. busybox ash; both managers.
REMOTE_PKGS='
mode=$1; shift
if command -v apk >/dev/null 2>&1; then
	apk update >/dev/null 2>&1 || echo "  warn  apk update failed: is the feed reachable?"
	inst=""
	for p in "$@"; do apk list -I "$p" 2>/dev/null | grep -q "^$p-[0-9]" && inst="$inst $p"; done
	up=$(apk list -u $inst 2>/dev/null | sed -n "s/^\([^ ]*\) .*\[upgradable from: \(.*\)\]$/\2 -> \1/p")
	upgrade() { apk upgrade $inst; }
elif command -v opkg >/dev/null 2>&1; then
	opkg update >/dev/null 2>&1 || echo "  warn  opkg update failed: is the feed reachable?"
	inst=""
	for p in "$@"; do opkg list-installed "$p" 2>/dev/null | grep -q "^$p " && inst="$inst $p"; done
	up=""
	for p in $inst; do
		l=$(opkg list-upgradable 2>/dev/null | grep "^$p - ")
		[ -n "$l" ] && up="$up
$l"
	done
	upgrade() { opkg upgrade $inst; }
else
	echo "  neither apk nor opkg"; exit 1
fi
up=$(printf "%s\n" "$up" | sed "/^$/d")
if [ -z "$up" ]; then
	echo "  packages    all current ($(echo $inst | wc -w) installed from the set)"
	exit 0
fi
echo "  packages    upgradable:"
printf "%s\n" "$up" | sed "s/^/                /"
[ "$mode" = upgrade ] || exit 0
upgrade || exit 1
# uhttpd only reads its plugins at start.
case "$up" in *uhttpd*) /etc/init.d/uhttpd restart >/dev/null 2>&1 ;; esac
echo "  packages    upgraded"
'

rrb_fetch() { # the pinned tree, checked, unpacked under $WORK; prints its path
	[ -n "$WORK" ] || WORK=$(mktemp -d "${TMPDIR:-/tmp}/openuf-deps.XXXXXX") || return 1
	_d="$WORK/rrb"
	if [ ! -d "$_d" ]; then
		mkdir -p "$_d" || return 1
		curl -fsSL -o "$WORK/rrb.tgz" "https://github.com/$RRB_REPO/archive/refs/tags/$RRB_TAG.tar.gz" \
			|| { echo "could not download rrb-unifi $RRB_TAG" >&2; return 1; }
		tar -xzf "$WORK/rrb.tgz" -C "$_d" || return 1
	fi
	_src=$(dirname "$(find "$_d" -name rrb-unifi-setup -type f | head -1)")
	[ -f "$_src/openuf-plugin/rrb-unifi.lua" ] || { echo "rrb-unifi $RRB_TAG: no openuf-plugin/rrb-unifi.lua" >&2; return 1; }
	_sha=$(sha256sum "$_src/openuf-plugin/rrb-unifi.lua" | cut -d' ' -f1)
	[ "$_sha" = "$RRB_SHA" ] || { echo "rrb-unifi $RRB_TAG: plugin sha256 $_sha is not setup.sh's pin $RRB_SHA" >&2; return 1; }
	printf '%s\n' "$_src"
}

rc=0
for h in $HOSTS; do
	echo "=== $h"
	if [ "$CHECK" = 1 ]; then mode=check; else mode=upgrade; fi
	# shellcheck disable=SC2086
	if ! printf '%s' "$REMOTE_PKGS" | remote "$h" "cat > /tmp/openuf-deps.sh; sh /tmp/openuf-deps.sh $mode $PKGSET; r=\$?; rm -f /tmp/openuf-deps.sh; exit \$r"; then
		echo "  packages    FAILED"; rc=1
	fi

	have=$(remote "$h" 'sed -n "s/^VERSION=//p" /usr/sbin/rrb-unifi-setup 2>/dev/null | head -1') || { echo "  unreachable"; rc=1; continue; }
	want=${RRB_TAG#v}
	if [ -z "$have" ]; then
		echo "  rrb-unifi   not installed (setup.sh installs it; left alone)"
	elif [ "$have" = "$want" ]; then
		echo "  rrb-unifi   $have, the pinned version"
	elif [ "$CHECK" = 1 ]; then
		echo "  rrb-unifi   $have; the pin is $want"
	else
		echo "  rrb-unifi   $have -> $want"
		src=$(rrb_fetch) || { rc=1; continue; }
		if tar -C "$src" -cf - . | remote "$h" "set -e; D=/tmp/rrb-unifi-$RRB_TAG; rm -rf \$D; mkdir -p \$D; tar -C \$D -xf -; cd \$D; sh ./rrb-unifi-setup install --yes; cd /; rm -rf \$D; /etc/init.d/openuf restart"; then
			echo "  rrb-unifi   $want installed; openUF restarted to load its plugin"
		else
			echo "  rrb-unifi   install FAILED (its output is above)"; rc=1
		fi
	fi
done
exit $rc
