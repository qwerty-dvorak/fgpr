#!/bin/sh
# Opt-in browser authenticator installation; does not change PAM or sudo.
# Usage: sudo ./install-fido.sh <unix-user> | uninstall
# Credential keys are deliberately retained on uninstall.
set -eu

cd "$(dirname "$0")"
ROOT=${ROOT:-}
BUILD=build/linux/x86_64/release

if [ -z "$ROOT" ] && [ "$(id -u)" != 0 ]; then
	echo "run as root: sudo $0 <unix-user> | uninstall" >&2
	exit 1
fi
if [ "${1:-}" = uninstall ]; then
	if [ -z "$ROOT" ] && [ -x /etc/init.d/elanfp-fido ]; then
		rc-service elanfp-fido stop || true
		rc-update del elanfp-fido default || true
	fi
	rm -f "$ROOT/usr/local/bin/elanfp-fido" "$ROOT/etc/init.d/elanfp-fido" \
		"$ROOT/etc/conf.d/elanfp-fido" "$ROOT/etc/udev/rules.d/99-elanfp-fido.rules"
	if [ -z "$ROOT" ]; then
		udevadm control --reload-rules
	fi
	echo "FIDO service removed; credential keys retained in /var/lib/elanfp-fido"
	exit 0
fi
if [ "$#" != 1 ]; then
	echo "usage: $0 <unix-user> | uninstall" >&2
	exit 2
fi
user=$1
case "$user" in
	''|[.-]*|*[!a-zA-Z0-9_.-]*) echo "invalid Unix user" >&2; exit 2 ;;
esac
getent passwd "$user" >/dev/null || { echo "unknown Unix user" >&2; exit 2; }
[ -f "$BUILD/elanfp-fido" ] || { echo "build first: xmake" >&2; exit 1; }
if [ -z "$ROOT" ] && [ -f /run/elanfp-fido.pid ]; then
	echo "stop the service before upgrading: sudo rc-service elanfp-fido stop" >&2
	exit 1
fi
install -D -m 0755 "$BUILD/elanfp-fido" "$ROOT/usr/local/bin/elanfp-fido"
install -D -m 0755 packaging/elanfp-fido.init "$ROOT/etc/init.d/elanfp-fido"
install -d -m 0755 "$ROOT/etc/conf.d" "$ROOT/etc/udev/rules.d"
install -d -m 0700 "$ROOT/var/lib/elanfp-fido"
printf 'elanfp_user="%s"\n' "$user" > "$ROOT/etc/conf.d/elanfp-fido"
printf '%s\n' \
	"# Local virtual FIDO key only; does not grant general hidraw or UHID access." \
	"SUBSYSTEM==\"hidraw\", KERNELS==\"0003:1209:EF01.*\", OWNER=\"$user\", MODE=\"0600\"" \
	> "$ROOT/etc/udev/rules.d/99-elanfp-fido.rules"
if [ -z "$ROOT" ]; then
	udevadm control --reload-rules
fi
echo "Installed for $user. No service started; no PAM or Firefox settings changed."
echo "Enroll first: sudo elanfp enroll $user right-index"
echo "Start: sudo rc-service elanfp-fido start"
echo "Optional boot enable: sudo rc-update add elanfp-fido default"
