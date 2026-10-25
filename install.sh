#!/bin/sh
# Install or remove fingerprint authentication for sudo.
#
#   sudo ./install.sh             install and enable for `sudo` and `sudo -i`
#   sudo ./install.sh uninstall   disable and remove (enrolled fingers kept)
#   sudo ./install.sh purge       uninstall and delete enrolled fingers
#
# Only /etc/pam.d/sudo and /etc/pam.d/sudo-i are edited: one line
#   auth  sufficient  pam_elanfp.so
# is put in front of their first auth line (backup: <file>.elanfp-backup).
# "sufficient" means a fingerprint can only let you in early; on timeout,
# mismatch, missing sensor or any error PAM continues to the password prompt.
set -eu

ROOT=${ROOT:-} # alternative root for testing, empty for the real system
BUILD=build/linux/x86_64/release
PAMLIB=$ROOT/lib64/security
BIN=$ROOT/usr/local/bin
DATA=$ROOT/var/lib/elanfp
SERVICES="sudo sudo-i"
LINE="auth		sufficient	pam_elanfp.so"

cd "$(dirname "$0")"
if [ -z "$ROOT" ] && [ "$(id -u)" != 0 ]; then
	echo "run as root: sudo $0 ${1:-}" >&2
	exit 1
fi

# Replace $1 with stdin atomically, keeping owner and mode.
replace() {
	cat > "$1.elanfp-tmp"
	chown --reference="$1" "$1.elanfp-tmp"
	chmod --reference="$1" "$1.elanfp-tmp"
	mv "$1.elanfp-tmp" "$1"
}

enable_pam() {
	f=$ROOT/etc/pam.d/$1
	[ -f "$f" ] || return 0
	if grep -q 'pam_elanfp\.so' "$f"; then
		echo "$f: already enabled"
		return 0
	fi
	if ! grep -Eq '^[[:space:]]*auth[[:space:]]' "$f"; then
		echo "$f: no auth line, left unchanged" >&2
		return 0
	fi
	cp -p "$f" "$f.elanfp-backup"
	awk -v l="$LINE" '!d && /^[[:space:]]*auth[[:space:]]/ { print l; d = 1 } { print }' \
		"$f" | replace "$f"
	echo "$f: enabled (backup $f.elanfp-backup)"
}

disable_pam() {
	f=$ROOT/etc/pam.d/$1
	[ -f "$f" ] || return 0
	if grep -q 'pam_elanfp\.so' "$f"; then
		grep -v 'pam_elanfp\.so' "$f" | replace "$f"
		echo "$f: disabled"
	fi
	rm -f "$f.elanfp-backup"
}

case "${1:-install}" in
install)
	if [ ! -f "$BUILD/elanfp" ] || [ ! -f "$BUILD/pam_elanfp.so" ]; then
		echo "build first: xmake" >&2
		exit 1
	fi
	install -D -m 0755 "$BUILD/elanfp" "$BIN/elanfp"
	install -D -m 0755 "$BUILD/pam_elanfp.so" "$PAMLIB/pam_elanfp.so"
	install -d -m 0700 "$DATA"
	for s in $SERVICES; do enable_pam "$s"; done
	echo "done. enroll with: sudo elanfp enroll <user> [finger-name]"
	;;
uninstall | purge)
	# PAM lines first, so the module is never referenced while missing
	for s in $SERVICES; do disable_pam "$s"; done
	rm -f "$PAMLIB/pam_elanfp.so" "$BIN/elanfp"
	if [ "$1" = purge ]; then
		rm -rf "$DATA"
		echo "removed, enrolled fingers deleted"
	else
		echo "removed, enrolled fingers kept in $DATA"
	fi
	;;
*)
	echo "usage: $0 [install|uninstall|purge]" >&2
	exit 2
	;;
esac
