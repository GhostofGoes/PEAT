#!/bin/sh

# PEAT easy installer (POSIX sh)
# Installs latest release PEAT binary to $PREFIX/bin/peat,
# man page to $PREFIX/share/man/man1, and updates the
# manual database (if 'mandb' command is present).
#
# Environment variables:
#   PREFIX   Installation prefix (default: /usr/local)
#   DESTDIR  Staging directory prepended to all install paths (default: empty)
#
# Examples:
#   sudo ./install_peat.sh
#   PREFIX="$HOME/.local" ./install_peat.sh

set -eu

REPO="${REPO:-sandialabs/PEAT}"
API_URL="https://github.com/$REPO/releases/latest/download"

BIN_URL="$API_URL/peat"
MAN_URL="$API_URL/peat.1"

PREFIX="${PREFIX:-/usr/local}"
DESTDIR="${DESTDIR:-}"

BIN_DIR="$DESTDIR$PREFIX/bin"
BIN_DST="$BIN_DIR/peat"

MAN_DIR="$DESTDIR$PREFIX/share/man/man1"
MAN_DST="$MAN_DIR/peat.1"

TMPDIR=${TMPDIR:-/tmp}

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

download_to() {
  url=$1
  out=$2

  if need_cmd curl; then
    curl -sfL -o "$out" "$url"
  elif need_cmd wget; then
    wget -qO "$out" "$url"
  else
    die "Neither curl nor wget is available; please install one to proceed."
  fi
}


# Require privileges if the install location isn't writable (e.g. /usr/local)
INSTALL_ROOT="$DESTDIR$PREFIX"
while [ ! -e "$INSTALL_ROOT" ]; do
  INSTALL_ROOT=$(dirname "$INSTALL_ROOT")
done
if [ "$(id -u)" -ne 0 ] && [ ! -w "$INSTALL_ROOT" ]; then
  if need_cmd sudo; then
    say "Re-running with sudo (needed to write to $DESTDIR$PREFIX)..."
    exec sudo -H -- env PREFIX="$PREFIX" DESTDIR="$DESTDIR" REPO="$REPO" "$0" "$@"
  else
    die "This installer must run as root (or install sudo)."
  fi
fi


TMPBIN="$TMPDIR/peat_bin_$$"
TMPMAN="$TMPDIR/peat_man_$$"
trap 'rm -f "$TMPBIN" "$TMPMAN"' EXIT HUP INT TERM


say "Downloading PEAT binary..."
download_to "$BIN_URL" "$TMPBIN"

say "Downloading man page..."
download_to "$MAN_URL" "$TMPMAN"


say "Installing peat to $BIN_DST ..."
[ -d "$BIN_DIR" ] || mkdir -p "$BIN_DIR"

if need_cmd install; then
  install -m 0755 "$TMPBIN" "$BIN_DST"
else
  cp -f "$TMPBIN" "$BIN_DST"
  chmod 0755 "$BIN_DST"
fi


say "Installing man page to $MAN_DST ..."
[ -d "$MAN_DIR" ] || mkdir -p "$MAN_DIR"
if need_cmd install; then
    install -m 0644 "$TMPMAN" "$MAN_DST"
else
    cp -f "$TMPMAN" "$MAN_DST"
    chmod 0644 "$MAN_DST"
fi

if [ -n "$DESTDIR" ]; then
    say "DESTDIR is set, skipping man database update"
elif need_cmd mandb; then
    say "Updating man database (mandb)..."
    mandb >/dev/null 2>&1 || mandb || true
else
    say "WARN: 'mandb' command not present, skipping man page update"
fi

say "Done! Try: peat --help"
