#!/usr/bin/env bash
# logfold installer.
#
# Usage (piped from GitHub raw):
#   curl -fsSL https://raw.githubusercontent.com/YanivSaar/LogFold/main/scripts/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/YanivSaar/LogFold/main/scripts/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/YanivSaar/LogFold/main/scripts/install.sh | bash -s -- --version v0.14.3
#
# Downloads the matching release tarball from GitHub, verifies its
# sha256 against the published sidecar, and installs the binary to
# $PREFIX/bin/logfold. Default prefix is /usr/local when run as root,
# or ~/.local when run as a regular user.
#
# Supported targets:
#   Linux x86_64  -> x86_64-unknown-linux-musl
#   Linux aarch64 -> aarch64-unknown-linux-musl
#
# Flags:
#   --version <tag>   release tag to install (default: latest)
#   --prefix  <dir>   install prefix; binary lands at <dir>/bin/logfold
#   --target  <t>    override auto-detected target triple
#   --no-verify       skip sha256 check (NOT recommended)
#   --help            print this and exit
#
# This script sets `set -euo pipefail` and `set -o errtrace`, so a
# failure in any step aborts the install cleanly.

set -euo pipefail
set -o errtrace

REPO="YanivSaar/LogFold"
VERSION=""
TARGET=""
PREFIX=""
VERIFY="yes"

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'logfold-install: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --prefix)  PREFIX="$2";  shift 2 ;;
        --target)  TARGET="$2";  shift 2 ;;
        --no-verify) VERIFY="no"; shift ;;
        -h|--help) usage ;;
        *) die "unknown flag: $1 (try --help)" ;;
    esac
done

# -- target auto-detect ----------------------------------------------------
if [[ -z "$TARGET" ]]; then
    uname_s="$(uname -s)"
    uname_m="$(uname -m)"
    case "$uname_s" in
        Linux) ;;
        Darwin) die "macOS prebuilt binaries aren't published; install via 'cargo install logfold' instead" ;;
        *) die "unsupported OS: $uname_s (Linux only for prebuilt tarballs)" ;;
    esac
    case "$uname_m" in
        x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
        aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
        *) die "unsupported CPU: $uname_m" ;;
    esac
fi

# -- prefix default --------------------------------------------------------
if [[ -z "$PREFIX" ]]; then
    if [[ "$(id -u)" = "0" ]]; then
        PREFIX="/usr/local"
    else
        PREFIX="$HOME/.local"
    fi
fi
BIN_DIR="$PREFIX/bin"

# -- version resolution ----------------------------------------------------
if [[ -z "$VERSION" ]]; then
    log "resolving latest release tag"
    api="https://api.github.com/repos/$REPO/releases/latest"
    tag="$(curl -fsSL "$api" 2>/dev/null | grep -oE '"tag_name"[^,]*' | head -n1 | sed 's/.*: *"//; s/".*//')"
    if [[ -z "$tag" ]]; then
        die "could not resolve latest release tag from $api — pass --version <tag> explicitly"
    fi
    VERSION="$tag"
fi

ARCHIVE="logfold-${VERSION}-${TARGET}.tar.gz"
BASE="https://github.com/$REPO/releases/download/${VERSION}"
URL="${BASE}/${ARCHIVE}"
SHA_URL="${URL}.sha256"

tmp="$(mktemp -d -t logfold-install.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

log "target  : $TARGET"
log "version : $VERSION"
log "prefix  : $PREFIX"
log "archive : $URL"

log "downloading tarball"
curl -fL --proto '=https' --tlsv1.2 -o "$tmp/$ARCHIVE" "$URL" \
    || die "download failed: $URL"

if [[ "$VERIFY" = "yes" ]]; then
    log "downloading checksum"
    curl -fL --proto '=https' --tlsv1.2 -o "$tmp/${ARCHIVE}.sha256" "$SHA_URL" \
        || die "checksum download failed: $SHA_URL"
    log "verifying sha256"
    (cd "$tmp" && sha256sum -c "${ARCHIVE}.sha256") \
        || die "sha256 mismatch — aborting install"
else
    log "skipping sha256 verification (--no-verify)"
fi

log "extracting"
tar -xzf "$tmp/$ARCHIVE" -C "$tmp"

src="$tmp/logfold-${VERSION}-${TARGET}/logfold"
[[ -f "$src" ]] || die "extracted archive is missing the logfold binary at $src"

log "installing to $BIN_DIR/logfold"
install -d -m 0755 "$BIN_DIR"
# install -m: owner from the invoking user. On a non-root run we land
# in ~/.local/bin which the user already owns.
install -m 0755 "$src" "$BIN_DIR/logfold"

if ! command -v logfold >/dev/null 2>&1 || [[ "$(command -v logfold)" != "$BIN_DIR/logfold" ]]; then
    cat >&2 <<EOF

Installed to $BIN_DIR/logfold but that directory is not on your PATH.
Add it, e.g.:
    echo 'export PATH="$BIN_DIR:\$PATH"' >> ~/.bashrc
    source ~/.bashrc

Or run it directly:
    $BIN_DIR/logfold --version

EOF
else
    log "done"
    "$BIN_DIR/logfold" --version || true
fi
