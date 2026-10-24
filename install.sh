#!/usr/bin/env bash
# logfold installer.
#
# Downloads the latest released binary, verifies its SHA-256, and
# installs it into /usr/local/bin (or $HOME/.local/bin when
# /usr/local is not writable). Zero dependencies beyond curl, tar,
# and sha256sum (or shasum on macOS).
#
# Quick install:
#     curl -fsSL https://raw.githubusercontent.com/YanivSaar/LogFold/main/install.sh | bash
#
# Pin a version:
#     curl -fsSL ... | LOGFOLD_VERSION=v0.1.0 bash
#
# Install into a custom prefix (binary goes to $PREFIX/bin):
#     curl -fsSL ... | LOGFOLD_PREFIX="$HOME/.local" bash
#
# Dry run (download + verify, but do not install):
#     curl -fsSL ... | LOGFOLD_DRY_RUN=1 bash

set -euo pipefail

REPO="YanivSaar/LogFold"
VERSION="${LOGFOLD_VERSION:-}"
PREFIX="${LOGFOLD_PREFIX:-}"
DRY_RUN="${LOGFOLD_DRY_RUN:-0}"

say()  { printf '  %s\n' "$*"; }
step() { printf '\n>> %s\n' "$*"; }
die()  { printf '\n!! %s\n' "$*" >&2; exit 1; }

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Linux)
      case "$arch" in
        x86_64|amd64)  echo "x86_64-unknown-linux-musl" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
        *) die "unsupported Linux architecture: $arch" ;;
      esac
      ;;
    Darwin)
      case "$arch" in
        x86_64)       echo "x86_64-apple-darwin" ;;
        arm64|aarch64) echo "aarch64-apple-darwin" ;;
        *) die "unsupported macOS architecture: $arch" ;;
      esac
      ;;
    *) die "unsupported OS: $os (Linux and macOS only right now)" ;;
  esac
}

latest_version() {
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | awk -F'"' '/"tag_name"/ { print $4; exit }'
}

choose_prefix() {
  if [ -n "$PREFIX" ]; then
    echo "$PREFIX"
    return
  fi
  if [ -w /usr/local/bin ]; then
    echo "/usr/local"
    return
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    echo "/usr/local"
    return
  fi
  echo "$HOME/.local"
}

verify_sha() {
  local sha_file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$sha_file" >/dev/null
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "$sha_file" >/dev/null
  else
    die "no sha256sum or shasum available on PATH"
  fi
}

main() {
  for tool in curl tar uname mktemp; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
  done

  step "resolving target and version"
  local target version
  target="$(detect_target)"
  if [ -z "$VERSION" ]; then
    version="$(latest_version)" \
      || die "could not query latest release from GitHub"
    [ -n "$version" ] || die "no releases published yet for $REPO"
  else
    version="$VERSION"
  fi
  say "target : $target"
  say "version: $version"

  local tmp
  tmp="$(mktemp -d)"
  trap "rm -rf '$tmp'" EXIT
  cd "$tmp"

  local archive sha base
  archive="logfold-${version}-${target}.tar.gz"
  sha="${archive}.sha256"
  base="https://github.com/${REPO}/releases/download/${version}"

  step "downloading tarball"
  curl -fsSL -o "$archive" "${base}/${archive}" \
    || die "could not download ${base}/${archive}"
  curl -fsSL -o "$sha" "${base}/${sha}" \
    || die "could not download ${base}/${sha}"

  step "verifying SHA-256"
  verify_sha "$sha"
  say "ok"

  step "extracting"
  tar -xzf "$archive"
  local src="logfold-${version}-${target}/logfold"
  [ -x "$src" ] || die "binary not found inside archive: $src"

  if [ "$DRY_RUN" = "1" ]; then
    step "dry run complete"
    say "would install $src to <prefix>/bin"
    exit 0
  fi

  local prefix bindir
  prefix="$(choose_prefix)"
  bindir="$prefix/bin"
  step "installing to $bindir"
  mkdir -p "$bindir"
  if [ -w "$bindir" ]; then
    install -m 0755 "$src" "$bindir/logfold"
  else
    sudo install -m 0755 "$src" "$bindir/logfold"
  fi

  step "done"
  "$bindir/logfold" --version 2>/dev/null \
    || say "installed, but '$bindir/logfold --version' did not run cleanly"
  echo
  case ":$PATH:" in
    *":$bindir:"*)
      say "$bindir is already on \$PATH. Run: logfold --help"
      ;;
    *)
      say "add $bindir to your \$PATH, e.g."
      say "  export PATH=\"$bindir:\$PATH\""
      ;;
  esac
}

main "$@"
