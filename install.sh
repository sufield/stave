#!/usr/bin/env sh
#
# Stave installer — downloads the appropriate release archive, verifies its
# SHA-256 against the published SHA256SUMS file, and installs the binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sufield/stave/main/install.sh | sh
#
# Or, audit first then run:
#   curl -fsSL https://raw.githubusercontent.com/sufield/stave/main/install.sh > install.sh
#   less install.sh         # review the script
#   sh install.sh
#
# Environment:
#   STAVE_VERSION       Tag to install (default: latest)
#   STAVE_INSTALL_DIR   Install directory (default: $HOME/.local/bin)
#   STAVE_VERIFY_SIG    If "1" and cosign is on PATH, verify the SHA256SUMS
#                       signature against the published Sigstore bundle.
#                       Off by default so the install works without cosign.
#
# Exit codes:
#   0  installed successfully
#   1  install failed (download, checksum, or extraction)
#   2  required tool missing (curl, sha256sum/shasum, tar)
#   3  unsupported OS or architecture

set -eu

# ----- configuration -------------------------------------------------------

REPO="sufield/stave"
BIN_NAME="stave"
INSTALL_DIR="${STAVE_INSTALL_DIR:-$HOME/.local/bin}"
WANT_VERSION="${STAVE_VERSION:-latest}"
VERIFY_SIG="${STAVE_VERIFY_SIG:-0}"

# ----- helpers -------------------------------------------------------------

err() { printf 'install: %s\n' "$*" >&2; }
info() { printf '==> %s\n' "$*"; }

need() {
	command -v "$1" >/dev/null 2>&1 || {
		err "required tool '$1' not found on PATH"
		exit 2
	}
}

# Detect a sha256 hasher and wrap it as: sha256_check <expected> <file>
sha256_check() {
	expected="$1"
	file="$2"
	if command -v sha256sum >/dev/null 2>&1; then
		actual=$(sha256sum "$file" | awk '{print $1}')
	elif command -v shasum >/dev/null 2>&1; then
		actual=$(shasum -a 256 "$file" | awk '{print $1}')
	else
		err "no sha256sum or shasum on PATH; cannot verify checksum"
		exit 2
	fi
	if [ "$expected" != "$actual" ]; then
		err "checksum mismatch for $(basename "$file")"
		err "  expected: $expected"
		err "  got:      $actual"
		exit 1
	fi
}

# ----- platform detection --------------------------------------------------

uname_s=$(uname -s 2>/dev/null || echo unknown)
case "$uname_s" in
	Linux)   os=linux ;;
	Darwin)  os=darwin ;;
	MINGW*|MSYS*|CYGWIN*) os=windows ;;
	*)
		err "unsupported OS: $uname_s"
		exit 3
		;;
esac

uname_m=$(uname -m 2>/dev/null || echo unknown)
case "$uname_m" in
	x86_64|amd64)   arch=amd64 ;;
	aarch64|arm64)  arch=arm64 ;;
	*)
		err "unsupported architecture: $uname_m"
		exit 3
		;;
esac

# ----- tool prerequisites --------------------------------------------------

need curl
if [ "$os" = "windows" ]; then
	need unzip
else
	need tar
fi

# ----- resolve version -----------------------------------------------------

if [ "$WANT_VERSION" = "latest" ]; then
	# Follow the redirect from /releases/latest to /releases/tag/vX.Y.Z and
	# extract the tag. The "v" prefix is the goreleaser convention.
	resolved=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
		"https://github.com/$REPO/releases/latest" 2>/dev/null \
		| sed 's#.*/tag/##')
	if [ -z "$resolved" ] || [ "$resolved" = "https://github.com/$REPO/releases/latest" ]; then
		err "could not resolve latest version (network or GitHub API issue)"
		exit 1
	fi
	tag="$resolved"
else
	# Allow callers to pass either "v0.0.4" or "0.0.4".
	case "$WANT_VERSION" in
		v*) tag="$WANT_VERSION" ;;
		*)  tag="v$WANT_VERSION" ;;
	esac
fi

version_no_v="${tag#v}"
info "installing stave $tag for $os/$arch"

# ----- staging -------------------------------------------------------------

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t stave-install)
trap 'rm -rf "$tmp"' EXIT INT TERM HUP

base_url="https://github.com/$REPO/releases/download/$tag"
if [ "$os" = "windows" ]; then
	archive_name="stave_${tag}_${os}_${arch}.zip"
else
	archive_name="stave_${tag}_${os}_${arch}.tar.gz"
fi

# ----- download checksums + archive ---------------------------------------

info "fetching SHA256SUMS"
curl -fsSL "$base_url/SHA256SUMS" -o "$tmp/SHA256SUMS"

# Optional: verify the SHA256SUMS file's cosign signature.
if [ "$VERIFY_SIG" = "1" ]; then
	if command -v cosign >/dev/null 2>&1; then
		info "fetching SHA256SUMS.sig and verifying with cosign"
		curl -fsSL "$base_url/SHA256SUMS.sig" -o "$tmp/SHA256SUMS.sig"
		cosign verify-blob \
			--bundle "$tmp/SHA256SUMS.sig" \
			--certificate-identity-regexp "https://github.com/$REPO/" \
			--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
			"$tmp/SHA256SUMS" \
			|| { err "cosign signature verification failed"; exit 1; }
	else
		err "STAVE_VERIFY_SIG=1 but cosign is not on PATH; aborting"
		exit 2
	fi
fi

info "fetching $archive_name"
curl -fsSL "$base_url/$archive_name" -o "$tmp/$archive_name"

# ----- verify checksum -----------------------------------------------------

expected=$(awk -v target="$archive_name" '$2 == target { print $1 }' "$tmp/SHA256SUMS")
if [ -z "$expected" ]; then
	err "no checksum entry for $archive_name in SHA256SUMS"
	exit 1
fi
sha256_check "$expected" "$tmp/$archive_name"
info "checksum OK"

# ----- extract -------------------------------------------------------------

mkdir -p "$tmp/extract"
case "$archive_name" in
	*.tar.gz) tar -xzf "$tmp/$archive_name" -C "$tmp/extract" ;;
	*.zip)    unzip -q "$tmp/$archive_name" -d "$tmp/extract" ;;
esac

if [ "$os" = "windows" ]; then
	bin_path="$tmp/extract/$BIN_NAME.exe"
else
	bin_path="$tmp/extract/$BIN_NAME"
fi
if [ ! -f "$bin_path" ]; then
	err "expected binary $bin_path not found in archive"
	exit 1
fi

# ----- install -------------------------------------------------------------

mkdir -p "$INSTALL_DIR"
dest="$INSTALL_DIR/$(basename "$bin_path")"
cp "$bin_path" "$dest"
chmod +x "$dest"
info "installed $dest"

# ----- post-install notes --------------------------------------------------

case ":$PATH:" in
	*":$INSTALL_DIR:"*) ;;
	*)
		echo
		echo "Note: $INSTALL_DIR is not on your PATH."
		echo "      Add this to your shell profile:"
		echo "          export PATH=\"$INSTALL_DIR:\$PATH\""
		;;
esac

echo
"$dest" --version 2>/dev/null || true
