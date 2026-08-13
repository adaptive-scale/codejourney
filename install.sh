#!/bin/sh
# CodeJourney installer
#
#   curl -fsSL https://raw.githubusercontent.com/adaptive-scale/codejourney/master/install.sh | sh
#
# Environment variables:
#   VERSION     release tag to install (default: latest)
#   INSTALL_DIR directory to install into (default: /usr/local/bin, or
#               ~/.local/bin when /usr/local/bin is not writable)

set -eu

REPO="adaptive-scale/codejourney"
BINARY="codejourney"
VERSION="${VERSION:-latest}"

info() { printf '\033[0;34m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[0;33mwarning:\033[0m %s\n' "$1" >&2; }
err() { printf '\033[0;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

need() {
	command -v "$1" >/dev/null 2>&1 || err "'$1' is required but was not found in PATH"
}

need uname
need tar
need mktemp

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL "$1" -o "$2"; }
	fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -qO "$2" "$1"; }
	fetch_stdout() { wget -qO- "$1"; }
else
	err "either 'curl' or 'wget' is required"
fi

# Detect platform ------------------------------------------------------------

os=$(uname -s)
case "$os" in
	Darwin) os="darwin" ;;
	Linux) os="linux" ;;
	*) err "unsupported operating system: $os (build from source: cargo build --release)" ;;
esac

arch=$(uname -m)
case "$arch" in
	arm64 | aarch64) arch="aarch64" ;;
	x86_64 | amd64) arch="x86_64" ;;
	*) err "unsupported architecture: $arch (build from source: cargo build --release)" ;;
esac

platform="${os}-${arch}"

# Resolve version ------------------------------------------------------------

if [ "$VERSION" = "latest" ]; then
	info "Resolving latest release..."
	VERSION=$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" |
		grep '"tag_name"' | head -1 | cut -d'"' -f4)
	[ -n "$VERSION" ] || err "could not resolve the latest release tag from the GitHub API"
fi

info "Installing ${BINARY} ${VERSION} for ${platform}"

# Download -------------------------------------------------------------------

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

base="https://github.com/${REPO}/releases/download/${VERSION}"

# Asset naming has varied across releases; try each known layout in turn.
asset=""
for candidate in \
	"${BINARY}-${platform}-${VERSION}.tar.gz" \
	"${BINARY}-${platform}.tar.gz"; do
	if fetch "${base}/${candidate}" "${tmp}/${candidate}" 2>/dev/null; then
		asset="$candidate"
		tar xzf "${tmp}/${asset}" -C "$tmp"
		break
	fi
done

if [ -z "$asset" ]; then
	fetch "${base}/${BINARY}-${platform}" "${tmp}/${BINARY}" 2>/dev/null ||
		err "no prebuilt binary for ${platform} in ${VERSION}.
Check https://github.com/${REPO}/releases/tag/${VERSION} for available assets,
or build from source:

  git clone https://github.com/${REPO}.git
  cd codejourney && cargo build --release"
fi

# `make dist` tars the binary under its platform-suffixed name; normalise it.
if [ ! -f "${tmp}/${BINARY}" ] && [ -f "${tmp}/${BINARY}-${platform}" ]; then
	mv "${tmp}/${BINARY}-${platform}" "${tmp}/${BINARY}"
fi

[ -f "${tmp}/${BINARY}" ] || err "downloaded archive did not contain a '${BINARY}' binary"
chmod +x "${tmp}/${BINARY}"

# Verify checksum if the release publishes one -------------------------------

if fetch "${base}/checksums.txt" "${tmp}/checksums.txt" 2>/dev/null ||
	fetch "${base}/checksums-${VERSION}.txt" "${tmp}/checksums.txt" 2>/dev/null; then
	if command -v shasum >/dev/null 2>&1; then
		sha_cmd="shasum -a 256"
	elif command -v sha256sum >/dev/null 2>&1; then
		sha_cmd="sha256sum"
	else
		sha_cmd=""
	fi
	if [ -n "$sha_cmd" ] && [ -f "${tmp}/${asset}" ]; then
		expected=$(grep " ${asset}\$" "${tmp}/checksums.txt" | head -1 | cut -d' ' -f1 || true)
		if [ -n "$expected" ]; then
			actual=$($sha_cmd "${tmp}/${asset}" | cut -d' ' -f1)
			[ "$expected" = "$actual" ] || err "checksum mismatch for ${asset}
  expected: ${expected}
  actual:   ${actual}"
			info "Checksum verified"
		fi
	fi
fi

# Install --------------------------------------------------------------------

if [ -n "${INSTALL_DIR:-}" ]; then
	target="$INSTALL_DIR"
elif [ -w /usr/local/bin ] 2>/dev/null; then
	target="/usr/local/bin"
elif [ "$(id -u)" = "0" ]; then
	target="/usr/local/bin"
else
	target="${HOME}/.local/bin"
fi

mkdir -p "$target" 2>/dev/null || err "cannot create install directory: $target"

if [ -w "$target" ]; then
	mv "${tmp}/${BINARY}" "${target}/${BINARY}"
elif command -v sudo >/dev/null 2>&1; then
	info "Elevating with sudo to write to ${target}"
	sudo mv "${tmp}/${BINARY}" "${target}/${BINARY}"
else
	err "no write permission for ${target}; retry with INSTALL_DIR=\$HOME/.local/bin"
fi

info "Installed ${target}/${BINARY}"

case ":${PATH}:" in
	*":${target}:"*) ;;
	*) warn "${target} is not on your PATH. Add it with:

  echo 'export PATH=\"${target}:\$PATH\"' >> ~/.zshrc && source ~/.zshrc" ;;
esac

"${target}/${BINARY}" --version 2>/dev/null || true
info "Run '${BINARY} scan' inside a git repository to get started."
