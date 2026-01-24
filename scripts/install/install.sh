#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/spikermint/vet"

setup_colors() {
    if [[ -t 1 ]]; then
        RESET='\033[0m'
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        DIM='\033[0;2m'
    else
        RESET='' RED='' GREEN='' DIM=''
    fi
}

error() {
    echo -e "${RED}error${RESET}: $*" >&2
    exit 1
}

info() {
    echo -e "${DIM}$*${RESET}"
}

detect_target() {
    local platform
    platform=$(uname -ms)

    case "$platform" in
        'Darwin x86_64')  echo "darwin-x64" ;;
        'Darwin arm64')   echo "darwin-arm64" ;;
        'Linux aarch64')  echo "linux-arm64" ;;
        'Linux arm64')    echo "linux-arm64" ;;
        'Linux x86_64')   echo "linux-x64" ;;
        'MINGW64'*)       echo "windows-x64" ;;
        *)                echo "linux-x64" ;;
    esac
}

is_rosetta() {
    [[ $(sysctl -n sysctl.proc_translated 2>/dev/null) == "1" ]]
}

build_download_url() {
    local target="$1"
    local version="$2"

    local base_url
    if [[ -z "$version" ]]; then
        base_url="$REPO/releases/latest/download"
    else
        base_url="$REPO/releases/download/$version"
    fi

    local filename="vet-$target"
    [[ "$target" == "windows-x64" ]] && filename="$filename.exe"

    echo "$base_url/$filename"
}

download_binary() {
    local url="$1"
    local dest="$2"

    curl --fail --location --progress-bar --output "$dest" "$url" || \
        error "Failed to download from $url"

    chmod +x "$dest"
}

main() {
    setup_colors

    if [[ "${OS:-}" == "Windows_NT" && "$(uname -ms)" != MINGW64* ]]; then
        powershell -c "irm https://vet.codes/install.ps1 | iex"
        exit $?
    fi

    local target
    target=$(detect_target)

    if [[ "$target" == "darwin-x64" ]] && is_rosetta; then
        target="darwin-arm64"
        info "Rosetta 2 detected. Using $target binary."
    fi

    local version="${1:-}"
    local install_dir="${VET_INSTALL:-$HOME/.vet}"
    local exe="$install_dir/bin/vet"

    mkdir -p "$install_dir/bin"
    download_binary "$(build_download_url "$target" "$version")" "$exe"

    echo
    echo -e "${GREEN}Installed to${RESET} $exe"

    if ! command -v vet >/dev/null; then
        echo
        echo "Add to your PATH:"
        echo "  export PATH=\"$install_dir/bin:\$PATH\""
    fi

    echo
    info "Run 'vet --help' to get started"
}

main "$@"