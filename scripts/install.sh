#!/usr/bin/env bash
set -Eeuo pipefail

# Maskman release installer. It intentionally delegates daemon configuration
# and service ownership to the maskman CLI after validating the release asset.

readonly REPOSITORY="backrunner/maskman"
readonly API_URL="https://api.github.com/repos/${REPOSITORY}/releases/latest"
readonly INSTALL_ROOT="/usr/local/bin"
readonly BINARY_PATH="${INSTALL_ROOT}/maskman"
readonly DEFAULT_CONFIG_LINUX="/etc/maskman/config.toml"
readonly DEFAULT_CONFIG_MACOS="/Library/Application Support/Maskman/config.toml"

color_mode="auto"
requested_version="${MASKMAN_VERSION:-latest}"
config_path=""
force_config=0
dry_run=0
use_color=0
tmp_dir=""

usage() {
    cat <<'EOF'
Usage: install.sh [options]

Install the latest signed Maskman release, create a bearer-authenticated
development-TLS configuration, install the native service, and start it.

Options:
  --version VERSION  Install an exact release version (default: latest)
  --config PATH      Configuration path (platform default if omitted)
  --force            Replace an existing configuration and credentials
  --color MODE       auto, always, or never (default: auto)
  --dry-run          Print the detected platform and paths without changes
  -h, --help         Show this help

Environment:
  MASKMAN_VERSION    Same as --version
  NO_COLOR            Disable ANSI output when --color auto is used
EOF
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '%s\n' "$*"
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

on_exit() {
    if [[ -n "$tmp_dir" && -d "$tmp_dir" ]]; then
        rm -rf -- "$tmp_dir"
    fi
}
trap on_exit EXIT

parse_args() {
    while (($# > 0)); do
        case "$1" in
            --version)
                (($# >= 2)) || fail "--version requires a value"
                requested_version="$2"
                shift 2
                ;;
            --config)
                (($# >= 2)) || fail "--config requires a path"
                config_path="$2"
                shift 2
                ;;
            --force)
                force_config=1
                shift
                ;;
            --color)
                (($# >= 2)) || fail "--color requires auto, always, or never"
                color_mode="$2"
                shift 2
                ;;
            --dry-run)
                dry_run=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fail "unknown option: $1 (try --help)"
                ;;
        esac
    done
    case "$color_mode" in
        auto|always|never) ;;
        *) fail "--color must be auto, always, or never" ;;
    esac
}

setup_colors() {
    if [[ "$color_mode" == "always" ]] || {
        [[ "$color_mode" == "auto" ]] && [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]] \
            && [[ "${TERM:-}" != "dumb" ]]
    }; then
        use_color=1
    fi
    if ((use_color)); then
        bold=$'\033[1m'
        green=$'\033[32m'
        yellow=$'\033[33m'
        reset=$'\033[0m'
    else
        bold=''
        green=''
        yellow=''
        reset=''
    fi
}

detect_platform() {
    os="$(uname -s)"
    machine="$(uname -m)"
    distro=""
    target=""
    config_default=""

    case "$os:$machine" in
        Linux:x86_64|Linux:amd64)
            target="x86_64-unknown-linux-musl"
            config_default="$DEFAULT_CONFIG_LINUX"
            ;;
        Linux:aarch64|Linux:arm64)
            target="aarch64-unknown-linux-musl"
            config_default="$DEFAULT_CONFIG_LINUX"
            ;;
        Darwin:arm64)
            target="aarch64-apple-darwin"
            config_default="$DEFAULT_CONFIG_MACOS"
            ;;
        Darwin:x86_64)
            fail "Intel macOS is not in the published target matrix; use an arm64 Mac or build from source"
            ;;
        *)
            fail "unsupported platform: ${os} ${machine}"
            ;;
    esac

    if [[ "$os" == "Linux" ]]; then
        [[ -r /etc/os-release ]] || fail "cannot identify Linux distribution (/etc/os-release is missing)"
        # shellcheck disable=SC1091
        . /etc/os-release
        distro="${ID:-unknown}"
        case ",${ID:-},${ID_LIKE:-}," in
            *,debian,*|*,ubuntu,*|*,linuxmint,*) package_family="debian" ;;
            *,rhel,*|*,fedora,*|*,centos,*|*,rocky,*|*,almalinux,*) package_family="redhat" ;;
            *,arch,*|*,manjaro,*) package_family="arch" ;;
            *) fail "unsupported Linux distribution: ${distro}" ;;
        esac
        command -v systemctl >/dev/null 2>&1 || fail "systemd/systemctl is required on Linux"
    else
        package_family="macos"
        command -v launchctl >/dev/null 2>&1 || fail "launchctl is required on macOS"
    fi

    [[ -n "$config_path" ]] || config_path="$config_default"
}

require_tools() {
    command -v curl >/dev/null 2>&1 || fail "curl is required"
    command -v tar >/dev/null 2>&1 || fail "tar is required"
    if [[ "$os" == "Linux" ]]; then
        command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
    else
        command -v shasum >/dev/null 2>&1 || fail "shasum is required"
    fi
}

require_root() {
    [[ "$(id -u)" -eq 0 ]] || fail "run this installer as root (for example: sudo $0)"
}

validate_version() {
    [[ "$1" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid release version: $1"
}

resolve_version() {
    if [[ "$requested_version" == "latest" ]]; then
        local metadata tag
        metadata="$(curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
            -H 'Accept: application/vnd.github+json' -A 'maskman-install/1' "$API_URL")" \
            || fail "could not read the latest GitHub release"
        tag="$(printf '%s' "$metadata" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
        [[ -n "$tag" ]] || fail "latest GitHub release did not contain a tag"
        requested_version="${tag#v}"
    else
        requested_version="${requested_version#v}"
    fi
    validate_version "$requested_version"
}

download_release() {
    local archive_name="maskman-${requested_version}-${target}.tar.gz"
    local archive_url="https://github.com/${REPOSITORY}/releases/download/v${requested_version}/${archive_name}"
    local checksum_url="${archive_url}.sha256"
    local archive="$tmp_dir/$archive_name"
    local checksum="$tmp_dir/${archive_name}.sha256"

    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        -A 'maskman-install/1' "$archive_url" -o "$archive" \
        || fail "could not download ${archive_name}"
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        -A 'maskman-install/1' "$checksum_url" -o "$checksum" \
        || fail "could not download the release checksum"

    local expected actual
    expected="$(awk '{ for (i = 1; i <= NF; i++) if (length($i) == 64 && $i ~ /^[[:xdigit:]]+$/) { print tolower($i); exit } }' "$checksum")"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail "release checksum has an invalid format"
    if [[ "$os" == "Linux" ]]; then
        actual="$(sha256sum "$archive" | awk '{print $1}')"
    else
        actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
    fi
    [[ "$actual" == "$expected" ]] || fail "release checksum verification failed"

    archive_path="$archive"
}

install_binary() {
    local extract_dir="$tmp_dir/extract"
    mkdir -p -- "$extract_dir" "$INSTALL_ROOT"
    [[ ! -L "$BINARY_PATH" ]] || fail "refusing to replace symbolic-link binary: $BINARY_PATH"
    tar -xzf "$archive_path" -C "$extract_dir"
    [[ -f "$extract_dir/maskman" && ! -L "$extract_dir/maskman" ]] \
        || fail "release archive does not contain a regular maskman binary"
    chmod 0755 "$extract_dir/maskman"
    install -m 0755 "$extract_dir/maskman" "$BINARY_PATH"
}

configure_and_start() {
    local config_dir setup_log token
    config_dir="$(dirname "$config_path")"
    mkdir -p -- "$config_dir"

    if [[ -e "$config_path" && "$force_config" -ne 1 ]]; then
        [[ ! -L "$config_path" ]] || fail "refusing to use symbolic-link configuration: $config_path"
        [[ -f "$config_path" ]] || fail "configuration path exists and is not a regular file: $config_path"
        "$BINARY_PATH" --color never --config "$config_path" config validate \
            >/dev/null || fail "existing configuration is invalid; use --force to replace it"
        token=""
        warn "existing configuration preserved; its bearer token cannot be recovered"
    else
        setup_log="$tmp_dir/setup.log"
        "$BINARY_PATH" --color never setup --non-interactive --development --yes \
            --enable-udp --output "$config_path" >"$setup_log" 2>&1 \
            || { sed -n '1,120p' "$setup_log" >&2; fail "Maskman setup failed"; }
        token="$(sed -n 's/^Bearer token (shown once): //p' "$setup_log" | head -n 1)"
        [[ "$token" =~ ^mm_[A-Za-z0-9_.-]+_[A-Za-z0-9_-]+$ ]] \
            || fail "setup did not return a bearer credential"
    fi

    "$BINARY_PATH" --color never --config "$config_path" config validate >/dev/null \
        || fail "generated configuration failed validation"
    "$BINARY_PATH" --color never --config "$config_path" install --yes \
        || fail "service installation failed"
    "$BINARY_PATH" --color never --config "$config_path" start --yes \
        || fail "service start failed"

    local attempts=0 status
    while ((attempts < 50)); do
        ((attempts += 1))
        status="$($BINARY_PATH --color never --config "$config_path" status --json 2>/dev/null || true)"
        if [[ "$status" == *'"ready":true'* ]]; then
            print_success "$token"
            return 0
        fi
        sleep 0.1
    done
    fail "service started but did not become ready; inspect with: $BINARY_PATH --config '$config_path' status"
}

print_success() {
    local token="$1"
    printf '\n%s%s Maskman is installed and running %s\n' "$bold" "$green" "$reset"
    printf '%s----------------------------------------------%s\n' "$bold" "$reset"
    printf '%s  Service:  running (%s)\n' "$bold" "$package_family"
    printf '  Config:   %s\n' "$config_path"
    printf '  Endpoint: https://<server-address>:443\n'
    if [[ -n "$token" ]]; then
        printf '  Bearer:   %s%s%s\n' "$yellow" "$token" "$reset"
        printf '\n%s  Store this bearer credential now; it is shown only once.%s\n' "$yellow" "$reset"
    else
        printf '  Bearer:   unchanged (the existing secret is not readable)\n'
    fi
    printf '%s----------------------------------------------%s\n' "$bold" "$reset"
    printf '  Check:    %s --config %s status\n' "$BINARY_PATH" "$config_path"
}

main() {
    parse_args "$@"
    setup_colors
    detect_platform
    if ((dry_run)); then
        info "platform: ${os} ${machine} (${package_family})"
        info "release target: ${target}"
        info "binary: ${BINARY_PATH}"
        info "config: ${config_path}"
        info "service: ${package_family} native service manager"
        exit 0
    fi
    require_tools
    require_root
    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/maskman-install.XXXXXX")"
    chmod 0700 "$tmp_dir"
    resolve_version
    info "installing Maskman ${requested_version} for ${target}"
    download_release
    install_binary
    configure_and_start
}

main "$@"
