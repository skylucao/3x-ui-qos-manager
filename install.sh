#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

VERSION=1.1.0
DEFAULT_REPOSITORY="skylucao/3x-ui-qos-manager"
DEFAULT_RELEASE_REF="v1.1.0"
XUI_INSTALLER_REF="v3.7.0"
XUI_INSTALLER_SHA256="a7f4fedcea3abe8987508d00f29834b8872e4e4e5059159eb19460d474b37cdc"

link_mbps=${QOS_LINK_MBPS:-}
reserve_mbps=${QOS_RESERVE_MBPS:-}
wan_interface=${QOS_WAN:-}
panel_host=${QOS_PANEL_HOST:-}
extra_management_ports=${QOS_EXTRA_MGMT_PORTS:-}
enable_bbr=yes
assume_yes=no
dry_run=no
temporary_root=
source_root=
backup_dir=
rollback_unit=
rollback_armed=no
backup_ready=no
finished=no

usage() {
    cat <<'EOF'
Usage: install.sh [options]

Installs per-inbound bandwidth controls and embeds them into 3x-ui.

Options:
  --link-mbps N       Physical/VPS line ceiling in Mbps (required unattended)
  --reserve-mbps N    Bandwidth reserved for management traffic
  --wan IFACE         WAN interface (auto-detected by default)
  --panel-host HOST   Public panel IPv4 address or DNS name
  --extra-mgmt PORTS  Additional protected TCP/UDP ports, comma-separated
  --no-bbr            Do not enable BBR
  --yes               Non-interactive mode
  --dry-run           Detect and validate without changing the machine
  -h, --help          Show this help

Environment equivalents: QOS_LINK_MBPS, QOS_RESERVE_MBPS, QOS_WAN,
QOS_PANEL_HOST, QOS_EXTRA_MGMT_PORTS, QOS_REPOSITORY, QOS_RELEASE_REF.
EOF
}

die() {
    echo "xui-qos install: $*" >&2
    exit 1
}

is_uint() {
    [[ $1 =~ ^[0-9]+$ ]]
}

service_active() {
    systemctl is-active --quiet "$1" && echo yes || echo no
}

service_enabled() {
    systemctl is-enabled --quiet "$1" 2>/dev/null && echo yes || echo no
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if (( rc != 0 )) && [[ "$backup_ready" == yes && "$finished" != yes ]]; then
        echo "xui-qos install: installation failed; restoring the previous state" >&2
        if [[ "$rollback_armed" == yes ]]; then
            systemctl stop "${rollback_unit}.timer" >/dev/null 2>&1 || true
        fi
        "$backup_dir/rollback.sh" "$backup_dir" || \
            echo "xui-qos install: automatic rollback reported an error; backup: $backup_dir" >&2
    fi
    if [[ -n "$temporary_root" && -d "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

while (( $# )); do
    case "$1" in
        --link-mbps)
            [[ $# -ge 2 ]] || die "$1 requires a value"
            link_mbps=$2; shift 2 ;;
        --reserve-mbps)
            [[ $# -ge 2 ]] || die "$1 requires a value"
            reserve_mbps=$2; shift 2 ;;
        --wan)
            [[ $# -ge 2 ]] || die "$1 requires a value"
            wan_interface=$2; shift 2 ;;
        --panel-host)
            [[ $# -ge 2 ]] || die "$1 requires a value"
            panel_host=$2; shift 2 ;;
        --extra-mgmt)
            [[ $# -ge 2 ]] || die "$1 requires a value"
            extra_management_ports=$2; shift 2 ;;
        --no-bbr)
            enable_bbr=no; shift ;;
        --yes)
            assume_yes=yes; shift ;;
        --dry-run)
            dry_run=yes; shift ;;
        -h|--help)
            usage; finished=yes; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || die "run as root (use sudo)"
[[ -d /run/systemd/system ]] || die "systemd is required"

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
else
    die "/etc/os-release is missing"
fi
case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "this release supports Debian and Ubuntu only" ;;
esac

if [[ "$dry_run" == no ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
        ca-certificates curl iproute2 kmod nginx openssl python3 tar util-linux
else
    for command_name in curl ip tc modprobe nginx openssl python3 systemctl; do
        command -v "$command_name" >/dev/null || die "$command_name is required for --dry-run"
    done
fi

exec 9>/run/lock/xui-qos-install.lock
flock -n 9 || die "another xui-qos installation is running"

# Bash does not populate BASH_SOURCE when this installer is piped to stdin.
script_dir=
if [[ -n ${BASH_SOURCE[0]:-} ]]; then
    script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)
fi
if [[ -n "$script_dir" && -f "$script_dir/src/xray-qos" ]]; then
    source_root=$script_dir
else
    repository=${QOS_REPOSITORY:-$DEFAULT_REPOSITORY}
    release_ref=${QOS_RELEASE_REF:-$DEFAULT_RELEASE_REF}
    [[ $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid QOS_REPOSITORY"
    [[ $release_ref =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid QOS_RELEASE_REF"
    temporary_root=$(mktemp -d /tmp/xui-qos-source.XXXXXXXX)
    curl -fL --retry 3 --connect-timeout 10 \
        "https://github.com/${repository}/archive/refs/tags/${release_ref}.tar.gz" \
        -o "$temporary_root/source.tar.gz"
    tar -xzf "$temporary_root/source.tar.gz" -C "$temporary_root"
    source_root=$(find "$temporary_root" -mindepth 1 -maxdepth 1 -type d -name '*-*' -print -quit)
    [[ -n "$source_root" && -f "$source_root/src/xray-qos" ]] || die "downloaded release is incomplete"
fi

for required_file in \
    src/xray-qos \
    src/qos-web/control.py \
    src/qos-web/web.py \
    src/qos-web/audit_view.py \
    src/qos-web/node_notes.py \
    src/qos-web/healthcheck.py \
    src/qos-web/static/dashboard.html \
    src/qos-web/static/xui-qos-integration.js \
    src/systemd/xray-qos.service \
    templates/nginx.conf.in \
    scripts/rollback-install.sh \
    scripts/uninstall.sh \
    scripts/verify.sh; do
    [[ -f "$source_root/$required_file" ]] || die "release file missing: $required_file"
done

if [[ ! -x /usr/local/x-ui/x-ui || ! -f /etc/systemd/system/x-ui.service ]]; then
    [[ "$dry_run" == no ]] || die "3x-ui is not installed; normal mode would install it"
    echo "xui-qos install: 3x-ui is missing; installing the official stable channel"
    xui_installer=$(mktemp /tmp/3x-ui-install.XXXXXXXX.sh)
    curl -fsSL --retry 3 --connect-timeout 10 \
        "https://raw.githubusercontent.com/MHSanaei/3x-ui/${XUI_INSTALLER_REF}/install.sh" \
        -o "$xui_installer"
    printf '%s  %s\n' "$XUI_INSTALLER_SHA256" "$xui_installer" | sha256sum -c - >/dev/null \
        || die "official 3x-ui installer checksum verification failed"
    XUI_NONINTERACTIVE=1 bash "$xui_installer" "$XUI_INSTALLER_REF"
    rm -f -- "$xui_installer"
fi

[[ -x /usr/local/x-ui/x-ui ]] || die "3x-ui executable is missing"
[[ -f /etc/x-ui/x-ui.db && ! -L /etc/x-ui/x-ui.db ]] || die "3x-ui SQLite database is missing or unsafe"
[[ $(stat -c '%U' /etc/x-ui/x-ui.db) == root ]] || die "3x-ui database must be root-owned"
systemctl cat x-ui.service >/dev/null || die "x-ui.service is missing"
systemctl cat x-ui.service | grep -q '/etc/default/x-ui' \
    || die "x-ui.service does not load /etc/default/x-ui; this 3x-ui build is unsupported"

db_value() {
    python3 - "$1" <<'PY'
import sqlite3, sys
connection = sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True, timeout=2)
try:
    row = connection.execute('SELECT value FROM settings WHERE key=?', (sys.argv[1],)).fetchone()
    print('' if row is None or row[0] is None else row[0])
finally:
    connection.close()
PY
}

python3 - <<'PY'
import sqlite3
connection = sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True, timeout=2)
try:
    settings = {row[1] for row in connection.execute('PRAGMA table_info(settings)')}
    inbounds = {row[1] for row in connection.execute('PRAGMA table_info(inbounds)')}
    if not {'key', 'value'} <= settings or not {'id', 'port', 'enable', 'node_id'} <= inbounds:
        raise SystemExit('unsupported 3x-ui SQLite schema')
finally:
    connection.close()
PY

panel_port=$(db_value webPort)
base_path=$(db_value webBasePath)
current_web_listen=$(db_value webListen)
certificate_file=$(db_value webCertFile)
key_file=$(db_value webKeyFile)
subscription_port=$(db_value subPort)

is_uint "$panel_port" && (( panel_port >= 1 && panel_port <= 65535 )) || die "invalid 3x-ui webPort"
[[ "$base_path" == /*/ && "$base_path" != *..* && $base_path =~ ^/[A-Za-z0-9_/-]*/$ ]] \
    || die "3x-ui webBasePath contains unsupported characters"

if [[ -n "$certificate_file" || -n "$key_file" ]]; then
    [[ -n "$certificate_file" && -n "$key_file" ]] || die "3x-ui TLS certificate configuration is incomplete"
    [[ "$certificate_file" == /* && "$key_file" == /* ]] || die "3x-ui certificate paths must be absolute"
    case "${certificate_file}${key_file}" in
        *$'\n'*|*$'\r'*|*\"*|*\;*) die "3x-ui certificate paths contain unsafe characters" ;;
    esac
    [[ -s "$certificate_file" && -s "$key_file" ]] || die "3x-ui certificate files are unreadable"
    upstream_scheme=https
    public_scheme=https
else
    upstream_scheme=http
    public_scheme=http
fi

env_value() {
    local path=$1 key=$2
    [[ -r "$path" ]] || return 0
    python3 - "$path" "$key" <<'PY'
from pathlib import Path
import shlex, sys
for raw in Path(sys.argv[1]).read_text(encoding='utf-8').splitlines():
    line = raw.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    key, value = line.split('=', 1)
    if key.strip() == sys.argv[2]:
        parts = shlex.split(value.strip(), comments=False, posix=True)
        if len(parts) == 1:
            print(parts[0])
        break
PY
}

existing_result_file=
if [[ -e /etc/xray-qos-web/install-result.env ]]; then
    [[ -f /etc/xray-qos-web/install-result.env && ! -L /etc/xray-qos-web/install-result.env ]] \
        || die "existing install metadata is not a regular file"
    [[ $(stat -c '%U' /etc/xray-qos-web/install-result.env) == root ]] \
        || die "existing install metadata must be root-owned"
    result_mode=$(stat -c '%a' /etc/xray-qos-web/install-result.env)
    (( (8#$result_mode & 022) == 0 )) || die "existing install metadata is writable by group or others"
    existing_result_file=/etc/xray-qos-web/install-result.env
fi

if [[ -z "$panel_host" && -r /etc/x-ui/install-result.env ]]; then
    panel_host=$(python3 - <<'PY'
from pathlib import Path
from urllib.parse import urlsplit
import shlex
path = Path('/etc/x-ui/install-result.env')
for raw in path.read_text(encoding='utf-8').splitlines():
    line = raw.strip()
    if line.startswith('export '):
        line = line[7:].lstrip()
    if not line.startswith('XUI_ACCESS_URL='):
        continue
    parts = shlex.split(line.split('=', 1)[1], comments=False, posix=True)
    if len(parts) == 1:
        print(urlsplit(parts[0]).hostname or '')
    break
PY
    )
fi
if [[ -z "$panel_host" && "$dry_run" == no ]]; then
    panel_host=$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)
fi
if [[ -z "$panel_host" ]]; then
    panel_host=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
fi
[[ $panel_host =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ && "$panel_host" != *..* ]] \
    || die "could not determine a safe panel host; use --panel-host"

if [[ -z "$wan_interface" ]]; then
    mapfile -t default_interfaces < <(
        ip -o -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1)}}' | sort -u
    )
    (( ${#default_interfaces[@]} == 1 )) || die "could not uniquely detect WAN; use --wan"
    wan_interface=${default_interfaces[0]}
fi
[[ $wan_interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || die "invalid WAN interface"
ip link show dev "$wan_interface" >/dev/null || die "WAN interface does not exist: $wan_interface"

if [[ -z "$link_mbps" ]]; then
    if [[ "$assume_yes" == no && -r /dev/tty ]]; then
        read -r -p "VPS total line speed in Mbps [1000]: " link_mbps </dev/tty
        link_mbps=${link_mbps:-1000}
    else
        die "--link-mbps is required in unattended mode"
    fi
fi
is_uint "$link_mbps" && (( link_mbps >= 2 && link_mbps <= 100000 )) || die "invalid --link-mbps"
if [[ -z "$reserve_mbps" ]]; then
    reserve_mbps=$(( link_mbps / 5 ))
    (( reserve_mbps > 50 )) && reserve_mbps=50
    (( reserve_mbps < 1 )) && reserve_mbps=1
fi
is_uint "$reserve_mbps" && (( reserve_mbps >= 1 && reserve_mbps < link_mbps )) \
    || die "reserve Mbps must be at least 1 and lower than line Mbps"

find_free_port() {
    python3 - "$@" <<'PY'
import socket, sys
excluded = {int(value) for value in sys.argv[2:]}
for port in range(int(sys.argv[1]), 65536):
    if port in excluded:
        continue
    sock = socket.socket()
    try:
        sock.bind(('127.0.0.1', port))
    except OSError:
        continue
    finally:
        sock.close()
    print(port)
    break
else:
    raise SystemExit('no free loopback port found')
PY
}

current_port_override=$(env_value /etc/default/x-ui XUI_PORT)
current_port_present=no
if [[ -n "$current_port_override" ]]; then
    is_uint "$current_port_override" && (( current_port_override >= 1 && current_port_override <= 65535 )) \
        || die "existing XUI_PORT is invalid"
    current_port_present=yes
fi

if [[ "$current_port_present" == yes && "$current_port_override" != "$panel_port" ]]; then
    upstream_port=$current_port_override
else
    upstream_port=$(find_free_port 21835 "$panel_port")
fi

# These values describe the state before the first installation. Preserve them
# across upgrades so a later uninstall does not restore the integrated
# loopback-only state and strand the panel.
previous_port_present=$current_port_present
previous_port_override=$current_port_override
previous_web_listen=$current_web_listen
if [[ -n "$existing_result_file" ]]; then
    previous_port_present=$(env_value "$existing_result_file" XUI_QOS_PREVIOUS_PORT_PRESENT)
    previous_port_override=$(env_value "$existing_result_file" XUI_QOS_PREVIOUS_PORT)
    previous_web_listen=$(env_value "$existing_result_file" XUI_QOS_PREVIOUS_WEB_LISTEN)
    [[ "$previous_port_present" == yes || "$previous_port_present" == no ]] \
        || die "existing install metadata has an invalid previous port flag"
    if [[ "$previous_port_present" == yes ]]; then
        is_uint "$previous_port_override" && (( previous_port_override >= 1 && previous_port_override <= 65535 )) \
            || die "existing install metadata has an invalid previous port"
    else
        previous_port_override=
    fi
fi

existing_backend_port=$(env_value /etc/xray-qos-web/web.env QOS_WEB_PORT)
if [[ -n "$existing_backend_port" ]] && is_uint "$existing_backend_port" && \
   (( existing_backend_port != panel_port && existing_backend_port != upstream_port )); then
    backend_port=$existing_backend_port
else
    backend_port=$(find_free_port 21834 "$panel_port" "$upstream_port")
fi

port_suffix=":$panel_port"
if [[ "$public_scheme" == https && "$panel_port" == 443 ]] || \
   [[ "$public_scheme" == http && "$panel_port" == 80 ]]; then
    port_suffix=
fi
public_authority="${panel_host}${port_suffix}"
public_origin="${public_scheme}://${public_authority}"
panel_url="${public_origin}${base_path}"

current_panel_socket=$(ss -H -ltnp "sport = :$panel_port" || true)
if [[ -n "$current_panel_socket" && "$current_panel_socket" != *x-ui* ]]; then
    if [[ "$current_panel_socket" != *nginx* || ! -f /etc/nginx/conf.d/xui-qos.conf ]]; then
        if [[ "$dry_run" == yes ]]; then
            echo "xui-qos install: warning: panel port $panel_port is already handled by another reverse proxy" >&2
        else
            die "panel port $panel_port is already handled by another reverse proxy; refusing to overwrite it"
        fi
    fi
fi

root_qdisc=$(tc -j qdisc show dev "$wan_interface" | python3 -c '
import json,sys
items=json.load(sys.stdin)
root=next((item for item in items if item.get("root") is True), None)
print((root or {}).get("kind", "noqueue"))
')
original_root_qdisc=$root_qdisc
if [[ -n "$existing_result_file" ]]; then
    original_root_qdisc=$(env_value "$existing_result_file" XUI_QOS_ORIGINAL_ROOT_QDISC)
    case "$original_root_qdisc" in
        fq|fq_codel|noqueue) ;;
        *) die "existing install metadata has an invalid original root qdisc" ;;
    esac
fi
case "$root_qdisc" in
    fq|fq_codel|noqueue) ;;
    htb)
        [[ -r /run/xray-qos/state.json && -x /usr/local/sbin/xray-qos ]] \
            || die "WAN already has an unowned HTB qdisc"
        python3 - "$wan_interface" <<'PY'
from pathlib import Path
import json, sys
state = json.loads(Path('/run/xray-qos/state.json').read_text(encoding='utf-8'))
if state.get('owned') is not True or state.get('wan') != sys.argv[1]:
    raise SystemExit('WAN HTB state is not owned by xray-qos')
PY
        ;;
    *) die "WAN root qdisc '$root_qdisc' is custom; refusing to replace it" ;;
esac

nginx -V 2>&1 | grep -q -- '--with-http_auth_request_module' || die "Nginx auth_request module is missing"
nginx -V 2>&1 | grep -q -- '--with-http_sub_module' || die "Nginx sub_filter module is missing"

echo "xui-qos install plan:"
echo "  panel:       $panel_url"
echo "  WAN:         $wan_interface"
echo "  line/reserve ${link_mbps}/${reserve_mbps} Mbps"
echo "  internal:    x-ui=$upstream_port web=$backend_port"
echo "  BBR:         $enable_bbr"

if [[ "$dry_run" == yes ]]; then
    echo "xui-qos install: dry-run OK; no changes made"
    finished=yes
    exit 0
fi

if [[ "$assume_yes" == no && -r /dev/tty ]]; then
    read -r -p "Continue? [Y/n]: " confirmation </dev/tty
    case "${confirmation:-y}" in y|Y|yes|YES) ;; *) die "cancelled" ;; esac
fi

if ! getent passwd xray-qos-web >/dev/null; then
    useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin xray-qos-web
fi

backup_dir="/var/backups/xui-qos/install-$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -m 0700 -o root -g root "$backup_dir/present" "$backup_dir/absent"

backup_item() {
    local target=$1 relative=${1#/}
    if [[ -e "$target" || -L "$target" ]]; then
        mkdir -p -- "$backup_dir/present/$(dirname -- "$relative")"
        cp -a -- "$target" "$backup_dir/present/$relative"
    else
        mkdir -p -- "$backup_dir/absent/$(dirname -- "$relative")"
        : >"$backup_dir/absent/$relative"
    fi
}

project_paths=(
    /etc/default/x-ui
    /etc/default/xray-qos
    /etc/modules-load.d/xui-qos.conf
    /etc/nginx/conf.d/xui-qos.conf
    /etc/sysctl.d/99-xui-qos-bbr.conf
    /etc/systemd/system/xray-qos.service
    /etc/systemd/system/xray-qos-control.service
    /etc/systemd/system/xray-qos-web.service
    /etc/xray-qos
    /etc/xray-qos-web
    /opt/xray-qos-web
    /usr/local/sbin/xray-qos
    /usr/local/sbin/xui-qos-rollback-install
    /usr/local/sbin/xui-qos-uninstall
    /usr/local/sbin/xui-qos-verify
)
for project_path in "${project_paths[@]}"; do
    backup_item "$project_path"
done

xui_db_mode=$(stat -c '%a' /etc/x-ui/x-ui.db)
original_tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control)
original_default_qdisc=$(sysctl -n net.core.default_qdisc)
python3 - "$backup_dir/x-ui.db" <<'PY'
import sqlite3, sys
source = sqlite3.connect('/etc/x-ui/x-ui.db')
target = sqlite3.connect(sys.argv[1])
try:
    source.backup(target)
finally:
    target.close(); source.close()
PY
chmod "$xui_db_mode" "$backup_dir/x-ui.db"

qos_was_active=$(service_active xray-qos.service)
control_was_active=$(service_active xray-qos-control.service)
web_was_active=$(service_active xray-qos-web.service)
nginx_was_active=$(service_active nginx.service)
xui_was_active=$(service_active x-ui.service)
qos_was_enabled=$(service_enabled xray-qos.service)
control_was_enabled=$(service_enabled xray-qos-control.service)
web_was_enabled=$(service_enabled xray-qos-web.service)

{
    printf 'WAN_INTERFACE=%q\n' "$wan_interface"
    printf 'ORIGINAL_ROOT_QDISC=%q\n' "$root_qdisc"
    printf 'XUI_DB_MODE=%q\n' "$xui_db_mode"
    printf 'ORIGINAL_TCP_CC=%q\n' "$original_tcp_cc"
    printf 'ORIGINAL_DEFAULT_QDISC=%q\n' "$original_default_qdisc"
    printf 'QOS_WAS_ACTIVE=%q\n' "$qos_was_active"
    printf 'CONTROL_WAS_ACTIVE=%q\n' "$control_was_active"
    printf 'WEB_WAS_ACTIVE=%q\n' "$web_was_active"
    printf 'NGINX_WAS_ACTIVE=%q\n' "$nginx_was_active"
    printf 'XUI_WAS_ACTIVE=%q\n' "$xui_was_active"
    printf 'QOS_WAS_ENABLED=%q\n' "$qos_was_enabled"
    printf 'CONTROL_WAS_ENABLED=%q\n' "$control_was_enabled"
    printf 'WEB_WAS_ENABLED=%q\n' "$web_was_enabled"
} >"$backup_dir/state.env"
install -o root -g root -m 0700 "$source_root/scripts/rollback-install.sh" "$backup_dir/rollback.sh"
backup_ready=yes

rollback_unit="xui-qos-rollback-$(date -u +%Y%m%d%H%M%S)-$$"
systemd-run --quiet --unit="$rollback_unit" --on-active=5m --timer-property=AccuracySec=1s \
    "$backup_dir/rollback.sh" "$backup_dir"
rollback_armed=yes

install -d -m 0700 -o root -g root /etc/xray-qos /etc/xray-qos-web
if [[ ! -e /etc/xray-qos/nodes.json ]]; then
    printf '%s\n' '{"version":1,"revision":0,"nodes":{}}' >/etc/xray-qos/nodes.json
    chmod 0600 /etc/xray-qos/nodes.json
fi

install -d -m 0755 -o root -g root /opt/xray-qos-web /opt/xray-qos-web/static
install -o root -g root -m 0755 "$source_root/src/xray-qos" /usr/local/sbin/xray-qos
install -o root -g root -m 0755 "$source_root/src/qos-web/control.py" /opt/xray-qos-web/control.py
install -o root -g root -m 0755 "$source_root/src/qos-web/web.py" /opt/xray-qos-web/web.py
install -o root -g root -m 0755 "$source_root/src/qos-web/healthcheck.py" /opt/xray-qos-web/healthcheck.py
install -o root -g root -m 0644 "$source_root/src/qos-web/audit_view.py" /opt/xray-qos-web/audit_view.py
install -o root -g root -m 0644 "$source_root/src/qos-web/node_notes.py" /opt/xray-qos-web/node_notes.py
# Notes are independent application state: preserve them on upgrade/rollback.
[[ ! -L /var/lib/xray-qos-web ]] || die "notes directory must not be a symlink"
if [[ -e /var/lib/xray-qos-web ]]; then
    [[ $(stat -c '%U' /var/lib/xray-qos-web) == xray-qos-web ]] || die "notes directory has an unexpected owner"
fi
install -d -m 0700 -o xray-qos-web -g xray-qos-web /var/lib/xray-qos-web
runuser -u xray-qos-web -- python3 -B /opt/xray-qos-web/node_notes.py
for static_file in "$source_root"/src/qos-web/static/*; do
    install -o root -g root -m 0644 "$static_file" "/opt/xray-qos-web/static/$(basename -- "$static_file")"
done
install -o root -g root -m 0644 "$source_root/src/systemd/xray-qos.service" /etc/systemd/system/xray-qos.service
install -o root -g root -m 0644 "$source_root/src/systemd/xray-qos-control.service" /etc/systemd/system/xray-qos-control.service
install -o root -g root -m 0644 "$source_root/src/systemd/xray-qos-web.service" /etc/systemd/system/xray-qos-web.service
install -o root -g root -m 0755 "$source_root/scripts/verify.sh" /usr/local/sbin/xui-qos-verify
install -o root -g root -m 0755 "$source_root/scripts/uninstall.sh" /usr/local/sbin/xui-qos-uninstall
install -o root -g root -m 0755 "$source_root/scripts/rollback-install.sh" /usr/local/sbin/xui-qos-rollback-install

management_ports=("$panel_port")
if is_uint "$subscription_port" && (( subscription_port >= 1 && subscription_port <= 65535 )); then
    management_ports+=("$subscription_port")
fi
if command -v sshd >/dev/null; then
    while read -r ssh_port; do
        is_uint "$ssh_port" && management_ports+=("$ssh_port")
    done < <(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
fi
IFS=',' read -r -a extra_ports_array <<<"$extra_management_ports"
for management_port in "${extra_ports_array[@]}"; do
    management_port=${management_port//[[:space:]]/}
    [[ -z "$management_port" ]] && continue
    is_uint "$management_port" && (( management_port >= 1 && management_port <= 65535 )) \
        || die "invalid extra management port: $management_port"
    management_ports+=("$management_port")
done
mapfile -t management_ports < <(printf '%s\n' "${management_ports[@]}" | sort -nu)
management_ports_text=${management_ports[*]}

{
    printf 'WAN=%s\n' "$wan_interface"
    printf 'DEFAULT_RATE=%smbit\n' "$reserve_mbps"
    printf 'LINK_EGRESS=%smbit\n' "$link_mbps"
    printf 'MGMT_PORTS="%s"\n' "$management_ports_text"
    printf 'XRAY_DB=/etc/x-ui/x-ui.db\n'
    printf 'QOS_PROFILES=/etc/xray-qos/nodes.json\n'
} >/etc/default/xray-qos
chmod 0600 /etc/default/xray-qos

proxy_secret=$(env_value /etc/xray-qos-web/web.env QOS_PROXY_SECRET)
embed_token=$(env_value /etc/xray-qos-web/web.env QOS_EMBED_TOKEN)
backend_path=$(env_value /etc/xray-qos-web/web.env QOS_WEB_BASE_PATH)
password_hash=$(env_value /etc/xray-qos-web/web.env QOS_WEB_PASSWORD_HASH)
[[ $proxy_secret =~ ^[a-f0-9]{64}$ ]] || proxy_secret=$(openssl rand -hex 32)
[[ $embed_token =~ ^[a-f0-9]{64}$ ]] || embed_token=$(openssl rand -hex 32)
[[ "$backend_path" == /*/ && "$backend_path" =~ ^/[A-Za-z0-9_-]+/$ ]] \
    || backend_path="/qos-internal-$(openssl rand -hex 12)/"
if [[ "$password_hash" != pbkdf2_sha256\$* ]]; then
    password_hash=$(python3 - <<'PY'
import base64, hashlib, secrets
password = secrets.token_urlsafe(32).encode()
salt = secrets.token_bytes(16)
digest = hashlib.pbkdf2_hmac('sha256', password, salt, 600000)
enc = lambda value: base64.urlsafe_b64encode(value).decode().rstrip('=')
print(f'pbkdf2_sha256$600000${enc(salt)}${enc(digest)}')
PY
    )
fi

{
    printf 'QOS_WEB_BIND=127.0.0.1\n'
    printf 'QOS_WEB_PORT=%s\n' "$backend_port"
    printf 'QOS_WEB_BASE_PATH=%s\n' "$backend_path"
    printf 'QOS_WEB_ORIGIN=%s\n' "$public_origin"
    printf 'QOS_WEB_USERNAME=embedded-disabled\n'
    printf "QOS_WEB_PASSWORD_HASH='%s'\n" "$password_hash"
    printf 'QOS_PROXY_SECRET=%s\n' "$proxy_secret"
    printf 'QOS_EMBED_ORIGIN=%s\n' "$public_origin"
    printf 'QOS_EMBED_TOKEN=%s\n' "$embed_token"
    printf 'QOS_CONTROL_SOCKET=/run/xray-qos-web/control.sock\n'
    printf 'QOS_WEB_STATIC=/opt/xray-qos-web/static\n'
    printf 'QOS_PANEL_URL=%s\n' "$panel_url"
} >/etc/xray-qos-web/web.env
chmod 0600 /etc/xray-qos-web/web.env

if [[ "$public_scheme" == https ]]; then
    listen_ssl=' ssl'
    tls_block=$(printf '%s\n' \
        "    ssl_certificate \"$certificate_file\";" \
        "    ssl_certificate_key \"$key_file\";" \
        '    ssl_protocols TLSv1.2 TLSv1.3;' \
        '    ssl_session_cache shared:XuiQosTLS:5m;' \
        '    ssl_session_timeout 1d;' \
        '    ssl_session_tickets off;')
else
    listen_ssl=
    tls_block='    # The source 3x-ui panel is HTTP; configure a certificate in 3x-ui to enable HTTPS.'
fi

export RENDER_PANEL_PORT=$panel_port RENDER_LISTEN_SSL=$listen_ssl \
    RENDER_TLS_BLOCK=$tls_block RENDER_BASE_PATH=$base_path \
    RENDER_UPSTREAM_SCHEME=$upstream_scheme RENDER_UPSTREAM_PORT=$upstream_port \
    RENDER_PUBLIC_SCHEME=$public_scheme RENDER_PUBLIC_AUTHORITY=$public_authority \
    RENDER_PUBLIC_HOST=$panel_host RENDER_BACKEND_PORT=$backend_port \
    RENDER_BACKEND_PATH=$backend_path RENDER_PROXY_SECRET=$proxy_secret \
    RENDER_EMBED_TOKEN=$embed_token
python3 - "$source_root/templates/nginx.conf.in" /etc/nginx/conf.d/xui-qos.conf <<'PY'
from pathlib import Path
import os, sys
mapping = {
    'PANEL_PORT': os.environ['RENDER_PANEL_PORT'],
    'LISTEN_SSL': os.environ['RENDER_LISTEN_SSL'],
    'TLS_BLOCK': os.environ['RENDER_TLS_BLOCK'],
    'BASE_PATH': os.environ['RENDER_BASE_PATH'],
    'UPSTREAM_SCHEME': os.environ['RENDER_UPSTREAM_SCHEME'],
    'UPSTREAM_PORT': os.environ['RENDER_UPSTREAM_PORT'],
    'PUBLIC_SCHEME': os.environ['RENDER_PUBLIC_SCHEME'],
    'PUBLIC_AUTHORITY': os.environ['RENDER_PUBLIC_AUTHORITY'],
    'PUBLIC_HOST': os.environ['RENDER_PUBLIC_HOST'],
    'BACKEND_PORT': os.environ['RENDER_BACKEND_PORT'],
    'BACKEND_PATH': os.environ['RENDER_BACKEND_PATH'],
    'PROXY_SECRET': os.environ['RENDER_PROXY_SECRET'],
    'EMBED_TOKEN': os.environ['RENDER_EMBED_TOKEN'],
}
text = Path(sys.argv[1]).read_text(encoding='utf-8')
for key, value in mapping.items():
    text = text.replace(f'@@{key}@@', value)
if '@@' in text:
    raise SystemExit('unresolved Nginx template token')
Path(sys.argv[2]).write_text(text, encoding='utf-8')
PY
chmod 0600 /etc/nginx/conf.d/xui-qos.conf
unset RENDER_PANEL_PORT RENDER_LISTEN_SSL RENDER_TLS_BLOCK RENDER_BASE_PATH \
    RENDER_UPSTREAM_SCHEME RENDER_UPSTREAM_PORT RENDER_PUBLIC_SCHEME \
    RENDER_PUBLIC_AUTHORITY RENDER_PUBLIC_HOST RENDER_BACKEND_PORT \
    RENDER_BACKEND_PATH RENDER_PROXY_SECRET RENDER_EMBED_TOKEN

python3 - "$upstream_port" <<'PY'
from pathlib import Path
import os, sys, tempfile
path = Path('/etc/default/x-ui')
lines = path.read_text(encoding='utf-8').splitlines() if path.exists() else []
result = []
replaced = False
for line in lines:
    if line.startswith('XUI_PORT='):
        if not replaced:
            result.append(f'XUI_PORT={sys.argv[1]}')
            replaced = True
        continue
    result.append(line)
if not replaced:
    result.append(f'XUI_PORT={sys.argv[1]}')
fd, name = tempfile.mkstemp(prefix='.x-ui.', dir=path.parent)
with os.fdopen(fd, 'w', encoding='utf-8') as handle:
    handle.write('\n'.join(result) + '\n')
    handle.flush(); os.fsync(handle.fileno())
os.chmod(name, 0o644)
os.replace(name, path)
PY

{
    printf 'XUI_QOS_VERSION=%q\n' "$VERSION"
    printf 'XUI_QOS_PANEL_URL=%q\n' "$panel_url"
    printf 'XUI_QOS_PUBLIC_SCHEME=%q\n' "$public_scheme"
    printf 'XUI_QOS_PUBLIC_AUTHORITY=%q\n' "$public_authority"
    printf 'XUI_QOS_PANEL_PORT=%q\n' "$panel_port"
    printf 'XUI_QOS_BASE_PATH=%q\n' "$base_path"
    printf 'XUI_QOS_UPSTREAM_PORT=%q\n' "$upstream_port"
    printf 'XUI_QOS_BACKEND_PORT=%q\n' "$backend_port"
    printf 'XUI_QOS_WAN=%q\n' "$wan_interface"
    printf 'XUI_QOS_ORIGINAL_ROOT_QDISC=%q\n' "$original_root_qdisc"
    printf 'XUI_QOS_PREVIOUS_PORT_PRESENT=%q\n' "$previous_port_present"
    printf 'XUI_QOS_PREVIOUS_PORT=%q\n' "$previous_port_override"
    printf 'XUI_QOS_PREVIOUS_WEB_LISTEN=%q\n' "$previous_web_listen"
    printf 'XUI_QOS_BBR_ENABLED=%q\n' "$enable_bbr"
    printf 'XUI_QOS_BACKUP_DIR=%q\n' "$backup_dir"
} >/etc/xray-qos-web/install-result.env
chmod 0600 /etc/xray-qos-web/install-result.env

/usr/bin/python3 -m py_compile \
    /usr/local/sbin/xray-qos \
    /opt/xray-qos-web/control.py \
    /opt/xray-qos-web/web.py \
    /opt/xray-qos-web/audit_view.py \
    /opt/xray-qos-web/node_notes.py \
    /opt/xray-qos-web/healthcheck.py
nginx -t

if [[ "$enable_bbr" == yes ]]; then
    modprobe tcp_bbr
    printf '%s\n' tcp_bbr >/etc/modules-load.d/xui-qos.conf
    {
        printf 'net.core.default_qdisc=fq\n'
        printf 'net.ipv4.tcp_congestion_control=bbr\n'
    } >/etc/sysctl.d/99-xui-qos-bbr.conf
    sysctl -q -p /etc/sysctl.d/99-xui-qos-bbr.conf
    [[ " $(sysctl -n net.ipv4.tcp_available_congestion_control) " == *' bbr '* ]] \
        || die "this kernel does not provide BBR; retry with --no-bbr"
fi

for module_name in ifb sch_htb sch_fq sch_fq_codel cls_flower act_mirred; do
    modprobe "$module_name"
done

if [[ "$root_qdisc" == fq_codel ]]; then
    tc qdisc replace dev "$wan_interface" root fq
fi

/usr/local/x-ui/x-ui setting -listenIP 127.0.0.1 >/dev/null
systemctl daemon-reload
systemctl enable xray-qos.service xray-qos-control.service xray-qos-web.service nginx.service >/dev/null
systemctl restart xray-qos.service
systemctl restart xray-qos-control.service
systemctl restart xray-qos-web.service
systemctl restart x-ui.service

upstream_ready=no
for _attempt in $(seq 1 30); do
    if curl -ksS -H "Host: $public_authority" -o /dev/null \
        "${upstream_scheme}://127.0.0.1:${upstream_port}${base_path}"; then
        upstream_ready=yes
        break
    fi
    sleep 1
done
[[ "$upstream_ready" == yes ]] || die "3x-ui did not start on the internal port"

nginx -t
systemctl reload-or-restart nginx.service
/usr/local/sbin/xui-qos-verify

systemctl stop "${rollback_unit}.timer"
rollback_armed=no
finished=yes

echo
echo "xui-qos install: completed"
echo "3x-ui: $panel_url"
echo "Open 3x-ui and click '网速 / 审计'. Node notes are ready; connection auditing is opt-in (see README)."
echo "Backup: $backup_dir"
