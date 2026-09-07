#!/usr/bin/env bash
# Explicit opt-in add-on; this script never changes Xray logging or sends mail.
set -Eeuo pipefail
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
temporary_root=
cleanup() {
    if [[ -n "$temporary_root" && "$temporary_root" == /tmp/xui-audit-source.* && -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
    fi
}
trap cleanup EXIT
source_root=
if [[ -n ${BASH_SOURCE[0]:-} ]]; then
    script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    [[ -f "$script_dir/../src/xray-audit/install_audit.py" ]] && source_root=$(cd -- "$script_dir/.." && pwd)
fi
if [[ -z "$source_root" ]]; then
    temporary_root=$(mktemp -d /tmp/xui-audit-source.XXXXXXXX)
    curl -fsSL --retry 3 --connect-timeout 10 \
        https://github.com/skylucao/3x-ui-qos-manager/archive/refs/tags/v1.2.0.tar.gz \
        -o "$temporary_root/source.tar.gz"
    tar -xzf "$temporary_root/source.tar.gz" -C "$temporary_root"
    source_root="$temporary_root/3x-ui-qos-manager-1.2.0"
fi
python3 -B "$source_root/src/xray-audit/install_audit.py" "$@"
