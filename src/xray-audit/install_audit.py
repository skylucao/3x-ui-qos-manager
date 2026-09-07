#!/usr/bin/env python3
"""Install optional audit services after the administrator configures logging."""
import argparse
from datetime import datetime
import fcntl
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile

from mail_report import address
from report import timezone_for, REPORT_TIMEZONE

HERE = Path(__file__).resolve().parent
APP = Path('/opt/xray-audit')
CONFIG = Path('/etc/xray-audit')
STATE = Path('/var/lib/xray-audit')
OUTPUT = Path('/var/lib/xray-audit-web')
UNIT = Path('/etc/systemd/system')
PROGRAMS = ('report.py', 'service_rules.py', 'snapshot.py', 'retention.py', 'daily.py', 'mail_report.py', 'reopen_logger.py')
UNITS = tuple('xray-audit-' + task + extension for task in ('daily', 'logrotate', 'snapshot') for extension in ('.service', '.timer'))
TIMERS = tuple(unit for unit in UNITS if unit.endswith('.timer'))


def validate_runtime(runtime):
    if runtime.get('log', {}).get('access') != '/var/log/x-ui/access.log':
        raise ValueError('First configure Xray access log as /var/log/x-ui/access.log in 3x-ui')
    api = runtime.get('api', {})
    if 'LoggerService' not in api.get('services', []):
        raise ValueError('Existing loopback LoggerService is required')
    import ipaddress
    listeners = [item for item in runtime.get('inbounds', []) if item.get('tag') == api.get('tag')]
    if len(listeners) != 1 or not ipaddress.ip_address(listeners[0].get('listen', '')).is_loopback:
        raise ValueError('LoggerService must have one loopback listener')


def safe_path(path):
    if path.is_symlink() or path.resolve() != path:
        raise ValueError('Unsafe managed path: ' + str(path))


def write(path, content, mode=0o600):
    safe_path(path)
    fd, temporary = tempfile.mkstemp(prefix='.audit-install-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as target:
            target.write(content); target.flush(); os.fsync(target.fileno()); os.fchmod(target.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run(*command):
    return subprocess.run(command, check=True, timeout=900)


def stop_existing_timers():
    existing = [unit for unit in TIMERS if (UNIT / unit).is_file()]
    if existing:
        run('systemctl', 'stop', *existing)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acknowledge-notice', action='store_true', help='Confirm users are informed of domain/IP auditing')
    parser.add_argument('--recipient', required=True, help='Daily digest recipient; SMTP remains in 3x-ui settings')
    args = parser.parse_args(argv)
    if not args.acknowledge_notice:
        parser.error('--acknowledge-notice is required; auditing is never enabled implicitly')
    recipient = address(args.recipient)
    if os.geteuid() != 0:
        parser.error('Run as root')
    os.umask(0o077)
    install_lock = Path('/run/lock/xui-qos-install.lock')
    safe_path(install_lock)
    # Share the base install/uninstall lock for the entire preflight and rollback.
    with install_lock.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('Another QoS/audit installation or uninstall is running') from None
        return install(recipient)


def install(recipient):
    for path in (APP, CONFIG, STATE, OUTPUT, STATE / 'reports', STATE / 'receipts'):
        safe_path(path)
    if APP.exists() and not (APP / '.managed-by-codex-audit').is_file():
        raise ValueError('Unknown audit installation; refusing to overwrite')
    if CONFIG.exists() and not (APP / '.managed-by-codex-audit').is_file():
        raise ValueError('Existing audit configuration is not managed')
    if STATE.exists() and not (APP / '.managed-by-codex-audit').is_file():
        raise ValueError('Existing audit state is not managed')
    if not (APP / '.managed-by-codex-audit').is_file() and any((UNIT / name).exists() for name in UNITS):
        raise ValueError('Existing audit units are not managed')
    if OUTPUT.exists() and not (OUTPUT / '.managed-by-xray-audit-web').is_file():
        raise ValueError('Existing export directory is not managed')
    for name in ('audit_view.py', 'node_notes.py'):
        if not (Path('/opt/xray-qos-web') / name).is_file():
            raise ValueError('Install QoS Manager v1.1.0 or newer first')
    web = pwd.getpwnam('xray-qos-web')
    if not shutil.which('logrotate'):
        raise ValueError('Install logrotate first: apt-get install logrotate')
    if not os.access('/usr/local/x-ui/bin/xray-linux-amd64', os.X_OK):
        raise ValueError('The audit add-on currently supports the native Linux AMD64 Xray binary only')
    runtime = Path('/usr/local/x-ui/bin/config.json')
    before_runtime = runtime.read_bytes()
    validate_runtime(json.loads(before_runtime))
    active = Path('/var/log/x-ui/access.log')
    safe_path(active)
    if not active.is_file() or active.stat().st_uid != 0 or active.stat().st_mode & 0o077:
        raise ValueError('Existing access.log must be root-owned and mode 0600')
    run('systemd-analyze', 'verify', *(str(HERE / name) for name in UNITS))
    targets = {APP / name: ((HERE / name).read_bytes(), 0o700) for name in PROGRAMS}
    targets.update({UNIT / name: ((HERE / name).read_bytes(), 0o644) for name in UNITS})
    targets[CONFIG / 'logrotate.conf'] = ((HERE / 'logrotate.conf').read_bytes(), 0o600)
    config_path = CONFIG / 'config.json'
    safe_path(config_path)
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    config.update(recipient=recipient, timezone=REPORT_TIMEZONE, raw_log_retention_days=7, report_retention_days=7)
    targets[config_path] = ((json.dumps(config, indent=2) + '\n').encode(), 0o600)
    for path in targets:
        safe_path(path)
    # Only application/configuration backups; no copies of expiring audit data.
    backup = Path(tempfile.mkdtemp(prefix='xray-audit-install-backup-', dir='/root'))
    old = {}
    for number, path in enumerate(targets):
        old[path] = (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
        if old[path]:
            (backup / str(number)).write_bytes(old[path][0])
    (backup / 'manifest.json').write_text(json.dumps({str(p): str(n) if old[p] else None for n, p in enumerate(targets)}, indent=2))
    previous = {unit: (subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode == 0,
                       subprocess.run(['systemctl', 'is-enabled', '--quiet', unit], capture_output=True).returncode == 0) for unit in TIMERS}
    for path in (APP, CONFIG, STATE, STATE / 'reports', STATE / 'receipts'):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path, 0o700)
    OUTPUT.mkdir(mode=0o2750, exist_ok=True)
    os.chown(OUTPUT, 0, web.pw_gid); os.chmod(OUTPUT, 0o2750)
    (APP / '.managed-by-codex-audit').touch(mode=0o600)
    (OUTPUT / '.managed-by-xray-audit-web').touch(mode=0o640)
    try:
        # Wait for current jobs to finish instead of killing an in-flight mail run.
        stop_existing_timers()
        with (STATE / 'daily.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            for path, (content, mode) in targets.items():
                write(path, content, mode)
            metadata = STATE / 'metadata.json'
            if not metadata.exists():
                write(metadata, json.dumps({'started_at': datetime.now(timezone_for(REPORT_TIMEZONE)).isoformat(), 'timezone': REPORT_TIMEZONE, 'scope': 'connection target domains/IPs only; no content'}).encode())
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', 'xray-audit-logrotate.service')
        run('systemctl', 'start', 'xray-audit-snapshot.service')
        assert runtime.read_bytes() == before_runtime, 'Xray configuration changed during install'
        run('systemctl', 'enable', *TIMERS)
        run('systemctl', 'start', *TIMERS)
    except Exception:
        subprocess.run(['systemctl', 'stop', *TIMERS], capture_output=True)
        with (STATE / 'daily.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            for path, value in old.items():
                if value:
                    write(path, value[0], value[1])
                elif path.is_file() and not path.is_symlink():
                    path.unlink()
        subprocess.run(['systemctl', 'daemon-reload'])
        for unit, (active_before, enabled_before) in previous.items():
            subprocess.run(['systemctl', 'enable' if enabled_before else 'disable', unit], capture_output=True)
            if active_before:
                subprocess.run(['systemctl', 'start', unit], capture_output=True)
        print('Previous application files restored; audit state retained. Backup:', backup)
        raise
    print('Audit installed: seven Shanghai calendar dates; mail at 09:00 after SMTP is configured.')
    print('No test email was sent. Xray was not restarted. Backup:', backup)


if __name__ == '__main__':
    raise SystemExit(main())
