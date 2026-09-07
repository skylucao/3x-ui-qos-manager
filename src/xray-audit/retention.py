#!/usr/bin/env python3
"""Two-calendar-day audit retention, independent of SMTP and report success."""
from datetime import date, datetime, timedelta
import gzip
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from report import LOG_NAME_RE, MAX_LINE_LENGTH, REPORT_TIMEZONE, timezone_for

MAX_DAYS = 2
STATE = Path('/var/lib/xray-audit')
OUTPUT = Path('/var/lib/xray-audit-web')
LOGS = Path('/var/log/x-ui')
DATE_NAME = re.compile(r'(?:setup-)?(\d{4}-\d{2}-\d{2})\.(?:json|txt)\Z')
STAMP = re.compile(rb'^(\d{4})/(\d{2})/(\d{2}) \d{2}:\d{2}:\d{2}(?:\.\d+)?\s')


def days(value=MAX_DAYS):
    try:
        return max(1, min(MAX_DAYS, int(value)))
    except (ValueError, TypeError, OverflowError):
        return MAX_DAYS


def cutoff_date(today, retention=MAX_DAYS):
    # Today and yesterday: two calendar buckets, not a rolling 48-hour window.
    return today - timedelta(days=days(retention) - 1)


def regular(path):
    return not path.is_symlink() and path.is_file() and path.stat().st_nlink == 1


def cleanup_dates(directory, cutoff, *, receipts=False):
    if directory.is_symlink() or directory.resolve() != directory or not directory.is_dir():
        raise ValueError('Unsafe retention directory')
    removed = 0
    for path in directory.iterdir():
        match = DATE_NAME.fullmatch(path.name)
        if not match or (path.name.startswith('setup-') and not receipts) or not regular(path):
            continue
        try:
            day = date.fromisoformat(match[1])
        except ValueError:
            continue
        if day < cutoff:
            path.unlink()
            removed += 1
    return removed


def cleanup_private(today, state=STATE, retention=MAX_DAYS):
    cutoff = cutoff_date(today, retention)
    result = {'reports_removed': cleanup_dates(state / 'reports', cutoff),
              'receipts_removed': cleanup_dates(state / 'receipts', cutoff, receipts=True)}
    for name in ('last-run.json', 'last-scheduled.json'):
        last = state / name
        if regular(last):
            try:
                if date.fromisoformat(json.loads(last.read_text())['report_date']) < cutoff:
                    last.unlink()
            except (ValueError, KeyError, TypeError):
                pass
    return result


def records(path):
    """Bound memory; an oversized physical line is a single invalid record."""
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rb') as source:
        while True:
            line = source.readline(MAX_LINE_LENGTH + 1)
            if not line:
                return
            if len(line) > MAX_LINE_LENGTH:
                while line and not line.endswith(b'\n'):
                    line = source.readline(MAX_LINE_LENGTH + 1)
                yield b''
            else:
                yield line


def retained(line, cutoff, today):
    match = STAMP.match(line)
    if not match:
        return False  # Undated data must not be retained indefinitely.
    try:
        return cutoff <= date(*(int(part) for part in match.groups())) <= today
    except ValueError:
        return False


def needs_pruning(path, cutoff, today):
    return any(not retained(line, cutoff, today) for line in records(path))


def prune_rotated(path, cutoff, today):
    if path.name == 'access.log' or not LOG_NAME_RE.fullmatch(path.name) or not regular(path):
        raise ValueError('Only regular, closed, rotated access logs may be pruned')
    if not needs_pruning(path, cutoff, today):
        return 0
    before = path.stat()
    fd, temporary = tempfile.mkstemp(prefix='.retention-', dir=path.parent)
    removed, kept = 0, 0
    try:
        with os.fdopen(fd, 'wb') as target:
            if hasattr(os, 'fchmod'):
                os.fchmod(target.fileno(), stat.S_IMODE(before.st_mode) & 0o600)
            destination = gzip.GzipFile(fileobj=target, mode='wb', filename='', mtime=0) if path.suffix == '.gz' else target
            try:
                for line in records(path):
                    if retained(line, cutoff, today):
                        destination.write(line)
                        kept += 1
                    else:
                        removed += 1
            finally:
                if destination is not target:
                    destination.close()
            target.flush()
            os.fsync(target.fileno())
        after = path.stat()
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError('Rotated log changed; pruning aborted')
        if kept:
            os.utime(temporary, ns=(before.st_atime_ns, before.st_mtime_ns))
            os.replace(temporary, path)
        else:
            path.unlink()
        return removed
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def rotated_logs():
    if LOGS.is_symlink() or LOGS.resolve() != LOGS:
        raise ValueError('Unsafe log directory')
    return [p for p in LOGS.iterdir() if p.name != 'access.log' and LOG_NAME_RE.fullmatch(p.name) and regular(p)]


def ensure_closed(paths, proc_root=Path('/proc')):
    """Check every process, including Xray still running a replaced binary."""
    identities = {(p.stat().st_dev, p.stat().st_ino) for p in paths}
    for proc in proc_root.iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            for descriptor in (proc / 'fd').iterdir():
                try:
                    info = descriptor.stat()
                    if (info.st_dev, info.st_ino) in identities:
                        raise RuntimeError('A process still holds a rotated log; pruning aborted')
                except FileNotFoundError:
                    continue
        except FileNotFoundError:
            continue


def cleanup_temporary(directory, prefix):
    """Under daily.lock, remove closed orphan writes, never an open file."""
    pattern = re.compile(re.escape(prefix) + r'[a-z0-9_]{8}\Z')
    removed = 0
    if directory.is_symlink() or directory.resolve() != directory:
        raise ValueError('Unsafe temporary retention directory')
    for path in directory.iterdir():
        if not pattern.fullmatch(path.name) or not regular(path):
            continue
        try:
            ensure_closed([path])
        except RuntimeError:
            continue
        path.unlink()
        removed += 1
    return removed


def maintain_logs(today, retention=MAX_DAYS):
    cutoff = cutoff_date(today, retention)
    command = ['/usr/sbin/logrotate', '--state', str(STATE / 'logrotate.status'), '/etc/xray-audit/logrotate.conf']
    # logrotate itself can compress/delete old files, so check BEFORE it runs.
    try:
        ensure_closed(rotated_logs())
    except RuntimeError:
        subprocess.run(['/usr/bin/python3', '/opt/xray-audit/reopen_logger.py'], check=True, timeout=25)
        ensure_closed(rotated_logs())
    subprocess.run(command, check=True, timeout=120)
    ensure_closed(rotated_logs())
    active = LOGS / 'access.log'
    if not regular(active):
        raise ValueError('Regular active access log is required')
    if needs_pruning(active, cutoff, today):
        # Rotate and reopen handles first; never truncate an active proxy log.
        subprocess.run(command[:1] + ['--force'] + command[1:], check=True, timeout=120)
        if not regular(active) or needs_pruning(active, cutoff, today):
            raise RuntimeError('Active log did not rotate cleanly')
    rotated = rotated_logs()
    ensure_closed(rotated)
    return sum(prune_rotated(path, cutoff, today) for path in rotated)


def main():
    import fcntl
    os.umask(0o077)
    if os.geteuid() != 0 or not Path('/opt/xray-audit/.managed-by-codex-audit').is_file():
        raise SystemExit('Managed audit installation and root are required')
    if OUTPUT.exists() and (OUTPUT.is_symlink() or not (OUTPUT / '.managed-by-xray-audit-web').is_file()):
        raise SystemExit('Managed web export directory is required')
    config = json.loads(Path('/etc/xray-audit/config.json').read_text())
    with (STATE / 'daily.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        today = datetime.now(timezone_for(REPORT_TIMEZONE)).date()
        # Do this before logrotate: a rotation failure must not retain old reports.
        result = cleanup_private(today, retention=config.get('report_retention_days', MAX_DAYS))
        result['web_reports_removed'] = cleanup_dates(OUTPUT, cutoff_date(today, config.get('report_retention_days', MAX_DAYS))) if OUTPUT.exists() else 0
        result['temporary_files_removed'] = cleanup_temporary(STATE / 'reports', '.report-') + cleanup_temporary(LOGS, '.retention-')
        if OUTPUT.exists():
            result['temporary_files_removed'] += cleanup_temporary(OUTPUT, '.snapshot-')
        print('Audit retention:', json.dumps(result), flush=True)
        result['raw_records_removed'] = maintain_logs(today, config.get('raw_log_retention_days', MAX_DAYS))
        print('Audit retention complete:', json.dumps(result), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
