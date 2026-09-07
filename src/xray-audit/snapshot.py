#!/usr/bin/env python3
"""Publish bounded, non-secret audit projections. Never send email or change Xray."""
from datetime import date, datetime
import html
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import unicodedata

import report
from service_rules import identify, RULESET_VERSION
from retention import cutoff_date, days, MAX_DAYS

STATE = Path('/var/lib/xray-audit')
OUTPUT = Path('/var/lib/xray-audit-web')
DATE_RE = re.compile(r'\d{4}-\d{2}-\d{2}\Z')
MAX_OUTPUT = 2 * 1024 * 1024
MAX_NODES = 100
MAX_TARGETS = 100


def read_json(path, limit=32 * 1024 * 1024):
    if not path.exists():
        raise FileNotFoundError('missing input')
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError('invalid input file')
    with path.open(encoding='utf-8') as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError('invalid object')
    return value


def label(value, limit=160):
    text = html.unescape(str(value))
    text = ''.join(' ' if unicodedata.category(c).startswith('C') else c for c in text)
    text = re.sub(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', '[标识已隐藏]', text)
    return ' '.join(text.split())[:limit]


def count(value):
    if type(value) is not int or not 0 <= value <= 10**15:
        raise ValueError('invalid counter')
    return value


def timestamp(value):
    if value is None:
        return None
    moment = datetime.fromisoformat(value)
    if moment.tzinfo is None:
        raise ValueError('timestamp requires timezone')
    return moment.astimezone(report.timezone_for(report.REPORT_TIMEZONE)).isoformat()


def project(source, kind):
    """Explicit allowlist: no raw tags, clients, source IPs, email IDs or log paths."""
    day = date.fromisoformat(source['report_date']).isoformat()
    nodes = []
    for position, entry in enumerate(source['nodes'][:MAX_NODES]):
        unmapped = bool(entry.get('unmapped'))
        node_id = str(entry.get('id', ''))
        if not unmapped and not node_id.isdecimal():
            raise ValueError('invalid node ID')
        targets = []
        for target in entry['destinations'][:MAX_TARGETS]:
            host = target['destination']
            # Revalidate host, excluding URL paths, queries and arbitrary strings.
            normalized, host_kind = report.destination_host('tcp:' + ('[' + host + ']' if ':' in host else host) + ':443')
            if normalized != host or target['kind'] != host_kind:
                raise ValueError('invalid destination')
            target_hours = target.get('hourly_connections')
            if target_hours is not None and (not isinstance(target_hours, list) or len(target_hours) != 24 or sum(count(n) for n in target_hours) != count(target['connections'])):
                raise ValueError('invalid destination hourly counters')
            targets.append({'destination': host, 'kind': host_kind, 'connections': count(target['connections']),
                            'first_seen': timestamp(target.get('first_seen')), 'last_seen': timestamp(target.get('last_seen')),
                            'hourly_connections': target_hours, 'classification': identify(host, host_kind)})
        hours = entry.get('hourly_connections')
        if hours is not None and (not isinstance(hours, list) or len(hours) != 24 or
                                  sum(count(n) for n in hours) != count(entry['total_connections'])):
            raise ValueError('invalid hourly counters')
        nodes.append({
            'key': 'unknown-' + str(position) if unmapped else 'node-' + node_id,
            'id': None if unmapped else node_id,
            'remark': '未映射记录 ' + str(position + 1) if unmapped else label(entry['remark']),
            'port': None if unmapped else count(entry['port']), 'protocol': label(entry['protocol'], 24),
            'enabled': bool(entry['enabled']), 'unmapped': unmapped,
            'total_connections': count(entry['total_connections']),
            'unique_destinations': count(entry['unique_destinations']),
            'first_seen': timestamp(entry['first_seen']), 'last_seen': timestamp(entry['last_seen']),
            'hourly_connections': hours, 'destinations': targets,
            'omitted_destinations': max(0, len(entry['destinations']) - len(targets)),
        })
    status = source['data_status']
    if status not in ('records_found', 'no_matching_records', 'partial_read_failure'):
        raise ValueError('invalid data status')
    coverage = source.get('coverage_status', 'unverified')
    if coverage not in ('unverified', 'before_collection', 'partial_first_day', 'collection_started_before_period', 'period_not_complete'):
        coverage = 'unverified'
    return {
        'schema_version': 1, 'report_date': day, 'timezone': report.REPORT_TIMEZONE, 'ruleset_version': RULESET_VERSION,
        'generated_at': timestamp(source['generated_at']), 'kind': kind,
        'collection_started_at': timestamp(source.get('collection_started_at')),
        'data_status': status, 'coverage_status': coverage,
        'total_connections': count(source['diagnostics']['accepted_connections']),
        'node_count': len(source['nodes']), 'omitted_nodes': max(0, len(source['nodes']) - len(nodes)),
        'unmapped_connections': count(source['diagnostics'].get('unmapped_connections', 0)),
        'malformed_lines': count(source['diagnostics'].get('malformed_lines', 0)),
        # Only expose a count of extra warnings, not untrusted/raw historical warning text.
        'source_warning_count': len(source.get('warnings', [])), 'nodes': nodes,
    }


def atomic_json(path, value):
    payload = (json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    if len(payload) > MAX_OUTPUT:
        raise ValueError('snapshot exceeds size limit')
    fd, temporary = tempfile.mkstemp(prefix='.snapshot-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as target:
            if hasattr(os, 'fchmod'):
                os.fchmod(target.fileno(), 0o640)
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def reclassify_cache(cached):
    """Upgrade retained historical views without inventing events or freshness."""
    if cached.get('ruleset_version') == RULESET_VERSION:
        return False
    for node in cached['nodes']:
        for target in node['destinations']:
            host, kind = target['destination'], target['kind']
            normalized, parsed_kind = report.destination_host('tcp:' + ('[' + host + ']' if ':' in host else host) + ':443')
            if normalized != host or kind != parsed_kind:
                raise ValueError('invalid historical destination')
            target['classification'] = identify(host, kind)
    cached['ruleset_version'] = RULESET_VERSION
    return True


def mail_status(state, daily_time='09:00'):
    summary = {'schedule': f'北京时间每天 {daily_time}，汇总前一天；各节点分段', 'state': 'not_run', 'report_date': None}
    try:
        last = read_json(state / 'last-run.json', 65536)
        summary['report_date'] = date.fromisoformat(last['report_date']).isoformat()
        summary['updated_at'] = timestamp(last['updated_at'])
        if last.get('run_state') == 'running':
            age = (datetime.now(report.timezone_for(report.REPORT_TIMEZONE)) - datetime.fromisoformat(last['updated_at'])).total_seconds()
            summary['state'] = 'running' if age <= 600 else 'failed'
        elif last.get('emailed'):
            summary['state'] = 'smtp_accepted'
        elif 'mail_exit_code' in last or last.get('generation_exit_code') != 0:
            summary['state'] = 'failed'
        else:
            summary['state'] = 'generated_only'
    except FileNotFoundError:
        pass
    except (OSError, ValueError, KeyError, TypeError):
        summary['state'] = 'unknown'
    return summary


def publish(now, build_current, state=STATE, output=OUTPUT, retention=MAX_DAYS, daily_time='09:00'):
    """Keep last-good current view on failure; never rewrite private daily reports."""
    today = now.date()
    cutoff = cutoff_date(today, retention)
    current_ok, history_failures = True, 0
    try:
        source = build_current(today)
        if source['report_date'] != today.isoformat():
            raise ValueError('wrong current date')
        atomic_json(output / (today.isoformat() + '.json'), project(source, 'live'))
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        current_ok = False
    private_reports = state / 'reports'
    if private_reports.is_dir():
        for path in private_reports.glob('*.json'):
            if not DATE_RE.fullmatch(path.stem) or path.is_symlink():
                continue
            try:
                day = date.fromisoformat(path.stem)
                if cutoff <= day < today:
                    source = read_json(path)
                    if source['report_date'] != path.stem:
                        raise ValueError('mismatched report date')
                    generated = datetime.fromisoformat(timestamp(source['generated_at']))
                    kind = 'daily' if generated.date() > day and source.get('coverage_status') != 'period_not_complete' else 'live'
                    candidate = project(source, kind)
                    cached_path = output / path.name
                    if cached_path.exists():
                        previous = read_json(cached_path, MAX_OUTPUT)
                        # A daytime manual report must not roll back a later live snapshot.
                        if datetime.fromisoformat(previous['generated_at']) > generated:
                            continue
                        if candidate['data_status'] == 'partial_read_failure' and previous['data_status'] != 'partial_read_failure':
                            history_failures += 1
                            continue
                    atomic_json(cached_path, candidate)
            except (OSError, ValueError, KeyError, TypeError):
                history_failures += 1
    dates = []
    for path in output.glob('*.json'):
        if not DATE_RE.fullmatch(path.stem) or path.is_symlink():
            continue
        try:
            day = date.fromisoformat(path.stem)
            if day < cutoff:
                path.unlink()  # Exact date-named managed cache only; never private reports.
                continue
            if day > today:
                continue
            cached = read_json(path, MAX_OUTPUT)
            if reclassify_cache(cached):
                atomic_json(path, cached)
            dates.append({key: cached[key] for key in ('report_date', 'generated_at', 'kind', 'data_status', 'node_count')})
        except (OSError, ValueError, KeyError, TypeError):
            history_failures += 1
    index = {'schema_version': 1, 'today': today.isoformat(), 'generated_at': now.isoformat(),
             'current_generation_ok': current_ok, 'history_failures': history_failures,
             'refresh_seconds': 120, 'retention_days': days(retention), 'earliest_date': cutoff.isoformat(), 'mail': mail_status(state, daily_time),
             'dates': sorted(dates, key=lambda item: item['report_date'], reverse=True)}
    atomic_json(output / 'index.json', index)
    return current_ok


def build_current(day):
    nodes, warnings, ignored = report.load_nodes('/etc/x-ui/x-ui.db', '/usr/local/x-ui/bin/config.json', True)
    paths = report.find_logs('/var/log/x-ui')
    failures = []
    source = report.aggregate(report.iter_log_lines(paths, failures), nodes, day, report.REPORT_TIMEZONE, ignored)
    source['warnings'].extend(warnings)
    if failures or not any(path.name == 'access.log' for path in paths):
        source['data_status'] = 'partial_read_failure'
    report.add_coverage(source, read_json(STATE / 'metadata.json', 65536)['started_at'])
    return source


def main():
    import fcntl
    os.umask(0o027)
    if OUTPUT.is_symlink() or not (OUTPUT / '.managed-by-xray-audit-web').is_file():
        raise SystemExit('Managed export directory is required')
    config = read_json(Path('/etc/xray-audit/config.json'), 65536)
    retention = days(config.get('report_retention_days', MAX_DAYS))
    # Cooperate with daily's exclusive lock; no email run is launched here.
    with (STATE / 'daily.lock').open('a') as daily_lock, (OUTPUT / '.snapshot.lock').open('a') as own_lock:
        try:
            fcntl.flock(daily_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            fcntl.flock(own_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Audit publisher skipped: another audit job is running')
            return 0
        import schedule_config
        success = publish(datetime.now(report.timezone_for(report.REPORT_TIMEZONE)), build_current, retention=retention, daily_time=schedule_config.read()['time'])
    print('Audit view updated' if success else 'Audit view retained; current generation failed')
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
