"""Read-only, size-bounded access to sanitized audit snapshots."""
from datetime import date, datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import threading
from urllib.parse import parse_qs

ROOT = Path('/var/lib/xray-audit-web')
MAX_BYTES = 2 * 1024 * 1024
READ_LOCK = threading.BoundedSemaphore(1)


def today():
    return datetime.now(timezone(timedelta(hours=8))).date()


def requested_date(query):
    if len(query) > 32:
        raise ValueError('invalid query')
    values = parse_qs(query, strict_parsing=True, keep_blank_values=True, max_num_fields=2)
    if set(values) != {'date'} or len(values['date']) != 1:
        raise ValueError('one date is required')
    value = values['date'][0]
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
        raise ValueError('invalid date')
    return date.fromisoformat(value).isoformat()


def read(name, root=ROOT):
    if name != 'index.json' and not re.fullmatch(r'\d{4}-\d{2}-\d{2}\.json', name):
        raise ValueError('invalid filename')
    current = today()
    cutoff = current - timedelta(days=1)
    if name != 'index.json' and not cutoff <= date.fromisoformat(name[:-5]) <= current:
        raise FileNotFoundError('Report is outside the retention window')
    with READ_LOCK:
        path = root / name
        if path.is_symlink():
            raise ValueError('symlinks not allowed')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise ValueError('invalid snapshot')
            payload = source.read(MAX_BYTES + 1)
        if len(payload) > MAX_BYTES:
            raise ValueError('oversized snapshot')
        data = json.loads(payload)
        if not isinstance(data, dict) or data.get('schema_version') != 1:
            raise ValueError('invalid snapshot schema')
        if name != 'index.json' and data.get('report_date') != name[:-5]:
            raise ValueError('mismatched snapshot')
        if name == 'index.json' and 'dates' in data:
            # Enforce visibility even while the periodic disk cleanup is delayed.
            data['dates'] = [entry for entry in data['dates'] if cutoff <= date.fromisoformat(entry['report_date']) <= current]
            data['retention_days'] = 2
            data['earliest_date'] = cutoff.isoformat()
            if data.get('mail', {}).get('report_date') and date.fromisoformat(data['mail']['report_date']) < cutoff:
                data['mail'] = {'state': 'not_run', 'report_date': None, 'schedule': data['mail'].get('schedule', '')}
            payload = json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        return payload
