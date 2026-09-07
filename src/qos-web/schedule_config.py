"""Shared, secret-free daily schedule contract; writes are root-controller only."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

PATH = Path('/etc/xray-qos/daily-schedule.json')
SHANGHAI = timezone(timedelta(hours=8))
TIME_RE = re.compile(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]')


def read(path=None):
    path = PATH if path is None else path
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('unsafe schedule path')
    exists = path.exists()
    raw = path.read_bytes() if exists else b''
    if len(raw) > 4096:
        raise ValueError('invalid schedule')
    value = json.loads(raw) if exists else {'version': 1, 'time': '09:00', 'effective_from': 0}
    if (not isinstance(value, dict) or set(value) != {'version', 'time', 'effective_from'} or value['version'] != 1
            or not isinstance(value['time'], str) or not TIME_RE.fullmatch(value['time'])
            or type(value['effective_from']) is not int or value['effective_from'] < 0):
        raise ValueError('invalid schedule')
    return {**value, 'revision': hashlib.sha256(raw).hexdigest()}


def due(now, value):
    now = now.astimezone(SHANGHAI)
    # Catch a cleanup lock or short outage, but never precede a newly saved next occurrence.
    return now.strftime('%H:%M') >= value['time'] and now.timestamp() >= value['effective_from']


def save(chosen, revision, path=None, now=None):
    path = PATH if path is None else path
    if not isinstance(chosen, str) or not TIME_RE.fullmatch(chosen):
        raise ValueError('时间必须为 00:00 到 23:59')
    current = read(path)
    if current['revision'] != revision:
        raise FileExistsError('设置已被其他页面修改，请重新载入')
    if chosen == current['time'] and path.exists():
        return current
    now = (now or datetime.now(SHANGHAI)).astimezone(SHANGHAI)
    hour, minute = map(int, chosen.split(':'))
    next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if next_run <= now:
        next_run += timedelta(days=1)
    value = {'version': 1, 'time': chosen, 'effective_from': int(next_run.timestamp())}
    fd, temporary = tempfile.mkstemp(prefix='.daily-schedule-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as target:
            if hasattr(os, 'fchmod'):
                os.fchmod(target.fileno(), 0o600)
            target.write((json.dumps(value) + '\n').encode()); target.flush(); os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return read(path)
