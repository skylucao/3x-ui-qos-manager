"""Independent node annotations. Never opens or changes the 3x-ui database."""
from contextlib import closing
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sqlite3
import time
import unicodedata

DB_PATH = Path('/var/lib/xray-qos-web/node-notes.sqlite3')
MAX_LENGTH = 200


class Conflict(Exception):
    def __init__(self, current):
        self.current = current


def identity(node_id, port, protocol):
    if type(node_id) is not int or not 1 <= node_id <= 2**53 - 1:
        raise ValueError('invalid node ID')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('invalid node port')
    if not isinstance(protocol, str) or not re.fullmatch(r'[a-z0-9_-]{1,32}', protocol):
        raise ValueError('invalid node protocol')
    return {'key': f'{node_id}:{port}:{protocol}', 'node_id': node_id, 'port': port, 'protocol': protocol}


def inventory(status, now=None):
    now = time.time() if now is None else now
    stamp = status.get('sample_time_ms')
    if not status.get('ok') or status.get('discovery_stale') or type(stamp) not in (int, float) or not 0 <= now - stamp / 1000 <= 15:
        raise RuntimeError('node discovery is not fresh')
    result = [identity(node['inbound_id'], node['port'], node['protocol']) for node in status['nodes']]
    if len(result) > 1000 or len({node['node_id'] for node in result}) != len(result):
        raise ValueError('invalid inventory')
    return result


def note_text(value):
    if not isinstance(value, str) or len(value) > MAX_LENGTH:
        raise ValueError('note must be at most 200 characters')
    if any(unicodedata.category(c).startswith('C') and c not in '\n\t' for c in value):
        raise ValueError('note contains control characters')
    return value.strip()


def initialize(path=DB_PATH):
    """Explicit deployment migration, not a request-time schema write."""
    if path.is_symlink():
        raise ValueError('symlink database is not allowed')
    with closing(sqlite3.connect(path, timeout=5)) as db:
        db.execute('CREATE TABLE IF NOT EXISTS node_notes (node_key TEXT PRIMARY KEY, note TEXT NOT NULL CHECK(length(note)<=200), revision INTEGER NOT NULL CHECK(revision>=1), updated_at TEXT NOT NULL)')
        db.commit()
    os.chmod(path, 0o600)


def connect(path, readonly=False):
    if path.is_symlink() or not path.is_file():
        raise ValueError('notes storage is unavailable')
    return sqlite3.connect(path.resolve().as_uri() + ('?mode=ro' if readonly else '?mode=rw'), uri=True, timeout=5)


def entry(db, node):
    row = db.execute('SELECT note, revision, updated_at FROM node_notes WHERE node_key=?', (node['key'],)).fetchone()
    return {**node, 'note': row[0] if row else '', 'revision': row[1] if row else 0, 'updated_at': row[2] if row else None}


def read(nodes, path=DB_PATH):
    with closing(connect(path, readonly=True)) as db:
        return [entry(db, node) for node in nodes]


def save(node, value, expected_revision, path=DB_PATH):
    value = note_text(value)
    if type(expected_revision) is not int or not 0 <= expected_revision <= 2**53 - 1:
        raise ValueError('invalid revision')
    with closing(connect(path)) as db:
        with db:
            db.execute('BEGIN IMMEDIATE')
            current = entry(db, node)
            if current['revision'] != expected_revision:
                raise Conflict(current)
            revision = current['revision'] + 1
            updated = datetime.now(timezone.utc).isoformat()
            db.execute('INSERT INTO node_notes(node_key,note,revision,updated_at) VALUES(?,?,?,?) ON CONFLICT(node_key) DO UPDATE SET note=excluded.note,revision=excluded.revision,updated_at=excluded.updated_at',
                       (node['key'], value, revision, updated))
        return {**node, 'note': value, 'revision': revision, 'updated_at': updated}


if __name__ == '__main__':
    initialize()
