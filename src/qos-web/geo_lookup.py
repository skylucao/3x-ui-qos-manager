"""Offline target-IP location reference, isolated from employee/activity reports."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import threading

from ip2region import searcher, util
from ptr_lookup import observed_ip, public_ip

UPSTREAM_COMMIT = 'cd40e3a1d532d645697999d646cf0e10481cef33'
UPSTREAM_VERSION = 'v3.17.0'
SOURCE_URL = 'https://github.com/lionsoul2014/ip2region/tree/' + UPSTREAM_VERSION
DATA_DIR = Path('/opt/xray-qos-web/ipdata')
DATASETS = {
    4: {'name': 'ip2region_v4.xdb', 'size': 11114380,
        'sha256': '6307a9696f5711f84bcb8b25f07894de68a64a0ed4a1cc7e990562dd3084f210'},
    6: {'name': 'ip2region_v6.xdb', 'size': 37258897,
        'sha256': '5b93da35ac28bc316dccc54a758381f7a874ae0461dd51ff5df5e34815586f11'},
}
LIMITATION = '这是连接目标 IP 的网络归属参考，不是员工所在地。CDN、云服务、Anycast 和资料滞后可能造成偏差，也不能据此判断访问了哪个网站。'
SLOTS = threading.BoundedSemaphore(2)
MAX_TARGETS = 100  # Same bound as the sanitized per-node web projection.


def verify_database(path, version):
    """Verify pinned bytes before passing a file to the upstream reader."""
    expected = DATASETS[version]
    if path.is_symlink() or path.resolve() != path.absolute():
        raise ValueError('unsafe IP database path')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected['size']:
            raise ValueError('unexpected IP database size/type')
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != expected['sha256']:
            raise ValueError('IP database integrity mismatch')
        util.verify(stream)
        header = util.load_header(stream)
        if header.version != util.XdbStructure30 or header.ipVersion != version or header.runtimePtrBytes != 4:
            raise ValueError('incompatible IP database')
        return datetime.fromtimestamp(header.createdAt, timezone.utc).date().isoformat()


def fields(region):
    if not isinstance(region, str) or len(region) > 1024:
        raise ValueError('invalid region result')
    if not region:
        return None
    parts = region.split('|')
    if len(parts) != 5:
        raise ValueError('unexpected region format')
    cleaned = []
    for value in parts:
        value = value.strip()
        if len(value) > 200 or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value):
            raise ValueError('invalid region field')
        cleaned.append(None if value in ('', '0', '-') else value)
    if cleaned[4] is not None and not re.fullmatch('[A-Z]{2}', cleaned[4]):
        raise ValueError('invalid country code')
    return dict(zip(('country', 'province', 'city', 'isp', 'country_code'), cleaned)) if any(cleaned) else None


def empty_result(status='unavailable'):
    return {'status': status, 'location': None, 'database_date': None,
            'provider': 'ip2region', 'dataset_version': UPSTREAM_VERSION,
            'source_url': SOURCE_URL, 'limitation': LIMITATION}


def locate_many(values):
    """One integrity check/reader per family per bounded, authorized batch."""
    if not isinstance(values, list) or len(values) > MAX_TARGETS:
        raise ValueError('invalid batch size')
    ips = {value: ipaddress.ip_address(public_ip(value)) for value in values}
    results = {value: empty_result() for value in ips}
    if not ips:
        return results
    if not SLOTS.acquire(blocking=False):
        return {value: empty_result('busy') for value in ips}
    try:
        for version in (4, 6):
            selected = {value: ip for value, ip in ips.items() if ip.version == version}
            if not selected:
                continue
            try:
                path = DATA_DIR / DATASETS[version]['name']
                # Never cache validation by mtime: same-size writes can evade it.
                date = verify_database(path, version)
                engine = searcher.new_with_file_only(util.IPv4 if version == 4 else util.IPv6, str(path))
                try:
                    for value, ip in selected.items():
                        results[value]['database_date'] = date
                        try:
                            location = fields(engine.search(ip.packed))
                            results[value].update(location=location, status='found' if location else 'not_found')
                        except (OSError, ValueError, IndexError, OverflowError):
                            results[value]['status'] = 'unavailable'
                finally:
                    engine.close()
            except FileNotFoundError:
                for value in selected:
                    results[value]['status'] = 'not_installed'
            except (OSError, ValueError, IndexError, OverflowError):
                # No filesystem paths, persisted results, or requested-IP logs.
                for value in selected:
                    results[value]['status'] = 'unavailable'
    finally:
        SLOTS.release()
    return results


def locate(value):
    return locate_many([value])[value]


def lookup(day, value, reader):
    return locate(observed_ip(day, value, reader))


def lookup_node(day, key, reader):
    if not isinstance(key, str) or not 1 <= len(key) <= 100:
        raise ValueError('invalid node key')
    # Every batch rechecks retention and exact membership BEFORE disk lookup.
    report = json.loads(reader(day + '.json'))
    if not isinstance(report, dict) or not isinstance(report.get('nodes'), list) or any(not isinstance(node, dict) for node in report['nodes']):
        raise ValueError('invalid projected nodes')
    node = next((node for node in report['nodes'] if node.get('key') == key), None)
    if node is None:
        raise FileNotFoundError('node not present in retained report')
    targets = node.get('destinations', [])
    if not isinstance(targets, list) or len(targets) > MAX_TARGETS:
        raise ValueError('invalid projected node size')
    results, public = {}, []
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError('invalid projected target')
        # Domain-only observations are never resolved into invented historical IPs.
        if target.get('kind') != 'ip':
            continue
        value = target.get('destination')
        if not isinstance(value, str) or len(value) > 45:
            raise ValueError('invalid projected IP')
        try:
            public_ip(value)
        except ValueError:
            results[value] = empty_result('not_public')
        else:
            public.append(value)
    results.update(locate_many(public))
    return {'report_date': day, 'node_key': key, 'results': results}
