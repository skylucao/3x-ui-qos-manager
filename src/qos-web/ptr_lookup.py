"""Bounded, on-demand reverse DNS; never used to infer a visited website."""
import ipaddress
import json
import re
import socket
import subprocess
import sys
import threading
import time
from collections import OrderedDict

SOCKET = '/run/xray-audit-ptr.sock'
CACHE = OrderedDict()
LOCK = threading.Lock()
SLOTS = threading.BoundedSemaphore(2)
LAST_QUERY = 0.0


def public_ip(value):
    if not isinstance(value, str) or len(value) > 45 or '%' in value:
        raise ValueError('invalid IP')
    ip = ipaddress.ip_address(value)
    if getattr(ip, 'ipv4_mapped', None):
        ip = ip.ipv4_mapped
    if (not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified
            or ip.is_loopback or ip.is_link_local or getattr(ip, 'is_site_local', False)):
        raise ValueError('public unicast IP required')
    return str(ip)


def hostname(value):
    if not isinstance(value, str):
        raise ValueError('invalid hostname')
    name = value.rstrip('.').lower()
    if len(name) > 253 or not name or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in name.split('.')):
        raise ValueError('invalid hostname')
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError('hostname is an IP')


def worker():
    # systemd bounds the entire process lifetime. dns NSS explicitly excludes /etc/hosts.
    raw = sys.stdin.buffer.readline(129)
    if len(raw) > 128 or not raw.endswith(b'\n'):
        return 1
    try:
        ip = public_ip(raw[:-1].decode('ascii'))
        result = subprocess.run(['/usr/bin/getent', '-s', 'dns', 'hosts', ip], capture_output=True, timeout=4, check=False)
        name = None
        if result.returncode == 0 and len(result.stdout) <= 65536:
            parts = result.stdout.decode('ascii').split()
            if len(parts) >= 2 and public_ip(parts[0]) == ip:
                name = hostname(parts[1])
        status = 'found' if name else 'not_found'
    except subprocess.TimeoutExpired:
        name, status = None, 'timeout'
    except (ValueError, OSError, UnicodeError):
        name, status = None, 'unavailable'
    print(json.dumps({'hostname': name, 'status': status}), flush=True)
    return 0


def exchange(ip):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(7)
        conn.connect(SOCKET)
        conn.sendall(ip.encode('ascii') + b'\n')
        conn.shutdown(socket.SHUT_WR)
        raw = bytearray()
        while len(raw) <= 1024:
            part = conn.recv(1025 - len(raw))
            if not part:
                break
            raw.extend(part)
            if b'\n' in part:
                break
        if len(raw) > 1024:
            raise ValueError('invalid worker response')
    result = json.loads(raw)
    if not isinstance(result, dict) or result.get('status') not in ('found', 'not_found', 'timeout', 'unavailable'):
        raise ValueError('invalid worker status')
    name = hostname(result['hostname']) if result['status'] == 'found' else None
    return {'hostname': name, 'status': result['status']}


def lookup(day, value, reader):
    global LAST_QUERY
    ip = public_ip(value)
    # Authorize on every call BEFORE cache use; expired dates and removed targets fail closed.
    report = json.loads(reader(day + '.json'))
    observed = False
    for node in report.get('nodes', []):
        for target in node.get('destinations', []):
            if target.get('kind') == 'ip':
                try:
                    observed |= public_ip(target['destination']) == ip
                except ValueError:
                    pass
    if not observed:
        raise FileNotFoundError('target not present in retained report')
    now = time.monotonic()
    with LOCK:
        expired = [key for key, entry in CACHE.items() if now - entry[0] >= 600]
        for key in expired:
            del CACHE[key]
        cached = CACHE.get(ip)
        if cached:
            return {**cached[1], 'cached': True}
        if now - LAST_QUERY < 1:
            return {'hostname': None, 'status': 'busy', 'cached': False}
        LAST_QUERY = now
    if not SLOTS.acquire(blocking=False):
        return {'hostname': None, 'status': 'busy', 'cached': False}
    try:
        try:
            result = exchange(ip)
        except (OSError, ValueError, KeyError, TypeError):
            result = {'hostname': None, 'status': 'unavailable'}
        with LOCK:
            CACHE[ip] = (now, result)
            while len(CACHE) > 512:
                CACHE.popitem(last=False)
        return {**result, 'cached': False}
    finally:
        SLOTS.release()


if __name__ == '__main__':
    raise SystemExit(worker())
