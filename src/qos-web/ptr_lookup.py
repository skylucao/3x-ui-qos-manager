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

# Curated name associations only, NOT verified IP ownership or observed activity.
# (suffix, exact-only, possible infrastructure, common uses, official provenance)
REFERENCE_RULES = (
    ('dns.google', True, '可能关联 Google Public DNS', '常见用途：域名解析；不能据此判断浏览了哪个网站。',
     'https://developers.google.com/speed/public-dns/docs/doh'),
    ('1e100.net', False, '可能关联 Google 共享网络基础设施', '可能承载多种 Google 产品，无法区分搜索、视频或其他服务。',
     'https://support.google.com/faqs/answer/174717?hl=en-GB'),
    ('googleusercontent.com', False, '可能关联 Google 托管资源 / 云基础设施', '常见用途：云主机、托管资源等；具体网站或应用未知。',
     'https://docs.cloud.google.com/compute/docs/instances/create-ptr-record'),
    ('amazonaws.com', False, '可能关联 AWS 云基础设施', '常见用途：云主机、存储或其他云服务；具体租户和网站未知。',
     'https://docs.aws.amazon.com/general/latest/gr/rande.html'),
    ('cloudfront.net', False, '可能关联 Amazon CloudFront CDN', '常见用途：网站静态资源、内容分发；具体站点未知。',
     'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LinkFormat.html'),
    ('cloudapp.azure.com', False, '可能关联 Microsoft Azure 云服务', '常见用途：云服务或虚拟机；具体租户和应用未知。',
     'https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-domains'),
    ('telegram.org', False, '可能关联 Telegram 网站 / 服务基础设施', '可能用于网站或服务连接；不能判断是否聊天、聊天对象或内容。',
     'https://core.telegram.org/api/config'),
    ('t.me', False, '可能关联 Telegram 链接 / 网站服务', '可能用于链接跳转或网站服务；不能判断是否聊天或浏览了哪个频道。',
     'https://core.telegram.org/api/config'),
    ('github.com', False, '可能关联 GitHub 网站 / API 服务', '可能用于网站、API 或开发工具连接；不能判断操作了哪个仓库。',
     'https://docs.github.com/en/enterprise-cloud@latest/admin/configuring-settings/hardening-security-for-your-enterprise/restricting-access-to-githubcom-using-a-corporate-proxy'),
    ('githubassets.com', False, '可能关联 GitHub 静态资源服务', '常见用途：网页资源加载；不能证明正在浏览或编写代码。',
     'https://docs.github.com/en/enterprise-cloud@latest/admin/configuring-settings/hardening-security-for-your-enterprise/restricting-access-to-githubcom-using-a-corporate-proxy'),
    ('githubusercontent.com', False, '可能关联 GitHub 托管资源服务', '常见用途：托管内容或资源下载；具体文件和操作未知。',
     'https://docs.github.com/en/enterprise-cloud@latest/admin/configuring-settings/hardening-security-for-your-enterprise/restricting-access-to-githubcom-using-a-corporate-proxy'),
)
REFERENCE_LIMITATION = '仅按 PTR 名称匹配，未验证 IP 归属；PTR 可自定义或失真，不能证明实际访问网站、使用 App 或聊天。'


def reference_for(value):
    """Return a separate, low-confidence hint; never feed it into audit statistics."""
    try:
        name = hostname(value)
    except ValueError:
        name = None
    for suffix, exact, possibility, uses, source in REFERENCE_RULES:
        if name and (name == suffix or (not exact and name.endswith('.' + suffix))):
            return {'possibility': possibility, 'common_uses': uses, 'confidence': 'low',
                    'basis': f'PTR 名称{"精确匹配" if exact else "匹配域名后缀"} {suffix}',
                    'source_url': source, 'limitation': REFERENCE_LIMITATION}
    return {'possibility': '无法确定具体网站 / 服务', 'confidence': 'unknown',
            'basis': 'PTR 名称未命中已核对的参考规则' if name else '没有可用的 PTR 名称',
            'common_uses': '一般可能是网站服务器、App 后台、云主机或 CDN；当前没有依据区分这些情况。',
            'source_url': None, 'limitation': REFERENCE_LIMITATION}


def present(result, cached=False):
    # Decorate after DNS IPC/cache; the worker stays bounded to a hostname/status.
    name = result.get('hostname') if result.get('status') == 'found' else None
    return {**result, 'cached': cached, 'reference': reference_for(name)}


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


def observed_ip(day, value, reader):
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
    return ip


def lookup(day, value, reader):
    global LAST_QUERY
    ip = observed_ip(day, value, reader)
    now = time.monotonic()
    with LOCK:
        expired = [key for key, entry in CACHE.items() if now - entry[0] >= 600]
        for key in expired:
            del CACHE[key]
        cached = CACHE.get(ip)
        if cached:
            return present(cached[1], cached=True)
        if now - LAST_QUERY < 1:
            return present({'hostname': None, 'status': 'busy'})
        LAST_QUERY = now
    if not SLOTS.acquire(blocking=False):
        return present({'hostname': None, 'status': 'busy'})
    try:
        try:
            result = exchange(ip)
        except (OSError, ValueError, KeyError, TypeError):
            result = {'hostname': None, 'status': 'unavailable'}
        with LOCK:
            CACHE[ip] = (now, result)
            while len(CACHE) > 512:
                CACHE.popitem(last=False)
        return present(result)
    finally:
        SLOTS.release()


if __name__ == '__main__':
    raise SystemExit(worker())
