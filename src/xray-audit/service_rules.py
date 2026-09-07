"""Conservative, offline domain associations, not app or human-activity detection.

Only curated subsets of the cited primary rule lists are used. No live lookup,
reverse DNS, visited-host requests, or employee data leaves this machine.
"""
import ipaddress
import re

RULESET_VERSION = '2026-09-07.1'
BASE = 'https://github.com/v2fly/domain-list-community/blob/master/data/'
RULES = [
    ('微信相关', '社交通讯', ('wechat.com', 'weixin.com', 'weixin.qq.com', 'wx.qq.com', 'wxs.qq.com', 'servicewechat.com'), 'https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash/WeChat/WeChat.list'),
    ('QQ相关', '社交通讯', ('im.qq.com', 'pd.qq.com', 'vip.qq.com', 'qzone.qq.com'), 'https://security.tencent.com/index.php/blog/msg/338?from_tab=announcement'),
    ('Telegram相关', '社交通讯', ('telegram.org', 'telegram.me', 't.me', 'tdesktop.com', 'telegram-cdn.org', 'cdn-telegram.org'), BASE + 'telegram'),
    ('YouTube相关', '视频服务', ('youtube.com', 'youtu.be', 'youtube-nocookie.com', 'youtubei.googleapis.com', 'youtube.googleapis.com', 'youtubeembeddedplayer.googleapis.com', 'ytimg.com', 'googlevideo.com'), BASE + 'youtube'),
    ('哔哩哔哩相关', '视频服务', ('bilibili.com', 'b23.tv', 'biliapi.com', 'biliapi.net', 'acgvideo.com'), BASE + 'bilibili'),
    ('抖音相关', '视频服务', ('douyin.com', 'iesdouyin.com', 'douyincdn.com', 'douyinpic.com', 'douyinstatic.com', 'douyinvod.com'), BASE + 'douyin'),
    ('TikTok相关', '视频服务', ('tiktok.com', 'tiktokv.com', 'tiktokv.us', 'tiktokv.eu', 'tiktokcdn.com', 'tiktokcdn-us.com', 'tiktokcdn-eu.com'), BASE + 'tiktok'),
    ('GitHub相关', '开发与代码托管', ('github.com', 'github.dev', 'githubassets.com', 'githubusercontent.com', 'ghcr.io'), BASE + 'github'),
    ('微软办公相关', '办公协作', ('office.com', 'office365.com', 'office.net', 'officeapps.live.com', 'sharepoint.com', 'sharepointonline.com', 'onenote.com', 'teams.microsoft.com', 'teams.cloud.microsoft'), 'https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide'),
    ('Google相关／未知具体服务', '综合服务', ('google.com', 'google.com.hk', 'googleapis.com', 'gstatic.com', 'googleusercontent.com'), BASE + 'google'),
    ('百度相关／未知具体服务', '综合服务', ('baidu.com', 'baidu.cn', 'baidu.com.cn', 'bdstatic.com', 'bdimg.com', 'baidustatic.com'), BASE + 'baidu'),
    ('腾讯相关／未知具体服务', '共享服务', ('qq.com', 'tencent.com', 'tencent.cn', 'tencent.com.cn', 'gtimg.com', 'gtimg.cn', 'qpic.cn', 'qlogo.cn'), BASE + 'tencent'),
]
INDEX = sorted(((suffix, service, category, source) for service, category, suffixes, source in RULES for suffix in suffixes), key=lambda row: -len(row[0]))


def identify(host, kind):
    unknown = {'service': '未知服务', 'category': '未分类', 'matched_suffix': None, 'source_url': None,
               'basis': '暂无匹配规则', 'ruleset_version': RULESET_VERSION}
    if kind != 'domain':
        return {**unknown, 'basis': '仅记录到 IP，不反查或按共享 IP 猜测'}
    if not isinstance(host, str) or len(host) > 253:
        return unknown
    host = host.rstrip('.').lower()
    try:
        ipaddress.ip_address(host)
        return {**unknown, 'basis': '仅记录到 IP，不反查或按共享 IP 猜测'}
    except ValueError:
        pass
    if not all(re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', part) for part in host.split('.')):
        return unknown
    for suffix, service, category, source in INDEX:
        if host == suffix or host.endswith('.' + suffix):
            return {'service': service, 'category': category, 'matched_suffix': suffix, 'source_url': source,
                    'basis': '域名后缀规则匹配，仅表示关联线索', 'ruleset_version': RULESET_VERSION}
    return unknown
