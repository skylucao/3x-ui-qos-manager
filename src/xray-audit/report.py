#!/usr/bin/env python3
"""Read-only Xray connection summaries. This module never sends mail."""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
from datetime import date, datetime, time, timedelta, timezone
import gzip
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import unicodedata
from urllib.parse import quote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import zlib

from service_rules import identify

REPORT_TIMEZONE = "Asia/Shanghai"
MAX_LINE_LENGTH = 65536
MAX_CONFIG_BYTES = 32 * 1024 * 1024
STAMP_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?\s+")
ACCEPT_RE = re.compile(r"^(?:from\s+)?\S+\s+accepted\s+(\S+)\s+\[([^\]\r\n]+)\](?:\s+.*)?$")
ROUTE_RE = re.compile(r"\s+(?:==>|->|>>)\s+")
LOG_NAME_RE = re.compile(r"^access\.log(?:\.gz|\.\d+(?:\.gz)?|-\d{8}(?:\.gz)?)?$")


def timezone_for(name, on_date=None):
    """Use system tzdata, with a standard-library-only modern Windows fallback."""
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        if name in ("UTC", "Etc/UTC"):
            return timezone.utc
        # Shanghai has used UTC+08 without seasonal changes since 1992.
        # Do not silently apply that rule to older historical dates.
        if name == REPORT_TIMEZONE and (on_date is None or on_date >= date(1992, 1, 1)):
            return timezone(timedelta(hours=8), REPORT_TIMEZONE)
        raise


def clean_label(value, limit=160):
    """Prevent control/header injection and HTML interpretation of display labels."""
    text = "".join(" " if unicodedata.category(ch).startswith("C") else ch for ch in str(value))
    return html.escape(" ".join(text.split())[:limit], quote=True)


def destination_host(value):
    """Return only the literal destination host; never infer names from IPs."""
    if not (value.startswith("tcp:") or value.startswith("udp:")):
        raise ValueError("unsupported destination transport")
    authority = re.split(r"[/\?#]", value[4:], maxsplit=1)[0]
    if not authority or "@" in authority:
        raise ValueError("invalid destination")
    if authority.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d{1,5})", authority)
        if not match:
            raise ValueError("invalid bracketed destination")
        host, port = match.groups()
        parsed = ipaddress.ip_address(host)
        if parsed.version != 6 or "%" in host:
            raise ValueError("invalid IPv6 destination")
        kind, host = "ip", str(parsed)
    else:
        match = re.fullmatch(r"([^:]+):(\d{1,5})", authority)
        if not match:
            raise ValueError("missing destination port")
        host, port = match.groups()
        host = host.rstrip(".").lower()
        try:
            host, kind = str(ipaddress.ip_address(host)), "ip"
        except ValueError:
            host = host.encode("idna").decode("ascii")
            if len(host) > 253 or not all(
                re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label)
                for label in host.split(".")
            ):
                raise ValueError("invalid domain destination")
            kind = "domain"
    if not 1 <= int(port) <= 65535:
        raise ValueError("invalid destination port")
    return host, kind


def load_nodes(db_path, runtime_path, include_ignored_tags=False):
    """Load non-secret metadata; optionally also return internal API tags."""
    db_path, runtime_path = Path(db_path), Path(runtime_path)
    if not db_path.is_file() or not runtime_path.is_file():
        raise ValueError("3x-ui database or runtime config is missing")
    if runtime_path.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError("runtime config exceeds size limit")
    uri = "file:" + quote(db_path.resolve().as_posix(), safe="/:") + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT id, remark, port, enable, protocol FROM inbounds ORDER BY id").fetchall()
    with runtime_path.open("r", encoding="utf-8") as source:
        runtime = json.load(source)
    if not isinstance(runtime, dict) or not isinstance(runtime.get("inbounds"), list):
        raise ValueError("runtime config has no valid inbounds list")
    ignored_tags = {"api"}
    api = runtime.get("api")
    if isinstance(api, dict) and isinstance(api.get("tag"), str) and api["tag"].strip():
        ignored_tags.add(api["tag"].strip())
    nodes = [
        {"id": str(row["id"]), "remark": row["remark"] or "unnamed", "port": int(row["port"]),
         "enabled": bool(row["enable"]), "protocol": row["protocol"] or "unknown", "tags": []}
        for row in rows
    ]
    warnings = []
    seen_tags = set()
    for inbound in runtime["inbounds"]:
        if not isinstance(inbound, dict):
            raise ValueError("invalid runtime inbound entry")
        tag, port, protocol = inbound.get("tag"), inbound.get("port"), inbound.get("protocol")
        # Access only these non-secret routing metadata fields, never settings/clients.
        _listen = inbound.get("listen")
        if not isinstance(tag, str) or not tag:
            continue
        if tag in ignored_tags:
            continue
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        matches = [node for node in nodes if node["port"] == port and node["protocol"] == protocol]
        if len(matches) == 1 and tag not in seen_tags:
            matches[0]["tags"].append(tag)
            seen_tags.add(tag)
        elif matches:
            warnings.append("运行配置标签存在重复或节点映射不唯一；原始标签不在报告中展示。")
    for node in nodes:
        if node["enabled"] and not node["tags"]:
            warnings.append("启用节点未匹配到运行配置标签：" + clean_label(node["remark"]))
    if include_ignored_tags:
        return nodes, warnings, tuple(sorted(ignored_tags))
    return nodes, warnings


def aggregate(lines, nodes, target_date, tz=REPORT_TIMEZONE, ignored_tags=("api",)):
    """Summarize an iterable of log lines without retaining sources or email IDs.

    target_date is the report date in Asia/Shanghai; tz is the log timestamp zone.
    Unknown tags are reported separately instead of attributing them to a person.
    """
    if isinstance(target_date, str):
        target_date = date.fromisoformat(target_date)
    log_zone = timezone_for(tz, target_date) if isinstance(tz, str) else tz
    report_zone = timezone_for(REPORT_TIMEZONE, target_date)
    ignored_tags = set(ignored_tags)
    node_reports, tag_index = {}, {}
    for node in nodes:
        key = "node:" + str(node["id"])
        if key in node_reports:
            raise ValueError("duplicate node ID")
        node_reports[key] = {
            "id": str(node["id"]), "remark": clean_label(node.get("remark", "unnamed")),
            "port": node.get("port"), "protocol": clean_label(node.get("protocol", "unknown")),
            "enabled": bool(node.get("enabled", True)), "unmapped": False,
            "total_connections": 0, "first_seen": None, "last_seen": None, "_counts": Counter(),
            "hourly_connections": [0] * 24, "_destination_times": {}, "_destination_hours": {},
        }
        for tag in node.get("tags", []):
            if tag in tag_index:
                raise ValueError("duplicate inbound tag mapping")
            tag_index[tag] = key
    diagnostics = {
        "scanned_lines": 0, "malformed_lines": 0, "oversized_lines": 0,
        "ignored_nonaccepted_lines": 0, "outside_period_lines": 0,
        "accepted_connections": 0, "unmapped_connections": 0,
        "ignored_internal_connections": 0,
    }
    for line in lines:
        diagnostics["scanned_lines"] += 1
        if len(line) > MAX_LINE_LENGTH:
            diagnostics["oversized_lines"] += 1
            diagnostics["malformed_lines"] += 1
            continue
        line = line.rstrip("\r\n")
        if not line:
            diagnostics["ignored_nonaccepted_lines"] += 1
            continue
        stamp = STAMP_RE.match(line)
        if not stamp:
            diagnostics["malformed_lines"] += 1
            continue
        try:
            moment = datetime.strptime(stamp.group(1), "%Y/%m/%d %H:%M:%S")
            if stamp.group(2):
                moment = moment.replace(microsecond=int(stamp.group(2)[:6].ljust(6, "0")))
            moment = moment.replace(tzinfo=log_zone).astimezone(report_zone)
        except (ValueError, OverflowError):
            diagnostics["malformed_lines"] += 1
            continue
        if moment.date() != target_date:
            diagnostics["outside_period_lines"] += 1
            continue
        body = line[stamp.end():]
        if " accepted " not in " " + body:
            diagnostics["ignored_nonaccepted_lines"] += 1
            continue
        parsed = ACCEPT_RE.fullmatch(body)
        if not parsed:
            diagnostics["malformed_lines"] += 1
            continue
        route = ROUTE_RE.split(parsed.group(2), maxsplit=1)
        if len(route) != 2 or not route[0].strip() or not route[1].strip():
            diagnostics["malformed_lines"] += 1
            continue
        tag = route[0].strip()
        if tag in ignored_tags:
            diagnostics["ignored_internal_connections"] += 1
            continue
        try:
            host, kind = destination_host(parsed.group(1))
        except (ValueError, UnicodeError):
            diagnostics["malformed_lines"] += 1
            continue
        key = tag_index.get(tag)
        if key is None:
            # Internal raw tag keys are not serialized or displayed.
            key = "unmapped:" + tag
            if key not in node_reports:
                node_reports[key] = {
                    "id": None, "remark": "未映射节点 " + str(1 + sum(item["unmapped"] for item in node_reports.values())), "port": None,
                    "protocol": "unknown", "enabled": None, "unmapped": True,
                    "total_connections": 0, "first_seen": None, "last_seen": None, "_counts": Counter(),
                    "hourly_connections": [0] * 24, "_destination_times": {}, "_destination_hours": {},
                }
            diagnostics["unmapped_connections"] += 1
        entry = node_reports[key]
        entry["total_connections"] += 1
        entry["_counts"][(host, kind)] += 1
        entry["hourly_connections"][moment.hour] += 1
        entry["_destination_hours"].setdefault((host, kind), [0] * 24)[moment.hour] += 1
        first, last = entry["_destination_times"].get((host, kind), (moment, moment))
        entry["_destination_times"][(host, kind)] = (min(first, moment), max(last, moment))
        if entry["first_seen"] is None or moment < entry["first_seen"]:
            entry["first_seen"] = moment
        if entry["last_seen"] is None or moment > entry["last_seen"]:
            entry["last_seen"] = moment
        diagnostics["accepted_connections"] += 1
    result_nodes = []
    for entry in node_reports.values():
        counts = entry.pop("_counts")
        destination_times = entry.pop("_destination_times")
        destination_hours = entry.pop("_destination_hours")
        entry["unique_destinations"] = len(counts)
        entry["destinations"] = [
            {"destination": host, "kind": kind, "connections": count,
             "first_seen": destination_times[(host, kind)][0].isoformat(),
             "last_seen": destination_times[(host, kind)][1].isoformat(),
             "hourly_connections": destination_hours[(host, kind)],
             "classification": identify(host, kind)}
            for (host, kind), count in sorted(counts.items(), key=lambda item: (-item[1], item[0][0]))
        ]
        for key in ("first_seen", "last_seen"):
            if entry[key] is not None:
                entry[key] = entry[key].isoformat()
        result_nodes.append(entry)
    return {
        "schema_version": 1, "report_date": target_date.isoformat(), "timezone": REPORT_TIMEZONE,
        "log_timezone": str(log_zone), "generated_at": datetime.now(report_zone).isoformat(),
        "data_status": "records_found" if diagnostics["accepted_connections"] else "no_matching_records",
        "coverage_status": "unverified", "diagnostics": diagnostics, "nodes": result_nodes,
        "warnings": [
            f"有 {diagnostics['unmapped_connections']} 条连接的入站标签无法匹配当前 3x-ui 节点，已独立列出，不能确定其节点归属。"
        ] if diagnostics["unmapped_connections"] else [], "log_sources": [],
    }


def add_coverage(report, started_at=None):
    """Mark first-day/incomplete coverage; never claim uninterrupted collection."""
    target = date.fromisoformat(report["report_date"])
    zone = timezone_for(REPORT_TIMEZONE, target)
    start, end = datetime.combine(target, time.min, zone), datetime.combine(target + timedelta(days=1), time.min, zone)
    now = datetime.now(zone)
    report["collection_started_at"] = None
    if started_at:
        started = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
        if started.tzinfo is None:
            raise ValueError("started_at must contain an explicit timezone offset")
        started = started.astimezone(zone)
        report["collection_started_at"] = started.isoformat()
        if started >= end:
            report["coverage_status"] = "before_collection"
            report["warnings"].append("报告日期早于访问记录启用时间，不能补查历史；本报告不是完整历史记录。")
        elif started > start:
            report["coverage_status"] = "partial_first_day"
            report["warnings"].append("首次启用当天仅包含启用后的部分记录，启用之前没有保存的历史无法补查。")
            report["warnings"].append("启用当天可能包含管理员到 api.ipify.org 的部署连通性验证；这些测试连接不能归因为员工操作。")
        else:
            report["coverage_status"] = "collection_started_before_period"
    else:
        report["warnings"].append("没有可验证的采集启用时间，无法确认当天日志覆盖完整。")
    if now < end:
        report["coverage_status"] = "period_not_complete"
        report["warnings"].append("报告日期尚未结束，当前只能生成不完整汇总。")
    if report["data_status"] == "no_matching_records":
        report["warnings"].append("未找到当日可识别的 accepted 连接记录；不等于无人访问，也可能是日志未启用、缺失、轮转过期或记录无法解析。")
    report["warnings"].append("汇总仅基于当前可读取日志；采集期间中断、已删除或未经过本服务器的连接无法核实。")
    return report


def render(report):
    """Render UTF-8 text/plain content (not HTML and never mail headers)."""
    lines = [
        f"节点连接日报 — {report['report_date']}（北京时间）",
        "统计口径：Xray accepted 连接记录；连接次数不等于网页访问次数、访问时长或流量。",
        "accepted 仅表示代理接受连接，不证明目标访问成功；包括转发至 blocked 出站的连接。",
        "只能看到日志中的目标域名或 IP；不反查猜测域名，不包含 HTTPS 路径、搜索词或视频内容。",
        "后台程序也会建立连接；共用节点不能据此确定具体员工。",
        "节点归属按当前数据库和运行标签映射；期间改名、删除节点或复用端口可能影响历史归属。",
        f"数据状态：{report['data_status']}；覆盖状态：{report['coverage_status']}",
    ]
    if report.get("collection_started_at"):
        lines.append("采集启用时间：" + report["collection_started_at"])
    for warning in report.get("warnings", []):
        lines.append("注意：" + clean_label(warning, 1000))
    lines.extend(["", f"节点数量：{len(report['nodes'])}；当日记录连接总数：{report['diagnostics']['accepted_connections']}"])
    if not report["nodes"]:
        lines.append("未发现可报告的节点；请检查节点数据库和运行配置。")
    for entry in report["nodes"]:
        state = "未映射" if entry["unmapped"] else ("启用" if entry["enabled"] else "停用")
        lines.extend([
            "", "=" * 48,
            f"节点：{entry['remark']}（ID：{entry['id'] or '未知'}；端口：{entry['port'] or '未知'}；{state}）",
            f"协议：{entry['protocol']}",
        ])
        if entry["total_connections"] == 0:
            lines.append("当日未检出可归属的 accepted 连接记录；这不是零访问的证明。")
            continue
        lines.extend([
            f"记录连接次数：{entry['total_connections']}；唯一目标域名/IP 数：{entry['unique_destinations']}",
            f"首次记录：{entry['first_seen']}；最后记录：{entry['last_seen']}",
        ])
        if "hourly_connections" in entry:
            hours = "；".join(f"{hour:02d}时 {count}次" for hour, count in enumerate(entry["hourly_connections"]) if count)
            lines.append("每小时记录连接数（不是在线或工作时长）：" + (hours or "无记录"))
        lines.append("目标 TOP 20（按记录连接次数排序）：")
        for rank, dest in enumerate(entry["destinations"][:20], 1):
            lines.append(f"  {rank:>2}. {dest['destination']} [{dest['kind']}] — {dest['connections']} 次")
        if len(entry["destinations"]) > 20:
            lines.append(f"  另有 {len(entry['destinations']) - 20} 个目标未在邮件正文展开。")
    diag = report["diagnostics"]
    lines.extend([
        "", "日志读取诊断（全部扫描文件，畸形行不一定属于报告日期）：",
        f"读取文件 {len(report.get('log_sources', []))} 个；扫描 {diag['scanned_lines']} 行；日期范围外 {diag['outside_period_lines']} 行；非 accepted/空行 {diag['ignored_nonaccepted_lines']} 行。",
        f"畸形行 {diag['malformed_lines']}（其中超长行 {diag['oversized_lines']}）；未映射节点的当日连接 {diag['unmapped_connections']} 次；已忽略内部 API 连接 {diag.get('ignored_internal_connections', 0)} 次。",
        "本报告不含来源 IP、原始日志 email 字段、完整 URL 路径或查询参数。",
    ])
    return "\n".join(lines) + "\n"


def find_logs(log_dir):
    directory = Path(log_dir)
    if not directory.is_dir():
        raise ValueError("log directory is missing")
    paths = sorted(path for path in directory.iterdir() if path.is_file() and LOG_NAME_RE.fullmatch(path.name))
    if not paths:
        raise ValueError("no access.log or supported rotated access logs found")
    return paths


def iter_log_lines(paths, failures):
    """Bound each physical line, drain oversized lines, and stream .gz files."""
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as source:
                while True:
                    chunk = source.readline(MAX_LINE_LENGTH + 1)
                    if not chunk:
                        break
                    oversized = len(chunk) > MAX_LINE_LENGTH
                    if oversized and not chunk.endswith("\n"):
                        while True:
                            tail = source.readline(MAX_LINE_LENGTH + 1)
                            if not tail or tail.endswith("\n"):
                                break
                    yield chunk
        except (OSError, EOFError, UnicodeError, zlib.error) as exc:
            # Do not include exception strings that might contain log content.
            failures.append({"file": clean_label(path.name), "error": type(exc).__name__})


def write_report(report, output_dir):
    directory = Path(output_dir)
    if directory.resolve() == Path('/var/lib/xray-audit/reports').resolve():
        from retention import cutoff_date
        today = datetime.now(timezone_for(REPORT_TIMEZONE)).date()
        if not cutoff_date(today) <= date.fromisoformat(report['report_date']) <= today:
            raise ValueError('Report date is outside managed retention window')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    base = date.fromisoformat(report["report_date"]).isoformat()
    payloads = {
        ".json": json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        ".txt": render(report),
    }
    for suffix, payload in payloads.items():
        descriptor, temporary = tempfile.mkstemp(prefix=".report-", dir=directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                if hasattr(os, "fchmod"):
                    os.fchmod(handle.fileno(), 0o600)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            target = directory / (base + suffix)
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", help="Report date YYYY-MM-DD in Asia/Shanghai; defaults to yesterday")
    parser.add_argument("--log-dir", default="/var/log/xray-audit")
    parser.add_argument("--xui-db", default="/etc/x-ui/x-ui.db")
    parser.add_argument("--runtime-config", default="/usr/local/x-ui/bin/config.json")
    parser.add_argument("--output-dir", default="/var/lib/xray-audit/reports")
    parser.add_argument("--log-timezone", default=REPORT_TIMEZONE)
    coverage = parser.add_mutually_exclusive_group()
    coverage.add_argument("--started-at", help="ISO 8601 timestamp with timezone offset")
    coverage.add_argument("--metadata", help="JSON file containing started_at; a supplied missing file is an error")
    args = parser.parse_args(argv)
    try:
        day = date.fromisoformat(args.date) if args.date else datetime.now(timezone_for(REPORT_TIMEZONE)).date() - timedelta(days=1)
        nodes, warnings, ignored_tags = load_nodes(args.xui_db, args.runtime_config, include_ignored_tags=True)
        paths = find_logs(args.log_dir)
        started_at = args.started_at
        if args.metadata:
            with Path(args.metadata).open("r", encoding="utf-8") as handle:
                metadata = json.load(handle)
            if not isinstance(metadata, dict) or not isinstance(metadata.get("started_at"), str):
                raise ValueError("metadata requires a started_at ISO timestamp")
            started_at = metadata["started_at"]
        failures = []
        report = aggregate(iter_log_lines(paths, failures), nodes, day, args.log_timezone, ignored_tags)
        report["log_sources"] = [clean_label(path.name) for path in paths]
        report["warnings"].extend(warnings)
        report["read_failures"] = failures
        if failures:
            report["data_status"] = "partial_read_failure"
            report["warnings"].append("部分日志无法完整读取，统计不完整：" + ", ".join(item["file"] for item in failures))
        if not any(path.name == "access.log" for path in paths):
            report["warnings"].append("活动 access.log 不存在；仅读取现存轮转文件，日志连续性无法确认。")
        add_coverage(report, started_at)
        if report["diagnostics"]["malformed_lines"]:
            report["warnings"].append("存在未计入统计的畸形或超长日志行，请查看日志读取诊断。")
        write_report(report, args.output_dir)
        print(f"Report written: {day.isoformat()} (status={report['data_status']})")
        return 1 if failures else 0
    except (OSError, ValueError, sqlite3.Error, KeyError, TypeError) as exc:
        # Input paths and raw log lines may contain sensitive data; print only class.
        print("Report failed: required input is missing, invalid, or unreadable (" + type(exc).__name__ + ").", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
