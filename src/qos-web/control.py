#!/usr/bin/env python3
"""Privileged local controller for the dynamic 3x-ui QoS dashboard."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import pwd
import re
import shlex
import signal
import socket
import sqlite3
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any


SOCKET_PATH = Path(os.environ.get("QOS_CONTROL_SOCKET", "/run/xray-qos-web/control.sock"))
WEB_USER = os.environ.get("QOS_WEB_USER", "xray-qos-web")
CONFIG_PATH = Path(os.environ.get("QOS_CONFIG", "/etc/default/xray-qos"))
STATE_PATH = Path(os.environ.get("QOS_STATE", "/run/xray-qos/state.json"))
QOS_COMMAND = os.environ.get("QOS_COMMAND", "/usr/local/sbin/xray-qos")
TC_COMMAND = "/usr/sbin/tc"
SS_COMMAND = "/usr/bin/ss"
MAX_MESSAGE = 4096
SAMPLE_INTERVAL = 1.0
SET_COOLDOWN = 0.75
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
RATE_RE = re.compile(r"^(\d+(?:\.\d+)?)(kbit|mbit|gbit)$")
PORT_RE = re.compile(r":(\d+)\s")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOG = logging.getLogger("xray-qos-control")


class ControllerError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def rate_to_mbps(value: str) -> float:
    match = RATE_RE.fullmatch(value)
    if not match:
        raise ControllerError("unhealthy", "限速配置格式错误")
    number = float(match.group(1))
    return number * {"kbit": 0.001, "mbit": 1.0, "gbit": 1000.0}[match.group(2)]


def display_number(value: float) -> int | float:
    return int(value) if value.is_integer() else round(value, 3)


def read_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ControllerError("unhealthy", "无法读取限速配置") from exc
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        try:
            parts = shlex.split(raw_value.strip(), comments=False, posix=True)
        except ValueError as exc:
            raise ControllerError("unhealthy", "限速配置格式错误") from exc
        if len(parts) != 1:
            raise ControllerError("unhealthy", "限速配置格式错误")
        values[key.strip()] = parts[0]
    return values


def read_config() -> dict[str, Any]:
    values = read_key_values(CONFIG_PATH)
    required = {"WAN", "DEFAULT_RATE", "LINK_EGRESS"}
    if required - values.keys():
        raise ControllerError("unhealthy", "限速配置不完整")
    wan = values["WAN"]
    if not IFACE_RE.fullmatch(wan):
        raise ControllerError("unhealthy", "网络接口配置异常")
    link = rate_to_mbps(values["LINK_EGRESS"])
    reserved = rate_to_mbps(values["DEFAULT_RATE"])
    if reserved >= link:
        raise ControllerError("unhealthy", "管理预留必须小于线路带宽")
    management_ports: set[int] = set()
    for token in values.get("MGMT_PORTS", "").split():
        if not token.isdigit() or not 1 <= int(token) <= 65535:
            raise ControllerError("unhealthy", "管理端口配置异常")
        management_ports.add(int(token))
    return {
        "wan": wan,
        "link_mbps": link,
        "reserved_mbps": reserved,
        "management_ports": management_ports,
        "xui_db": Path(values.get("XRAY_DB", "/etc/x-ui/x-ui.db")),
        "profiles": Path(values.get("QOS_PROFILES", "/etc/xray-qos/nodes.json")),
    }


def read_profiles(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": 1, "revision": 0, "nodes": {}}
    except (OSError, json.JSONDecodeError) as exc:
        raise ControllerError("unhealthy", "节点限速策略不可用") from exc
    if not isinstance(document, dict) or set(document) != {"version", "revision", "nodes"}:
        raise ControllerError("unhealthy", "节点限速策略格式错误")
    revision = document.get("revision")
    nodes = document.get("nodes")
    if document.get("version") != 1 or type(revision) is not int or revision < 0 or not isinstance(nodes, dict):
        raise ControllerError("unhealthy", "节点限速策略格式错误")
    normalized: dict[str, dict[str, int]] = {}
    for raw_id, profile in nodes.items():
        if not isinstance(raw_id, str) or not raw_id.isdigit() or not isinstance(profile, dict):
            raise ControllerError("unhealthy", "节点限速策略格式错误")
        if set(profile) != {"download_mbps", "upload_mbps"}:
            raise ControllerError("unhealthy", "节点限速策略格式错误")
        down = profile["download_mbps"]
        up = profile["upload_mbps"]
        if type(down) is not int or type(up) is not int or down < 1 or up < 1:
            raise ControllerError("unhealthy", "节点限速策略格式错误")
        normalized[str(int(raw_id))] = {"download_mbps": down, "upload_mbps": up}
    return {"version": 1, "revision": revision, "nodes": normalized}


def read_inbounds(database: Path) -> list[dict[str, Any]]:
    if not database.is_absolute():
        raise ControllerError("unhealthy", "3x-ui 数据库路径无效")
    try:
        connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=2.0)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=1500")
        columns = {row[1] for row in connection.execute("PRAGMA table_info(inbounds)")}
        required = {"id", "remark", "enable", "listen", "port", "protocol", "node_id", "up", "down"}
        if not required.issubset(columns):
            raise ControllerError("unhealthy", "3x-ui 数据结构暂不兼容")
        sort_expression = "COALESCE(sub_sort_index, 0)" if "sub_sort_index" in columns else "0"
        rows = connection.execute(
            f"SELECT id, remark, enable, listen, port, protocol, {sort_expression}, up, down "
            "FROM inbounds WHERE node_id IS NULL ORDER BY 7, id"
        ).fetchall()
    except sqlite3.Error as exc:
        raise ControllerError("unhealthy", "暂时无法读取 3x-ui 节点") from exc
    finally:
        if "connection" in locals():
            connection.close()
    result: list[dict[str, Any]] = []
    for raw_id, raw_remark, raw_enable, raw_listen, raw_port, raw_protocol, raw_sort, raw_up, raw_down in rows:
        if type(raw_id) is not int or raw_id <= 0:
            continue
        try:
            port = int(raw_port)
            sort_index = int(raw_sort or 0)
            total_up = max(0, int(raw_up or 0))
            total_down = max(0, int(raw_down or 0))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        remark = str(raw_remark or "").strip()[:128] or f"节点 {raw_id}"
        protocol = str(raw_protocol or "unknown").strip()[:32] or "unknown"
        listen = str(raw_listen or "").strip()[:128]
        result.append(
            {
                "inbound_id": raw_id,
                "id": f"xui:{raw_id}",
                "name": remark,
                "enabled": bool(raw_enable),
                "listen": listen,
                "port": port,
                "protocol": protocol,
                "sort_index": sort_index,
                "db_up": total_up,
                "db_down": total_down,
            }
        )
    return result


def listen_supported(value: str) -> bool:
    if value in {"", "*", "0.0.0.0", "::", "[::]"}:
        return True
    if value.lower() == "localhost":
        return False
    candidate = value.strip("[]")
    try:
        return not ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def annotate_support(inbounds: list[dict[str, Any]], management_ports: set[int]) -> None:
    active_counts: dict[int, int] = {}
    for inbound in inbounds:
        if inbound["enabled"]:
            active_counts[inbound["port"]] = active_counts.get(inbound["port"], 0) + 1
    for inbound in inbounds:
        supported = True
        reason = ""
        if inbound["port"] in management_ports:
            supported = False
            reason = "端口属于管理服务，禁止限速"
        elif inbound["enabled"] and active_counts.get(inbound["port"], 0) > 1:
            supported = False
            reason = "多个启用节点共用此端口，无法单独限速"
        elif not listen_supported(inbound["listen"]):
            supported = False
            reason = "此节点只监听本机地址，当前模式不支持限速"
        inbound["qos_supported"] = supported
        inbound["qos_reason"] = reason


def run_json(command: list[str], timeout: float = 5.0) -> Any:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=True,
            shell=False,
            cwd="/",
            env=COMMAND_ENV,
        )
        return json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise ControllerError("unhealthy", "无法读取线路状态") from exc


def device_stats(device: str, handles: set[str]) -> dict[str, dict[str, int]]:
    if not handles:
        return {}
    data = run_json([TC_COMMAND, "-j", "-s", "class", "show", "dev", device])
    if not isinstance(data, list):
        raise ControllerError("unhealthy", "线路状态格式异常")
    found: dict[str, dict[str, int]] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        item_handle = str(item.get("classid") or item.get("handle") or "")
        if item_handle not in handles:
            continue
        stats = item.get("stats", {})
        found[item_handle] = {
            "bytes": max(0, int(stats.get("bytes", 0))),
            "packets": max(0, int(stats.get("packets", 0))),
            "drops": max(0, int(stats.get("drops", 0))),
        }
    return found


def run_qos(arguments: list[str], timeout: float) -> tuple[int, str, str, bool]:
    try:
        process = subprocess.Popen(
            [QOS_COMMAND, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            cwd="/",
            env=COMMAND_ENV,
            start_new_session=True,
        )
    except OSError as exc:
        return 127, "", str(exc), False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr, False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            # xray-qos catches TERM and restores its last-known-good tc plan.
            # Give that bounded rollback enough time to finish before SIGKILL.
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
        return process.returncode, stdout, stderr, True


def listening_ports() -> set[int]:
    try:
        completed = subprocess.run(
            [SS_COMMAND, "-H", "-lntu"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            check=True,
            shell=False,
            cwd="/",
            env=COMMAND_ENV,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    ports: set[int] = set()
    for line in completed.stdout.splitlines():
        match = PORT_RE.search(line)
        if match:
            ports.add(int(match.group(1)))
    return ports


def read_runtime_state() -> dict[str, Any] | None:
    try:
        document = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict) or document.get("version") != 2 or not isinstance(document.get("nodes"), list):
        return None
    return document


def runtime_resources_present(runtime: dict[str, Any]) -> bool:
    wan = str(runtime.get("wan", ""))
    if not IFACE_RE.fullmatch(wan):
        return False
    try:
        completed = subprocess.run(
            [TC_COMMAND, "qdisc", "show", "dev", wan],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            check=False,
            shell=False,
            cwd="/",
            env=COMMAND_ENV,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    nodes = runtime.get("nodes", [])
    has_root = re.search(r"^qdisc htb 1: root", completed.stdout, re.MULTILINE) is not None
    if bool(nodes) != has_root:
        return False
    return all(
        isinstance(node, dict)
        and IFACE_RE.fullmatch(str(node.get("ifb", ""))) is not None
        and Path("/sys/class/net", str(node["ifb"])).exists()
        for node in nodes
    )


def topology_needs_sync(
    config: dict[str, Any],
    profiles: dict[str, Any],
    inbounds: list[dict[str, Any]],
    runtime: dict[str, Any] | None,
) -> bool:
    if runtime is None:
        return bool(profiles["nodes"])
    if not runtime_resources_present(runtime):
        return True
    if runtime.get("wan") != config["wan"]:
        return True
    if abs(float(runtime.get("link_kbit", -1)) / 1000 - config["link_mbps"]) > 1e-9:
        return True
    if abs(float(runtime.get("reserved_kbit", -1)) / 1000 - config["reserved_mbps"]) > 1e-9:
        return True
    expected: list[tuple[int, int, int, int]] = []
    for inbound in inbounds:
        profile = profiles["nodes"].get(str(inbound["inbound_id"]))
        if profile and inbound["enabled"] and inbound["qos_supported"]:
            expected.append(
                (
                    inbound["inbound_id"],
                    inbound["port"],
                    profile["download_mbps"] * 1000,
                    profile["upload_mbps"] * 1000,
                )
            )
    actual = [
        (int(node.get("id", -1)), int(node.get("port", -1)), int(node.get("down_kbit", -1)), int(node.get("up_kbit", -1)))
        for node in runtime.get("nodes", [])
        if isinstance(node, dict)
    ]
    return expected != actual


class QosState:
    def __init__(self) -> None:
        self.operation_lock = threading.Lock()
        self.cache_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.previous: dict[int, dict[str, Any]] = {}
        self.cache: dict[str, Any] = {"ok": False, "code": "starting", "message": "正在读取线路状态"}
        self.last_set = 0.0
        self.last_integrity_check = 0.0
        self.next_sync_retry = 0.0

    def sample_locked(self, *, allow_sync: bool = True) -> dict[str, Any]:
        now_mono = time.monotonic()
        now_wall = time.time()
        config = read_config()
        profiles = read_profiles(config["profiles"])
        inbounds = read_inbounds(config["xui_db"])
        annotate_support(inbounds, config["management_ports"])
        runtime = read_runtime_state()
        topology_error = ""
        topology_changed = topology_needs_sync(config, profiles, inbounds, runtime)
        periodic_check_due = now_mono - self.last_integrity_check >= 30.0
        if allow_sync and now_mono >= self.next_sync_retry and (topology_changed or periodic_check_due):
            returncode, stdout, stderr, timed_out = run_qos(["sync"], timeout=90)
            if timed_out or returncode != 0:
                detail = "timeout" if timed_out else (stderr or stdout)[-600:]
                LOG.error("QOS_AUTO_SYNC_FAIL detail=%r", detail)
                topology_error = "限速规则自动同步失败"
                self.next_sync_retry = now_mono + 5.0
            else:
                self.last_integrity_check = now_mono
                self.next_sync_retry = 0.0
            runtime = read_runtime_state()

        runtime_nodes = {
            int(node["id"]): node
            for node in (runtime or {}).get("nodes", [])
            if isinstance(node, dict) and type(node.get("id")) is int
        }
        wan_handles = {f"1:{node['slot']}" for node in runtime_nodes.values() if type(node.get("slot")) is int}
        wan_stats: dict[str, dict[str, int]] = {}
        if wan_handles:
            try:
                wan_stats = device_stats(config["wan"], wan_handles)
            except ControllerError:
                topology_error = topology_error or "限速统计暂不可用"

        active_ports = listening_ports()
        nodes: list[dict[str, Any]] = []
        new_previous: dict[int, dict[str, Any]] = {}
        for inbound in inbounds:
            inbound_id = inbound["inbound_id"]
            profile = profiles["nodes"].get(str(inbound_id))
            runtime_node = runtime_nodes.get(inbound_id)
            if runtime_node is not None and (
                int(runtime_node.get("port", -1)) != inbound["port"]
                or profile is None
                or int(runtime_node.get("down_kbit", -1)) != profile["download_mbps"] * 1000
                or int(runtime_node.get("up_kbit", -1)) != profile["upload_mbps"] * 1000
            ):
                runtime_node = None
            source = "3x-ui"
            rate_down_counter = inbound["db_down"]
            rate_up_counter = inbound["db_up"]
            down_packets = up_packets = down_drops = up_drops = 0
            if runtime_node is not None:
                handle = f"1:{runtime_node['slot']}"
                download_stats = wan_stats.get(handle)
                try:
                    upload_stats = device_stats(runtime_node["ifb"], {"2:1"}).get("2:1")
                except ControllerError:
                    upload_stats = None
                    topology_error = topology_error or "限速统计暂不可用"
                if download_stats is not None and upload_stats is not None:
                    source = "linux-qos"
                    rate_down_counter = download_stats["bytes"]
                    rate_up_counter = upload_stats["bytes"]
                    down_packets = download_stats["packets"]
                    up_packets = upload_stats["packets"]
                    down_drops = download_stats["drops"]
                    up_drops = upload_stats["drops"]
                else:
                    topology_error = topology_error or "限速统计暂不可用"

            rates = {"download_mbps": 0.0, "upload_mbps": 0.0}
            previous = self.previous.get(inbound_id)
            if previous and previous["source"] == source:
                elapsed = now_mono - previous["monotonic"]
                if elapsed > 0:
                    rates["download_mbps"] = round(max(0, rate_down_counter - previous["down"]) * 8 / elapsed / 1_000_000, 3)
                    rates["upload_mbps"] = round(max(0, rate_up_counter - previous["up"]) * 8 / elapsed / 1_000_000, 3)
            new_previous[inbound_id] = {
                "source": source,
                "monotonic": now_mono,
                "down": rate_down_counter,
                "up": rate_up_counter,
            }

            enabled = inbound["enabled"]
            online = enabled and inbound["port"] in active_ports
            if not enabled:
                mode = "disabled"
            elif not inbound["qos_supported"]:
                mode = "unsupported"
            elif profile is None:
                mode = "unlimited"
            elif runtime_node is None:
                mode = "pending"
            else:
                mode = "limited"
            default_down = min(100, int(config["link_mbps"]))
            default_up = min(30, int(config["link_mbps"]))
            nodes.append(
                {
                    "id": inbound["id"],
                    "inbound_id": inbound_id,
                    "name": inbound["name"],
                    "protocol": inbound["protocol"],
                    "port": inbound["port"],
                    "inbound_enabled": enabled,
                    "online": online,
                    "qos_supported": inbound["qos_supported"],
                    "qos_reason": inbound["qos_reason"],
                    "qos_mode": mode,
                    "limit_enabled": profile is not None,
                    "limit_download_mbps": profile["download_mbps"] if profile else None,
                    "limit_upload_mbps": profile["upload_mbps"] if profile else None,
                    "suggested_download_mbps": default_down,
                    "suggested_upload_mbps": default_up,
                    "download_mbps": rates["download_mbps"] if enabled else 0.0,
                    "upload_mbps": rates["upload_mbps"] if enabled else 0.0,
                    "total_download_bytes": inbound["db_down"],
                    "total_upload_bytes": inbound["db_up"],
                    "download_packets": down_packets,
                    "upload_packets": up_packets,
                    "download_drops": down_drops,
                    "upload_drops": up_drops,
                    "stats_source": source,
                }
            )
        self.previous = new_previous
        inventory_source = [
            [item["inbound_id"], item["name"], item["protocol"], item["port"], item["inbound_enabled"]]
            for item in nodes
        ]
        inventory_revision = hashlib.sha256(
            json.dumps(inventory_source, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:16]
        aggregate_down = round(sum(float(item["download_mbps"]) for item in nodes), 3)
        aggregate_up = round(sum(float(item["upload_mbps"]) for item in nodes), 3)
        enabled_nodes = [item for item in nodes if item["inbound_enabled"]]
        result = {
            "ok": True,
            "sample_time_ms": int(now_wall * 1000),
            "config_revision": profiles["revision"],
            "inventory_revision": inventory_revision,
            "discovery_stale": False,
            "service_healthy": not topology_error and all(item["online"] for item in enabled_nodes),
            "message": topology_error,
            "constraints": {
                "link_egress_mbps": display_number(config["link_mbps"]),
                "reserved_mbps": display_number(config["reserved_mbps"]),
                "individual_max_mbps": display_number(config["link_mbps"]),
                "aggregate_download_mbps": aggregate_down,
                "aggregate_upload_mbps": aggregate_up,
            },
            "nodes": nodes,
        }
        return result

    def update_sample(self) -> None:
        if not self.operation_lock.acquire(blocking=False):
            return
        try:
            try:
                result = self.sample_locked()
            except ControllerError as exc:
                with self.cache_lock:
                    previous_cache = json.loads(json.dumps(self.cache))
                if previous_cache.get("ok") and isinstance(previous_cache.get("nodes"), list):
                    previous_cache.update(
                        {
                            "sample_time_ms": int(time.time() * 1000),
                            "service_healthy": False,
                            "discovery_stale": True,
                            "message": exc.message,
                        }
                    )
                    result = previous_cache
                else:
                    result = {"ok": False, "code": exc.code, "message": exc.message}
            except Exception:
                LOG.exception("unexpected sampler failure")
                result = {"ok": False, "code": "unhealthy", "message": "线路状态暂不可用"}
        finally:
            self.operation_lock.release()
        with self.cache_lock:
            self.cache = result

    def sampler_loop(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            self.update_sample()
            self.stop_event.wait(max(0.05, SAMPLE_INTERVAL - (time.monotonic() - started)))

    def status(self) -> dict[str, Any]:
        with self.cache_lock:
            return json.loads(json.dumps(self.cache))

    def set_limit(self, request: dict[str, Any]) -> dict[str, Any]:
        expected = {
            "v",
            "op",
            "node_id",
            "limit_enabled",
            "down_mbps",
            "up_mbps",
            "expected_revision",
            "actor_ip",
        }
        if set(request) != expected:
            raise ControllerError("invalid", "请求字段不正确")
        node_id = request.get("node_id")
        limit_enabled = request.get("limit_enabled")
        down = request.get("down_mbps")
        up = request.get("up_mbps")
        revision = request.get("expected_revision")
        actor_ip = request.get("actor_ip")
        if type(node_id) is not int or node_id <= 0 or type(limit_enabled) is not bool:
            raise ControllerError("invalid", "节点格式不正确")
        if type(down) is not int or type(up) is not int or type(revision) is not int or revision < 0:
            raise ControllerError("invalid", "速度或版本格式不正确")
        if not isinstance(actor_ip, str) or len(actor_ip) > 64:
            actor_ip = "unknown"
        else:
            try:
                actor_ip = str(ipaddress.ip_address(actor_ip))
            except ValueError:
                actor_ip = "unknown"

        if not self.operation_lock.acquire(blocking=False):
            raise ControllerError("busy", "控制器正忙，请稍后再试")
        try:
            now = time.monotonic()
            if now - self.last_set < SET_COOLDOWN:
                raise ControllerError("busy", "操作太频繁，请稍后再试")
            config = read_config()
            maximum = int(config["link_mbps"])
            if limit_enabled and (not 1 <= down <= maximum or not 1 <= up <= maximum):
                raise ControllerError("invalid", f"速度必须是 1 到 {maximum} Mbps 的整数")
            profiles = read_profiles(config["profiles"])
            if profiles["revision"] != revision:
                raise ControllerError("conflict", "配置已被其他页面更新，请刷新后重试")
            inbounds = read_inbounds(config["xui_db"])
            annotate_support(inbounds, config["management_ports"])
            inbound = next((item for item in inbounds if item["inbound_id"] == node_id), None)
            if inbound is None:
                raise ControllerError("not_found", "节点已从 3x-ui 删除")
            if limit_enabled and not inbound["qos_supported"]:
                raise ControllerError("invalid", inbound["qos_reason"] or "此节点无法单独限速")
            self.last_set = now
            mode = "on" if limit_enabled else "off"
            returncode, stdout, stderr, timed_out = run_qos(
                ["set", str(node_id), mode, str(down), str(up), str(revision)], timeout=90
            )
            if timed_out or returncode != 0:
                detail = "timeout" if timed_out else (stderr or stdout)[-600:]
                LOG.error("QOS_SET_FAIL actor_ip=%s node_id=%d detail=%r", actor_ip, node_id, detail)
                raise ControllerError("failed", "限速应用失败，原设置已保留")
            self.previous = {}
            status = self.sample_locked(allow_sync=False)
            with self.cache_lock:
                self.cache = status
            LOG.info(
                "QOS_SET_OK actor_ip=%s node_id=%d enabled=%s down=%d up=%d revision=%d",
                actor_ip,
                node_id,
                limit_enabled,
                down,
                up,
                status["config_revision"],
            )
            action = "已启用" if limit_enabled else "已取消"
            return {"ok": True, "message": f"节点 {node_id} {action}限速", "status": status}
        finally:
            self.operation_lock.release()


STATE = QosState()


def read_request(conn: socket.socket) -> dict[str, Any]:
    conn.settimeout(4)
    chunks = bytearray()
    while len(chunks) <= MAX_MESSAGE:
        part = conn.recv(min(1024, MAX_MESSAGE + 1 - len(chunks)))
        if not part:
            break
        chunks.extend(part)
        if b"\n" in part:
            break
    if len(chunks) > MAX_MESSAGE:
        raise ControllerError("invalid", "请求过大")
    raw = bytes(chunks).split(b"\n", 1)[0]
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerError("invalid", "请求格式错误") from exc
    if not isinstance(request, dict):
        raise ControllerError("invalid", "请求格式错误")
    return request


def response_for(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("v") != 1 or not isinstance(request.get("op"), str):
        raise ControllerError("invalid", "协议版本不正确")
    if request["op"] == "status":
        if set(request) != {"v", "op"}:
            raise ControllerError("invalid", "请求字段不正确")
        return STATE.status()
    if request["op"] == "set":
        return STATE.set_limit(request)
    raise ControllerError("invalid", "不支持的操作")


def send_response(conn: socket.socket, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    conn.sendall(encoded)


def handle_connection(conn: socket.socket, web_uid: int) -> None:
    with conn:
        payload: dict[str, Any]
        try:
            credentials = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, peer_uid, _peer_gid = struct.unpack("3i", credentials)
            if peer_uid != web_uid:
                LOG.warning("CONTROL_PEER_REJECT uid=%d", peer_uid)
                payload = {"ok": False, "code": "forbidden", "message": "拒绝访问"}
            else:
                payload = response_for(read_request(conn))
        except ControllerError as exc:
            payload = {"ok": False, "code": exc.code, "message": exc.message}
        except (ConnectionError, socket.timeout):
            return
        except Exception:
            LOG.exception("unexpected control request failure")
            payload = {"ok": False, "code": "failed", "message": "控制器内部错误"}
        try:
            send_response(conn, payload)
        except (BrokenPipeError, ConnectionError, OSError, socket.timeout):
            return


def serve() -> None:
    web_entry = pwd.getpwnam(WEB_USER)
    web_uid = web_entry.pw_uid
    web_gid = web_entry.pw_gid
    SOCKET_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(SOCKET_PATH.parent, 0, web_gid)
    os.chmod(SOCKET_PATH.parent, 0o750)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_socket():
        SOCKET_PATH.unlink()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCKET_PATH))
    os.chown(SOCKET_PATH, 0, web_gid)
    os.chmod(SOCKET_PATH, 0o660)
    server.listen(16)
    server.settimeout(1)

    sampler = threading.Thread(target=STATE.sampler_loop, name="qos-sampler", daemon=True)
    sampler.start()

    def stop(_signum: int, _frame: Any) -> None:
        STATE.stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    LOG.info("controller ready socket=%s peer_uid=%d", SOCKET_PATH, web_uid)

    slots = threading.BoundedSemaphore(16)
    pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="qos-control")
    try:
        while not STATE.stop_event.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            if not slots.acquire(blocking=False):
                conn.close()
                continue
            future = pool.submit(handle_connection, conn, web_uid)

            def release_slot(_future: Any) -> None:
                try:
                    slots.release()
                except ValueError:
                    pass

            future.add_done_callback(release_slot)
    finally:
        STATE.stop_event.set()
        server.close()
        pool.shutdown(wait=True, cancel_futures=True)
        try:
            SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass
        sampler.join(timeout=2)


if __name__ == "__main__":
    serve()
