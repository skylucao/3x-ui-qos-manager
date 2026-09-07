#!/usr/bin/env python3
"""Unprivileged web application for the xray-qos dashboard."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
from collections import deque
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import audit_view
import node_notes


BIND = os.environ.get("QOS_WEB_BIND", "127.0.0.1")
PORT = int(os.environ.get("QOS_WEB_PORT", "21834"))
BASE_PATH = os.environ.get("QOS_WEB_BASE_PATH", "/")
BASE_PREFIX = BASE_PATH.rstrip("/")
EXPECTED_ORIGIN = os.environ["QOS_WEB_ORIGIN"]
PROXY_SECRET = os.environ["QOS_PROXY_SECRET"]
EMBED_ORIGIN = os.environ.get("QOS_EMBED_ORIGIN", "")
EMBED_TOKEN = os.environ.get("QOS_EMBED_TOKEN", "")
USERNAME = os.environ["QOS_WEB_USERNAME"]
PASSWORD_HASH = os.environ["QOS_WEB_PASSWORD_HASH"]
CONTROL_SOCKET = os.environ.get("QOS_CONTROL_SOCKET", "/run/xray-qos-web/control.sock")
STATIC_DIR = Path(os.environ.get("QOS_WEB_STATIC", "/opt/xray-qos-web/static"))
PANEL_URL = os.environ.get("QOS_PANEL_URL", "")

if not BASE_PATH.startswith("/") or not BASE_PATH.endswith("/") or ".." in BASE_PATH:
    raise SystemExit("QOS_WEB_BASE_PATH must start and end with / and may not contain ..")

COOKIE_NAME = "xrayqos_session"
COOKIE_PATH = BASE_PATH
MAX_BODY = 4096
MAX_CONTROL_RESPONSE = 512 * 1024
SESSION_IDLE = 30 * 60
SESSION_ABSOLUTE = 8 * 60 * 60
MAX_SESSIONS = 128
LOGIN_WINDOW = 10 * 60
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_TIME = 15 * 60
MAX_LOGIN_IPS = 4096
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{40,128}$")
if bool(EMBED_ORIGIN) != bool(EMBED_TOKEN):
    raise SystemExit("QOS_EMBED_ORIGIN and QOS_EMBED_TOKEN must be configured together")
if EMBED_TOKEN and not TOKEN_RE.fullmatch(EMBED_TOKEN):
    raise SystemExit("QOS_EMBED_TOKEN has an invalid format")
EMBED_CSRF = hashlib.sha256(f"xray-qos-embed:{EMBED_TOKEN}".encode("utf-8")).hexdigest()
STATIC_TYPES = {
    "app.css": "text/css; charset=utf-8",
    "login.js": "application/javascript; charset=utf-8",
    "dashboard.js": "application/javascript; charset=utf-8",
    "audit.js": "application/javascript; charset=utf-8",
    "audit.css": "text/css; charset=utf-8",
    "notes.js": "application/javascript; charset=utf-8",
    "notes.css": "text/css; charset=utf-8",
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOG = logging.getLogger("xray-qos-web")

SESSIONS: dict[str, dict[str, Any]] = {}
SESSIONS_LOCK = threading.Lock()
LOGIN_STATE: dict[str, dict[str, Any]] = {}
LOGIN_LOCK = threading.Lock()
PBKDF_SEMAPHORE = threading.BoundedSemaphore(2)


def b64decode_nopad(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_password(candidate: str) -> bool:
    try:
        algorithm, iterations, salt_text, digest_text = PASSWORD_HASH.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        expected = b64decode_nopad(digest_text)
        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            candidate.encode("utf-8"),
            b64decode_nopad(salt_text),
            int(iterations),
        )
        return hmac.compare_digest(calculated, expected)
    except (ValueError, TypeError):
        return False


def session_digest(token: str) -> str | None:
    if not TOKEN_RE.fullmatch(token):
        return None
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def path_for(suffix: str = "") -> str:
    return f"{BASE_PREFIX}/{suffix}" if suffix else f"{BASE_PREFIX}/"


def create_session() -> tuple[str, dict[str, Any]]:
    raw = secrets.token_urlsafe(32)
    now = time.monotonic()
    session = {
        "created": now,
        "last": now,
        "csrf": secrets.token_urlsafe(32),
    }
    with SESSIONS_LOCK:
        expired = [
            key
            for key, value in SESSIONS.items()
            if now - value["last"] > SESSION_IDLE or now - value["created"] > SESSION_ABSOLUTE
        ]
        for key in expired:
            SESSIONS.pop(key, None)
        while len(SESSIONS) >= MAX_SESSIONS:
            oldest = min(SESSIONS, key=lambda key: SESSIONS[key]["created"])
            SESSIONS.pop(oldest, None)
        digest = session_digest(raw)
        if digest is None:
            raise RuntimeError("generated an invalid session token")
        SESSIONS[digest] = session
    return raw, session


def get_session(raw_token: str | None, touch: bool = True) -> tuple[str, dict[str, Any]] | None:
    if not raw_token:
        return None
    digest = session_digest(raw_token)
    if digest is None:
        return None
    now = time.monotonic()
    with SESSIONS_LOCK:
        session = SESSIONS.get(digest)
        if session is None:
            return None
        if now - session["last"] > SESSION_IDLE or now - session["created"] > SESSION_ABSOLUTE:
            SESSIONS.pop(digest, None)
            return None
        if touch:
            session["last"] = now
        return digest, session.copy()


def remove_session(raw_token: str | None) -> None:
    if not raw_token:
        return
    digest = session_digest(raw_token)
    if digest is None:
        return
    with SESSIONS_LOCK:
        SESSIONS.pop(digest, None)


def reserve_login_attempt(ip: str, now: float) -> bool:
    with LOGIN_LOCK:
        stale = [
            key
            for key, value in LOGIN_STATE.items()
            if now - value["last_seen"] > LOGIN_WINDOW + LOGIN_LOCK_TIME
        ]
        for key in stale:
            LOGIN_STATE.pop(key, None)
        if ip not in LOGIN_STATE and len(LOGIN_STATE) >= MAX_LOGIN_IPS:
            oldest = min(LOGIN_STATE, key=lambda key: LOGIN_STATE[key]["last_seen"])
            LOGIN_STATE.pop(oldest, None)
        entry = LOGIN_STATE.setdefault(
            ip,
            {"failures": deque(), "locked_until": 0.0, "last_seen": now},
        )
        entry["last_seen"] = now
        failures: deque[float] = entry["failures"]
        while failures and now - failures[0] > LOGIN_WINDOW:
            failures.popleft()
        if entry["locked_until"] > now or len(failures) >= LOGIN_MAX_FAILURES:
            entry["locked_until"] = max(entry["locked_until"], now + LOGIN_LOCK_TIME)
            return False
        failures.append(now)
        return True


def finish_login_attempt(ip: str, success: bool, now: float) -> None:
    with LOGIN_LOCK:
        entry = LOGIN_STATE.get(ip)
        if success:
            LOGIN_STATE.pop(ip, None)
        elif entry is not None:
            entry["last_seen"] = now
            if len(entry["failures"]) >= LOGIN_MAX_FAILURES:
                entry["locked_until"] = now + LOGIN_LOCK_TIME


def control_request(payload: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_BODY:
        raise RuntimeError("control request too large")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(165)
    try:
        client.connect(CONTROL_SOCKET)
        client.sendall(encoded)
        client.shutdown(socket.SHUT_WR)
        chunks = bytearray()
        while len(chunks) <= MAX_CONTROL_RESPONSE:
            part = client.recv(8192)
            if not part:
                break
            chunks.extend(part)
            if b"\n" in part:
                break
        if len(chunks) > MAX_CONTROL_RESPONSE:
            raise RuntimeError("control response too large")
        response = json.loads(bytes(chunks).split(b"\n", 1)[0].decode("utf-8"))
        if not isinstance(response, dict):
            raise RuntimeError("invalid control response")
        return response
    finally:
        client.close()


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32
    allow_reuse_address = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.request_slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = ""
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(8)

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.info("HTTP ip=%s %s", self.client_ip(), fmt % args)

    def trusted_proxy(self) -> bool:
        try:
            peer_is_loopback = ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            return False
        provided = self.headers.get("X-Qos-Proxy-Secret", "").encode("utf-8")
        expected = PROXY_SECRET.encode("ascii")
        return peer_is_loopback and hmac.compare_digest(provided, expected)

    def client_ip(self) -> str:
        forwarded = self.headers.get("X-Real-IP", "") if self.trusted_proxy() else ""
        candidate = forwarded.strip() if forwarded else self.client_address[0]
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return self.client_address[0]

    def route(self) -> str:
        return urlsplit(self.path).path

    def raw_cookie(self) -> str | None:
        header = self.headers.get("Cookie")
        if not header or len(header) > 2048:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:
            return None
        morsel = cookie.get(COOKIE_NAME)
        return morsel.value if morsel else None

    def current_session(self, touch: bool = True) -> tuple[str, dict[str, Any]] | None:
        if self.embedded_request():
            return "xui-embedded", {"created": 0.0, "last": time.monotonic(), "csrf": EMBED_CSRF}
        return get_session(self.raw_cookie(), touch=touch)

    def embedded_request(self) -> bool:
        if not EMBED_TOKEN or not self.trusted_proxy():
            return False
        provided = self.headers.get("X-Qos-Embed-Token", "").encode("utf-8")
        return hmac.compare_digest(provided, EMBED_TOKEN.encode("ascii"))

    def security_headers(self) -> None:
        embedded = self.embedded_request()
        frame_ancestors = "'self'" if embedded else "'none'"
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN" if embedded else "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            f"connect-src 'self'; img-src 'self' data:; frame-ancestors {frame_ancestors}; "
            "base-uri 'none'; form-action 'self'",
        )

    def send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.close_connection = True
        self.send_response(status)
        self.security_headers()
        self.send_header("Connection", "close")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for name, value in extra_headers:
                self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(
        self,
        status: int,
        payload: dict[str, Any],
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_bytes(status, body, "application/json; charset=utf-8", extra_headers)

    def send_static(self, name: str) -> None:
        content_type = STATIC_TYPES.get(name)
        if not content_type:
            self.send_error_json(HTTPStatus.NOT_FOUND, "页面不存在")
            return
        try:
            body = (STATIC_DIR / name).read_bytes()
        except OSError:
            self.send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "页面资源不可用")
            return
        self.send_bytes(HTTPStatus.OK, body, content_type)

    def send_error_json(self, status: int, message: str) -> None:
        self.send_json(status, {"ok": False, "message": message})

    def read_json(self) -> dict[str, Any] | None:
        if self.headers.get("Transfer-Encoding"):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "不支持分块请求")
            return None
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self.send_error_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "请求类型必须是 JSON")
            return None
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.send_error_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "请求内容过大")
            return None
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except socket.timeout:
            self.send_error_json(HTTPStatus.REQUEST_TIMEOUT, "读取请求超时")
            return None
        except (UnicodeDecodeError, json.JSONDecodeError, OSError):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "JSON 格式错误")
            return None
        if not isinstance(value, dict):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "请求格式错误")
            return None
        return value

    def valid_origin(self) -> bool:
        expected = EMBED_ORIGIN if self.embedded_request() else EXPECTED_ORIGIN
        return self.headers.get("Origin", "") == expected

    def require_session_and_csrf(self) -> tuple[str, dict[str, Any]] | None:
        session_data = self.current_session()
        if session_data is None:
            self.send_error_json(HTTPStatus.UNAUTHORIZED, "登录已失效")
            return None
        if not self.valid_origin():
            self.send_error_json(HTTPStatus.FORBIDDEN, "请求来源校验失败")
            return None
        csrf = self.headers.get("X-CSRF-Token", "")
        if not TOKEN_RE.fullmatch(csrf) or not hmac.compare_digest(
            csrf.encode("ascii"), session_data[1]["csrf"].encode("ascii")
        ):
            self.send_error_json(HTTPStatus.FORBIDDEN, "安全令牌校验失败")
            return None
        return session_data

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        if not self.trusted_proxy():
            self.send_error_json(HTTPStatus.FORBIDDEN, "拒绝访问")
            return
        path = self.route()
        if BASE_PREFIX and path == BASE_PREFIX:
            self.send_response(HTTPStatus.PERMANENT_REDIRECT)
            self.security_headers()
            self.send_header("Connection", "close")
            self.send_header("Location", path_for())
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.close_connection = True
            return
        if path in (path_for(), path_for("audit")):
            session_data = self.current_session()
            if path == path_for("audit") and not session_data:
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "请先登录 3x-ui 或节点管理页面")
                return
            filename = ("audit.html" if path == path_for("audit") else "dashboard.html") if session_data else "login.html"
            try:
                text = (STATIC_DIR / filename).read_text(encoding="utf-8")
            except OSError:
                self.send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "页面资源不可用")
                return
            if session_data:
                text = text.replace("__CSRF_TOKEN__", html.escape(session_data[1]["csrf"], quote=True))
                text = text.replace("__PANEL_URL__", html.escape(PANEL_URL, quote=True))
                text = text.replace("__BODY_CLASS__", "embedded" if self.embedded_request() else "")
            self.send_bytes(HTTPStatus.OK, text.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path in (path_for("api/audit/index"), path_for("api/audit/report")):
            if self.current_session() is None:
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "请先登录")
                return
            try:
                query = urlsplit(self.path).query
                if path == path_for("api/audit/index"):
                    if query:
                        raise ValueError("unexpected query")
                    name = "index.json"
                else:
                    name = audit_view.requested_date(query) + ".json"
            except ValueError:
                self.send_error_json(HTTPStatus.BAD_REQUEST, "日期参数无效")
                return
            try:
                payload = audit_view.read(name)
            except FileNotFoundError:
                self.send_error_json(HTTPStatus.NOT_FOUND, "该日期尚无可用汇总")
                return
            except (OSError, ValueError, TypeError):
                self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, "审计汇总暂不可用，请稍后重试")
                return
            self.send_bytes(HTTPStatus.OK, payload, "application/json; charset=utf-8")
            return
        for name in STATIC_TYPES:
            if path == path_for(name):
                self.send_static(name)
                return
        if path == path_for("api/status"):
            if self.current_session() is None:
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "请先登录")
                return
            try:
                result = control_request({"v": 1, "op": "status"})
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
                LOG.exception("CONTROL_STATUS_FAIL")
                self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, "限速控制器暂不可用")
                return
            self.send_json(HTTPStatus.OK if result.get("ok") else HTTPStatus.SERVICE_UNAVAILABLE, result)
            return
        if path == path_for("api/notes"):
            if self.current_session() is None:
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "请先登录")
                return
            if urlsplit(self.path).query:
                self.send_error_json(HTTPStatus.BAD_REQUEST, "备注请求不接受查询参数")
                return
            try:
                nodes = node_notes.inventory(control_request({"v": 1, "op": "nodes"}))
                data = node_notes.read(nodes)
            except (OSError, RuntimeError, ValueError, KeyError, TypeError, sqlite3.Error):
                self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, "节点或备注暂不可用，未进行任何修改")
                return
            self.send_json(HTTPStatus.OK, {"ok": True, "nodes": data})
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "页面不存在")

    def do_POST(self) -> None:
        if not self.trusted_proxy():
            self.send_error_json(HTTPStatus.FORBIDDEN, "拒绝访问")
            return
        path = self.route()
        if path == path_for("api/login"):
            self.handle_login()
            return
        if path == path_for("api/logout"):
            session_data = self.require_session_and_csrf()
            if session_data is None:
                return
            remove_session(self.raw_cookie())
            expired = (
                f"{COOKIE_NAME}=; Path={COOKIE_PATH}; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
            )
            self.send_json(HTTPStatus.OK, {"ok": True}, [("Set-Cookie", expired)])
            return
        if path == path_for("api/set"):
            self.handle_set()
            return
        if path == path_for("api/notes"):
            self.handle_note()
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "页面不存在")

    def handle_note(self) -> None:
        if self.require_session_and_csrf() is None:
            return
        if urlsplit(self.path).query:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "备注请求不接受查询参数")
            return
        payload = self.read_json()
        if payload is None:
            return
        try:
            if set(payload) != {"node_id", "port", "protocol", "note", "expected_revision"}:
                raise ValueError("unexpected fields")
            chosen = node_notes.identity(payload["node_id"], payload["port"], payload["protocol"])
            value = node_notes.note_text(payload["note"])
            revision = payload["expected_revision"]
            if type(revision) is not int or not 0 <= revision <= 2**53 - 1:
                raise ValueError("invalid revision")
        except (ValueError, KeyError, TypeError):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "备注限 200 字，节点信息或版本号无效")
            return
        try:
            nodes = node_notes.inventory(control_request({"v": 1, "op": "nodes"}))
            if chosen not in nodes:
                self.send_error_json(HTTPStatus.CONFLICT, "节点已删除或端口/协议已变更，请刷新后核对")
                return
            saved = node_notes.save(chosen, value, revision)
        except node_notes.Conflict as conflict:
            self.send_json(HTTPStatus.CONFLICT, {"ok": False, "message": "其他页面已修改备注，请先载入最新备注", "current": conflict.current})
            return
        except (OSError, RuntimeError, ValueError, KeyError, TypeError, sqlite3.Error):
            self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, "备注保存未能确认，请刷新核对后再试")
            return
        self.send_json(HTTPStatus.OK, {"ok": True, "node": saved})

    def handle_login(self) -> None:
        if not self.valid_origin():
            self.send_error_json(HTTPStatus.FORBIDDEN, "请求来源校验失败")
            return
        payload = self.read_json()
        if payload is None:
            return
        if set(payload) != {"username", "password"}:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "请求字段不正确")
            return
        username = payload.get("username")
        password = payload.get("password")
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 128 or len(password) > 256:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "账号或密码格式错误")
            return

        ip = self.client_ip()
        now = time.monotonic()
        if not reserve_login_attempt(ip, now):
            self.send_error_json(HTTPStatus.TOO_MANY_REQUESTS, "失败次数过多，请稍后再试")
            return

        username_ok = username == USERNAME
        with PBKDF_SEMAPHORE:
            password_ok = verify_password(password)
        if not (username_ok and password_ok):
            finish_login_attempt(ip, False, time.monotonic())
            LOG.warning("AUTH_FAIL ip=%s", ip)
            self.send_error_json(HTTPStatus.UNAUTHORIZED, "账号或密码错误")
            return

        finish_login_attempt(ip, True, time.monotonic())
        raw_token, _session = create_session()
        cookie = (
            f"{COOKIE_NAME}={raw_token}; Path={COOKIE_PATH}; Max-Age={SESSION_ABSOLUTE}; "
            "Secure; HttpOnly; SameSite=Strict"
        )
        LOG.info("AUTH_OK ip=%s", ip)
        self.send_json(HTTPStatus.OK, {"ok": True}, [("Set-Cookie", cookie)])

    def handle_set(self) -> None:
        if self.require_session_and_csrf() is None:
            return
        payload = self.read_json()
        if payload is None:
            return
        expected = {
            "node_id",
            "limit_enabled",
            "download_mbps",
            "upload_mbps",
            "expected_revision",
        }
        if set(payload) != expected:
            self.send_error_json(HTTPStatus.BAD_REQUEST, "请求字段不正确")
            return
        node_id = payload.get("node_id")
        limit_enabled = payload.get("limit_enabled")
        down = payload.get("download_mbps")
        up = payload.get("upload_mbps")
        revision = payload.get("expected_revision")
        if (
            type(node_id) is not int
            or node_id <= 0
            or type(limit_enabled) is not bool
            or type(down) is not int
            or type(up) is not int
            or type(revision) is not int
            or revision < 0
        ):
            self.send_error_json(HTTPStatus.BAD_REQUEST, "节点或速度格式错误")
            return
        request = {
            "v": 1,
            "op": "set",
            "node_id": node_id,
            "limit_enabled": limit_enabled,
            "down_mbps": down,
            "up_mbps": up,
            "expected_revision": revision,
            "actor_ip": self.client_ip(),
        }
        try:
            result = control_request(request)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
            LOG.exception("CONTROL_SET_FAIL ip=%s node_id=%s", self.client_ip(), node_id)
            self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, "限速控制器暂不可用")
            return
        if result.get("ok"):
            self.send_json(HTTPStatus.OK, result)
            return
        status = {
            "invalid": HTTPStatus.BAD_REQUEST,
            "conflict": HTTPStatus.CONFLICT,
            "not_found": HTTPStatus.NOT_FOUND,
            "busy": HTTPStatus.TOO_MANY_REQUESTS,
            "forbidden": HTTPStatus.FORBIDDEN,
            "unhealthy": HTTPStatus.SERVICE_UNAVAILABLE,
        }.get(str(result.get("code")), HTTPStatus.INTERNAL_SERVER_ERROR)
        self.send_json(status, result)


def main() -> None:
    server = LimitedThreadingHTTPServer((BIND, PORT), Handler)
    LOG.info("web ready bind=%s:%d base_path=%s", BIND, PORT, BASE_PATH)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
