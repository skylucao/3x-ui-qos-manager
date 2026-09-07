#!/usr/bin/env python3
"""Local health check for the QoS controller, run as xray-qos-web."""

from __future__ import annotations

import json
import socket
import sys


SOCKET_PATH = "/run/xray-qos-web/control.sock"
MAX_RESPONSE = 512 * 1024


def request(payload: dict) -> dict:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(165)
    try:
        client.connect(SOCKET_PATH)
        client.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
        client.shutdown(socket.SHUT_WR)
        raw = bytearray()
        while b"\n" not in raw and len(raw) <= MAX_RESPONSE:
            part = client.recv(8192)
            if not part:
                break
            raw.extend(part)
        result = json.loads(bytes(raw).split(b"\n", 1)[0])
        if not isinstance(result, dict):
            raise RuntimeError("controller returned a non-object")
        return result
    finally:
        client.close()


status = request({"v": 1, "op": "status"})
if status.get("ok") is not True:
    raise SystemExit(f"controller unhealthy: {status.get('message', 'unknown error')}")

if "--set-current" in sys.argv:
    node = next((item for item in status.get("nodes", []) if item.get("limit_enabled")), None)
    if node is not None:
        result = request(
            {
                "v": 1,
                "op": "set",
                "node_id": int(node["inbound_id"]),
                "limit_enabled": True,
                "down_mbps": int(node["limit_download_mbps"]),
                "up_mbps": int(node["limit_upload_mbps"]),
                "expected_revision": int(status["config_revision"]),
                "actor_ip": "127.0.0.1",
            }
        )
        if result.get("ok") is not True:
            raise SystemExit(f"controller write check failed: {result.get('message', 'unknown error')}")

print("controller-health-ok")

import node_notes
node_notes.read(node_notes.inventory(request({"v": 1, "op": "nodes"})))
print("node-notes-health-ok")
