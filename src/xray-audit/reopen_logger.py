#!/usr/bin/env python3
"""Reopen Xray logs after rotation through its existing loopback API."""
import ipaddress
import json
import subprocess

with open("/usr/local/x-ui/bin/config.json", encoding="utf-8") as handle:
    config = json.load(handle)
api = config.get("api", {})
if "LoggerService" not in api.get("services", []):
    raise SystemExit("LoggerService is not enabled; no configuration was changed")
listeners = [item for item in config.get("inbounds", []) if item.get("tag") == api.get("tag")]
if len(listeners) != 1:
    raise SystemExit("Could not uniquely identify the existing API listener")
listener = listeners[0]
host = listener.get("listen", "")
if not ipaddress.ip_address(host).is_loopback:
    raise SystemExit("Refusing to contact a non-loopback API endpoint")
port = int(listener["port"])
endpoint = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
subprocess.run(["/usr/local/x-ui/bin/xray-linux-amd64", "api", "restartlogger",
                f"--server={endpoint}"], check=True, timeout=20)
print("Xray log handles reopened; proxy process was not restarted")
