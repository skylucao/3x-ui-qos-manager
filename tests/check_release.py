#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_NAMES = {"web.env", "nodes.json", "install-result.env", "metadata.json", "last-run.json", "node-notes.sqlite3"}
FORBIDDEN_SUFFIXES = {".pyc", ".tgz", ".zip", ".gz", ".db", ".sqlite", ".sqlite3", ".pem", ".key", ".cer", ".crt"}
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "filled proxy secret": re.compile(r"^QOS_PROXY_SECRET=[A-Za-z0-9_-]{32,}$", re.MULTILINE),
    "filled embed token": re.compile(r"^QOS_EMBED_TOKEN=[A-Za-z0-9_-]{32,}$", re.MULTILINE),
}


def main() -> int:
    errors: list[str] = []
    for path in ROOT.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if relative.as_posix() == 'src/xray-audit/config.json' or any(part in {'reports', 'receipts'} for part in relative.parts[:-1]):
            errors.append(f"private audit state: {relative}")
            continue
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES or re.fullmatch(r'(?:setup-)?\d{4}-\d{2}-\d{2}\.(?:txt|json)', path.name):
            errors.append(f"forbidden artifact: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"unexpected binary file: {relative}")
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{label}: {relative}")
    install_text = (ROOT / "install.sh").read_text(encoding="utf-8")
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
    if "__REPO_SLUG__" in install_text or "__REPO_SLUG__" in readme_text:
        errors.append("repository slug placeholder is unresolved")
    if "MHSanaei/3x-ui/master/install.sh" in install_text:
        errors.append("3x-ui installer must be pinned to a release")
    if not re.search(r'^XUI_INSTALLER_SHA256="[a-f0-9]{64}"$', install_text, re.MULTILINE):
        errors.append("3x-ui installer checksum is missing")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("release-safety-check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
