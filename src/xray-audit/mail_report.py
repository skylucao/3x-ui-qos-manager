#!/usr/bin/env python3
"""TLS-only SMTP delivery using the existing 3x-ui settings. Never log secrets."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, parseaddr
import hashlib
import json
import os
from pathlib import Path
import re
import smtplib
import socket
import sqlite3
import ssl
import sys
import tempfile

MAIL_KEYS = (
    "smtpEnable", "smtpHost", "smtpPort", "smtpUsername", "smtpPassword",
    "smtpFrom", "smtpEncryptionType",
)


class MailNotReady(Exception):
    pass


def read_settings(database):
    uri = Path(database).resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=10)) as connection:
        placeholders = ",".join("?" for _ in MAIL_KEYS)
        return dict(connection.execute(
            f"SELECT key,value FROM settings WHERE key IN ({placeholders})", MAIL_KEYS
        ))


def address(value):
    if "\r" in value or "\n" in value or len(value) > 254:
        raise MailNotReady("Invalid mail address")
    value = value.strip()
    parsed = parseaddr(value)[1]
    if parsed != value or not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", value):
        raise MailNotReady("Invalid mail address")
    return value


def validate(settings, recipient):
    if settings.get("smtpEnable", "false").lower() != "true":
        raise MailNotReady("Enable and save SMTP in the 3x-ui panel first")
    for key in ("smtpHost", "smtpUsername", "smtpPassword"):
        if not settings.get(key):
            raise MailNotReady(f"Missing setting: {key}")
    host = settings["smtpHost"].strip()
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host) or host.startswith("."):
        raise MailNotReady("Invalid SMTP host")
    try:
        port = int(settings.get("smtpPort", ""))
    except ValueError:
        raise MailNotReady("Invalid SMTP port") from None
    if not 1 <= port <= 65535:
        raise MailNotReady("Invalid SMTP port")
    encryption = settings.get("smtpEncryptionType", "starttls").lower()
    if encryption not in ("tls", "ssl", "starttls"):
        raise MailNotReady("SMTP must use SSL or STARTTLS; plaintext is not allowed")
    sender = address(settings.get("smtpFrom") or settings["smtpUsername"])
    return host, port, encryption, sender, address(recipient)


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".mail-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def deliver(settings, recipient, subject, body, receipt_path):
    host, port, encryption, sender, recipient = validate(settings, recipient)
    if "\n" in subject or "\r" in subject:
        raise MailNotReady("Invalid subject")
    receipt_path = Path(receipt_path)
    if receipt_path.exists():
        previous = json.loads(receipt_path.read_text(encoding="utf-8"))
        if previous.get("state") in ("accepted_by_smtp", "sending", "uncertain"):
            print(f"Mail not resent: {previous['state']}")
            return previous["state"] == "accepted_by_smtp"
    digest = hashlib.sha256((recipient + subject).encode()).hexdigest()[:32]
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = f"<xray-audit-{digest}@{sender.rsplit('@', 1)[1]}>"
    message.set_content(body)
    context = ssl.create_default_context()
    client = None
    submitted = False
    receipt = {"recipient": recipient, "subject": subject,
               "updated_at": datetime.now(timezone.utc).isoformat()}
    try:
        if encryption in ("tls", "ssl"):
            client = smtplib.SMTP_SSL(host, port, timeout=30, context=context)
        else:
            client = smtplib.SMTP(host, port, timeout=30)
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
        client.login(settings["smtpUsername"], settings["smtpPassword"])
        receipt["state"] = "sending"
        atomic_json(receipt_path, receipt)
        submitted = True
        refused = client.send_message(message)
        if refused:
            raise RuntimeError("SMTP recipient refused")
        receipt["state"] = "accepted_by_smtp"
        atomic_json(receipt_path, receipt)
        print("Mail accepted by SMTP server; inbox delivery is not independently confirmed")
        return True
    except Exception as exc:
        receipt["state"] = "uncertain" if submitted else "not_sent"
        receipt["error_type"] = type(exc).__name__
        atomic_json(receipt_path, receipt)
        raise RuntimeError(f"Mail {receipt['state']}: {type(exc).__name__}") from None
    finally:
        if client is not None:
            try:
                client.quit()
            except Exception:
                client.close()


def main():
    import fcntl

    parser = argparse.ArgumentParser()
    parser.add_argument("--xui-db", default="/etc/x-ui/x-ui.db")
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument("--body-file")
    parser.add_argument("--subject")
    parser.add_argument("--receipt")
    args = parser.parse_args()
    os.umask(0o077)
    settings = read_settings(args.xui_db)
    try:
        host, port, encryption, _sender, recipient = validate(settings, args.recipient)
        if args.check_config:
            print(json.dumps({"ready": True, "host": host, "port": port,
                              "encryption": encryption, "recipient": recipient}))
            return 0
        if not all((args.body_file, args.subject, args.receipt)):
            parser.error("Sending requires --body-file, --subject and --receipt")
        body_path = Path(args.body_file)
        if body_path.stat().st_size > 2 * 1024 * 1024:
            raise MailNotReady("Report exceeds 2 MiB email size limit")
        receipt = Path(args.receipt)
        receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (receipt.parent / ".send.lock").open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            success = deliver(settings, args.recipient, args.subject,
                              body_path.read_text(encoding="utf-8"), receipt)
        return 0 if success else 75
    except MailNotReady as exc:
        print(f"SMTP_PENDING: {exc}", file=sys.stderr)
        return 78
    except Exception as exc:
        print(f"SMTP_FAILED: {type(exc).__name__}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
