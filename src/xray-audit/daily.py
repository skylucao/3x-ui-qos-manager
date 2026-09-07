#!/usr/bin/env python3
"""Generate a node-separated daily digest and deliver it to the configured owner."""

import argparse
from datetime import date, datetime, timedelta
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
from zoneinfo import ZoneInfo

from mail_report import atomic_json
from retention import cleanup_private, cutoff_date

APP = Path(__file__).resolve().parent
STATE = Path("/var/lib/xray-audit")
REPORTS = STATE / "reports"
CONFIG = Path('/etc/xray-audit/config.json')
SHANGHAI = ZoneInfo("Asia/Shanghai")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--date", type=date.fromisoformat)
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--test-email", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    REPORTS.mkdir(parents=True, exist_ok=True, mode=0o700)
    (STATE / 'receipts').mkdir(parents=True, exist_ok=True, mode=0o700)
    with (STATE / "daily.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        now = datetime.now(SHANGHAI)
        day = args.date or (now.date() - timedelta(days=1))
        retention = config.get('report_retention_days', 7)
        cleanup_private(now.date(), STATE, retention)
        if not args.test_email and not cutoff_date(now.date(), retention) <= day <= now.date():
            print('Requested report date is outside the retention window', file=sys.stderr)
            return 2
        if args.test_email:
            body_file = STATE / "setup-test.txt"
            body_file.write_text(
                "这是公司节点审计日报的发信测试。\n\n"
                "计划：北京时间每天09:00发送前一天的汇总，各节点分段列出。\n"
                "只汇总连接目标域名/IP和连接次数，不收集网页正文、聊天或视频内容。\n"
                "本测试邮件不包含员工的访问记录。\n", encoding="utf-8")
            subject = "公司节点审计日报：发信测试"
            receipt = STATE / "receipts" / f"setup-{now.date().isoformat()}.json"
        else:
            report_run = subprocess.run([
                sys.executable, str(APP / "report.py"), "--date", day.isoformat(),
                "--log-dir", "/var/log/x-ui", "--xui-db", "/etc/x-ui/x-ui.db",
                "--runtime-config", "/usr/local/x-ui/bin/config.json",
                "--output-dir", str(REPORTS), "--log-timezone", "Asia/Shanghai",
                "--metadata", str(STATE / "metadata.json"),
            ], capture_output=True, text=True, timeout=240)
            body_file = REPORTS / f"{day.isoformat()}.txt"
            generated = report_run.returncode == 0 and body_file.is_file()
            status = {"report_date": day.isoformat(), "updated_at": now.isoformat(),
                      "generated": generated, "emailed": False,
                      "generation_exit_code": report_run.returncode}
            atomic_json(STATE / "last-run.json", status)
            if not generated:
                print("Audit generation failed; no stale report will be sent", file=sys.stderr)
                return 1
            if args.generate_only:
                print(f"Generated node-separated report: {day.isoformat()}; email not requested")
                return 0
            subject = f"公司节点访问审计日报 {day.isoformat()}（按节点分组）"
            receipt = STATE / "receipts" / f"{day.isoformat()}.json"
        send_run = subprocess.run([
            sys.executable, str(APP / "mail_report.py"), "--xui-db", "/etc/x-ui/x-ui.db",
            "--recipient", config["recipient"], "--body-file", str(body_file),
            "--subject", subject, "--receipt", str(receipt),
        ], timeout=150)
        if not args.test_email:
            status["emailed"] = send_run.returncode == 0
            status["mail_exit_code"] = send_run.returncode
            atomic_json(STATE / "last-run.json", status)
        return send_run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
