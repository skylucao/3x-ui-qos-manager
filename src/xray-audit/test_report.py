import gzip
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("audit_report", Path(__file__).with_name("report.py"))
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


def node(ident=1, tag="inbound-10001", **kwargs):
    return dict(id=str(ident), remark="test node", port=10000 + ident, enabled=True, protocol="vless", tags=[tag], **kwargs)


def line(destination="tcp:example.com:443", tag="inbound-10001", stamp="2026/09/06 12:34:56", arrow="->"):
    return f"{stamp} from 192.0.2.123:54321 accepted {destination} [{tag} {arrow} direct] email: private-employee\n"


class ReportTests(unittest.TestCase):
    def test_routes_microseconds_and_privacy(self):
        lines = [line(stamp="2026/09/06 00:00:01.123456789", arrow=arrow) for arrow in ("->", ">>", "==>")]
        result = report.aggregate(lines, [node(), node(2, "inbound-10002")], "2026-09-06")
        first, unused = result["nodes"]
        self.assertEqual(first["total_connections"], 3)
        self.assertEqual(first["unique_destinations"], 1)
        self.assertIn(".123456+08:00", first["first_seen"])
        self.assertEqual(unused["total_connections"], 0)
        serialized = json.dumps(result) + report.render(result)
        self.assertNotIn("192.0.2.123", serialized)
        self.assertNotIn("private-employee", serialized)

    def test_domains_ips_no_reverse_lookup(self):
        lines = [line("tcp:EXAMPLE.com.:443"), line("udp:203.0.113.7:53"), line("tcp:[2001:db8::7]:443")]
        data = report.aggregate(lines, [node()], "2026-09-06")["nodes"][0]
        self.assertEqual(data["unique_destinations"], 3)
        self.assertEqual({item["destination"] for item in data["destinations"]}, {"example.com", "203.0.113.7", "2001:db8::7"})
        self.assertEqual(sum(item["kind"] == "ip" for item in data["destinations"]), 2)

    def test_urls_queries_not_retained(self):
        result = report.aggregate([line("tcp:example.com:443/private?q=secret#fragment")], [node()], "2026-09-06")
        self.assertEqual(result["nodes"][0]["destinations"][0]["destination"], "example.com")
        self.assertNotIn("private?q=secret", json.dumps(result))

    def test_shanghai_date_with_utc_logs_and_unordered_records(self):
        logs = [line(stamp="2026/09/06 15:59:59"), line(stamp="2026/09/05 16:00:00"), line(stamp="2026/09/06 16:00:00")]
        result = report.aggregate(logs, [node()], "2026-09-06", "UTC")
        data = result["nodes"][0]
        self.assertEqual(data["total_connections"], 2)
        self.assertEqual(data["first_seen"], "2026-09-06T00:00:00+08:00")
        self.assertEqual(data["last_seen"], "2026-09-06T23:59:59+08:00")
        self.assertEqual(result["diagnostics"]["outside_period_lines"], 1)
        self.assertEqual(len(data["hourly_connections"]), 24)
        self.assertEqual(data["hourly_connections"][0], 1)
        self.assertEqual(data["hourly_connections"][23], 1)
        self.assertEqual(sum(data["hourly_connections"]), 2)
        self.assertEqual(data["destinations"][0]["first_seen"], data["first_seen"])
        self.assertEqual(data["destinations"][0]["last_seen"], data["last_seen"])

    def test_malformed_and_unknown_tag(self):
        logs = ["bad line\n", line("tcp:bad-domain:99999"), line(tag="orphan"), "x" * (report.MAX_LINE_LENGTH + 1), "2026/09/06 10:00:00 from 192.0.2.1 rejected tcp:example.com:443\n"]
        result = report.aggregate(logs, [node()], "2026-09-06")
        self.assertEqual(result["diagnostics"]["malformed_lines"], 3)
        self.assertEqual(result["diagnostics"]["oversized_lines"], 1)
        self.assertEqual(result["diagnostics"]["unmapped_connections"], 1)
        self.assertTrue(result["nodes"][-1]["unmapped"])
        self.assertTrue(any("无法匹配" in warning for warning in result["warnings"]))

    def test_internal_api_is_excluded_and_external_unknown_is_reported(self):
        logs = [line(tag="api"), line(tag="new-external-node"), line()]
        result = report.aggregate(logs, [node()], "2026-09-06")
        self.assertEqual(result["diagnostics"]["ignored_internal_connections"], 1)
        self.assertEqual(result["diagnostics"]["accepted_connections"], 2)
        self.assertEqual(result["diagnostics"]["unmapped_connections"], 1)
        self.assertEqual(len(result["nodes"]), 2)
        self.assertEqual(result["nodes"][-1]["remark"], "未映射节点 1")
        self.assertNotIn("new-external-node", json.dumps(result) + report.render(result))
        self.assertTrue(any("无法匹配" in warning for warning in result["warnings"]))

    def test_custom_runtime_api_tag_is_excluded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db, runtime = self.make_inputs(root)
            config = json.loads(runtime.read_text(encoding="utf-8"))
            config["api"] = {"tag": "management-api"}
            config["inbounds"].append({"tag": "management-api", "port": 62789, "protocol": "tunnel", "listen": "127.0.0.1"})
            runtime.write_text(json.dumps(config), encoding="utf-8")
            nodes, warnings, ignored = report.load_nodes(db, runtime, include_ignored_tags=True)
            self.assertEqual(set(ignored), {"api", "management-api"})
            result = report.aggregate([line(tag="management-api"), line()], nodes, "2026-09-06", ignored_tags=ignored)
            self.assertEqual(result["diagnostics"]["ignored_internal_connections"], 1)
            self.assertEqual(result["diagnostics"]["accepted_connections"], 1)
            self.assertEqual(result["diagnostics"]["unmapped_connections"], 0)
            self.assertEqual(len(result["nodes"]), 2)

    def test_accepted_does_not_imply_success_and_remark_may_name_employee(self):
        result = report.aggregate([line().replace("-> direct", "-> blocked")], [node()], "2026-09-06")
        self.assertEqual(result["nodes"][0]["total_connections"], 1)
        text = report.render(result)
        self.assertIn("不证明目标访问成功", text)
        self.assertIn("blocked", text)
        self.assertIn("原始日志 email 字段", text)
        self.assertNotIn("员工标识字段", text)

    def test_labels_cleaned(self):
        metadata = node()
        metadata["remark"] = '<img src=x>\r\nBcc: victim@example.com\u202e'
        text = report.render(report.aggregate([], [metadata], "2026-09-06"))
        self.assertNotIn("<img", text)
        self.assertNotIn("\nBcc:", text)
        self.assertNotIn("\u202e", text)

    def test_no_records_is_not_zero_activity(self):
        result = report.add_coverage(report.aggregate([], [node()], "2026-09-06"), "2026-09-06T15:00:00+08:00")
        self.assertEqual(result["coverage_status"], "partial_first_day")
        text = report.render(result)
        self.assertIn("不等于无人访问", text)
        self.assertIn("无法补查", text)
        self.assertIn("这不是零访问的证明", text)

    def test_collection_starts_later_and_naive_time_rejected(self):
        result = report.add_coverage(report.aggregate([], [], "2026-09-05"), "2026-09-06T00:00:00+08:00")
        self.assertEqual(result["coverage_status"], "before_collection")
        with self.assertRaises(ValueError):
            report.add_coverage(report.aggregate([], [], "2026-09-05"), "2026-09-06T00:00:00")

    def test_top20_text_but_full_json(self):
        result = report.aggregate([line(f"tcp:host{i}.example:443") for i in range(25)], [node()], "2026-09-06")
        self.assertEqual(len(result["nodes"][0]["destinations"]), 25)
        text = report.render(result)
        self.assertEqual(text.count("[domain]"), 20)
        self.assertIn("另有 5 个目标", text)

    def test_read_rotated_gzip_and_drain_oversized(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "access.log").write_text("x" * (report.MAX_LINE_LENGTH * 3) + "\n" + line(), encoding="utf-8")
            with gzip.open(root / "access.log.1.gz", "wt", encoding="utf-8") as handle:
                handle.write(line())
            (root / "error.log").write_text("ignored", encoding="utf-8")
            failures = []
            paths = report.find_logs(root)
            result = report.aggregate(report.iter_log_lines(paths, failures), [node()], "2026-09-06")
            self.assertEqual(len(paths), 2)
            self.assertEqual(result["diagnostics"]["scanned_lines"], 3)
            self.assertEqual(result["diagnostics"]["oversized_lines"], 1)
            self.assertEqual(result["diagnostics"]["accepted_connections"], 2)
            self.assertEqual(failures, [])

    def test_corrupt_gzip_is_reported_without_content(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "access.log.1.gz"
            path.write_bytes(b"not a gzip, source-secret")
            failures = []
            self.assertEqual(list(report.iter_log_lines([path], failures)), [])
            self.assertEqual(len(failures), 1)
            self.assertNotIn("source-secret", json.dumps(failures))

    def make_inputs(self, root):
        db = root / "x-ui.db"
        with closing(sqlite3.connect(db)) as conn:
            conn.execute("CREATE TABLE inbounds (id INTEGER, remark TEXT, port INTEGER, enable INTEGER, protocol TEXT, settings TEXT)")
            conn.executemany("INSERT INTO inbounds VALUES (?, ?, ?, ?, ?, ?)", [
                (1, "node one", 10001, 1, "vless", "DO-NOT-READ-CLIENT-SECRET"),
                (2, "node two", 10002, 0, "shadowsocks", "DO-NOT-READ-CLIENT-SECRET"),
            ])
            conn.commit()
        runtime = root / "config.json"
        runtime.write_text(json.dumps({"inbounds": [
            {"tag": "inbound-10001", "port": 10001, "protocol": "vless", "listen": "0.0.0.0", "settings": {"secret": "DO-NOT-EXPORT"}},
        ]}), encoding="utf-8")
        return db, runtime

    def test_database_mapping_and_no_secret_export(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db, runtime = self.make_inputs(root)
            nodes, warnings = report.load_nodes(db, runtime)
            self.assertEqual(nodes[0]["tags"], ["inbound-10001"])
            self.assertFalse(nodes[1]["enabled"])
            self.assertEqual(warnings, [])
            self.assertNotIn("DO-NOT-", json.dumps(nodes))
            with self.assertRaises(ValueError):
                report.load_nodes(root / "missing.db", runtime)
            self.assertFalse((root / "missing.db").exists())

    def test_cli_files_permissions_and_missing_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db, runtime = self.make_inputs(root)
            logs, output = root / "logs", root / "reports"
            logs.mkdir()
            (logs / "access.log").write_text(line(), encoding="utf-8")
            args = ["--date", "2026-09-06", "--log-dir", str(logs), "--xui-db", str(db), "--runtime-config", str(runtime), "--output-dir", str(output), "--started-at", "2026-09-06T01:00:00+08:00"]
            self.assertEqual(report.main(args), 0)
            textfile, jsonfile = output / "2026-09-06.txt", output / "2026-09-06.json"
            self.assertTrue(textfile.is_file())
            self.assertEqual(json.loads(jsonfile.read_text(encoding="utf-8"))["coverage_status"], "partial_first_day")
            if os.name != "nt":
                self.assertEqual(textfile.stat().st_mode & 0o777, 0o600)
                self.assertEqual(jsonfile.stat().st_mode & 0o777, 0o600)
            (logs / "access.log").unlink()
            self.assertEqual(report.main(args), 2)

    def test_metadata_and_partial_read_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db, runtime = self.make_inputs(root)
            logs = root / "logs"
            logs.mkdir()
            (logs / "access.log").write_text(line(), encoding="utf-8")
            (logs / "access.log.1.gz").write_bytes(b"bad")
            metadata = root / "metadata.json"
            metadata.write_text(json.dumps({"started_at": "2026-09-06T00:00:00+08:00"}), encoding="utf-8")
            args = ["--date", "2026-09-06", "--log-dir", str(logs), "--xui-db", str(db), "--runtime-config", str(runtime), "--output-dir", str(root / "reports"), "--metadata", str(metadata)]
            self.assertEqual(report.main(args), 1)
            data = json.loads((root / "reports" / "2026-09-06.json").read_text(encoding="utf-8"))
            self.assertEqual(data["data_status"], "partial_read_failure")
            self.assertEqual(len(data["read_failures"]), 1)


if __name__ == "__main__":
    unittest.main()
