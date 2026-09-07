import http.client
from datetime import date
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import audit_view
import node_notes


class CacheTests(unittest.TestCase):
    def setUp(self):
        clock = patch.object(audit_view, 'today', return_value=date(2026, 9, 7))
        clock.start()
        self.addCleanup(clock.stop)

    def test_expired_report_denied_and_stale_index_filtered(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for day in ('2026-08-31', '2026-09-01', '2026-09-07', '2026-09-08'):
                (root / (day + '.json')).write_text(json.dumps({'schema_version': 1, 'report_date': day}))
            for day in ('2026-08-31', '2026-09-08'):
                with self.assertRaises(FileNotFoundError):
                    audit_view.read(day + '.json', root)
            self.assertEqual(json.loads(audit_view.read('2026-09-01.json', root))['report_date'], '2026-09-01')
            (root / 'index.json').write_text(json.dumps({'schema_version': 1, 'dates': [{'report_date': '2026-08-31'}, {'report_date': '2026-09-01'}]}))
            index = json.loads(audit_view.read('index.json', root))
            self.assertEqual(index['dates'], [{'report_date': '2026-09-01'}])
            self.assertEqual(index['retention_days'], 7)

    def test_strict_dates(self):
        self.assertEqual(audit_view.requested_date('date=2026-09-07'), '2026-09-07')
        for query in ('', 'date=../../secret', 'date=2026-02-30', 'date=2026-09-07&date=2026-09-08', 'date=2026-09-07&file=a', 'date=%2Fetc%2Fpasswd'):
            with self.subTest(query=query), self.assertRaises(ValueError):
                audit_view.requested_date(query)

    def test_size_schema_and_basename(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / 'index.json'
            path.write_text('{"schema_version":1}', encoding='utf-8')
            self.assertEqual(json.loads(audit_view.read('index.json', root)), {'schema_version': 1})
            with self.assertRaises(ValueError):
                audit_view.read('../index.json', root)
            path.write_bytes(b'x' * (audit_view.MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                audit_view.read('index.json', root)
            path.write_text('{}', encoding='utf-8')
            with self.assertRaises(ValueError):
                audit_view.read('index.json', root)

    def test_mismatched_date_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / '2026-09-07.json').write_text('{"schema_version":1,"report_date":"2026-09-06"}', encoding='utf-8')
            with self.assertRaises(ValueError):
                audit_view.read('2026-09-07.json', root)

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink check')
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'real.json').write_text('{"schema_version":1}', encoding='utf-8')
            (root / 'index.json').symlink_to(root / 'real.json')
            with self.assertRaises(ValueError):
                audit_view.read('index.json', root)


class RouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = patch.dict(os.environ, {
            'QOS_WEB_ORIGIN': 'https://test.invalid', 'QOS_PROXY_SECRET': 'test-proxy-secret',
            'QOS_WEB_USERNAME': 'test', 'QOS_WEB_PASSWORD_HASH': 'invalid',
            'QOS_WEB_BASE_PATH': '/', 'QOS_EMBED_ORIGIN': 'https://test.invalid',
            'QOS_EMBED_TOKEN': 'a' * 64,
            'QOS_WEB_STATIC': str(Path(__file__).with_name('static')),
        })
        cls.env.start()
        spec = importlib.util.spec_from_file_location('test_web_app', Path(__file__).with_name('web.py'))
        cls.web = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.web)
        from http.server import ThreadingHTTPServer
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), cls.web.Handler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join()
        cls.env.stop()

    def get(self, path, proxy=True, embed=False, extra=None):
        headers = {'X-Qos-Proxy-Secret': 'test-proxy-secret'} if proxy else {}
        if embed:
            headers['X-Qos-Embed-Token'] = 'a' * 64
        headers.update(extra or {})
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request('GET', path, headers=headers)
        response = conn.getresponse()
        status, payload, returned = response.status, response.read(), dict(response.getheaders())
        conn.close()
        return status, payload, returned

    def test_all_audit_routes_need_proxy_and_session(self):
        for path in ('/audit', '/api/audit/index', '/api/audit/report?date=2026-09-07', '/api/notes'):
            with self.subTest(path=path):
                self.assertEqual(self.get(path, proxy=False, embed=True)[0], 403)
                self.assertEqual(self.get(path)[0], 401)
                self.assertEqual(self.get(path, extra={'Cookie': 'xrayqos_session=' + 'b' * 64})[0], 401)

    def test_authenticated_page_and_no_store(self):
        status, payload, headers = self.get('/audit', embed=True)
        self.assertEqual(status, 200)
        self.assertIn('网站连接审计'.encode(), payload)
        self.assertIn('no-store', headers['Cache-Control'])
        self.assertIn("frame-ancestors 'self'", headers['Content-Security-Policy'])

    def test_query_validation_precedes_file_access(self):
        with patch.object(audit_view, 'read') as read:
            for path in ('/api/audit/index?anything=1', '/api/audit/report?date=../../passwd', '/api/audit/report?date=2026-09-07&date=2026-09-08'):
                self.assertEqual(self.get(path, embed=True)[0], 400)
            read.assert_not_called()

    def test_authenticated_read_and_safe_failure(self):
        with patch.object(audit_view, 'read', return_value=b'{"schema_version":1}'):
            status, payload, headers = self.get('/api/audit/index', embed=True)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(payload), {'schema_version': 1})
            self.assertIn('no-store', headers['Cache-Control'])
        with patch.object(audit_view, 'read', side_effect=ValueError('private sensitive source')):
            status, payload, _ = self.get('/api/audit/index', embed=True)
            self.assertEqual(status, 503)
            self.assertNotIn(b'private sensitive', payload)

    def post_note(self, payload, authorized=True, origin='https://test.invalid', csrf=None):
        headers = {'X-Qos-Proxy-Secret': 'test-proxy-secret', 'Content-Type': 'application/json', 'Origin': origin}
        if authorized:
            headers['X-Qos-Embed-Token'] = 'a' * 64
        if csrf is not False:
            headers['X-CSRF-Token'] = self.web.EMBED_CSRF if csrf is None else csrf
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request('POST', '/api/notes', body=json.dumps(payload), headers=headers)
        response = conn.getresponse()
        result = response.status, json.loads(response.read())
        conn.close()
        return result

    def test_note_write_auth_origin_csrf_and_fields(self):
        payload = {'node_id': 1, 'port': 443, 'protocol': 'vless', 'note': 'test', 'expected_revision': 0}
        with patch.object(node_notes, 'save') as save, patch.object(self.web, 'control_request') as control:
            self.assertEqual(self.post_note(payload, authorized=False)[0], 401)
            self.assertEqual(self.post_note(payload, origin='https://evil.invalid')[0], 403)
            self.assertEqual(self.post_note(payload, csrf=False)[0], 403)
            self.assertEqual(self.post_note({**payload, 'note': '中' * 201})[0], 400)
            self.assertEqual(self.post_note({**payload, 'unwanted': True})[0], 400)
            save.assert_not_called(); control.assert_not_called()

    def test_notes_use_fresh_inventory_and_reject_changed_node(self):
        import time
        payload = {'node_id': 1, 'port': 443, 'protocol': 'vless', 'note': '财务部', 'expected_revision': 0}
        status = {'ok': True, 'sample_time_ms': time.time() * 1000, 'nodes': [{'inbound_id': 1, 'port': 443, 'protocol': 'vless'}]}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'notes.sqlite3'; node_notes.initialize(path)
            real_save = node_notes.save; real_read = node_notes.read
            with patch.object(self.web, 'control_request', return_value=status) as control, patch.object(node_notes, 'save', side_effect=lambda n, text, revision: real_save(n, text, revision, path)), patch.object(node_notes, 'read', side_effect=lambda nodes: real_read(nodes, path)):
                self.assertEqual(self.post_note(payload)[0], 200)
                self.assertEqual(self.post_note(payload)[0], 409)
                code, body, _ = self.get('/api/notes', embed=True)
                self.assertEqual(code, 200); self.assertEqual(json.loads(body)['nodes'][0]['note'], '财务部')
                status['nodes'][0]['port'] = 8443
                self.assertEqual(self.post_note({**payload, 'expected_revision': 1})[0], 409)
                status['nodes'] = []
                self.assertEqual(self.post_note({**payload, 'expected_revision': 1})[0], 409)
                self.assertTrue(all(call.args[0] == {'v': 1, 'op': 'nodes'} for call in control.call_args_list))


if __name__ == '__main__':
    unittest.main()
