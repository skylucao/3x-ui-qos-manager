from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import node_notes as notes


class NotesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'notes.sqlite3'
        notes.initialize(self.path)
        self.node = notes.identity(1, 443, 'vless')

    def test_persists_and_empty_note_keeps_version(self):
        self.assertEqual(notes.read([self.node], self.path)[0]['revision'], 0)
        saved = notes.save(self.node, ' 财务部\n公司电脑 ', 0, self.path)
        self.assertEqual(saved['note'], '财务部\n公司电脑')
        self.assertEqual(notes.read([self.node], self.path)[0], saved)
        cleared = notes.save(self.node, '', 1, self.path)
        self.assertEqual(cleared['revision'], 2)
        with self.assertRaises(notes.Conflict):
            notes.save(self.node, 'old', 0, self.path)

    def test_competing_creates_only_one_wins(self):
        def writer(text):
            try:
                notes.save(self.node, text, 0, self.path)
                return True
            except notes.Conflict:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(writer, ['one', 'two']))
        self.assertEqual(sorted(results), [False, True])

    def test_conflict_does_not_overwrite(self):
        notes.save(self.node, 'first', 0, self.path)
        with self.assertRaises(notes.Conflict) as failure:
            notes.save(self.node, 'second', 0, self.path)
        self.assertEqual(failure.exception.current['note'], 'first')
        self.assertEqual(notes.read([self.node], self.path)[0]['note'], 'first')

    def test_identity_changes_do_not_inherit_note(self):
        notes.save(self.node, 'employee-A', 0, self.path)
        for node in (notes.identity(1, 8443, 'vless'), notes.identity(1, 443, 'vmess'), notes.identity(2, 443, 'vless')):
            self.assertEqual(notes.read([node], self.path)[0]['note'], '')

    def test_plaintext_and_parameterized_sql(self):
        value = '<script>alert(1)</script>\n\' OR 1=1; --'
        notes.save(self.node, value, 0, self.path)
        self.assertEqual(notes.read([self.node], self.path)[0]['note'], value)
        self.assertEqual(notes.read([notes.identity(2, 443, 'vless')], self.path)[0]['note'], '')

    def test_character_and_identity_validation(self):
        for value in ('中' * 200, '😀' * 200):
            self.assertEqual(notes.note_text(value), value)
        for value in ('中' * 201, '😀' * 201, 'a\x00', '\u202e', '\ud800', None):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                notes.note_text(value)
        for params in ((True, 443, 'vless'), (0, 443, 'vless'), (1, 0, 'vless'), (1, 443, '../secret'), ('1 OR 1', 443, 'vless')):
            with self.assertRaises(ValueError):
                notes.identity(*params)

    def test_stale_inventory_rejected(self):
        valid = {'ok': True, 'sample_time_ms': 100000, 'nodes': [{'inbound_id': 1, 'port': 443, 'protocol': 'vless'}]}
        self.assertEqual(notes.inventory(valid, now=105), [self.node])
        for update in ({'discovery_stale': True}, {'sample_time_ms': 80000}, {'ok': False}, {'sample_time_ms': 200000}):
            with self.assertRaises(RuntimeError):
                notes.inventory({**valid, **update}, now=105)

    def test_read_does_not_change_database_and_missing_does_not_create(self):
        before = self.path.read_bytes()
        notes.read([self.node], self.path)
        self.assertEqual(before, self.path.read_bytes())
        missing = self.path.with_name('missing.sqlite3')
        with self.assertRaises(ValueError):
            notes.read([self.node], missing)
        self.assertFalse(missing.exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX file modes')
    def test_database_permissions_and_symlink_rejected(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        link = self.path.with_name('link.sqlite3')
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            notes.read([self.node], link)


@unittest.skipIf(os.name == 'nt', 'controller uses POSIX pwd and Unix sockets')
class ControllerInventoryTests(unittest.TestCase):
    def test_nodes_operation_is_fresh_and_read_only(self):
        import control
        rows = [{'inbound_id': 1, 'port': 443, 'protocol': 'vless', 'name': 'private-name', 'db_up': 10}]
        with patch.object(control, 'read_key_values', return_value={'XRAY_DB': '/tmp/synthetic-db'}), patch.object(control, 'read_inbounds', return_value=rows) as read, patch.object(control, 'run_qos', side_effect=AssertionError('mutation')), patch.object(control.STATE, 'sample_locked', side_effect=AssertionError('sampling')), patch.object(control.STATE, 'status', side_effect=AssertionError('cached')):
            result = control.response_for({'v': 1, 'op': 'nodes'})
            read.assert_called_once_with(Path('/tmp/synthetic-db'))
            self.assertEqual(result['nodes'], [{'inbound_id': 1, 'port': 443, 'protocol': 'vless'}])
            with self.assertRaises(control.ControllerError):
                control.response_for({'v': 1, 'op': 'nodes', 'path': '/secret'})


if __name__ == '__main__':
    unittest.main()
