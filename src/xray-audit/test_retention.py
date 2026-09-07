from datetime import date, datetime
import gzip
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import retention


def event(day, payload=b'accepted tcp:example.test:443 [in -> direct]'):
    return day.replace('-', '/').encode() + b' 12:00:00.123 ' + payload + b'\n'


class RetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.today = date(2026, 9, 7)
        self.cutoff = date(2026, 9, 1)

    def test_boundaries_and_capped_configuration(self):
        self.assertEqual(retention.cutoff_date(self.today), self.cutoff)
        self.assertEqual(retention.cutoff_date(date(2027, 1, 1)), date(2026, 12, 26))
        self.assertEqual(retention.cutoff_date(date(2028, 3, 1)), date(2028, 2, 24))
        for value in (30, 90, None, 'invalid'):
            self.assertEqual(retention.cutoff_date(self.today, value), self.cutoff)
        self.assertEqual(retention.cutoff_date(self.today, 1), self.today)

    def test_dates_only_delete_owned_expired_files(self):
        for name in ('2026-08-31.json', '2026-08-31.txt', '2026-09-01.json', 'node-notes.sqlite3', 'keep.json', '2026-02-30.json', 'setup-2026-08-31.json'):
            (self.root / name).write_text('{}')
        self.assertEqual(retention.cleanup_dates(self.root, self.cutoff), 2)
        self.assertTrue((self.root / '2026-09-01.json').exists())
        self.assertTrue((self.root / 'node-notes.sqlite3').exists())
        self.assertTrue((self.root / 'setup-2026-08-31.json').exists())
        self.assertEqual(retention.cleanup_dates(self.root, self.cutoff, receipts=True), 1)

    def test_cleanup_private_reports_receipts_and_status_not_metadata(self):
        for name in ('reports', 'receipts'):
            folder = self.root / name
            folder.mkdir()
            (folder / '2026-08-31.json').write_text('{}')
            (folder / '2026-09-01.json').write_text('{}')
        (self.root / 'last-run.json').write_text(json.dumps({'report_date': '2026-08-31'}))
        (self.root / 'metadata.json').write_text('{}')
        result = retention.cleanup_private(self.today, self.root)
        self.assertEqual(result, {'reports_removed': 1, 'receipts_removed': 1})
        self.assertFalse((self.root / 'last-run.json').exists())
        self.assertTrue((self.root / 'metadata.json').exists())

    def test_mixed_plain_and_compressed_records_keep_boundary_and_duplicates(self):
        valid = event('2026-09-01') + event('2026-09-07') * 2
        original = event('2026-08-31') + valid + b'undated\n' + event('2026-09-08')
        for name in ('access.log.1', 'access.log.2.gz'):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(gzip.compress(original) if name.endswith('.gz') else original)
                self.assertEqual(retention.prune_rotated(path, self.cutoff, self.today), 3)
                self.assertEqual(b''.join(retention.records(path)), valid)
                self.assertEqual(retention.prune_rotated(path, self.cutoff, self.today), 0)

    def test_fully_expired_deleted_and_active_untouched(self):
        path = self.root / 'access.log.1'
        path.write_bytes(event('2026-08-31'))
        self.assertEqual(retention.prune_rotated(path, self.cutoff, self.today), 1)
        self.assertFalse(path.exists())
        active = self.root / 'access.log'
        active.write_bytes(event('2026-08-31'))
        with self.assertRaises(ValueError):
            retention.prune_rotated(active, self.cutoff, self.today)
        self.assertTrue(active.exists())

    def test_oversized_lines_drained_without_losing_next_record(self):
        path = self.root / 'access.log.1'
        path.write_bytes(b'x' * (retention.MAX_LINE_LENGTH * 2) + b'\n' + event('2026-09-07'))
        self.assertEqual(retention.prune_rotated(path, self.cutoff, self.today), 1)
        self.assertEqual(path.read_bytes(), event('2026-09-07'))

    def test_atomic_failure_keeps_original_and_cleans_temp(self):
        path = self.root / 'access.log.1'
        payload = event('2026-08-31') + event('2026-09-01')
        path.write_bytes(payload)
        with patch.object(retention.os, 'replace', side_effect=OSError('failure')):
            with self.assertRaises(OSError):
                retention.prune_rotated(path, self.cutoff, self.today)
        self.assertEqual(path.read_bytes(), payload)
        self.assertEqual(list(self.root.glob('.retention-*')), [])

    def test_orphan_managed_temps_cleaned_but_open_and_unrelated_preserved(self):
        old = self.root / '.report-abcdefgh'; old.write_bytes(b'audit')
        recent = self.root / '.report-12345678'; recent.write_bytes(b'audit')
        unrelated = self.root / '.unrelated-abcdefgh'; unrelated.write_bytes(b'keep')
        modified = datetime.fromisoformat('2026-08-31T12:00:00+08:00').timestamp()
        os.utime(old, (modified, modified)); os.utime(unrelated, (modified, modified))
        def check(paths):
            if paths == [recent]:
                raise RuntimeError('writer still holds this file')
        with patch.object(retention, 'ensure_closed', side_effect=check):
            self.assertEqual(retention.cleanup_temporary(self.root, '.report-'), 1)
        self.assertFalse(old.exists()); self.assertTrue(recent.exists()); self.assertTrue(unrelated.exists())

    def test_open_rotated_inode_blocks_logrotate_if_reopen_does_not_fix_it(self):
        with patch.object(retention, 'rotated_logs', return_value=[]), patch.object(retention, 'ensure_closed', side_effect=RuntimeError('still open')), patch.object(retention.subprocess, 'run') as run:
            with self.assertRaises(RuntimeError):
                retention.maintain_logs(self.today)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], ['/usr/bin/python3', '/opt/xray-audit/reopen_logger.py'])

    def test_active_mixed_file_rotated_before_pruning(self):
        active = self.root / 'access.log'
        active.write_bytes(event('2026-08-31') + event('2026-09-01'))
        def rotate(command, **kwargs):
            if '--force' in command:
                active.rename(self.root / 'access.log.1')
                active.write_bytes(b'')
        with patch.object(retention, 'LOGS', self.root), patch.object(retention, 'ensure_closed'), patch.object(retention.subprocess, 'run', side_effect=rotate) as run:
            self.assertEqual(retention.maintain_logs(self.today), 1)
            self.assertEqual(run.call_count, 2)
        self.assertEqual((self.root / 'access.log.1').read_bytes(), event('2026-09-01'))
        self.assertEqual(active.read_bytes(), b'')

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink support')
    def test_symlink_and_hardlink_not_deleted(self):
        original = self.root / 'keep.txt'
        original.write_bytes(b'private')
        (self.root / '2026-08-31.json').symlink_to(original)
        os.link(original, self.root / '2026-08-31.txt')
        self.assertEqual(retention.cleanup_dates(self.root, self.cutoff), 0)
        self.assertEqual(original.read_bytes(), b'private')

    @unittest.skipIf(os.name == 'nt', 'POSIX proc-style links')
    def test_open_inode_detection_does_not_depend_on_binary_path(self):
        log = self.root / 'access.log.1'; log.write_bytes(event('2026-08-31'))
        procs = self.root / 'proc'
        descriptors = procs / '123' / 'fd'; descriptors.mkdir(parents=True)
        (descriptors / '4').symlink_to(log)
        (procs / '123' / 'exe').symlink_to('/old/xray (deleted)')
        with self.assertRaises(RuntimeError):
            retention.ensure_closed([log], procs)
        (descriptors / '4').unlink()
        retention.ensure_closed([log], procs)

    def test_direct_managed_old_report_write_blocked(self):
        import report
        with self.assertRaises(ValueError):
            report.write_report({'report_date': '2000-01-01'}, '/var/lib/xray-audit/reports')


@unittest.skipIf(os.name == 'nt', 'Daily runner requires Linux fcntl and system tzdata')
class DailyRetentionTests(unittest.TestCase):
    def test_cleanup_before_failure_generate_only_and_smtp_timeout(self):
        import daily
        import subprocess
        import sys
        from types import SimpleNamespace
        for mode in ('generation_failure', 'generate_only', 'smtp_failure', 'smtp_timeout'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                state = Path(folder)
                reports = state / 'reports'; reports.mkdir()
                (state / 'receipts').mkdir()
                old = reports / '2026-08-31.json'; old.write_text('{}')
                config = state / 'config.json'; config.write_text('{"recipient":"test@example.invalid","report_retention_days":30}')
                def run(command, **kwargs):
                    if command[1].endswith('report.py') and not command[1].endswith('mail_report.py'):
                        if mode != 'generation_failure':
                            (reports / '2026-09-06.txt').write_text('test report')
                        return SimpleNamespace(returncode=1 if mode == 'generation_failure' else 0)
                    if mode == 'smtp_timeout':
                        raise subprocess.TimeoutExpired(command, 150)
                    return SimpleNamespace(returncode=1)
                argv = ['daily.py'] + (['--generate-only'] if mode == 'generate_only' else [])
                with patch.object(daily, 'STATE', state), patch.object(daily, 'REPORTS', reports), patch.object(daily, 'CONFIG', config), patch.object(sys, 'argv', argv), patch.object(daily, 'datetime') as clock, patch.object(daily.subprocess, 'run', side_effect=run):
                    clock.now.return_value = datetime.fromisoformat('2026-09-07T09:00:00+08:00')
                    if mode == 'smtp_timeout':
                        with self.assertRaises(subprocess.TimeoutExpired):
                            daily.main()
                    else:
                        self.assertEqual(daily.main(), 0 if mode == 'generate_only' else 1)
                self.assertFalse(old.exists())


if __name__ == '__main__':
    unittest.main()
