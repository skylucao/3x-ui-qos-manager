from datetime import datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import schedule_config as schedule


class ScheduleTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'schedule.json'
        self.now = datetime.fromisoformat('2026-09-07T15:30:00+08:00')

    def test_default_first_save_next_day_and_noop(self):
        initial = schedule.read(self.path)
        self.assertEqual(initial['time'], '09:00')
        saved = schedule.save('09:00', initial['revision'], self.path, self.now)
        self.assertEqual(saved['effective_from'], int(datetime.fromisoformat('2026-09-08T09:00:00+08:00').timestamp()))
        self.assertEqual(schedule.save('09:00', saved['revision'], self.path, self.now), saved)

    def test_next_occurrence_equal_current_minute_and_midnight(self):
        for chosen, expected in [('15:30', '2026-09-08T15:30:00+08:00'), ('16:00', '2026-09-07T16:00:00+08:00'), ('00:00', '2026-09-08T00:00:00+08:00')]:
            saved = schedule.save(chosen, schedule.read(self.path)['revision'], self.path, self.now)
            self.assertEqual(saved['effective_from'], int(datetime.fromisoformat(expected).timestamp()))
            self.assertFalse(schedule.due(self.now, saved))
            self.assertTrue(schedule.due(datetime.fromisoformat(expected), saved))

    def test_delayed_due_uses_shanghai(self):
        value = {'time': '09:00', 'effective_from': 0}
        self.assertFalse(schedule.due(datetime.fromisoformat('2026-09-07T00:59:00+00:00'), value))
        self.assertTrue(schedule.due(datetime.fromisoformat('2026-09-07T01:05:00+00:00'), value))

    def test_strict_validation_and_conflict(self):
        revision = schedule.read(self.path)['revision']
        for value in ('9:00', '24:00', '09:60', '09:00\n', '09:00:00', None, True, '$(id)'):
            with self.assertRaises(ValueError): schedule.save(value, revision, self.path, self.now)
        schedule.save('16:00', revision, self.path, self.now)
        with self.assertRaises(FileExistsError): schedule.save('17:00', revision, self.path, self.now)

    def test_corrupt_config_fails_closed(self):
        for raw in ('{broken', '', 'null', '[]'):
            self.path.write_text(raw)
            with self.assertRaises(ValueError): schedule.read(self.path)

    def test_failed_atomic_replace_preserves_schedule(self):
        current = schedule.save('09:00', schedule.read(self.path)['revision'], self.path, self.now)
        before = self.path.read_bytes()
        with patch.object(schedule.os, 'replace', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError): schedule.save('10:00', current['revision'], self.path, self.now)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.path.parent.glob('.daily-schedule-*')))

    def test_audit_copy_matches(self):
        source = Path(__file__).with_name('schedule_config.py')
        self.assertEqual(source.read_bytes(), (source.parent.parent / 'xray-audit/schedule_config.py').read_bytes())
