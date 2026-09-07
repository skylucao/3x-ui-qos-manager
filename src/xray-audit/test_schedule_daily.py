from datetime import datetime
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.name == 'posix', 'daily scheduler requires fcntl')
class DailyScheduleTests(unittest.TestCase):
    def setUp(self):
        import daily
        self.daily = daily
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name); (self.state / 'receipts').mkdir(); (self.state / 'reports').mkdir()
        self.now = datetime.fromisoformat('2026-09-07T09:05:00+08:00')
        schedule = patch.object(daily.schedule_config, 'read', return_value={'time': '09:00', 'effective_from': 0})
        schedule.start(); self.addCleanup(schedule.stop)

    def test_delayed_once_per_day_and_changed_time_no_resend(self):
        self.assertTrue(self.daily.claim_scheduled(self.now, self.state))
        self.assertFalse(self.daily.claim_scheduled(self.now.replace(hour=16), self.state))
        self.assertTrue(self.daily.claim_scheduled(self.now.replace(day=8), self.state))

    def test_receipt_barrier_preserves_success_and_uncertain(self):
        path = self.state / 'receipts/2026-09-06.json'
        for status in ('accepted_by_smtp', 'sending', 'uncertain'):
            path.write_text(json.dumps({'state': status}))
            self.assertFalse(self.daily.claim_scheduled(self.now, self.state))
        self.assertFalse((self.state / 'last-scheduled.json').exists())

    def test_not_due_and_corrupt_marker_fail_closed(self):
        self.assertFalse(self.daily.claim_scheduled(self.now.replace(hour=8), self.state))
        (self.state / 'last-scheduled.json').write_text('{broken')
        with self.assertRaises(ValueError): self.daily.claim_scheduled(self.now, self.state)

    def test_attempt_retention(self):
        import retention
        (self.state / 'last-scheduled.json').write_text('{"report_date":"2026-09-05"}')
        retention.cleanup_private(self.now.date(), self.state)
        self.assertFalse((self.state / 'last-scheduled.json').exists())

    def test_bounded_process_timeout_and_start_failure(self):
        import subprocess
        for error, expected in ((subprocess.TimeoutExpired(['report'], 240), 124), (OSError('failed'), 127)):
            with patch.object(self.daily.subprocess, 'run', side_effect=error):
                self.assertEqual(self.daily.bounded_run(['report'], timeout=240).returncode, expected)
