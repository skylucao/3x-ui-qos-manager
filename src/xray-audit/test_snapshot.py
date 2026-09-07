from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import snapshot
from test_report import line, node, report


def source(day='2026-09-07', nodes=None, lines=None):
    value = report.aggregate(lines if lines is not None else [line(stamp=day.replace('-', '/') + ' 10:00:00')],
                             nodes if nodes is not None else [node()], day)
    value['generated_at'] = day + 'T12:00:00+08:00'
    return value


class ProjectionTests(unittest.TestCase):
    def test_allowlist_and_unknown_tags(self):
        secret = '12345678-abcd-1234-abcd-123456789abc'
        raw = source('2026-09-06', lines=[line(tag=secret), line(tag='192.0.2.123'), line()])
        raw['log_sources'] = ['/private/log/path']
        raw['warnings'] = ['private-employee and ' + secret]
        raw['nodes'][0]['clients'] = [{'secret': secret}]
        exported = snapshot.project(raw, 'live')
        payload = json.dumps(exported)
        for text in (secret, '192.0.2.123', 'private-employee', '/private/log/path', 'clients'):
            self.assertNotIn(text, payload)
        self.assertEqual(len({item['key'] for item in exported['nodes']}), 3)

    def test_old_daily_has_no_invented_hours_or_target_timestamps(self):
        raw = source()
        del raw['nodes'][0]['hourly_connections']
        del raw['nodes'][0]['destinations'][0]['first_seen']
        del raw['nodes'][0]['destinations'][0]['last_seen']
        entry = snapshot.project(raw, 'daily')['nodes'][0]
        self.assertIsNone(entry['hourly_connections'])
        self.assertIsNone(entry['destinations'][0]['first_seen'])

    def test_targets_bounded_but_totals_preserved(self):
        raw = source(lines=[line('tcp:h' + str(i) + '.example:443', stamp='2026/09/07 12:00:00') for i in range(105)])
        view = snapshot.project(raw, 'live')['nodes'][0]
        self.assertEqual(len(view['destinations']), 100)
        self.assertEqual(view['omitted_destinations'], 5)
        self.assertEqual(view['unique_destinations'], 105)
        self.assertEqual(view['total_connections'], 105)

    def test_invalid_destination_and_inconsistent_counters_rejected(self):
        raw = source()
        raw['nodes'][0]['destinations'][0]['destination'] = 'example.com/private'
        with self.assertRaises(ValueError):
            snapshot.project(raw, 'live')
        raw = source()
        raw['nodes'][0]['hourly_connections'][0] = 100
        with self.assertRaises(ValueError):
            snapshot.project(raw, 'live')

    def test_empty_and_dynamic_node_lists(self):
        value = snapshot.project(source(nodes=[node(), node(2, 'two')], lines=[]), 'live')
        self.assertEqual(value['node_count'], 2)
        self.assertEqual(value['nodes'][1]['total_connections'], 0)
        self.assertEqual(value['data_status'], 'no_matching_records')
        self.assertEqual(value['nodes'][1]['hourly_connections'], [0] * 24)

    def test_duplicate_connections_not_deduplicated(self):
        event = line(stamp='2026/09/07 01:00:00')
        value = snapshot.project(source(lines=[event, event]), 'live')
        self.assertEqual(value['nodes'][0]['hourly_connections'][1], 2)

    def test_label_decoding_and_control_characters(self):
        self.assertEqual(snapshot.label('&lt;test&gt;\n\u202e'), '<test>')
        self.assertEqual(snapshot.label('12345678-abcd-1234-abcd-123456789abc'), '[标识已隐藏]')
        self.assertEqual(snapshot.label('员工_12345678-abcd-1234-abcd-123456789abc节点'), '员工_[标识已隐藏]节点')


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state, self.output = self.root / 'state', self.root / 'output'
        (self.state / 'reports').mkdir(parents=True)
        self.output.mkdir()
        self.now = datetime.fromisoformat('2026-09-07T12:00:00+08:00')

    def publish(self, builder=lambda day: source(day.isoformat()), now=None):
        return snapshot.publish(now or self.now, builder, self.state, self.output)

    def test_failed_generation_keeps_last_good_and_marks_failure(self):
        self.assertTrue(self.publish())
        before = (self.output / '2026-09-07.json').read_bytes()
        def broken(day):
            raise ValueError('raw private failure text')
        self.assertFalse(self.publish(broken))
        self.assertEqual(before, (self.output / '2026-09-07.json').read_bytes())
        index = snapshot.read_json(self.output / 'index.json')
        self.assertFalse(index['current_generation_ok'])
        self.assertNotIn('raw private', json.dumps(index))

    def test_history_nodes_not_replaced_with_current_nodes(self):
        historical = source('2026-09-06', nodes=[node(9, 'nine')], lines=[])
        historical['generated_at'] = '2026-09-07T09:00:00+08:00'
        saved = self.state / 'reports' / '2026-09-06.json'
        saved.write_text(json.dumps(historical), encoding='utf-8')
        self.publish()
        view = snapshot.read_json(self.output / saved.name)
        self.assertEqual(view['kind'], 'daily')
        self.assertEqual(view['nodes'][0]['id'], '9')
        self.assertEqual(json.loads(saved.read_text(encoding='utf-8')), historical)

    def test_midnight_live_cache_not_promoted_to_daily(self):
        self.publish()
        self.publish(now=self.now + timedelta(days=1))
        self.assertEqual(snapshot.read_json(self.output / '2026-09-07.json')['kind'], 'live')

    def test_older_manual_report_cannot_roll_back_later_snapshot(self):
        self.publish()
        manual = source()
        manual['generated_at'] = '2026-09-07T10:00:00+08:00'
        manual['coverage_status'] = 'period_not_complete'
        (self.state / 'reports' / '2026-09-07.json').write_text(json.dumps(manual), encoding='utf-8')
        self.publish(now=self.now + timedelta(days=1))
        saved = snapshot.read_json(self.output / '2026-09-07.json')
        self.assertEqual(saved['generated_at'], '2026-09-07T12:00:00+08:00')
        self.assertEqual(saved['kind'], 'live')

    def test_retained_cache_classification_upgraded_without_new_events(self):
        cached = snapshot.project(source('2026-09-06', lines=[line('tcp:203.0.113.7:443')]), 'live')
        cached['ruleset_version'] = 'old'
        item = cached['nodes'][0]['destinations'][0]
        item['classification'] = {'service': 'wrong_old_ip_guess'}
        del item['hourly_connections']
        original_time, original_count = cached['generated_at'], cached['total_connections']
        snapshot.atomic_json(self.output / '2026-09-06.json', cached)
        self.publish()
        saved = snapshot.read_json(self.output / '2026-09-06.json')
        self.assertEqual(saved['nodes'][0]['destinations'][0]['classification']['service'], '未知服务')
        self.assertNotIn('hourly_connections', saved['nodes'][0]['destinations'][0])
        self.assertEqual(saved['generated_at'], original_time)
        self.assertEqual(saved['total_connections'], original_count)
        self.assertEqual(saved['kind'], 'live')

    def test_retention_only_owned_dates_and_not_private_reports(self):
        for directory in (self.output, self.state / 'reports'):
            (directory / '2026-01-01.json').write_text('{}', encoding='utf-8')
        (self.output / 'keep.json').write_text('{}', encoding='utf-8')
        self.publish()
        self.assertFalse((self.output / '2026-01-01.json').exists())
        self.assertTrue((self.state / 'reports' / '2026-01-01.json').exists())
        self.assertTrue((self.output / 'keep.json').exists())

    def test_exactly_seven_dates_even_when_current_generation_fails(self):
        for age in range(9):
            day = (self.now - timedelta(days=age)).date().isoformat()
            snapshot.atomic_json(self.output / (day + '.json'), snapshot.project(source(day), 'live'))
        def broken(day):
            raise ValueError('failed current generation')
        self.assertFalse(self.publish(broken))
        index = snapshot.read_json(self.output / 'index.json')
        self.assertEqual(len(index['dates']), 7)
        self.assertEqual(index['earliest_date'], '2026-09-01')
        self.assertFalse((self.output / '2026-08-31.json').exists())

    def test_mail_not_changed_by_publication(self):
        value = {'report_date': '2026-09-07', 'updated_at': self.now.isoformat(), 'generated': True, 'emailed': False, 'generation_exit_code': 0}
        saved = self.state / 'last-run.json'
        saved.write_text(json.dumps(value), encoding='utf-8')
        before = saved.read_bytes()
        self.publish()
        self.assertEqual(saved.read_bytes(), before)
        self.assertEqual(snapshot.read_json(self.output / 'index.json')['mail']['state'], 'generated_only')

    def test_corrupt_history_retains_cache_with_warning(self):
        saved = self.state / 'reports' / '2026-09-06.json'
        saved.write_text(json.dumps(source('2026-09-06')), encoding='utf-8')
        self.publish()
        before = (self.output / saved.name).read_bytes()
        saved.write_text('bad', encoding='utf-8')
        self.publish()
        self.assertEqual(before, (self.output / saved.name).read_bytes())
        self.assertEqual(snapshot.read_json(self.output / 'index.json')['history_failures'], 1)

    def test_atomic_publication_failure_does_not_overwrite(self):
        path = self.output / '2026-09-07.json'
        snapshot.atomic_json(path, {'old': True})
        with patch.object(snapshot.os, 'replace', side_effect=OSError('disk error')):
            with self.assertRaises(OSError):
                snapshot.atomic_json(path, {'new': True})
        self.assertEqual(snapshot.read_json(path), {'old': True})
        self.assertEqual(list(self.output.glob('.snapshot-*')), [])

    @unittest.skipIf(os.name == 'nt', 'POSIX mode check')
    def test_cache_is_group_readable_not_world_readable(self):
        self.publish()
        self.assertEqual((self.output / 'index.json').stat().st_mode & 0o777, 0o640)


if __name__ == '__main__':
    unittest.main()
