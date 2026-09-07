import unittest
import service_rules
import snapshot
from test_report import report, line, node


class ServiceRulesTests(unittest.TestCase):
    def test_specific_domain_beats_provider(self):
        for host, expected in [('api.weixin.qq.com', '微信相关'), ('youtubei.googleapis.com', 'YouTube相关'), ('im.qq.com', 'QQ相关')]:
            self.assertEqual(service_rules.identify(host, 'domain')['service'], expected)

    def test_shared_domains_not_called_chat_or_search(self):
        for host in ('mail.qq.com', 'v.qq.com', 'map.qq.com', 'qpic.cn', 'qlogo.cn'):
            self.assertEqual(service_rules.identify(host, 'domain')['service'], '腾讯相关／未知具体服务')
        self.assertEqual(service_rules.identify('googleapis.com', 'domain')['service'], 'Google相关／未知具体服务')

    def test_domain_boundary_and_ip_unknown(self):
        for host in ('evilqq.com', 'qq.com.example.net', 'youtube.com.evil.test', 'https://youtube.com', 'unknown.example'):
            self.assertEqual(service_rules.identify(host, 'domain')['service'], '未知服务')
        self.assertEqual(service_rules.identify('203.0.113.8', 'ip')['service'], '未知服务')
        self.assertEqual(service_rules.identify('203.0.113.8', 'domain')['service'], '未知服务')

    def test_all_rules_have_provenance_and_unique_suffixes(self):
        all_suffixes = []
        for service, category, suffixes, source in service_rules.RULES:
            self.assertTrue(source.startswith('https://'))
            all_suffixes.extend(suffixes)
            for suffix in suffixes:
                self.assertEqual(service_rules.identify(suffix, 'domain')['service'], service)
        self.assertEqual(len(all_suffixes), len(set(all_suffixes)))

    def test_target_hours_are_discrete_not_duration(self):
        logs = [line('tcp:www.youtube.com:443', stamp='2026/09/06 10:00:00'), line('tcp:www.youtube.com:443', stamp='2026/09/06 10:30:00'), line('tcp:www.youtube.com:443', stamp='2026/09/06 12:00:00')]
        data = report.aggregate(logs, [node()], '2026-09-06')
        item = data['nodes'][0]['destinations'][0]
        self.assertEqual(item['hourly_connections'][10], 2)
        self.assertEqual(item['hourly_connections'][11], 0)
        self.assertEqual(item['hourly_connections'][12], 1)
        self.assertEqual(sum(item['hourly_connections']), item['connections'])
        self.assertNotIn('duration', item)

    def test_legacy_enrichment_does_not_invent_hour_buckets(self):
        raw = report.aggregate([line('tcp:telegram.org:443')], [node()], '2026-09-06')
        item = raw['nodes'][0]['destinations'][0]
        del item['hourly_connections']
        item['classification'] = {'service': 'untrusted history annotation'}
        projected = snapshot.project(raw, 'daily')['nodes'][0]['destinations'][0]
        self.assertIsNone(projected['hourly_connections'])
        self.assertEqual(projected['classification']['service'], 'Telegram相关')


if __name__ == '__main__':
    unittest.main()
