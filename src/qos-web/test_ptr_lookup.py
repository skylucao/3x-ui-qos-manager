import json
import unittest
from urllib.parse import urlsplit
from unittest.mock import Mock, patch
import ptr_lookup as ptr


class PtrTests(unittest.TestCase):
    def setUp(self):
        ptr.CACHE.clear()
        ptr.LAST_QUERY = -1000
        self.reader = Mock(return_value=json.dumps({'nodes': [{'destinations': [{'kind': 'ip', 'destination': '8.8.8.8'}]}]}))

    def test_public_validation(self):
        for value in ('127.0.0.1', '10.0.0.1', '169.254.1.1', '::1', 'fc00::1', 'ff0e::1', '224.0.0.1', '0.0.0.0', '100.64.0.1', '203.0.113.1', 'fec0::1', '::ffff:127.0.0.1', '2001:4860:4860::8888%eth0', '-x', True):
            with self.subTest(value=value), self.assertRaises(ValueError): ptr.public_ip(value)
        self.assertEqual(ptr.public_ip('::ffff:8.8.8.8'), '8.8.8.8')
        self.assertEqual(ptr.public_ip('2001:4860:4860:0:0:0:0:8888'), '2001:4860:4860::8888')

    def test_hostname_is_plain_validated_text(self):
        self.assertEqual(ptr.hostname('DNS.Google.'), 'dns.google')
        for value in ('<script>', 'abc\n.com', 'https://example.com/', '-bad.test', 'bad..test', '8.8.8.8', 'a'*64 + '.test'):
            with self.assertRaises(ValueError): ptr.hostname(value)

    def test_cache_rechecks_membership_and_expiry(self):
        with patch.object(ptr, 'exchange', return_value={'status': 'found', 'hostname': 'dns.google'}) as exchange:
            self.assertFalse(ptr.lookup('2026-09-07', '8.8.8.8', self.reader)['cached'])
            self.assertTrue(ptr.lookup('2026-09-07', '8.8.8.8', self.reader)['cached'])
            exchange.assert_called_once()
            self.reader.return_value = '{"nodes":[]}'
            with self.assertRaises(FileNotFoundError): ptr.lookup('2026-09-07', '8.8.8.8', self.reader)
            self.reader.side_effect = FileNotFoundError('expired')
            with self.assertRaises(FileNotFoundError): ptr.lookup('2026-09-07', '8.8.8.8', self.reader)

    def test_unknown_and_domain_never_resolved(self):
        with patch.object(ptr, 'exchange') as exchange:
            with self.assertRaises(FileNotFoundError): ptr.lookup('2026-09-07', '1.1.1.1', self.reader)
            with self.assertRaises(ValueError): ptr.lookup('2026-09-07', 'example.com', self.reader)
            exchange.assert_not_called()

    def test_failure_cached_and_concurrency_bounded(self):
        with patch.object(ptr, 'exchange', side_effect=OSError('private error')) as exchange:
            self.assertEqual(ptr.lookup('2026-09-07', '8.8.8.8', self.reader)['status'], 'unavailable')
            self.assertTrue(ptr.lookup('2026-09-07', '8.8.8.8', self.reader)['cached'])
            exchange.assert_called_once()
        ptr.CACHE.clear()
        ptr.SLOTS.acquire(); ptr.SLOTS.acquire()
        try: self.assertEqual(ptr.lookup('2026-09-07', '8.8.8.8', self.reader)['status'], 'busy')
        finally: ptr.SLOTS.release(); ptr.SLOTS.release()

    def test_cache_ttl(self):
        with patch.object(ptr, 'exchange', return_value={'status': 'not_found', 'hostname': None}) as exchange, patch.object(ptr.time, 'monotonic', side_effect=[0, 601]):
            ptr.lookup('2026-09-07', '8.8.8.8', self.reader)
            self.assertFalse(ptr.lookup('2026-09-07', '8.8.8.8', self.reader)['cached'])
            self.assertEqual(exchange.call_count, 2)

    def test_reference_rules_have_provenance_and_low_confidence(self):
        for suffix, exact, possibility, uses, source in ptr.REFERENCE_RULES:
            name = suffix if exact else 'sample.' + suffix
            with self.subTest(name=name):
                value = ptr.reference_for(name.upper() + '.')
                self.assertEqual(value['confidence'], 'low')
                self.assertEqual(value['possibility'], possibility)
                self.assertIn(suffix, value['basis'])
                self.assertEqual(urlsplit(source).scheme, 'https')
                self.assertIn('不能证明', value['limitation'])

    def test_reference_suffix_boundaries_and_unknown_fallback(self):
        for value in (None, '<script>', '8.8.8.8', 'youtube.example.test', 'qq.example.test',
                      'not1e100.net', '1e100.net.evil.test', 'a.dns.google', 'telegram.org.evil.test',
                      'notgithub.com', 'unknown.example.test'):
            with self.subTest(value=value):
                result = ptr.reference_for(value)
                self.assertEqual(result['confidence'], 'unknown')
                self.assertIsNone(result['source_url'])
                self.assertIn('无法确定', result['possibility'])

    def test_reference_never_claims_specific_product_on_shared_cloud(self):
        for name in ('host.1e100.net', 'bucket.amazonaws.com', 'a.googleusercontent.com',
                     'a.cloudfront.net', 'vm.cloudapp.azure.com'):
            with self.subTest(name=name):
                result = ptr.reference_for(name)
                self.assertEqual(result['confidence'], 'low')
                self.assertNotIn('YouTube', result['possibility'])
                self.assertNotIn('EC2', result['possibility'])

    def test_reference_is_response_only_and_recreated_after_cache(self):
        raw = self.reader.return_value
        dns = {'status': 'found', 'hostname': 'dns.google'}
        with patch.object(ptr, 'exchange', return_value=dns):
            first = ptr.lookup('2026-09-07', '8.8.8.8', self.reader)
            self.assertEqual(first['reference']['confidence'], 'low')
            first['reference']['possibility'] = 'changed by caller'
            second = ptr.lookup('2026-09-07', '8.8.8.8', self.reader)
            self.assertTrue(second['cached'])
            self.assertNotEqual(second['reference']['possibility'], 'changed by caller')
        self.assertEqual(self.reader.return_value, raw)
        self.assertNotIn('reference', dns)
        self.assertNotIn('reference', ptr.CACHE['8.8.8.8'][1])

    def test_negative_results_have_no_service_guess(self):
        for status in ('not_found', 'timeout', 'unavailable', 'busy'):
            result = ptr.present({'status': status, 'hostname': 'dns.google'})
            self.assertEqual(result['reference']['confidence'], 'unknown')
