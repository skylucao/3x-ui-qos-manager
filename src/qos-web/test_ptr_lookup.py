import json
import unittest
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
