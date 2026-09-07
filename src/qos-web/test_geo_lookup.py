import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

import geo_lookup as geo
import install_ipdata


def fixture(version, region='Example Country|Example Province|Example City|Example ISP|ZZ'):
    ip = ipaddress.ip_address('8.8.8.8' if version == 4 else '2001:4860:4860::8888').packed
    data = region.encode()
    data_ptr = 256 + 524288
    index_ptr = data_ptr + len(data)
    raw = bytearray(index_ptr + (14 if version == 4 else 38))
    struct.pack_into('<HHIIIHH', raw, 0, 3, 1, 1783612371, index_ptr, index_ptr, version, 4)
    struct.pack_into('<II', raw, 256 + (ip[0] * 256 + ip[1]) * 8, index_ptr, index_ptr)
    raw[data_ptr:index_ptr] = data
    address = ip[::-1] if version == 4 else ip
    raw[index_ptr:] = address + address + struct.pack('<HI', len(data), data_ptr)
    return bytes(raw)


class GeoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.blobs = {version: fixture(version) for version in (4, 6)}
        self.specs = {v: {'name': f'ip2region_v{v}.xdb', 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} for v, raw in self.blobs.items()}
        for version, raw in self.blobs.items():
            (self.directory / self.specs[version]['name']).write_bytes(raw)
        for target, name, value in ((geo, 'DATA_DIR', self.directory), (geo, 'DATASETS', self.specs), (install_ipdata, 'DATASETS', self.specs)):
            context = patch.object(target, name, value); context.start(); self.addCleanup(context.stop)
        self.reader = Mock(return_value=json.dumps({'nodes': [{'destinations': [
            {'kind': 'ip', 'destination': '8.8.8.8'}, {'kind': 'ip', 'destination': '2001:4860:4860::8888'}]}]}))

    def test_both_ip_families_use_actual_upstream_reader_without_network(self):
        raw_report = self.reader.return_value
        with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('network forbidden')), patch.object(socket, 'gethostbyaddr', side_effect=AssertionError('DNS forbidden')):
            for ip in ('8.8.8.8', '::ffff:8.8.8.8', '2001:4860:4860::8888'):
                with self.subTest(ip=ip):
                    result = geo.lookup('2026-09-07', ip, self.reader)
                    self.assertEqual(result['status'], 'found')
                    self.assertEqual(result['location']['isp'], 'Example ISP')
                    self.assertEqual(result['location']['country_code'], 'ZZ')
                    self.assertEqual(result['database_date'], '2026-07-09')
                    self.assertIn('不是员工所在地', result['limitation'])
        self.assertEqual(self.reader.return_value, raw_report)

    def test_authorization_precedes_database_and_lookup(self):
        geo.lookup('2026-09-07', '8.8.8.8', self.reader)
        with patch.object(geo, 'locate') as locate:
            self.reader.return_value = '{"nodes":[]}'
            with self.assertRaises(FileNotFoundError): geo.lookup('2026-09-07', '8.8.8.8', self.reader)
            self.reader.side_effect = FileNotFoundError('expired')
            with self.assertRaises(FileNotFoundError): geo.lookup('2026-09-07', '8.8.8.8', self.reader)
            locate.assert_not_called()

    def test_private_invalid_and_unobserved_addresses_rejected(self):
        with patch.object(geo, 'locate') as locate:
            for value in ('10.0.0.1', '::1', 'example.com', '8.8.8.8%eth0', True, '224.0.0.1'):
                with self.subTest(value=value), self.assertRaises(ValueError): geo.lookup('2026-09-07', value, self.reader)
            with self.assertRaises(FileNotFoundError): geo.lookup('2026-09-07', '1.1.1.1', self.reader)
            locate.assert_not_called()

    def test_missing_corrupt_and_changed_database_fail_closed(self):
        path = self.directory / self.specs[4]['name']
        geo.lookup('2026-09-07', '8.8.8.8', self.reader)
        raw = bytearray(self.blobs[4]); raw[-1] ^= 1; path.write_bytes(raw)
        self.assertEqual(geo.lookup('2026-09-07', '8.8.8.8', self.reader)['status'], 'unavailable')
        path.write_bytes(b'truncated')
        self.assertEqual(geo.lookup('2026-09-07', '8.8.8.8', self.reader)['status'], 'unavailable')
        path.unlink()
        self.assertEqual(geo.lookup('2026-09-07', '8.8.8.8', self.reader)['status'], 'not_installed')

    def test_missing_values_and_malformed_records(self):
        self.assertIsNone(geo.fields(''))
        self.assertIsNone(geo.fields('0|0|0|0|0'))
        self.assertIsNone(geo.fields('Example|0|0|0|ZZ')['city'])
        for value in ('A|B', 'A|B|C|D|bad', 'A|B|C\n<script>|D|ZZ', 'A' * 1025):
            with self.assertRaises(ValueError): geo.fields(value)
        with patch.object(geo.searcher, 'new_with_file_only') as factory:
            engine = factory.return_value
            engine.search.return_value = ''
            self.assertEqual(geo.lookup('2026-09-07', '8.8.8.8', self.reader)['status'], 'not_found')
            engine.close.assert_called_once()

    def test_reader_closed_and_busy_is_bounded(self):
        with patch.object(geo.searcher, 'new_with_file_only') as factory:
            engine = factory.return_value; engine.search.side_effect = ValueError('private path detail')
            result = geo.lookup('2026-09-07', '8.8.8.8', self.reader)
            self.assertEqual(result['status'], 'unavailable')
            self.assertNotIn('private path', json.dumps(result))
            engine.close.assert_called_once()
        geo.SLOTS.acquire(); geo.SLOTS.acquire()
        try: self.assertEqual(geo.lookup('2026-09-07', '8.8.8.8', self.reader)['status'], 'busy')
        finally: geo.SLOTS.release(); geo.SLOTS.release()

    def test_node_batch_verifies_each_family_once_and_skips_domains(self):
        self.reader.return_value = json.dumps({'nodes': [{'key': 'node:1', 'destinations': [
            {'kind': 'ip', 'destination': '8.8.8.8'}, {'kind': 'ip', 'destination': '8.8.8.8'},
            {'kind': 'ip', 'destination': '2001:4860:4860::8888'},
            {'kind': 'ip', 'destination': '10.0.0.1'}, {'kind': 'domain', 'destination': 'example.test'}]}]})
        with patch.object(geo, 'verify_database', wraps=geo.verify_database) as verify, patch.object(geo.searcher, 'new_with_file_only', wraps=geo.searcher.new_with_file_only) as factory, patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS not allowed')):
            result = geo.lookup_node('2026-09-07', 'node:1', self.reader)
            self.assertEqual(verify.call_count, 2)
            self.assertEqual(factory.call_count, 2)
            self.assertEqual(result['report_date'], '2026-09-07')
            self.assertEqual(result['node_key'], 'node:1')
            self.assertEqual(len(result['results']), 3)
            self.assertEqual(result['results']['10.0.0.1']['status'], 'not_public')
            self.assertEqual(result['results']['8.8.8.8']['status'], 'found')
            self.assertNotIn('example.test', result['results'])
            geo.lookup_node('2026-09-07', 'node:1', self.reader)
            self.assertEqual(verify.call_count, 4, 'each new batch must recheck actual bytes')

    def test_node_batch_membership_retention_and_bounds_precede_lookup(self):
        with patch.object(geo, 'locate_many') as locate:
            for key in ('', 'a' * 101, [], None):
                with self.assertRaises(ValueError): geo.lookup_node('2026-09-07', key, self.reader)
            with self.assertRaises(FileNotFoundError): geo.lookup_node('2026-09-07', 'missing', self.reader)
            self.reader.return_value = json.dumps({'nodes': [{'key': 'node:1', 'destinations': [{'kind': 'ip', 'destination': '8.8.8.8'}] * 101}]})
            with self.assertRaises(ValueError): geo.lookup_node('2026-09-07', 'node:1', self.reader)
            self.reader.side_effect = FileNotFoundError('expired')
            with self.assertRaises(FileNotFoundError): geo.lookup_node('2026-09-07', 'node:1', self.reader)
            locate.assert_not_called()
        with self.assertRaises(ValueError): geo.locate_many(['8.8.8.8'] * 101)

    def test_node_batch_empty_and_one_family_failure_are_isolated(self):
        self.reader.return_value = json.dumps({'nodes': [{'key': 'node:1', 'destinations': []}]})
        with patch.object(geo, 'verify_database') as verify:
            self.assertEqual(geo.lookup_node('2026-09-07', 'node:1', self.reader)['results'], {})
            verify.assert_not_called()
        (self.directory / self.specs[6]['name']).unlink()
        result = geo.locate_many(['8.8.8.8', '2001:4860:4860::8888'])
        self.assertEqual(result['8.8.8.8']['status'], 'found')
        self.assertEqual(result['2001:4860:4860::8888']['status'], 'not_installed')

    def test_installer_reuses_verified_files_without_network(self):
        with patch.object(install_ipdata, 'download') as download:
            install_ipdata.install(self.directory)
            download.assert_not_called()
        self.assertEqual((self.directory / self.specs[4]['name']).read_bytes(), self.blobs[4])

    @unittest.skipIf(os.name == 'nt', 'POSIX directory modes')
    def test_new_install_directory_readable_under_private_umask(self):
        destination = self.directory / 'new-ipdata'
        def download(spec, target):
            version = 4 if spec['name'].endswith('v4.xdb') else 6
            target.write_bytes(self.blobs[version])
        old_mask = os.umask(0o077)
        try:
            with patch.object(install_ipdata, 'download', side_effect=download): install_ipdata.install(destination)
        finally:
            os.umask(old_mask)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
        self.assertEqual((destination / self.specs[4]['name']).stat().st_mode & 0o777, 0o644)

    def test_installer_failure_does_not_replace_existing_family(self):
        path = self.directory / self.specs[6]['name']; path.write_bytes(b'old database')
        with patch.object(install_ipdata, 'download', side_effect=ValueError('checksum mismatch')):
            with self.assertRaises(ValueError): install_ipdata.install(self.directory)
        self.assertEqual(path.read_bytes(), b'old database')
        self.assertEqual((self.directory / self.specs[4]['name']).read_bytes(), self.blobs[4])
        self.assertFalse(list(self.directory.glob('.ipdata-download-*')))

    def test_download_rejects_oversize_and_bad_hash_and_redirects(self):
        for raw in (b'oversized', b'bad'):
            with patch.object(install_ipdata.urllib.request, 'build_opener') as opener:
                opener.return_value.open.return_value = io.BytesIO(raw)
                with self.assertRaises(ValueError): install_ipdata.download({'name': 'test.xdb', 'size': 3, 'sha256': '0'*64}, self.directory / 'test-download')
            (self.directory / 'test-download').unlink()
        with self.assertRaises(ValueError): install_ipdata.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://example.test/')


if __name__ == '__main__':
    unittest.main()
