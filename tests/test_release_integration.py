#!/usr/bin/env python3
"""Non-mutating packaging tests; never run a live installer from CI."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class ReleaseIntegrationTests(unittest.TestCase):
    def test_version_refs_match(self):
        version = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
        installer = (ROOT / 'install.sh').read_text(encoding='utf-8')
        self.assertIn('VERSION=' + version, installer)
        self.assertIn('DEFAULT_RELEASE_REF="v' + version + '"', installer)
        self.assertIn('/v' + version + '/install.sh', (ROOT / 'README.md').read_text(encoding='utf-8'))
        self.assertIn('/refs/tags/v' + version + '.tar.gz', (ROOT / 'scripts/install-audit.sh').read_text(encoding='utf-8'))

    def test_notes_modules_storage_and_verification_wired(self):
        installer = (ROOT / 'install.sh').read_text(encoding='utf-8')
        for name in ('audit_view.py', 'node_notes.py'):
            self.assertIn('/opt/xray-qos-web/' + name, installer)
        self.assertIn('runuser -u xray-qos-web -- python3 -B /opt/xray-qos-web/node_notes.py', installer)
        unit = (ROOT / 'src/systemd/xray-qos-web.service').read_text(encoding='utf-8')
        self.assertIn('StateDirectory=xray-qos-web', unit)
        self.assertIn('StateDirectoryMode=0700', unit)
        self.assertIn('node_notes.read', (ROOT / 'src/qos-web/healthcheck.py').read_text(encoding='utf-8'))
        self.assertNotIn('/var/lib/xray-qos-web\n', installer.split('project_paths=(', 1)[1].split(')', 1)[0])

    def test_audit_is_opt_in_and_example_has_no_real_recipient(self):
        installer = (ROOT / 'install.sh').read_text(encoding='utf-8')
        self.assertNotIn('systemctl enable xray-audit-', installer)
        self.assertNotIn('activate_logging.py', installer)
        config = json.loads((ROOT / 'src/xray-audit/config.json.example').read_text(encoding='utf-8'))
        self.assertEqual(config['recipient'], 'owner@example.com')
        self.assertEqual(config['report_retention_days'], 2)
        self.assertEqual(config['raw_log_retention_days'], 2)

    @unittest.skipIf(os.name == 'nt', 'Optional installer requires Linux fcntl')
    def test_audit_installer_requires_explicit_notice_before_mutation(self):
        sys.path.insert(0, str(ROOT / 'src/xray-audit'))
        self.addCleanup(lambda: sys.path.remove(str(ROOT / 'src/xray-audit')))
        spec = importlib.util.spec_from_file_location('optional_audit_installer', ROOT / 'src/xray-audit/install_audit.py')
        installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)
        with patch.object(installer, 'run') as run:
            with self.assertRaises(SystemExit):
                installer.main(['--recipient', 'owner@example.com'])
            run.assert_not_called()
        with tempfile.TemporaryDirectory() as directory, patch.object(installer, 'UNIT', Path(directory)), patch.object(installer, 'run') as run:
            installer.stop_existing_timers()
            run.assert_not_called()
            (Path(directory) / 'xray-audit-snapshot.timer').write_text('unit')
            installer.stop_existing_timers()
            run.assert_called_once_with('systemctl', 'stop', 'xray-audit-snapshot.timer')
        runtime = {'log': {'access': '/var/log/x-ui/access.log'}, 'api': {'tag': 'api', 'services': ['LoggerService']}, 'inbounds': [{'tag': 'api', 'listen': '127.0.0.1', 'port': 62789}]}
        installer.validate_runtime(runtime)
        runtime['inbounds'][0]['listen'] = '0.0.0.0'
        with self.assertRaises(ValueError):
            installer.validate_runtime(runtime)
        for name in installer.PROGRAMS + installer.UNITS:
            self.assertTrue((ROOT / 'src/xray-audit' / name).is_file(), name)


class SettingsIntegrationTests(unittest.TestCase):
    def test_ip_geo_reader_and_pinned_download_wired_before_mutations(self):
        installer = (ROOT / 'install.sh').read_text(encoding='utf-8')
        for name in ('geo_lookup.py', 'install_ipdata.py'):
            self.assertIn('/opt/xray-qos-web/' + name, installer)
        self.assertLess(installer.index('--destination "$temporary_root/ipdata"'), installer.index('installing the official stable channel'))
        self.assertIn('/opt/xray-qos-web/ipdata/ip2region_v${family}.xdb', installer)
        for name in ('__init__.py', 'searcher.py', 'util.py', 'LICENSE', 'LICENSE.upstream', 'NOTICE.md'):
            self.assertTrue((ROOT / 'src/qos-web/ip2region' / name).is_file())
        self.assertFalse(list(ROOT.rglob('*.xdb')))
        unit = (ROOT / 'src/systemd/xray-qos-web.service').read_text(encoding='utf-8')
        self.assertIn('IPAddressDeny=any', unit)
        self.assertIn('MemoryMax=96M', unit)

    def test_schedule_preserved_on_uninstall_and_ptr_stopped(self):
        uninstall = (ROOT / 'scripts/uninstall.sh').read_text()
        self.assertNotIn('rm -rf -- /opt/xray-qos-web /etc/xray-qos-web /etc/xray-qos', uninstall)
        self.assertIn('systemctl stop xray-audit-ptr.socket', uninstall)
        self.assertIn('rmdir -- /etc/xray-qos', uninstall)
        self.assertIn('PTR_WAS_ACTIVE', (ROOT / 'scripts/rollback-install.sh').read_text())

    def test_schedule_timer_gates_in_runner(self):
        timer = (ROOT / 'src/xray-audit/xray-audit-daily.timer').read_text()
        self.assertIn('OnCalendar=*-*-* *:*:00 Asia/Shanghai', timer)
        self.assertIn('Persistent=false', timer)
        self.assertIn('daily.py --scheduled', (ROOT / 'src/xray-audit/xray-audit-daily.service').read_text())
        installer = (ROOT / 'install.sh').read_text()
        for name in ('schedule_config.py', 'ptr_lookup.py'):
            self.assertIn('"$source_root/src/qos-web/' + name + '"', installer)


if __name__ == '__main__':
    unittest.main()
