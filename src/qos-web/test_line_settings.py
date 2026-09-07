import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.name == 'posix', 'QoS CLI requires Linux/fcntl')
class LineSettingsTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).parents[1] / 'xray-qos'
        loader = importlib.machinery.SourceFileLoader('tested_qos', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.q = importlib.util.module_from_spec(spec); sys.modules[loader.name] = self.q; loader.exec_module(self.q)
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name); self.file = self.root / 'qos.conf'
        self.file.write_bytes(b'WAN=eth0\nDEFAULT_RATE=50mbit\nLINK_EGRESS=1000mbit\nMGMT_PORTS="22 2096"\n')
        self.profiles = {'version': 1, 'revision': 4, 'nodes': {'2': {'download_mbps': 100, 'upload_mbps': 30}}}
        self.config = self.q.Config('eth0', 1000000, 50000, frozenset([22, 2096]), self.root / 'xui.db', self.root / 'nodes.json')
        for key, value in [('CONFIG_PATH', self.file), ('load_config', lambda: self.config), ('read_profiles', lambda path: self.profiles), ('trusted_regular_file', lambda *a, **k: None), ('discover_inbounds', lambda path: []), ('build_plan', lambda *a: {'old': True})]:
            mocked = patch.object(self.q, key, value); mocked.start(); self.addCleanup(mocked.stop)
        self.old = self.file.read_bytes()
        self.rev = self.q.line_revision(self.old, self.profiles)

    def test_noop_never_rebuilds_and_invalid_never_writes(self):
        with patch.object(self.q, 'synchronize') as sync:
            self.q.set_line(1000, 50, self.rev)
            for args in [(99, 1, self.rev), (1000, 1000, self.rev), (True, 1, self.rev), (1000, 50, 'stale')]:
                with self.assertRaises(self.q.QosError): self.q.set_line(*args)
            sync.assert_not_called()
        self.assertEqual(self.file.read_bytes(), self.old)

    def test_apply_preserves_unrelated_config_and_profiles(self):
        with patch.object(self.q, 'synchronize') as sync:
            self.q.set_line(900, 40, self.rev); sync.assert_called_once()
        self.assertIn(b'LINK_EGRESS=900mbit', self.file.read_bytes())
        self.assertIn(b'MGMT_PORTS="22 2096"', self.file.read_bytes())
        self.assertEqual(self.profiles['revision'], 4)

    def test_tc_failure_restores_config_and_plan(self):
        with patch.object(self.q, 'synchronize', side_effect=self.q.QosError('tc failure')), patch.object(self.q, 'apply_transaction') as restore:
            with self.assertRaises(self.q.QosError): self.q.set_line(900, 40, self.rev)
            restore.assert_called_once_with({'old': True}, force=True)
        self.assertEqual(self.file.read_bytes(), self.old)

    def test_recovery_failure_is_reported(self):
        with patch.object(self.q, 'synchronize', side_effect=self.q.QosError('tc failure')), patch.object(self.q, 'apply_transaction', side_effect=self.q.QosError('restore failure')):
            with self.assertRaisesRegex(self.q.QosError, 'recovery failed'): self.q.set_line(900, 40, self.rev)
