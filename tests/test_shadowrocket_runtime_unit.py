"""Publish new formats on upgrade without falsely rejecting older renderers."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('bash'), 'Requires Linux Bash')
class ShadowrocketRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='anyharbor-export-compare-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.old, self.new = self.base / 'old', self.base / 'new'
        for path in (self.old, self.new):
            path.mkdir()
            (path / 'state.json').write_text('{}\n')
            (path / 'profiles').mkdir()
            (path / 'profiles/athena.yaml').write_text('proxies: []\n')
        text = (ROOT / 'src/anytls-runtime.sh').read_text()
        self.function = re.search(r'^manager_exports_equal\(\) \{\n.*?^\}', text, re.M | re.S).group(0)

    def compare(self, mode=None):
        command = '\nmanager_exports_equal "$OLD" "$NEW"' + (' "$MODE"' if mode is not None else '')
        return subprocess.run(['bash', '-c', self.function + command],
                              env=os.environ | {'OLD': str(self.old), 'NEW': str(self.new),
                                                'MODE': mode or ''},
                              capture_output=True, timeout=10).returncode

    def test_legacy_generation_without_shadowrocket_remains_equal(self):
        self.assertEqual(self.compare(), 0)

    def test_new_shadowrocket_outputs_force_generation_switch(self):
        for name in ('shadowrocket', 'subscriptions_shadowrocket'):
            with self.subTest(directory=name):
                directory = self.new / name
                directory.mkdir()
                (directory / 'fixture.txt').write_text('synthetic-new-output\n')
                self.assertNotEqual(self.compare(), 0)
                shutil.rmtree(directory)

    def test_shadowrocket_changes_are_not_hidden_by_unchanged_old_formats(self):
        for name in ('shadowrocket', 'subscriptions_shadowrocket'):
            for generation in (self.old, self.new):
                (generation / name).mkdir()
                (generation / name / 'fixture.txt').write_text('same-synthetic-output\n')
        self.assertEqual(self.compare(), 0)
        self.assertEqual(self.compare('rollback'), 0)
        (self.new / 'shadowrocket/fixture.txt').write_text('changed-synthetic-output\n')
        self.assertNotEqual(self.compare(), 0)
        self.assertNotEqual(self.compare('rollback'), 0)

    def current_shadowrocket_outputs(self):
        for name in ('shadowrocket', 'subscriptions_shadowrocket'):
            (self.old / name).mkdir()
            (self.old / name / 'fixture.txt').write_text('synthetic-current-output\n')

    def test_rollback_accepts_missing_new_formats_but_upgrade_stays_strict(self):
        self.current_shadowrocket_outputs()
        self.assertNotEqual(self.compare(), 0)
        self.assertNotEqual(self.compare('strict'), 0)
        self.assertEqual(self.compare('rollback'), 0)

    def test_rollback_does_not_ignore_existing_new_format_differences(self):
        self.current_shadowrocket_outputs()
        (self.new / 'shadowrocket').mkdir()
        (self.new / 'shadowrocket/fixture.txt').write_text('different-output\n')
        self.assertNotEqual(self.compare('rollback'), 0)
        (self.new / 'shadowrocket/fixture.txt').write_text('synthetic-current-output\n')
        self.assertEqual(self.compare('rollback'), 0)

    def test_rollback_keeps_all_original_formats_strict(self):
        self.current_shadowrocket_outputs()
        for name in ('profiles', 'nodes', 'subscriptions', 'v2rayn', 'subscriptions_v2rayn'):
            with self.subTest(directory=name):
                for generation in (self.old, self.new):
                    (generation / name).mkdir(exist_ok=True)
                    (generation / name / 'fixture.txt').write_text('custom-prefix-preserved\n')
                self.assertEqual(self.compare('rollback'), 0)
                (self.new / name / 'fixture.txt').write_text('changed-or-missing-prefix\n')
                self.assertNotEqual(self.compare('rollback'), 0)
                (self.new / name / 'fixture.txt').write_text('custom-prefix-preserved\n')

    def test_rollback_rejects_changed_state_prefix_and_changed_export_name(self):
        self.current_shadowrocket_outputs()
        for generation in (self.old, self.new):
            (generation / 'state.json').write_text(json.dumps({'node_prefix': 'SG'}))
            (generation / 'profiles/athena.yaml').write_text('name: SG AnyTLS Athena\n')
        self.assertEqual(self.compare('rollback'), 0)
        (self.new / 'state.json').write_text(json.dumps({'node_prefix': 'GZ'}))
        self.assertNotEqual(self.compare('rollback'), 0)
        (self.new / 'state.json').write_text(json.dumps({'node_prefix': 'SG'}))
        (self.new / 'profiles/athena.yaml').write_text('name: GZ AnyTLS Athena\n')
        self.assertNotEqual(self.compare('rollback'), 0)

    def test_rollback_does_not_treat_a_dangling_new_format_symlink_as_absent(self):
        self.current_shadowrocket_outputs()
        (self.new / 'shadowrocket').symlink_to(self.base / 'missing')
        self.assertNotEqual(self.compare('rollback'), 0)

    def test_unknown_comparison_mode_is_rejected(self):
        self.assertNotEqual(self.compare('ignore-all'), 0)


if __name__ == '__main__':
    unittest.main()
