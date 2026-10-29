"""Per-group exit isolation, schema barriers and identity preservation."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'src' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


state = module('warp_state', 'anytls-state.py')
updater = module('warp_updater', 'anytls-update.py')


class WarpStateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='anyharbor-warp-state-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / 'state.json'
        state.main(['init', str(self.path), 'proxy.example.test', '8443'])
        self.initial = state.load(self.path)
        self.initial['tls_mode'], self.initial['tls_verify'] = 'imported', 'pki'
        state.write_json(self.path, self.initial)

    def command(self, command, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            state.main([command, str(self.path), *args])
        return output.getvalue().strip()

    def render(self):
        with mock.patch.object(state, 'certificate_info', return_value='ab' * 32):
            state.render(self.directory)
        return json.loads((self.directory / 'config.json').read_text())

    def test_existing_direct_state_does_not_migrate_or_change_runtime_shape(self):
        self.assertEqual(state.normalized(self.initial), self.initial)
        self.assertEqual(self.command('group-egress', 'athena'), 'direct')
        self.assertEqual(self.command('get', 'active_warp_group_count'), '0')
        config = self.render()
        self.assertNotIn('route', config)
        self.assertEqual(config['outbounds'], [{'type': 'direct', 'tag': 'direct'}])
        self.assertIn('    udp: true\n', (self.directory / 'profiles/athena.yaml').read_text())
        self.assertEqual(state.load(self.path), self.initial)

    def test_exit_switch_is_credentials_preserving_and_schema_barrier_is_sticky(self):
        self.command('group', 'egress', 'athena', 'warp')
        changed = state.load(self.path)
        expected = copy.deepcopy(self.initial)
        expected['schema'] = 3
        expected['groups'][0]['egress'] = 'warp'
        self.assertEqual(changed, expected)
        self.command('group', 'egress', 'athena', 'direct')
        changed = state.load(self.path)
        expected['groups'][0]['egress'] = 'direct'
        self.assertEqual(changed, expected)
        self.assertEqual(self.command('get', 'warp_group_count'), '0')
        self.assertEqual(self.command('group-egress', 'athena'), 'direct')
        self.assertEqual(changed['schema'], 3)

    def test_disabled_warp_identity_still_requires_schema_barrier(self):
        raw = copy.deepcopy(self.initial)
        raw['groups'][1].update(enabled=False, egress='warp')
        state.write_json(self.path, raw)
        normalized = state.load(self.path)
        self.assertEqual(normalized['schema'], 3)
        self.assertEqual(self.command('get', 'warp_group_count'), '1')
        self.assertEqual(self.command('get', 'active_warp_group_count'), '0')
        config = self.render()
        self.assertEqual(config['outbounds'], [{'type': 'direct', 'tag': 'direct'}])
        self.assertEqual(config['route']['rules'][-1], {'action': 'reject'})
        self.assertNotIn('apollo', config['route']['rules'][0]['auth_user'])
        self.command('group', 'remove', 'apollo')
        self.assertEqual(state.load(self.path)['schema'], 3)

    def test_invalid_exit_and_unknown_schema_fail_without_writing(self):
        saved = self.path.read_bytes()
        for invalid in ('auto', 'WARP', '', 'direct,warp'):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                self.command('group', 'egress', 'athena', invalid)
            self.assertEqual(self.path.read_bytes(), saved)
        for invalid in (None, False, [], {}, 1, 'auto'):
            raw = copy.deepcopy(self.initial)
            raw['groups'][0]['egress'] = invalid
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                state.normalized(raw)
        raw = copy.deepcopy(self.initial)
        raw['schema'] = 4
        with self.assertRaises(ValueError):
            state.normalized(raw)

    def test_auth_routes_reject_warp_udp_and_never_fall_back_to_direct(self):
        self.command('group', 'egress', 'athena', 'warp')
        self.command('group', 'egress', 'apollo', 'warp')
        self.command('group', 'disable', 'apollo')
        config = self.render()
        rules = config['route']['rules']
        self.assertEqual(config['outbounds'][1], {
            'type': 'socks', 'tag': 'warp', 'server': '127.0.0.1',
            'server_port': 40000, 'version': '5', 'network': 'tcp'})
        self.assertEqual(rules[0], {'inbound': ['anytls-in'], 'auth_user': ['athena'],
                                    'network': 'udp', 'action': 'reject'})
        self.assertEqual(rules[1], {'inbound': ['anytls-in'], 'auth_user': ['athena'],
                                    'network': 'tcp', 'action': 'route', 'outbound': 'warp'})
        self.assertEqual(set(rules[2]['auth_user']),
                         {g['id'] for g in self.initial['groups'][2:]})
        self.assertEqual(rules[2]['outbound'], 'direct')
        self.assertEqual(rules[-1], {'action': 'reject'})
        self.assertEqual({rule['action'] for rule in rules}, {'route', 'reject'})
        self.assertNotIn('dns', config)
        self.assertIn('    udp: false\n', (self.directory / 'profiles/athena.yaml').read_text())
        self.assertIn('    udp: true\n', (self.directory / 'profiles/hermes.yaml').read_text())
        self.assertFalse((self.directory / 'profiles/apollo.yaml').exists())

    def test_all_warp_groups_cannot_match_a_direct_route(self):
        for group in self.initial['groups']:
            self.command('group', 'egress', group['id'], 'warp')
        config = self.render()
        self.assertFalse(any(rule.get('outbound') == 'direct' for rule in config['route']['rules']))
        self.assertEqual(config['route']['rules'][-1], {'action': 'reject'})

    def test_core_rollback_preserves_exit_and_schema_with_current_identity(self):
        candidate = self.directory / 'candidate.json'
        historical = copy.deepcopy(self.initial)
        historical['port'] = 9444
        state.write_json(candidate, historical)
        self.command('group', 'egress', 'athena', 'warp')
        self.command('group', 'rotate', 'apollo')
        current = state.load(self.path)
        state.main(['preserve-identity', str(self.path), str(candidate)])
        merged = state.load(candidate)
        self.assertEqual(merged['groups'], current['groups'])
        self.assertEqual(merged['schema'], 3)
        self.assertEqual(merged['port'], 9444)
        self.assertEqual(merged['subscription'], current['subscription'])

    def test_lists_report_exit_without_credentials(self):
        self.command('group', 'egress', 'athena', 'warp')
        text = self.command('list')
        ui = self.command('list-ui')
        self.assertIn('athena\tAthena\tenabled\twarp', text)
        self.assertIn('apollo\tApollo\tenabled\tdirect', text)
        self.assertIn('WARP · TCP', ui)
        self.assertIn('直连', ui)
        for group in state.load(self.path)['groups']:
            self.assertNotIn(group['password'], text + ui)
            self.assertNotIn(group['token'], text + ui)

    @unittest.skipUnless(shutil.which('sing-box') and shutil.which('openssl'),
                         'The packaged Linux integration image provides sing-box and OpenSSL.')
    def test_real_core_accepts_generated_auth_user_reject_and_socks_config(self):
        current = state.load(self.path)
        current['tls_mode'], current['tls_verify'] = 'self-signed', 'pin'
        state.write_json(self.path, current)
        state.main(['certificate', str(self.directory)])
        self.command('group', 'egress', 'athena', 'warp')
        state.render(self.directory)
        checked = subprocess.run(['sing-box', 'check', '-c', str(self.directory / 'config.json')],
                                 capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)


class WarpUpgradeProtectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='anyharbor-warp-upgrade-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.old, self.new = root / 'old', root / 'new'
        self.old.mkdir()
        state.main(['init', str(self.old / 'state.json'), 'proxy.example.test', '8443'])
        for name in ('sing-box', 'server.crt', 'server.key'):
            (self.old / name).write_text('synthetic-' + name)
        (self.old / 'config.json').write_text('{"outbounds":[{"type":"direct","tag":"direct"}]}')
        shutil.copytree(self.old, self.new)

    def modify(self, directory, change):
        path = directory / 'state.json'
        raw = json.loads(path.read_text())
        change(raw)
        state.write_json(path, raw)

    def test_bootstrap_upgrade_preserves_schema2_and_default_direct(self):
        self.assertEqual(updater.protect(self.old, self.new), 'same_runtime')
        self.modify(self.new, lambda raw: raw['groups'][0].update(egress='direct'))
        self.assertEqual(updater.protect(self.old, self.new), 'same_runtime')

    def test_upgrade_rejects_exit_change_with_identical_password_and_token(self):
        self.modify(self.new, lambda raw: raw.update(schema=3))
        self.modify(self.new, lambda raw: raw['groups'][0].update(egress='warp'))
        with self.assertRaisesRegex(ValueError, 'egress'):
            updater.protect(self.old, self.new)
        self.modify(self.old, lambda raw: raw.update(schema=3))
        self.modify(self.old, lambda raw: raw['groups'][0].update(egress='warp'))
        self.assertEqual(updater.protect(self.old, self.new), 'same_runtime')
        self.modify(self.new, lambda raw: raw['groups'][0].pop('egress'))
        with self.assertRaisesRegex(ValueError, 'egress'):
            updater.protect(self.old, self.new)

    def test_upgrade_cannot_drop_schema_barrier_even_after_all_groups_return_direct(self):
        self.modify(self.old, lambda raw: raw.update(schema=3))
        with self.assertRaisesRegex(ValueError, 'barrier'):
            updater.protect(self.old, self.new)
        self.modify(self.new, lambda raw: raw.update(schema=3))
        self.assertEqual(updater.protect(self.old, self.new), 'same_runtime')

    def test_warp_cannot_be_persisted_with_schema2_package_transport_marker(self):
        for path in (self.old, self.new):
            self.modify(path, lambda raw: raw['groups'][0].update(egress='warp'))
        with self.assertRaisesRegex(ValueError, 'barrier'):
            updater.protect(self.old, self.new)


if __name__ == '__main__':
    unittest.main()
