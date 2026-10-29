"""Official AnyTLS URI generation and lifecycle checks using synthetic accounts."""
import base64
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, unquote, urlsplit


HELPER = Path(__file__).resolve().parents[1] / 'src/anytls-state.py'
spec = importlib.util.spec_from_file_location('shadowrocket_state', HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
PUBLIC_CERTIFICATE = b'-----BEGIN CERTIFICATE-----\nU1lOVEhFVElD\n-----END CERTIFICATE-----\n'


class ShadowrocketTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='anyharbor-shadowrocket-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.state_path = self.directory / 'state.json'
        helper.main(['init', str(self.state_path), '203.0.113.9', '38225'])
        self.state = helper.load(self.state_path)
        self.state['groups'] = self.state['groups'][:3]
        self.state['groups'][1]['enabled'] = False
        self.state['groups'][0]['password'] = 'Synthetic-password-@:/?#%+&= 中文 space'
        self.state['groups'][0]['label'] = 'Athena 雅典娜 /?#%+&='
        self.state['sni'] = 'proxy.example.test'
        self.state['tls_mode'], self.state['tls_verify'] = 'imported', 'pki'
        self.state['subscription'] = {'domain': 'sub.example.test', 'port': 38226}
        self.render()

    def render(self):
        helper.write_json(self.state_path, self.state)
        with mock.patch.object(helper, 'certificate_info', return_value='ab' * 32), \
                mock.patch.object(helper, 'call', return_value=PUBLIC_CERTIFICATE):
            helper.render(self.directory)

    def snapshot(self):
        return {str(path.relative_to(self.directory)): path.read_bytes()
                for path in self.directory.rglob('*') if path.is_file()}

    def invoke(self, command, *arguments):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            helper.main([command, str(self.state_path), *map(str, arguments)])
        return stream.getvalue()

    def reject_without_output(self, command, *arguments):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), self.assertRaises(ValueError) as error:
            helper.main([command, str(self.state_path), *map(str, arguments)])
        self.assertEqual(stream.getvalue(), '')
        for group in self.state['groups']:
            self.assertNotIn(group['password'], str(error.exception))
            self.assertNotIn(group['token'], str(error.exception))
        return str(error.exception)

    def test_uri_uses_official_fields_percent_encoding_and_verified_tls(self):
        group = self.state['groups'][0]
        output = self.invoke('export-shadowrocket', self.directory, 'athena')
        self.assertEqual(len(output.splitlines()), 1)
        self.assertEqual(output, (self.directory / 'shadowrocket/athena.txt').read_text())
        self.assertTrue(output.startswith('anytls://'))
        uri = urlsplit(output.strip())
        self.assertEqual(unquote(uri.username), group['password'])
        self.assertIsNone(uri.password)  # Auth belongs in the URI username field.
        self.assertEqual(uri.hostname, '203.0.113.9')
        self.assertEqual(uri.port, 38225)
        self.assertEqual(parse_qs(uri.query), {'sni': ['proxy.example.test'], 'insecure': ['0']})
        self.assertEqual(unquote(uri.fragment), 'GZ AnyTLS · ' + group['label'])
        for encoded in ('%40', '%3A', '%2F', '%3F', '%23', '%25', '%2B', '%26', '%3D', '%20'):
            self.assertIn(encoded, uri.username)
        self.assertNotIn(group['password'], output)
        self.assertNotIn(' ', output.strip())
        self.assertNotIn('insecure=1', output)

    def test_ipv6_formatter_brackets_address_without_changing_sni_or_port(self):
        # The formatter supports the official URI syntax. This does not widen
        # the manager's existing IPv4/DNS installation and listener contract.
        state = {**self.state, 'server': '2001:db8::42', 'port': 65432}
        output = helper.shadowrocket_share(state, state['groups'][0], 'IPv6 / node')
        self.assertIn('@[2001:db8::42]:65432/', output)
        uri = urlsplit(output)
        self.assertEqual(uri.hostname, '2001:db8::42')
        self.assertEqual(uri.port, 65432)
        self.assertEqual(parse_qs(uri.query)['sni'], [state['sni']])
        self.assertEqual(unquote(uri.fragment), 'IPv6 / node')

    def test_display_override_and_domain_address_are_preserved(self):
        group = self.state['groups'][0]
        group['node_name'] = 'Custom / 测试 # Node'
        self.state['server'] = 'edge.example.test'
        self.render()
        uri = urlsplit(self.invoke('export-shadowrocket', self.directory, 'athena').strip())
        self.assertEqual(uri.hostname, 'edge.example.test')
        self.assertEqual(unquote(uri.fragment), group['node_name'])
        self.assertEqual(parse_qs(uri.query)['sni'], ['proxy.example.test'])

    def test_standard_base64_subscription_and_original_formats_share_exact_account(self):
        before = copy.deepcopy(self.state)
        for group in helper.active(self.state):
            node, profile, v2rayn = helper.group_documents(self.state, group, None, None)
            for path, expected in [
                    ('nodes/' + group['id'] + '.yaml', node),
                    ('profiles/' + group['id'] + '.yaml', profile),
                    ('subscriptions/' + group['token'] + '.yaml', profile),
                    ('v2rayn/' + group['id'] + '.txt', v2rayn),
                    ('subscriptions_v2rayn/' + group['token'] + '.txt',
                     base64.b64encode(v2rayn.encode()).decode() + '\n')]:
                self.assertEqual((self.directory / path).read_bytes(), expected.encode())
            raw = (self.directory / 'shadowrocket' / (group['id'] + '.txt')).read_bytes()
            subscription = (self.directory / 'subscriptions_shadowrocket' / (group['token'] + '.txt')).read_bytes()
            self.assertEqual(subscription, base64.b64encode(raw) + b'\n')
            self.assertEqual(base64.b64decode(subscription.strip(), validate=True), raw)
            payload = v2rayn.strip().removeprefix('v2rayn://anytls/')
            old = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
            uri = urlsplit(raw.decode().strip())
            self.assertEqual(unquote(uri.username), old['Password'])
            self.assertEqual(uri.hostname, old['Address'])
            self.assertEqual(uri.port, old['Port'])
            self.assertEqual(unquote(uri.fragment), old['Remarks'])
            self.assertEqual(parse_qs(uri.query)['sni'], [old['Sni']])
        self.assertEqual(helper.load(self.state_path), before)
        self.assertFalse((self.directory / 'shadowrocket/apollo.txt').exists())

    def test_exports_are_read_only_and_missing_third_format_never_prints_partial_credentials(self):
        before = self.snapshot()
        self.invoke('export-shadowrocket', self.directory, 'athena')
        self.invoke('export-all', self.directory, 'athena')
        self.invoke('links', 'shadowrocket', 'athena')
        self.invoke('links-all', 'athena')
        self.assertEqual(self.snapshot(), before)
        for group in ('apollo', 'missing', '../athena'):
            self.reject_without_output('export-shadowrocket', self.directory, group)
            self.reject_without_output('links', 'shadowrocket', group)
        self.reject_without_output('export-shadowrocket', self.directory)
        self.reject_without_output('export-shadowrocket', self.directory, 'athena', 'extra')
        (self.directory / 'shadowrocket/athena.txt').unlink()
        self.reject_without_output('export-shadowrocket', self.directory, 'athena')
        self.reject_without_output('export-all', self.directory, 'athena')

    def test_pin_rerender_clears_shadowrocket_outputs_without_rotating_accounts(self):
        self.state['tls_verify'] = 'pin'
        self.render()
        for name in ('shadowrocket', 'subscriptions_shadowrocket'):
            self.assertTrue((self.directory / name).is_dir())
            self.assertEqual(list((self.directory / name).iterdir()), [])
        self.assertEqual(helper.load(self.state_path)['groups'], self.state['groups'])
        for command in ('export-shadowrocket',):
            message = self.reject_without_output(command, self.directory, 'athena')
            self.assertIn('证书固定', message)
        self.reject_without_output('links', 'shadowrocket', 'athena')
        for command, arguments in [('export-all', (self.directory, 'athena')), ('links-all', ('athena',))]:
            output = self.invoke(command, *arguments)
            self.assertIn('证书固定', output)
            self.assertNotIn('anytls://', output)
            self.assertNotIn('/r/', output)
            self.assertIn('v2rayN', output)
            self.assertIn('Clash', output)

    def test_pin_rejects_even_stale_shadowrocket_files_before_reading_credentials(self):
        before = self.snapshot()
        self.state['tls_verify'] = 'pin'
        helper.write_json(self.state_path, self.state)
        self.assertEqual((self.directory / 'shadowrocket/athena.txt').read_bytes(), before['shadowrocket/athena.txt'])
        self.reject_without_output('export-shadowrocket', self.directory, 'athena')
        self.reject_without_output('links', 'shadowrocket', 'athena')
        self.assertNotIn('anytls://', self.invoke('export-all', self.directory, 'athena'))
        with self.assertRaisesRegex(ValueError, '证书固定'):
            helper.shadowrocket_share(self.state, self.state['groups'][0], 'Athena')

    def test_rotate_removes_old_token_and_preserves_other_groups_all_formats(self):
        group = self.state['groups'][0]
        old = copy.deepcopy(group)
        other = self.state['groups'][2]
        before = self.snapshot()
        helper.edit_group(self.state, 'rotate', ['athena'])
        self.render()
        self.assertNotEqual(group['token'], old['token'])
        self.assertNotEqual(group['password'], old['password'])
        for directory, suffix in [('subscriptions', '.yaml'), ('subscriptions_v2rayn', '.txt'),
                                  ('subscriptions_shadowrocket', '.txt')]:
            self.assertFalse((self.directory / directory / (old['token'] + suffix)).exists())
            self.assertTrue((self.directory / directory / (group['token'] + suffix)).is_file())
            path = directory + '/' + other['token'] + suffix
            self.assertEqual((self.directory / path).read_bytes(), before[path])
        uri = urlsplit(self.invoke('export-shadowrocket', self.directory, 'athena').strip())
        self.assertEqual(unquote(uri.username), group['password'])
        self.assertEqual(helper.load(self.state_path)['groups'][2], other)

    def test_disable_reenable_and_remove_clear_plain_and_subscription_residue(self):
        group = self.state['groups'][0]
        for action in ('disable', 'enable', 'remove'):
            with self.subTest(action=action):
                old = copy.deepcopy(group)
                helper.edit_group(self.state, action, ['athena'])
                self.render()
                for directory, suffix in [('subscriptions', '.yaml'), ('subscriptions_v2rayn', '.txt'),
                                          ('subscriptions_shadowrocket', '.txt')]:
                    self.assertFalse((self.directory / directory / (old['token'] + suffix)).exists())
                self.assertEqual((self.directory / 'shadowrocket/athena.txt').exists(), action == 'enable')
                self.assertTrue((self.directory / 'shadowrocket/hermes.txt').is_file())
                if action != 'enable':
                    self.reject_without_output('export-shadowrocket', self.directory, 'athena')
                    self.reject_without_output('links', 'shadowrocket', 'athena')


if __name__ == '__main__':
    unittest.main()
