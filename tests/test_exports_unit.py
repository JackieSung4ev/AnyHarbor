"""Read-only export and numeric selection regressions; no network or services."""
import base64
import contextlib
import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'src/anytls-state.py'
MANAGER = ROOT / 'src/anytls-manager.sh'
SUBSCRIPTION = ROOT / 'src/anytls-subscription.sh'
spec = importlib.util.spec_from_file_location('export_state', HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
BASH = shutil.which('bash')


class ExportFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='gz-exports-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.state_path = self.directory / 'state.json'
        helper.main(['init', str(self.state_path), 'proxy.example.test', '8443'])
        self.state = helper.load(self.state_path)
        self.state['groups'] = self.state['groups'][:3]
        self.state['groups'][1]['enabled'] = False
        self.state['tls_mode'] = 'imported'
        self.state['tls_verify'] = 'pki'
        self.state['subscription'] = {'domain': 'sub.example.test', 'port': 9443}
        helper.write_json(self.state_path, self.state)
        # Actual renderer, with certificate verification outside these read-only tests.
        with mock.patch.object(helper, 'certificate_info', return_value='00' * 32):
            helper.render(self.directory)
        self.configuration = self.directory / 'nginx'
        self.configuration.mkdir()
        (self.configuration / 'nginx.conf').write_text(
            '# Subscription formats: clash,v2rayn\n# Subscription format: shadowrocket\n')

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
        with contextlib.redirect_stdout(stream), self.assertRaises((ValueError, OSError)):
            helper.main([command, str(self.state_path), *map(str, arguments)])
        self.assertEqual(stream.getvalue(), '')


class ExportStateTests(ExportFixture):
    def test_combined_export_contains_only_requested_groups_formats_without_writes(self):
        before = self.snapshot()
        output = self.invoke('export-all', self.directory, 'athena')
        self.assertIn('Clash / Mihomo YAML', output)
        self.assertIn('v2rayN 分享链接', output)
        self.assertIn('Shadowrocket / AnyTLS 分享链接', output)
        self.assertIn((self.directory / 'profiles/athena.yaml').read_text(), output)
        self.assertIn((self.directory / 'v2rayn/athena.txt').read_text(), output)
        self.assertIn((self.directory / 'shadowrocket/athena.txt').read_text(), output)
        for group in self.state['groups'][1:]:
            self.assertNotIn(group['password'], output)
            self.assertNotIn(group['token'], output)
        self.assertEqual(self.snapshot(), before)

    def test_raw_exports_remain_exact_and_v2rayn_decodes_to_same_credentials(self):
        clash = self.invoke('export', self.directory, 'athena')
        share = self.invoke('export-v2rayn', self.directory, 'athena')
        self.assertEqual(clash, (self.directory / 'profiles/athena.yaml').read_text())
        self.assertEqual(share, (self.directory / 'v2rayn/athena.txt').read_text())
        self.assertEqual(len(share.splitlines()), 1)
        payload = share.strip().removeprefix('v2rayn://anytls/')
        decoded = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        self.assertEqual(decoded['Password'], self.state['groups'][0]['password'])
        self.assertEqual(decoded['Address'], self.state['server'])
        self.assertEqual(decoded['AllowInsecure'], 'false')

    def test_combined_export_rejects_ambiguous_disabled_unknown_missing_and_extra_args(self):
        before = self.snapshot()
        for arguments in [(self.directory,), (self.directory, 'apollo'),
                          (self.directory, 'unknown'), (self.directory, '../athena'),
                          (self.directory, 'athena', 'extra')]:
            with self.subTest(arguments=arguments):
                self.reject_without_output('export-all', *arguments)
        self.assertEqual(self.snapshot(), before)
        (self.directory / 'v2rayn/athena.txt').unlink()
        self.reject_without_output('export-all', self.directory, 'athena')

    def test_legacy_raw_clash_fallback_remains_readable_without_migrating_state(self):
        raw = dict(self.state)
        raw['schema'] = 1
        raw['password'] = raw.pop('groups')[0]['password']
        helper.write_json(self.state_path, raw)
        profile = 'proxies:\n  - name: Legacy\n    type: anytls\n'
        (self.directory / 'mihomo-profile.yaml').write_text(profile)
        before = self.snapshot()
        self.assertEqual(self.invoke('export', self.directory), profile)
        self.reject_without_output('export-all', self.directory)
        self.assertEqual(self.snapshot(), before)

    def test_combined_subscriptions_group_filter_excludes_other_groups_and_passwords(self):
        before = self.snapshot()
        output = self.invoke('links-all', 'athena')
        group = self.state['groups'][0]
        self.assertIn('https://sub.example.test:9443/s/' + group['token'], output)
        self.assertIn('https://sub.example.test:9443/v/' + group['token'], output)
        self.assertIn('https://sub.example.test:9443/r/' + group['token'], output)
        for other in self.state['groups'][1:]:
            self.assertNotIn(other['token'], output)
        for other in self.state['groups']:
            self.assertNotIn(other['password'], output)
        self.assertEqual(self.snapshot(), before)

    def test_all_subscriptions_include_only_active_groups_and_raw_csv_stays_compatible(self):
        output = self.invoke('links-all')
        for group in self.state['groups']:
            self.assertEqual(group['token'] in output, group['enabled'])
        for format_name, route in [('clash', 's'), ('v2rayn', 'v'), ('shadowrocket', 'r')]:
            with self.subTest(format=format_name):
                raw = self.invoke('links', format_name)
                rows = list(csv.reader(io.StringIO(raw)))
                self.assertEqual(rows[0], ['id', 'label', 'url'])
                self.assertEqual([row[0] for row in rows[1:]], ['athena', 'hermes'])
                self.assertEqual(rows[1][2], 'https://sub.example.test:9443/' + route + '/'
                                 + self.state['groups'][0]['token'])
                filtered = list(csv.reader(io.StringIO(self.invoke('links', format_name, 'hermes'))))
                self.assertEqual([row[0] for row in filtered[1:]], ['hermes'])
        self.assertEqual(self.invoke('links'), self.invoke('links', 'clash'))

    def test_invalid_subscription_selection_produces_no_partial_header_or_url(self):
        for command, arguments in [('links-all', ('apollo',)), ('links-all', ('missing',)),
                                   ('links-all', ('athena', 'extra')),
                                   ('links', ('unsupported',)), ('links', ('clash', 'apollo'))]:
            with self.subTest(command=command, arguments=arguments):
                self.reject_without_output(command, *arguments)
        self.state['subscription'] = None
        helper.write_json(self.state_path, self.state)
        self.reject_without_output('links-all')

    def test_numeric_choices_skip_disabled_groups_and_map_visible_numbers(self):
        before = self.snapshot()
        output = self.invoke('group-options')
        self.assertEqual(output, '  1) Athena (athena)\n  2) Hermes (hermes)\n')
        self.assertEqual(self.invoke('group-number', '2'), 'hermes\n')
        for number in ('', '0', '3', '-1', '01', 'athena'):
            with self.subTest(number=number):
                self.reject_without_output('group-number', number)
        self.assertEqual(self.snapshot(), before)

    def test_numeric_choice_scopes_include_only_valid_targets(self):
        self.assertEqual(self.invoke('group-options', 'disabled'), '  1) Apollo (apollo)\n')
        self.assertEqual(self.invoke('group-number', '1', 'disabled'), 'apollo\n')
        self.assertEqual(self.invoke('group-number', '2', 'all'), 'apollo\n')
        self.reject_without_output('group-number', '2', 'disabled')
        self.reject_without_output('group-options', 'unknown-scope')
        self.state['groups'][1]['enabled'] = True
        helper.write_json(self.state_path, self.state)
        self.reject_without_output('group-options', 'disabled')


@unittest.skipUnless(sys.platform.startswith('linux') and BASH,
                     'Requires Linux and Bash; no root privileges are needed')
class ExportShellTests(ExportFixture):
    def run_shell(self, body, input_text=''):
        manager = MANAGER.read_text()
        names = ('show_export', 'show_v2rayn_export', 'show_clash_export',
                 'show_shadowrocket_export',
                 'menu_select_group', 'menu_export', 'main')
        functions = '\n'.join(re.search(r'^' + name + r'\(\) \{\n.*?^\}\n',
                                        manager, re.MULTILINE | re.DOTALL).group(0)
                              for name in names)
        script = r'''
set -euo pipefail
BASE="$TEST_DIRECTORY/base"
source "$SUB_MODULE"
die() { printf '%s\n' "$*" >&2; exit 70; }
current() { printf '%s\n' "$TEST_DIRECTORY"; }
py() { python3 "$STATE_HELPER" "$@"; }
root_readonly() { :; }
root_and_tools() { :; }
owned_base() { :; }
lock_base() { :; }
subscription_current_config() { printf '%s/nginx\n' "$TEST_DIRECTORY"; }
show_summary() { printf '%s\n' 'Choose a group.' >&2; }
ui_section() { printf '%s\n' "$*"; }
ui_item() { printf '%s) %s\n' "$1" "$2"; }
ui_heading() { printf '%s\n' "$*"; }
ui_note() { printf '%s\n' "$*"; }
systemctl() { return 0; }
'''
        # Use a script file so read consumes the supplied answers, not shell code.
        script_path = self.directory / 'exercise.sh'
        script_path.write_text(script + functions + '\n' + body + '\n')
        return subprocess.run([BASH, str(script_path)], input=input_text, text=True,
                              capture_output=True, encoding='utf-8', timeout=10,
                              env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                                   'LC_ALL': 'C.UTF-8', 'HOME': str(self.directory),
                                   'TEST_DIRECTORY': str(self.directory),
                                   'STATE_HELPER': str(HELPER), 'SUB_MODULE': str(SUBSCRIPTION)})

    def test_shell_default_export_and_explicit_raw_formats(self):
        result = self.run_shell('main export athena')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Clash / Mihomo YAML', result.stdout)
        self.assertIn('v2rayn://anytls/', result.stdout)
        for command, filename in [('export athena clash', 'profiles/athena.yaml'),
                                  ('export-clash athena', 'profiles/athena.yaml'),
                                  ('export athena v2rayn', 'v2rayn/athena.txt'),
                                  ('export-v2rayn athena', 'v2rayn/athena.txt'),
                                  ('export athena shadowrocket', 'shadowrocket/athena.txt'),
                                  ('export-shadowrocket athena', 'shadowrocket/athena.txt')]:
            with self.subTest(command=command):
                result = self.run_shell('main ' + command)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, (self.directory / filename).read_text())

    def test_numeric_export_menu_selects_correct_enabled_group(self):
        result = self.run_shell('menu_export export', '2\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn((self.directory / 'v2rayn/hermes.txt').read_text(), result.stdout)
        self.assertNotIn(self.state['groups'][0]['password'], result.stdout)
        for answer in ('', '3\n', 'athena\n'):
            with self.subTest(answer=answer):
                result = self.run_shell('menu_export export', answer)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('v2rayn://', result.stdout)
                self.assertNotIn('password:', result.stdout)

    def test_subscription_short_command_and_single_format_preserve_group_filter(self):
        result = self.run_shell('main sub athena')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('/s/' + self.state['groups'][0]['token'], result.stdout)
        self.assertIn('/v/' + self.state['groups'][0]['token'], result.stdout)
        self.assertIn('/r/' + self.state['groups'][0]['token'], result.stdout)
        self.assertNotIn(self.state['groups'][2]['token'], result.stdout)
        result = self.run_shell('subscription_links clash hermes')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.invoke('links', 'clash', 'hermes'))

    def test_subscription_menu_selects_one_group_or_all_using_numbers(self):
        result = self.run_shell('subscription_command', '3\n2\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('/s/' + self.state['groups'][2]['token'], result.stdout)
        self.assertIn('/v/' + self.state['groups'][2]['token'], result.stdout)
        self.assertIn('/r/' + self.state['groups'][2]['token'], result.stdout)
        self.assertNotIn(self.state['groups'][0]['token'], result.stdout)
        result = self.run_shell('subscription_command', '3\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        for group in self.state['groups']:
            self.assertEqual(group['token'] in result.stdout, group['enabled'])

    def test_legacy_subscription_routes_fail_combined_before_exposing_links(self):
        (self.configuration / 'nginx.conf').write_text('# legacy Clash-only configuration\n')
        result = self.run_shell('subscription_links all athena')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('refresh', result.stderr)
        result = self.run_shell('subscription_links clash athena')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_shell_arguments_fail_before_printing_credentials(self):
        for command in ('main export athena unknown', 'main export athena all extra',
                        'main export-v2rayn athena extra', 'main sub athena extra',
                        'subscription_links bad athena', 'subscription_links all athena extra'):
            with self.subTest(command=command):
                result = self.run_shell(command)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
