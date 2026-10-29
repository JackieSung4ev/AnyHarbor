"""Shadowrocket shell dispatch, legacy-route guards and publication permissions."""
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANAGER = ROOT / 'src/anytls-manager.sh'
SUBSCRIPTION = ROOT / 'src/anytls-subscription.sh'
BASH = shutil.which('bash')
TOKEN = 'A' * 43


@unittest.skipUnless(sys.platform.startswith('linux') and BASH,
                     'Requires Linux and Bash; no root or network needed')
class ShadowrocketShellTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='anyharbor-shadowrocket-shell-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.base = self.directory / 'base'
        self.generation = self.base / 'releases/current-generation'
        self.generation.mkdir(parents=True)
        self.configuration = self.base / 'subscription/releases/nginx'
        self.configuration.mkdir(parents=True)
        (self.base / 'subscription/.user-created').touch()
        self.set_routes(shadowrocket=True)
        for name in ('state.json', 'config.json', 'server.crt', 'server.key'):
            (self.generation / name).write_text('private fixture\n')
            (self.generation / name).chmod(0o600)
        for name in ('server.crt', 'server.key'):
            (self.configuration / name).write_text('certificate fixture\n')
        for name in ('profiles', 'v2rayn', 'shadowrocket'):
            directory = self.generation / name
            directory.mkdir(mode=0o700)
            filename = directory / ('athena.yaml' if name == 'profiles' else 'athena.txt')
            filename.write_text('private group fixture\n')
            filename.chmod(0o600)
        for name, suffix in (('subscriptions', 'yaml'), ('subscriptions_v2rayn', 'txt'),
                             ('subscriptions_shadowrocket', 'txt')):
            directory = self.generation / name
            directory.mkdir(mode=0o700)
            (directory / f'{TOKEN}.{suffix}').write_text('public token fixture\n')
            (directory / f'{TOKEN}.{suffix}').chmod(0o600)

    def set_routes(self, shadowrocket):
        text = '# Subscription formats: clash,v2rayn\n'
        if shadowrocket:
            text += '# Subscription format: shadowrocket\n'
        (self.configuration / 'nginx.conf').write_text(text)

    def run_shell(self, body, answers='', **settings):
        text = MANAGER.read_text()
        names = ('show_export', 'show_v2rayn_export', 'show_clash_export',
                 'show_shadowrocket_export', 'show_summary', 'help_text', 'main')
        functions = '\n'.join(re.search(r'^' + name + r'\(\) \{\n.*?^\}\n', text,
                                       re.MULTILINE | re.DOTALL).group(0) for name in names)
        script = r'''
set -euo pipefail
BASE="$TEST_ROOT/base"
source "$SUB_MODULE"
die() { printf '%s\n' "$*" >&2; exit 70; }
say() { printf '%s\n' "$*"; }
current() { printf '%s\n' "$GENERATION"; }
subscription_current_config() { printf '%s\n' "$CONFIGURATION"; }
subscription_owned() { :; }
subscription_guard_unit() { :; }
guard_generation() { [[ "$1" == "$GENERATION" ]]; }
root_readonly() { [[ ! -L "$1" ]] || die 'fixture symlink rejected'; }
root_and_tools() { :; }
owned_base() { :; }
lock_base() { :; }
chown() { printf '%s\0' "$@" >>"$TEST_ROOT/chown.args"; }
systemctl() { :; }
ui_heading() { :; }
ui_section() { :; }
ui_note() { printf '%s\n' "$*"; }
ui_item() { :; }
menu_select_group() { printf -v "$1" '%s' athena; }
py() {
    if [[ "$1" == get ]]; then
        case "$3" in
            subscription_enabled) printf '1\n';;
            tls_verify) printf '%s\n' "$TLS_VERIFY";;
            active_group_count) printf '2\n';;
            subscription_domain) printf 'sub.example.test\n';;
            subscription_port) printf '9443\n';;
            *) return 99;;
        esac
        return
    fi
    [[ "$1" != list-ui ]] || return 0
    printf '%s\0' "$@" >"$TEST_ROOT/helper.args"
    if [[ "$TLS_VERIFY" != pki && ( "$1" == export-shadowrocket || ( "$1" == links && "$3" == shadowrocket ) ) ]]; then
        die 'fixture state helper rejects Shadowrocket without PKI'
    fi
    printf 'fixture-raw-output\n'
}
'''
        environment = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C.UTF-8',
            'HOME': str(self.directory), 'TEST_ROOT': str(self.directory),
            'GENERATION': str(self.generation), 'CONFIGURATION': str(self.configuration),
            'SUB_MODULE': str(SUBSCRIPTION), 'TLS_VERIFY': 'pki', **settings,
        }
        return subprocess.run([BASH, '--noprofile', '--norc', '-c', script + functions + '\n' + body],
                              input=answers, text=True, encoding='utf-8', capture_output=True,
                              cwd=self.directory, env=environment, timeout=10)

    def arguments(self):
        return (self.directory / 'helper.args').read_bytes().decode().rstrip('\0').split('\0')

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_shadowrocket_export_and_alias_pass_group_to_correct_helper(self):
        for command in ('export athena shadowrocket', 'export-shadowrocket athena'):
            with self.subTest(command=command):
                result = self.run_shell('main ' + command)
                self.assert_success(result)
                self.assertEqual(result.stdout, 'fixture-raw-output\n')
                self.assertEqual(self.arguments(), ['export-shadowrocket',
                                 str(self.generation / 'state.json'), str(self.generation), 'athena'])

    def test_default_and_old_single_formats_keep_original_dispatch(self):
        for command, helper in (('export athena', 'export-all'), ('export athena clash', 'export'),
                                ('export-clash athena', 'export'),
                                ('export athena v2rayn', 'export-v2rayn'),
                                ('export-v2rayn athena', 'export-v2rayn')):
            with self.subTest(command=command):
                result = self.run_shell('main ' + command)
                self.assert_success(result)
                self.assertEqual(self.arguments()[0], helper)
                self.assertEqual(self.arguments()[-1], 'athena')

    def test_invalid_new_alias_arguments_print_no_raw_content(self):
        for command in ('main export-shadowrocket athena extra',
                        'main export athena shadowrocket extra',
                        'subscription_links shadowrocket athena extra'):
            with self.subTest(command=command):
                result = self.run_shell(command)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertFalse((self.directory / 'helper.args').exists())

    def test_pki_shadowrocket_and_all_require_new_route_before_printing_links(self):
        self.set_routes(shadowrocket=False)
        for format_name in ('all', 'shadowrocket'):
            with self.subTest(format=format_name):
                result = self.run_shell(f'subscription_links {format_name} athena')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertIn('refresh', result.stderr)
                self.assertFalse((self.directory / 'helper.args').exists())
        for format_name in ('clash', 'v2rayn'):
            with self.subTest(format=format_name):
                result = self.run_shell(f'subscription_links {format_name} athena')
                self.assert_success(result)
                self.assertEqual(self.arguments(), ['links', str(self.generation / 'state.json'),
                                                   format_name, 'athena'])

    def test_missing_or_symlinked_shadowrocket_directory_is_not_advertised(self):
        directory = self.generation / 'subscriptions_shadowrocket'
        shutil.rmtree(directory)
        for symlinked in (False, True):
            with self.subTest(symlinked=symlinked):
                if symlinked:
                    directory.symlink_to(self.generation / 'subscriptions_v2rayn')
                result = self.run_shell('subscription_links shadowrocket athena')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('refresh', result.stderr)
                self.assertEqual(result.stdout, '')

    def test_ready_links_and_short_sub_keep_group_selection(self):
        result = self.run_shell('subscription_links shadowrocket athena')
        self.assert_success(result)
        self.assertEqual(self.arguments(), ['links', str(self.generation / 'state.json'),
                                           'shadowrocket', 'athena'])
        result = self.run_shell('main sub athena')
        self.assert_success(result)
        self.assertEqual(self.arguments(), ['links-all', str(self.generation / 'state.json'), 'athena'])

    def test_pin_mode_all_keeps_legacy_routes_and_explicit_shadowrocket_uses_helper_rejection(self):
        self.set_routes(shadowrocket=False)
        shutil.rmtree(self.generation / 'subscriptions_shadowrocket')
        result = self.run_shell('subscription_links all athena', TLS_VERIFY='pin')
        self.assert_success(result)
        self.assertEqual(self.arguments()[0], 'links-all')
        for command in ('subscription_links shadowrocket athena', 'main export-shadowrocket athena'):
            with self.subTest(command=command):
                result = self.run_shell(command, TLS_VERIFY='pin')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertIn('without PKI', result.stderr)
                self.assertNotIn('refresh', result.stderr)

    def test_numeric_menu_nine_requests_only_shadowrocket_for_selected_group(self):
        result = self.run_shell('subscription_command', answers='9\n')
        self.assert_success(result)
        self.assertEqual(self.arguments(), ['links', str(self.generation / 'state.json'),
                                           'shadowrocket', 'athena'])

    def test_published_token_files_get_read_permissions_private_files_do_not(self):
        result = self.run_shell('subscription_publish_permissions "$GENERATION"')
        self.assert_success(result)
        for name, suffix in (('subscriptions', 'yaml'), ('subscriptions_v2rayn', 'txt'),
                             ('subscriptions_shadowrocket', 'txt')):
            self.assertEqual(stat.S_IMODE((self.generation / name).stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE((self.generation / name / f'{TOKEN}.{suffix}').stat().st_mode), 0o640)
        for name in ('state.json', 'config.json', 'server.crt', 'server.key',
                     'profiles/athena.yaml', 'v2rayn/athena.txt', 'shadowrocket/athena.txt'):
            self.assertEqual(stat.S_IMODE((self.generation / name).stat().st_mode), 0o600)
        for name in ('profiles', 'v2rayn', 'shadowrocket'):
            self.assertEqual(stat.S_IMODE((self.generation / name).stat().st_mode), 0o700)

    def test_old_generation_without_shadowrocket_public_directory_is_supported(self):
        shutil.rmtree(self.generation / 'subscriptions_shadowrocket')
        result = self.run_shell('subscription_publish_permissions "$GENERATION"')
        self.assert_success(result)
        self.assertFalse((self.generation / 'subscriptions_shadowrocket').exists())

    def test_publication_rejects_group_filename_and_symlink_without_exposing_target(self):
        directory = self.generation / 'subscriptions_shadowrocket'
        invalid = directory / 'athena.txt'
        invalid.write_text('not a token filename\n')
        invalid.chmod(0o600)
        result = self.run_shell('subscription_publish_permissions "$GENERATION"')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(stat.S_IMODE(invalid.stat().st_mode), 0o600)
        invalid.unlink()
        target = self.generation / 'server.key'
        token_file = directory / f'{TOKEN}.txt'
        token_file.unlink()
        token_file.symlink_to(target)
        result = self.run_shell('subscription_publish_permissions "$GENERATION"')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(target.read_text(), 'private fixture\n')

    def test_publication_rejects_a_shadowrocket_directory_symlink(self):
        directory = self.generation / 'subscriptions_shadowrocket'
        shutil.rmtree(directory)
        directory.symlink_to(self.generation / 'shadowrocket')
        result = self.run_shell('subscription_publish_permissions "$GENERATION"')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(stat.S_IMODE((self.generation / 'shadowrocket').stat().st_mode), 0o700)

    def test_nginx_keeps_legacy_routes_and_adds_separate_plain_text_shadowrocket_route(self):
        result = self.run_shell('subscription_write_config "$CONFIGURATION" sub.example.test 9443')
        self.assert_success(result)
        text = (self.configuration / 'nginx.conf').read_text()
        self.assertIn('# Subscription formats: clash,v2rayn\n', text)
        self.assertIn('# Subscription format: shadowrocket\n', text)
        for prefix, directory, token, suffix in (
                ('s', 'subscriptions', 'subscription_token', 'yaml'),
                ('v', 'subscriptions_v2rayn', 'v2rayn_token', 'txt'),
                ('r', 'subscriptions_shadowrocket', 'shadowrocket_token', 'txt')):
            self.assertIn(f'^/{prefix}/(?<{token}>[A-Za-z0-9_-]{{43}})$', text)
            self.assertIn(f'alias {self.base}/current/{directory}/${token}.{suffix};', text)
        route = text.split('location ~ "^/r/', 1)[1].split('        }', 1)[0]
        self.assertIn('default_type text/plain;', route)
        self.assertIn('limit_except GET { deny all; }', route)
        self.assertNotIn('/current/shadowrocket/', text)

    def test_summary_only_claims_shadowrocket_files_when_available_and_help_is_current(self):
        result = self.run_shell('show_summary')
        self.assert_success(result)
        self.assertIn('/current/shadowrocket/<组ID>.txt', result.stdout)
        result = self.run_shell('show_summary', TLS_VERIFY='pin')
        self.assert_success(result)
        self.assertNotIn('/current/shadowrocket/<组ID>.txt', result.stdout)
        self.assertIn('不会跳过证书验证', result.stdout)
        result = self.run_shell('help_text')
        self.assert_success(result)
        self.assertIn('1.7.2', result.stdout)
        self.assertIn('export-shadowrocket', result.stdout)
        self.assertIn('subscription check', result.stdout)


if __name__ == '__main__':
    unittest.main()
