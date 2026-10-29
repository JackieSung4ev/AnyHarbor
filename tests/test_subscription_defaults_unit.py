"""Subscription input defaults with real CA/hostname verification and no services."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'src' / 'anytls-subscription.sh'
HELPER = ROOT / 'src' / 'anytls-state.py'
BASH = shutil.which('bash')
spec = importlib.util.spec_from_file_location('subscription_defaults_state', HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


@unittest.skipUnless(sys.platform.startswith('linux') and BASH and shutil.which('openssl'),
                     'Requires Linux, Bash and OpenSSL; no root or network needed')
class SubscriptionDefaultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificates = tempfile.TemporaryDirectory(prefix='anyharbor-defaults-ca-')
        cls.addClassCleanup(cls.certificates.cleanup)
        cls.certs = Path(cls.certificates.name)

        def openssl(*args):
            subprocess.run(['openssl', *args], cwd=cls.certs, check=True,
                           capture_output=True, timeout=15)

        openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '2',
                '-subj', '/CN=Disposable AnyHarbor unit CA',
                '-addext', 'basicConstraints=critical,CA:TRUE')
        openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-keyout', 'server.key', '-out', 'server.csr',
                '-subj', '/CN=proxy.example.test')
        (cls.certs / 'extensions').write_text(
            'subjectAltName=DNS:proxy.example.test,DNS:sub.example.test\n'
            'basicConstraints=critical,CA:FALSE\n'
            'extendedKeyUsage=serverAuth\n')
        openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
                '-CAcreateserial', '-out', 'server.crt', '-days', '2',
                '-extfile', 'extensions')
        openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-keyout', 'untrusted.key', '-out', 'untrusted.crt', '-days', '2',
                '-subj', '/CN=proxy.example.test',
                '-addext', 'subjectAltName=DNS:proxy.example.test')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='anyharbor-defaults-unit-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.generation = self.directory / 'base/releases/proxy'
        self.generation.mkdir(parents=True)
        self.configuration = self.directory / 'base/subscription/releases/saved'
        self.state_path = self.generation / 'state.json'
        helper.main(['init', str(self.state_path), '192.0.2.1', '8443'])
        state = helper.load(self.state_path)
        state['sni'] = 'proxy.example.test'
        helper.write_json(self.state_path, state)
        for name in ('server.crt', 'server.key'):
            shutil.copyfile(self.certs / name, self.generation / name)

    def save_subscription(self, enabled=True):
        self.configuration.mkdir(parents=True)
        for name in ('server.crt', 'server.key'):
            shutil.copyfile(self.certs / name, self.configuration / name)
        (self.configuration / 'metadata.json').write_text(json.dumps(
            {'domain': 'sub.example.test', 'port': 38226}))
        (self.configuration.parent.parent / 'current').symlink_to(self.configuration)
        if enabled:
            state = helper.load(self.state_path)
            state['subscription'] = {'domain': 'sub.example.test', 'port': 38226}
            helper.write_json(self.state_path, state)

    def run_shell(self, body, answers='', **settings):
        script = r'''
set -euo pipefail
BASE="$TEST_ROOT/base"
source "$MODULE"
die() { printf '%s\n' "$*" >&2; exit 70; }
say() { printf '%s\n' "$*"; }
current() { printf '%s\n' "$GENERATION"; }
root_readonly() { :; }
subscription_guard_unit() { printf 'unit\n' >>"$TEST_ROOT/guards"; }
subscription_current_config() { printf '%s\n' "$CONFIGURATION"; }
# Swap only the CA bundle for this fixture; execute real OpenSSL verification.
openssl() {
    local -a args=("$@")
    local index
    for ((index=0; index<${#args[@]}; index++)); do
        if [[ "${args[index]}" == /etc/ssl/certs/ca-certificates.crt ]]; then args[index]=$TEST_CA; fi
    done
    command openssl "${args[@]}"
}
py() {
    if [[ "$1" == check-subscriptions ]]; then
        printf '%s\0' "$@" >"$TEST_ROOT/check.args"
        return "${CHECK_STATUS:-0}"
    fi
    python3 "$HELPER" "$@"
}
read() { printf '%s\0' "$@" >>"$TEST_ROOT/read.args"; builtin read "$@"; }
nginx() { :; }
systemctl() { return 1; }
free_port() {
    printf '%s\0' "$domain" "$certificate" "$key" "$port" >"$TEST_ROOT/selected.args"
    if [[ ${BUSY:-0} == 1 ]]; then die 'fixture port is busy'; fi
    exit 77
}
subscription_initialize() { die 'Unexpected live mutation'; }
ui_heading() { :; }
ui_section() { :; }
ui_note() { :; }
ui_item() { printf '%s %s\n' "$@"; }
menu_select_group() { printf -v "$1" '%s' athena; }
'''
        environment = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
            'LC_ALL': 'C.UTF-8', 'HOME': str(self.directory),
            'TEST_ROOT': str(self.directory), 'GENERATION': str(self.generation),
            'CONFIGURATION': str(self.configuration), 'MODULE': str(MODULE),
            'HELPER': str(HELPER), 'TEST_CA': str(self.certs / 'ca.crt'), **settings,
        }
        return subprocess.run([BASH, '--noprofile', '--norc', '-c', script + '\n' + body],
                              input=answers, text=True, encoding='utf-8', capture_output=True,
                              env=environment, cwd=self.directory, timeout=15)

    def arguments(self, filename):
        return (self.directory / filename).read_bytes().decode().rstrip('\0').split('\0')

    def assert_selected(self, result, domain, directory, port):
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.arguments('selected.args'),
                         [domain, str(directory / 'server.crt'),
                          str(directory / 'server.key'), str(port)])

    def test_first_enable_reuses_sni_and_certificate_asks_only_port(self):
        before = {p.name: p.read_bytes() for p in self.generation.iterdir()}
        result = self.run_shell('subscription_enable', '38226\n')
        self.assert_selected(result, 'proxy.example.test', self.generation, 38226)
        self.assertEqual(self.arguments('read.args'), ['-r', '-p', 'HTTPS 订阅端口 [9443]：', 'answer'])
        self.assertIn('复用订阅域名：proxy.example.test', result.stdout)
        self.assertIn('菜单 8', result.stdout)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.generation.iterdir()})

    def test_first_enable_empty_port_uses_9443(self):
        result = self.run_shell('subscription_enable', '\n')
        self.assert_selected(result, 'proxy.example.test', self.generation, 9443)

    def test_enabled_and_disabled_saved_subscription_keep_domain_certificate_port(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                if not self.configuration.exists():
                    self.save_subscription(enabled)
                else:
                    state = helper.load(self.state_path)
                    state['subscription'] = None
                    helper.write_json(self.state_path, state)
                result = self.run_shell('subscription_enable', '\n')
                self.assert_selected(result, 'sub.example.test', self.configuration, 38226)

    def test_untrusted_certificate_fails_before_asking_or_changing_state(self):
        shutil.copyfile(self.certs / 'untrusted.crt', self.generation / 'server.crt')
        result = self.run_shell('subscription_enable', '38226\n')
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn('不会跳过证书验证', result.stderr)
        self.assertFalse((self.directory / 'read.args').exists())
        self.assertFalse((self.directory / 'selected.args').exists())

    def test_mismatched_domain_and_ip_are_not_automatically_reused(self):
        for domain in ('wrong.example.test', '192.0.2.2', '2001:db8::1'):
            with self.subTest(domain=domain):
                state = helper.load(self.state_path)
                state['sni'] = domain
                helper.write_json(self.state_path, state)
                result = self.run_shell('subscription_enable', '38226\n')
                self.assertEqual(result.returncode, 70, result.stderr)
                self.assertIn('菜单 8', result.stderr)
                self.assertFalse((self.directory / 'read.args').exists())

    def test_saved_state_mismatch_and_missing_config_do_not_fall_back(self):
        self.save_subscription()
        state = helper.load(self.state_path)
        state['subscription']['port'] = 9443
        helper.write_json(self.state_path, state)
        result = self.run_shell('subscription_enable', '\n')
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn('不一致', result.stderr)
        (self.configuration.parent.parent / 'current').unlink()
        result = self.run_shell('subscription_enable', '\n')
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn('缺少 HTTPS 配置', result.stderr)
        self.assertFalse((self.directory / 'read.args').exists())

    def test_complete_arguments_do_not_prompt_or_use_defaults(self):
        result = self.run_shell('subscription_default_settings() { die "unexpected defaults"; }; '
                                'subscription_enable sub.example.test "$GENERATION/server.crt" '
                                '"$GENERATION/server.key" 38226')
        self.assert_selected(result, 'sub.example.test', self.generation, 38226)
        self.assertFalse((self.directory / 'read.args').exists())

    def test_domain_only_prompts_for_new_paths_instead_of_reusing_saved_certificate(self):
        self.save_subscription()
        result = self.run_shell('subscription_enable proxy.example.test',
                                str(self.generation / 'server.crt') + '\n' +
                                str(self.generation / 'server.key') + '\n')
        self.assert_selected(result, 'proxy.example.test', self.generation, 9443)
        self.assertEqual(self.arguments('read.args').count('-p'), 2)

    def test_invalid_port_is_rejected_before_port_or_service_mutation(self):
        for port in ('0', '1023', '65536', 'invalid'):
            with self.subTest(port=port):
                result = self.run_shell('subscription_enable', port + '\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.directory / 'selected.args').exists())

    def test_busy_port_and_eof_stop_before_initialization(self):
        result = self.run_shell('subscription_enable', '38226\n', BUSY='1')
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn('fixture port is busy', result.stderr)
        result = self.run_shell('subscription_enable')
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn('输入结束', result.stderr)

    def test_refresh_still_passes_all_saved_fields_noninteractively(self):
        self.save_subscription()
        result = self.run_shell('subscription_enable() { printf "%s\\0" "$@" >"$TEST_ROOT/refresh.args"; }; '
                                'subscription_refresh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.arguments('refresh.args'), ['sub.example.test',
                         str(self.configuration / 'server.crt'),
                         str(self.configuration / 'server.key'), '38226'])
        self.assertFalse((self.directory / 'read.args').exists())

    def test_manual_menu_asks_all_fields_preserving_default_saved_port(self):
        self.save_subscription()
        answers = '8\nproxy.example.test\n' + str(self.generation / 'server.crt') + '\n'
        answers += str(self.generation / 'server.key') + '\n\n'
        result = self.run_shell('subscription_command menu', answers)
        self.assert_selected(result, 'proxy.example.test', self.generation, 38226)
        self.assertEqual(self.arguments('read.args').count('-p'), 5)

    def test_check_dispatch_omits_empty_group_and_propagates_failure(self):
        self.save_subscription()
        result = self.run_shell('subscription_command check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.arguments('check.args'), ['check-subscriptions', str(self.generation)])
        result = self.run_shell('subscription_command check athena', CHECK_STATUS='23')
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(self.arguments('check.args'), ['check-subscriptions', str(self.generation), 'athena'])

    def test_check_menu_selects_one_group_and_disabled_subscription_is_rejected(self):
        result = self.run_shell('subscription_command check')
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertFalse((self.directory / 'check.args').exists())
        self.save_subscription()
        result = self.run_shell('subscription_command menu', '7\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.arguments('check.args'), ['check-subscriptions', str(self.generation), 'athena'])


if __name__ == '__main__':
    unittest.main()
