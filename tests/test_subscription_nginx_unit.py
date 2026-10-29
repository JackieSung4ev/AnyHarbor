"""Linux shell regressions with isolated fixtures, no root or network required."""
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
BASH = shutil.which('bash')


@unittest.skipUnless(sys.platform.startswith('linux') and BASH,
                     'Requires Linux and Bash; no root privileges are needed')
class SubscriptionNginxTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='gz-subscription-unit-')
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)
        self.candidate = self.scratch / 'candidate'
        self.candidate.mkdir()

    def run_shell(self, body, **values):
        environment = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
            'HOME': str(self.scratch),
            'LANG': 'C.UTF-8',
            'LC_ALL': 'C.UTF-8',
            'MODULE': str(MODULE),
            'TEST_ROOT': str(self.scratch),
            'CANDIDATE': str(self.candidate),
            'PROBE_MODE': 'lua',
            'HELPER_MODE': 'ok',
            'LUA_LIBRARY': '/fixture/nginx/lualib',
            'ACTIVE': 'yes',
            'HTTP_CODE': '404',
            'CURL_STATUS': '0',
            'CURL_ERROR': '',
            **values,
        }
        script = r'''
set -euo pipefail
umask 077
BASE="$TEST_ROOT/base"
mkdir -p "$BASE"
source "$MODULE"
die() { printf '%s\n' "$*" >&2; exit 70; }
# Ownership is the only privileged operation in the functions exercised here.
chown() { printf '%s\0' "$@" >>"$TEST_ROOT/chown.args"; }
sleep() { :; }
runuser() {
    printf '%s\0' "$@" >>"$TEST_ROOT/runuser.args"
    cp -- "$CANDIDATE/lua-probe.conf" "$TEST_ROOT/probe-observed.conf"
    case "$PROBE_MODE" in
        lua) return 0 ;;
        stock) printf '%s\n' 'nginx: [emerg] unknown directive "lua_package_path"' >&2; return 1 ;;
        permission) printf '%s\n' 'runuser: cannot set groups: Operation not permitted' >&2; return 1 ;;
        config) printf '%s\n' 'nginx: [emerg] invalid number of arguments in "pid" directive' >&2; return 1 ;;
        *) return 99 ;;
    esac
}
py() {
    printf '%s\0' "$@" >>"$TEST_ROOT/helper.args"
    if [[ "$HELPER_MODE" == unsafe ]]; then
        printf '%s\n' 'fixture Lua library is writable by a non-root user' >&2
        return 23
    fi
    printf '%s\n' "$LUA_LIBRARY"
}
subscription_metadata() {
    case "$2" in domain) printf '%s\n' sub.example.test ;; port) printf '%s\n' 9443 ;; *) return 98 ;; esac
}
systemctl() {
    printf '%s\0' "$@" >>"$TEST_ROOT/systemctl.args"
    [[ "$1" != is-active || "$ACTIVE" == yes ]]
}
curl() {
    printf '%s\0' "$@" >>"$TEST_ROOT/curl.args"
    printf '%s\n' attempt >>"$TEST_ROOT/curl.calls"
    [[ -z "$CURL_ERROR" ]] || printf '%s\n' "$CURL_ERROR" >&2
    printf '%s' "$HTTP_CODE"
    return "$CURL_STATUS"
}
'''
        return subprocess.run([BASH, '--noprofile', '--norc', '-s'],
                              input=script + '\n' + body, text=True,
                              encoding='utf-8', capture_output=True,
                              cwd=self.scratch, env=environment, timeout=15)

    def arguments(self, filename):
        return (self.scratch / filename).read_bytes().decode().rstrip('\0').split('\0')

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stock_nginx_omits_lua_without_calling_library_discovery(self):
        result = self.run_shell(
            'subscription_nginx_lua_path "$CANDIDATE" /fixture/nginx -e stderr',
            PROBE_MODE='stock')
        self.assert_success(result)
        self.assertEqual(result.stdout, '')
        self.assertFalse((self.scratch / 'helper.args').exists())
        self.assertFalse((self.candidate / 'lua-probe.conf').exists())
        self.assertFalse((self.candidate / 'lua-probe.log').exists())
        args = self.arguments('runuser.args')
        self.assertEqual(args[:6], ['-u', 'jackie-anytls-sub', '--', '/fixture/nginx', '-e', 'stderr'])
        self.assertIn('-t', args)
        self.assertEqual(args[args.index('-p') + 1], str(self.scratch / 'base/subscription') + '/')
        probe = (self.scratch / 'probe-observed.conf').read_text()
        self.assertIn('lua_package_path', probe)
        self.assertNotIn('include ', probe)
        self.assertNotIn('load_module ', probe)

    def test_lua_capability_returns_only_the_helper_selected_directory(self):
        result = self.run_shell('subscription_nginx_lua_path "$CANDIDATE" /fixture/nginx')
        self.assert_success(result)
        self.assertEqual(result.stdout, '/fixture/nginx/lualib\n')
        self.assertEqual(self.arguments('helper.args'), ['nginx-lua-path', '/fixture/nginx'])
        self.assertFalse((self.candidate / 'lua-probe.conf').exists())
        self.assertFalse((self.candidate / 'lua-probe.log').exists())

    def test_probe_permission_or_unrelated_config_errors_are_not_stock_nginx(self):
        for mode, diagnostic in [('permission', 'cannot set groups'), ('config', 'invalid number of arguments')]:
            with self.subTest(mode=mode):
                result = self.run_shell('subscription_nginx_lua_path "$CANDIDATE" /fixture/nginx',
                                        PROBE_MODE=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)
                self.assertIn('能力检查失败', result.stderr)
                self.assertFalse((self.scratch / 'helper.args').exists())

    def test_unsafe_library_rejection_propagates_through_command_substitution(self):
        result = self.run_shell('selected=$(subscription_nginx_lua_path "$CANDIDATE" /fixture/nginx)\n'
                                'printf "UNEXPECTED_SUCCESS:%s" "$selected"', HELPER_MODE='unsafe')
        self.assertEqual(result.returncode, 23)
        self.assertIn('writable by a non-root user', result.stderr)
        self.assertNotIn('UNEXPECTED_SUCCESS', result.stdout)

    def prepare_certificate_files(self):
        # These functions only render paths; they do not inspect certificate data.
        (self.candidate / 'server.crt').write_text('fixture certificate, not real PEM\n')
        (self.candidate / 'server.key').write_text('fixture key, not a private key\n')

    def test_generated_config_uses_an_absolute_complete_lua_search_path(self):
        self.prepare_certificate_files()
        result = self.run_shell('subscription_write_config "$CANDIDATE" sub.example.test 9443 "$LUA_LIBRARY"')
        self.assert_success(result)
        config = (self.candidate / 'nginx.conf').read_text()
        self.assertIn('lua_package_path "/fixture/nginx/lualib/?.lua;/fixture/nginx/lualib/?/init.lua";', config)
        self.assertNotIn(';;', config)
        self.assertNotIn('lua_load_resty_core', config)
        self.assertNotIn('load_module ', config)
        self.assertEqual(json.loads((self.candidate / 'metadata.json').read_text()),
                         {'domain': 'sub.example.test', 'port': 9443})

    def test_stock_generated_config_has_no_lua_directive(self):
        self.prepare_certificate_files()
        result = self.run_shell('subscription_write_config "$CANDIDATE" sub.example.test 9443')
        self.assert_success(result)
        self.assertNotIn('lua_package_path', (self.candidate / 'nginx.conf').read_text())

    def test_lua_path_injection_is_rejected_before_overwriting_config(self):
        path = self.candidate / 'nginx.conf'
        path.write_text('existing fixture config\n')
        for value in ['relative/lib', '$prefix/lualib', '/safe/lib;include /tmp/site',
                      '/safe/lib"; include /tmp/site; #', '/safe/lib\nother', '/safe/lib name']:
            with self.subTest(path=value):
                result = self.run_shell('subscription_write_config "$CANDIDATE" sub.example.test 9443 "$LUA_LIBRARY"',
                                        LUA_LIBRARY=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Lua 库路径不符合要求', result.stderr)
                self.assertEqual(path.read_text(), 'existing fixture config\n')

    def test_health_accepts_verified_tls_404_and_removes_diagnostics(self):
        (self.candidate / 'health-check.log').write_text('old fixture diagnostic\n')
        result = self.run_shell('subscription_healthy "$CANDIDATE"')
        self.assert_success(result)
        self.assertFalse((self.candidate / 'health-check.log').exists())
        args = self.arguments('curl.args')
        self.assertEqual(args[-1], 'https://sub.example.test:9443/')
        self.assertEqual(args[args.index('--resolve') + 1], 'sub.example.test:9443:127.0.0.1')
        self.assertEqual(args[args.index('--noproxy') + 1], '*')
        self.assertEqual(args[args.index('--proto') + 1], '=https')
        self.assertNotIn('-k', args)
        self.assertNotIn('--insecure', args)
        self.assertEqual((self.scratch / 'curl.calls').read_text().splitlines(), ['attempt'])

    def test_health_reports_tls_failure_with_exit_status_and_bounded_diagnostic(self):
        diagnostic = '\n'.join(['curl: (60) SSL certificate problem'] + [f'fixture detail {i}' for i in range(1, 12)])
        result = self.run_shell('subscription_healthy "$CANDIDATE"', CURL_STATUS='60',
                                HTTP_CODE='000', CURL_ERROR=diagnostic)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('service-active=yes', result.stderr)
        self.assertIn('curl-exit=60', result.stderr)
        self.assertIn('HTTP=000', result.stderr)
        self.assertIn('SSL certificate problem', result.stderr)
        self.assertNotIn('fixture detail 8', result.stderr)
        self.assertEqual(len((self.scratch / 'curl.calls').read_text().splitlines()), 5)

    def test_health_requires_both_successful_curl_and_expected_http_status(self):
        for status, http in [('0', '200'), ('60', '404')]:
            with self.subTest(curl_status=status, http_status=http):
                result = self.run_shell('subscription_healthy "$CANDIDATE"', CURL_STATUS=status, HTTP_CODE=http)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'curl-exit={status}', result.stderr)
                self.assertIn(f'HTTP={http}', result.stderr)

    def test_health_inactive_service_never_attempts_network_request(self):
        result = self.run_shell('subscription_healthy "$CANDIDATE"', ACTIVE='no')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('service-active=no', result.stderr)
        self.assertIn('未执行', result.stderr)
        self.assertFalse((self.scratch / 'curl.args').exists())


if __name__ == '__main__':
    unittest.main()
