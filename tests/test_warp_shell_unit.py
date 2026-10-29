"""WARP shell control flow with only temporary-file/command fixtures.

No APT, systemd, Cloudflare registration or network command reaches the host.
Functions are extracted verbatim except absolute WARP paths redirected into
the fixture. Conditional invocations deliberately suppress Bash errexit, so
critical safety boundaries must explicitly check each command's return status.
"""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'src/anytls-state.py'
BASH = shutil.which('bash')
spec = importlib.util.spec_from_file_location('warp_shell_state', HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
VALID_LISTENER = 'LISTEN 0 4096 127.0.0.1:40000 0.0.0.0:* users:(("warp-svc",pid=123,fd=3))'


def function(text, name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}\n', text, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError('Missing shell function: ' + name)
    return match.group(0)


@unittest.skipUnless(sys.platform.startswith('linux') and BASH and shutil.which('timeout'),
                     'Requires Linux, Bash and timeout; no root privileges are needed')
class WarpShellTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='anyharbor-warp-shell-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.base = self.directory / 'base'
        self.base.mkdir()
        self.current = self.directory / 'current'
        self.current.mkdir()
        self.state_path = self.current / 'state.json'
        helper.main(['init', str(self.state_path), 'proxy.example.test', '8443'])
        state = helper.load(self.state_path)
        state['groups'] = state['groups'][:2]
        helper.write_json(self.state_path, state)
        self.events = self.directory / 'events'
        self.events.touch()
        self.registration = self.directory / 'registration-present'
        self.cli = self.directory / 'warp-cli'
        self.template = self.directory / 'cli-template'
        self.template.write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ "$1 $2 $3" == '--accept-tos --no-ansi --no-paginate' ]] || exit 91
shift 3
printf 'cli:%s\\n' "$*" >> "$TEST_EVENTS"
[[ "$*" != "${FAIL_CLI:-__none__}" ]] || exit 71
if [[ "$*" == "${FAIL_AFTER_REGISTER:-__none__}" ]] && grep -Fqx 'cli:registration new' "$TEST_EVENTS"; then exit 71; fi
case "$*" in
    'registration new')
        [[ ! -e "$TEST_DIRECTORY/registration-present" ]] || { printf 'Duplicate fixture registration.\\n' >&2; exit 92; }
        printf 'registered\\n' > "$TEST_DIRECTORY/registration-present";;
    'registration show'|'tunnel protocol set MASQUE'|'connect')
        [[ -f "$TEST_DIRECTORY/registration-present" ]] || {
            printf 'Error: Missing registration. Try running: "warp-cli registration new"\\n' >&2
            exit 74
        };;
esac
exit 0
''')
        self.template.chmod(0o755)
        runtime = (ROOT / 'src/anytls-runtime.sh').read_text()
        names = ('warp_owned', 'warp_no_mdm', 'warp_cli', 'warp_listener_check', 'warp_check', 'warp_require_ready',
                 'warp_set_proxy', 'warp_connect', 'warp_wait_ready', 'warp_setup', 'warp_select_egress')
        functions = '\n'.join(function(runtime, name) for name in names)
        functions += '\n' + function((ROOT / 'src/anytls-manager.sh').read_text(), 'group_command')
        # Only redirect the fixed system paths. Command implementations below
        # are fixtures; no production source or control-flow expression changes.
        functions = functions.replace('/usr/bin/warp-cli', '$TEST_DIRECTORY/warp-cli')
        functions = functions.replace('/usr/bin/warp-svc', '$TEST_DIRECTORY/warp-svc')
        functions = functions.replace('/var/lib/cloudflare-warp', '$TEST_DIRECTORY/cloudflare-warp')
        prelude = r'''
#!/usr/bin/env bash
set -euo pipefail
BASE="$TEST_DIRECTORY/base"
WORK=''
record() { printf '%s\n' "$*" >> "$TEST_EVENTS"; }
say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 70; }
ui_heading() { say "$1"; }
ui_section() { say "$*"; }
ui_item() { say "$*"; }
ui_note() { say "$*"; }
ui_warn() { say "$*"; }
ui_prompt() { IFS= read -r -p "$2" "$1"; }
root_readonly() { [[ -f "$1" && ! -L "$1" ]] || die 'Unsafe fixture file.'; }
free_port() { record "free-port:$*"; [[ ${BUSY_PORT:-0} == 0 ]] || die 'Occupied fixture port.'; }
current() { printf '%s\n' "$TEST_DIRECTORY/current"; }
py() { python3 "$STATE_HELPER" "$@"; }
clone_current() {
    record clone
    WORK="$TEST_DIRECTORY/candidate"
    mkdir "$WORK"
    cp "$TEST_DIRECTORY/current/state.json" "$WORK/state.json"
}
finalize_generation() { record finalize; }
activate() { record activate; }
show_summary() { :; }
warp_install_package() {
    record install-package
    [[ ${FAIL_INSTALL:-0} == 0 ]] || return 72
    cp "$CLI_TEMPLATE" "$TEST_DIRECTORY/warp-cli"
    chmod 0755 "$TEST_DIRECTORY/warp-cli"
}
systemctl() {
    record "systemctl:$*"
    case "$*" in
        'cat warp-svc.service') [[ ${EXISTING_SERVICE:-0} == 1 ]];;
        'is-active --quiet warp-svc.service') [[ ${SERVICE_ACTIVE:-1} == 1 ]];;
        'enable --now warp-svc.service') [[ ${FAIL_ENABLE:-0} == 0 ]];;
        *) die 'Unexpected fixture systemctl command.';;
    esac
}
ss() { record ss; printf '%s\n' "$LISTENERS"; return "${FAIL_SS:-0}"; }
curl() {
    record curl
    printf 'curl-arg:%s\n' "$@" >> "$TEST_EVENTS"
    [[ ${FAIL_CURL:-0} == 0 ]] || return 73
    printf '%s\n' "$TRACE"
}
sleep() { record sleep; }
dpkg-query() { [[ ${EXISTING_PACKAGE:-0} == 1 ]] && printf 'install ok installed'; }
command() {
    if [[ "$1" == -v && ( "$2" == warp-cli || "$2" == warp-svc ) ]]; then
        [[ ${EXISTING_PATH:-0} == 1 ]]
    else builtin command "$@"; fi
}
'''
        self.worker = self.directory / 'fixture.sh'
        self.worker.write_text(prelude.lstrip() + '\n' + functions + r'''
case "$1" in
    setup) warp_setup;;
    setup-if) if warp_setup; then record completed; else record failed; fi;;
    connect-if) if warp_connect; then record completed; else record failed; fi;;
    check) warp_check;;
    listener) warp_listener_check;;
    group) shift; group_command "$@";;
    *) die 'Unknown fixture operation.';;
esac
''')

    def install_fixture_cli(self, managed=None):
        shutil.copyfile(self.template, self.cli)
        self.cli.chmod(0o755)
        if managed is not None:
            (self.base / '.warp-owner').write_text('anyharbor-warp-v1:' + managed + '\n')
        if managed == 'registered':
            self.registration.write_text('registered\n')

    def set_group_egress(self, egress, enabled=True):
        state = helper.load(self.state_path)
        state['groups'][0]['egress'] = egress
        state['groups'][0]['enabled'] = enabled
        if egress == 'warp':
            state['schema'] = 3
        helper.write_json(self.state_path, state)

    def invoke(self, *arguments, answers='', tty=False, **settings):
        environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C.UTF-8',
                       'HOME': str(self.directory), 'TEST_DIRECTORY': str(self.directory),
                       'TEST_EVENTS': str(self.events), 'STATE_HELPER': str(HELPER),
                       'CLI_TEMPLATE': str(self.template), 'LISTENERS': VALID_LISTENER,
                       'TRACE': 'fl=fixture\nwarp=on', **settings}
        options = {'text': True, 'capture_output': True, 'encoding': 'utf-8',
                   'timeout': 10, 'env': environment}
        if not tty:
            return subprocess.run([BASH, str(self.worker), *arguments], input=answers, **options)
        import pty
        master, slave = pty.openpty()
        try:
            os.write(master, answers.encode())
            return subprocess.run([BASH, str(self.worker), *arguments], stdin=slave, **options)
        finally:
            os.close(slave)
            os.close(master)

    def actions(self):
        return self.events.read_text().splitlines()

    def cli_actions(self):
        return [item.removeprefix('cli:') for item in self.actions() if item.startswith('cli:')]

    def assert_no_group_change(self, before):
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertNotIn('clone', self.actions())
        self.assertNotIn('activate', self.actions())
        self.assertFalse((self.directory / 'candidate').exists())

    def test_cancel_or_eof_never_installs_registers_or_records_terms_acceptance(self):
        for answer in ('no\n', '\n', ''):
            with self.subTest(answer=repr(answer)):
                result = self.invoke('setup', answers=answer)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('install-package', self.actions())
                self.assertEqual(self.cli_actions(), [])
                self.assertFalse((self.base / '.warp-owner').exists())

    def test_existing_unmanaged_client_is_checked_without_reconfiguration(self):
        self.install_fixture_cli()
        result = self.invoke('setup', answers='WARP\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('curl', self.actions())
        self.assertNotIn('install-package', self.actions())
        self.assertEqual(self.cli_actions(), [])
        self.assertFalse((self.base / '.warp-owner').exists())

    def test_existing_unmanaged_data_or_service_never_installs_or_registers(self):
        for existing in ('data', 'service', 'package', 'path'):
            with self.subTest(existing=existing):
                data = self.directory / 'cloudflare-warp'
                if existing == 'data':
                    data.mkdir()
                result = self.invoke('setup', answers='WARP\n',
                                     EXISTING_SERVICE=str(int(existing == 'service')),
                                     EXISTING_PACKAGE=str(int(existing == 'package')),
                                     EXISTING_PATH=str(int(existing == 'path')))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('install-package', self.actions())
                self.assertEqual(self.cli_actions(), [])
                self.assertFalse((self.base / '.warp-owner').exists())
                if data.exists():
                    data.rmdir()

    def test_mdm_policy_blocks_setup_and_reconnect_without_mutations(self):
        self.install_fixture_cli('registered')
        policy = self.directory / 'cloudflare-warp/mdm.xml'
        policy.parent.mkdir()
        policy.write_text('<fixture-policy/>')
        for operation in ('setup-if', 'connect-if'):
            with self.subTest(operation=operation):
                self.events.write_text('')
                result = self.invoke(operation, answers='WARP\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('MDM', result.stderr)
                self.assertEqual(self.actions(), [])
                self.assertEqual(policy.read_text(), '<fixture-policy/>')

    def test_prepared_marker_with_partial_install_is_not_automatically_taken_over(self):
        self.install_fixture_cli('prepared')
        result = self.invoke('setup-if', answers='WARP\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('上次安装未确认完成', result.stderr)
        self.assertEqual(self.actions(), [])
        self.assertEqual((self.base / '.warp-owner').read_text(), 'anyharbor-warp-v1:prepared\n')

    def test_fresh_setup_configures_proxy_before_registration_and_connection(self):
        result = self.invoke('setup', answers='WARP\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cli_actions(), ['disconnect', 'mode proxy', 'proxy port 40000',
                                             'registration new',
                                             'disconnect', 'mode proxy', 'proxy port 40000',
                                             'tunnel protocol set MASQUE', 'connect'])
        self.assertEqual(self.actions().count('install-package'), 1)
        self.assertEqual((self.base / '.warp-owner').read_text(), 'anyharbor-warp-v1:registered\n')
        self.assertNotIn('clone', self.actions())
        self.assertNotIn('activate', self.actions())

    def test_each_proxy_setting_failure_stops_before_registration_even_inside_if(self):
        steps = ['disconnect', 'mode proxy', 'proxy port 40000']
        self.install_fixture_cli('installed')
        for index, step in enumerate(steps):
            with self.subTest(step=step):
                self.events.write_text('')
                result = self.invoke('setup-if', FAIL_CLI=step)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.cli_actions(), steps[:index + 1])
                self.assertNotIn('curl', self.actions())
                self.assertEqual((self.base / '.warp-owner').read_text(), 'anyharbor-warp-v1:installed\n')

    def test_package_failure_does_not_start_service_or_configure_client(self):
        result = self.invoke('setup-if', answers='WARP\n', FAIL_INSTALL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cli_actions(), [])
        self.assertNotIn('systemctl:enable --now warp-svc.service', self.actions())

    def test_post_registration_settings_failure_never_connects(self):
        self.install_fixture_cli('installed')
        for step in ('disconnect', 'mode proxy', 'proxy port 40000', 'tunnel protocol set MASQUE'):
            with self.subTest(step=step):
                self.events.write_text('')
                (self.base / '.warp-owner').write_text('anyharbor-warp-v1:installed\n')
                self.registration.unlink(missing_ok=True)
                result = self.invoke('setup-if', FAIL_AFTER_REGISTER=step)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('registration new', self.cli_actions())
                self.assertEqual(self.cli_actions()[-1], step)
                self.assertNotIn('connect', self.cli_actions())
                self.assertNotIn('curl', self.actions())
                self.assertEqual((self.base / '.warp-owner').read_text(), 'anyharbor-warp-v1:registering\n')

    def test_170_installed_stage_resumes_without_reinstall_or_group_changes(self):
        # 1.7.0 stopped after the three local proxy settings but before creating
        # any registration. This is the exact state reported by the user.
        self.install_fixture_cli('installed')
        before = self.state_path.read_bytes()
        result = self.invoke('setup-if')
        self.assertEqual(result.returncode, 0, result.stderr)
        actions = self.cli_actions()
        self.assertEqual(actions.count('registration new'), 1)
        self.assertLess(actions.index('registration new'), actions.index('tunnel protocol set MASQUE'))
        self.assertLess(actions.index('tunnel protocol set MASQUE'), actions.index('connect'))
        self.assertNotIn('install-package', self.actions())
        self.assert_no_group_change(before)
        self.assertEqual((self.base / '.warp-owner').read_text(), 'anyharbor-warp-v1:registered\n')

    def test_protocol_failure_after_registration_retries_without_new_registration(self):
        self.install_fixture_cli('installed')
        before = self.state_path.read_bytes()
        result = self.invoke('setup-if', FAIL_CLI='tunnel protocol set MASQUE')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.registration.exists())
        self.assertEqual(self.cli_actions().count('registration new'), 1)
        self.assertEqual(self.cli_actions()[-1], 'tunnel protocol set MASQUE')
        self.assertNotIn('connect', self.cli_actions())
        self.assertNotIn('curl', self.actions())
        self.assert_no_group_change(before)
        self.events.write_text('')
        result = self.invoke('setup-if')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cli_actions(), ['registration show', 'disconnect', 'mode proxy',
                                             'proxy port 40000', 'tunnel protocol set MASQUE', 'connect'])
        self.assertNotIn('install-package', self.actions())
        self.assert_no_group_change(before)

    def test_registered_reconnect_protocol_failure_never_connects(self):
        self.install_fixture_cli('registered')
        before = self.state_path.read_bytes()
        result = self.invoke('connect-if', FAIL_CLI='tunnel protocol set MASQUE')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cli_actions(), ['registration show', 'disconnect', 'mode proxy',
                                             'proxy port 40000', 'tunnel protocol set MASQUE'])
        self.assertNotIn('curl', self.actions())
        self.assert_no_group_change(before)

    def test_service_enable_failure_stops_even_inside_if(self):
        self.install_fixture_cli('installed')
        result = self.invoke('setup-if', FAIL_ENABLE='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('systemctl:enable --now warp-svc.service', self.actions())
        self.assertEqual(self.cli_actions(), [])
        self.assertNotIn('curl', self.actions())

    def test_registration_failure_is_not_repeated_without_confirmed_existing_registration(self):
        self.install_fixture_cli('installed')
        result = self.invoke('setup-if', FAIL_CLI='registration new')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cli_actions()[-1], 'registration new')
        self.assertNotIn('connect', self.cli_actions())
        self.assertEqual((self.base / '.warp-owner').read_text(), 'anyharbor-warp-v1:registering\n')
        self.events.write_text('')
        result = self.invoke('setup-if', FAIL_CLI='registration show')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cli_actions(), ['registration show'])

    def test_connect_failure_cannot_report_success_even_inside_if(self):
        self.install_fixture_cli('registered')
        for operation in ('setup-if', 'connect-if'):
            with self.subTest(operation=operation):
                self.events.write_text('')
                result = self.invoke(operation, FAIL_CLI='connect')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.cli_actions()[-1], 'connect')
                self.assertNotIn('completed', self.actions())
                self.assertNotIn('curl', self.actions())

    def test_failed_exit_health_after_connect_does_not_claim_completion_or_change_groups(self):
        self.install_fixture_cli('installed')
        before = self.state_path.read_bytes()
        result = self.invoke('setup-if', TRACE='warp=off')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cli_actions()[-1], 'connect')
        self.assertEqual(self.actions().count('curl'), 4)
        self.assertNotIn('completed', self.actions())
        self.assert_no_group_change(before)

    def test_health_uses_socks_remote_dns_and_explicitly_disables_no_proxy_bypass(self):
        self.install_fixture_cli()
        result = self.invoke('check', NO_PROXY='*', no_proxy='*', HTTPS_PROXY='http://unexpected.invalid:1')
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = [event.removeprefix('curl-arg:') for event in self.actions() if event.startswith('curl-arg:')]
        self.assertEqual(arguments[0], '-q')
        self.assertEqual(arguments[arguments.index('--noproxy') + 1], '')
        self.assertEqual(arguments[arguments.index('--proxy') + 1], 'socks5h://127.0.0.1:40000')
        self.assertEqual(arguments[arguments.index('--proto') + 1], '=https')
        self.assertEqual(arguments[-1], 'https://www.cloudflare.com/cdn-cgi/trace')
        self.assertNotIn('--insecure', arguments)
        self.assertNotIn('-k', arguments)

    def test_health_rejects_off_or_misleading_trace_and_transport_failure(self):
        self.install_fixture_cli()
        for trace in ('warp=off', 'warp=onX', 'note=warp=on', 'warp='):
            with self.subTest(trace=trace):
                result = self.invoke('check', TRACE=trace)
                self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(self.invoke('check', FAIL_CURL='1').returncode, 0)
        self.assertEqual(self.invoke('check', TRACE='warp=plus\r\n').returncode, 0)

    def test_health_rejects_nonloopback_wrong_process_or_extra_public_listener_before_curl(self):
        self.install_fixture_cli()
        rows = ['', VALID_LISTENER.replace('127.0.0.1:40000', '0.0.0.0:40000'),
                VALID_LISTENER.replace('"warp-svc"', '"unrelated"'),
                VALID_LISTENER + '\n' + VALID_LISTENER.replace('127.0.0.1:40000', '[::]:40000')]
        for listeners in rows:
            with self.subTest(listeners=listeners):
                self.events.write_text('')
                self.assertNotEqual(self.invoke('check', LISTENERS=listeners).returncode, 0)
                self.assertNotIn('curl', self.actions())
        self.assertNotEqual(self.invoke('check', FAIL_SS='1').returncode, 0)

    def test_inactive_service_does_not_run_https_probe(self):
        self.install_fixture_cli()
        self.assertNotEqual(self.invoke('check', SERVICE_ACTIVE='0').returncode, 0)
        self.assertNotIn('curl', self.actions())

    def test_failed_health_prevents_group_egress_change_and_generation_creation(self):
        self.install_fixture_cli()
        before = self.state_path.read_bytes()
        result = self.invoke('group', 'egress', 'athena', 'warp', TRACE='warp=off')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_group_change(before)

    def test_failed_health_prevents_reenabling_warp_group(self):
        self.set_group_egress('warp', enabled=False)
        before = self.state_path.read_bytes()
        result = self.invoke('group', 'enable', 'athena')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_group_change(before)

    def test_changing_to_direct_does_not_require_warp_client(self):
        self.set_group_egress('warp')
        result = self.invoke('group', 'egress', 'athena', 'direct')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), ['clone', 'finalize', 'activate'])
        candidate = helper.load(self.directory / 'candidate/state.json')
        self.assertEqual(candidate['groups'][0]['egress'], 'direct')

    def test_reenabling_direct_group_does_not_require_warp_client(self):
        self.set_group_egress('direct', enabled=False)
        result = self.invoke('group', 'enable', 'athena')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), ['clone', 'finalize', 'activate'])

    def test_adding_warp_group_through_tty_checks_health_before_allocating_credentials(self):
        before = self.state_path.read_bytes()
        result = self.invoke('group', 'add', answers='2\n', tty=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_group_change(before)

    def test_tty_add_warp_saves_selected_egress_only_after_successful_health_check(self):
        self.install_fixture_cli()
        before = helper.load(self.state_path)
        result = self.invoke('group', 'add', answers='2\n', tty=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(self.actions().index('curl'), self.actions().index('clone'))
        self.assertEqual(self.actions()[-3:], ['clone', 'finalize', 'activate'])
        candidate = helper.load(self.directory / 'candidate/state.json')
        self.assertEqual(candidate['groups'][:2], before['groups'])
        self.assertEqual(candidate['groups'][-1]['egress'], 'warp')
        self.assertEqual(candidate['schema'], 3)

    def test_noninteractive_add_defaults_to_direct_without_warp_client(self):
        result = self.invoke('group', 'add')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), ['clone', 'finalize', 'activate'])
        candidate = helper.load(self.directory / 'candidate/state.json')
        self.assertEqual(len(candidate['groups']), 3)
        self.assertEqual(candidate['groups'][-1].get('egress', 'direct'), 'direct')


if __name__ == '__main__':
    unittest.main()
