"""Numeric menu control flow using real child Bash processes and a fixture lock."""
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
MANAGER = ROOT / 'src/anytls-manager.sh'
SUBSCRIPTION = ROOT / 'src/anytls-subscription.sh'
HELPER = ROOT / 'src/anytls-state.py'
BASH = shutil.which('bash')
spec = importlib.util.spec_from_file_location('menu_state', HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


@unittest.skipUnless(sys.platform.startswith('linux') and BASH and shutil.which('flock'),
                     'Requires Linux, Bash and flock; no root privileges are needed')
class NumericMenuTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='gz-menu-unit-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.state_path = self.directory / 'state.json'
        helper.main(['init', str(self.state_path), 'proxy.example.test', '8443'])
        state = helper.load(self.state_path)
        state['groups'] = state['groups'][:3]
        state['groups'][1]['enabled'] = False
        state['subscription'] = {'domain': 'sub.example.test', 'port': 9443}
        helper.write_json(self.state_path, state)
        self.events = self.directory / 'events'
        self.events.touch()
        self.worker = self.directory / 'manager-fixture.sh'
        manager = MANAGER.read_text()
        subscription = SUBSCRIPTION.read_text()

        def function(text, name):
            return re.search(r'^' + name + r'\(\) \{\n.*?^\}\n', text,
                             re.MULTILINE | re.DOTALL).group(0)

        names = ('menu_select_group', 'menu_export', 'menu_settings', 'menu_updates', 'menu_git_source',
                 'menu_run', 'menu', 'group_menu', 'main')
        functions = '\n'.join(function(manager, name) for name in names)
        functions += '\n' + function(subscription, 'subscription_command')
        prelude = r'''
#!/usr/bin/env bash
set -euo pipefail
SELF=$(readlink -f -- "${BASH_SOURCE[0]}")
MANAGER="$TEST_DIRECTORY/absent-installed-launcher"
BASE="$TEST_DIRECTORY/base"
MANAGER_CURRENT="$BASE/manager-current"
LAUNCHER_MARK='# Managed by gz-anytls-launcher-v1'
APP_NAME=AnyHarbor
SERVICE=fixture.service
SUB_SERVICE=fixture-sub.service
MANAGER_VERSION=fixture
record() { printf '%s\n' "$*" >> "$TEST_EVENTS"; }
die() { printf '%s\n' "$*" >&2; exit 70; }
current() { printf '%s\n' "$TEST_DIRECTORY"; }
py() { python3 "$STATE_HELPER" "$@"; }
root_and_tools() { :; }
root_readonly() { [[ -f "$1" && ! -L "$1" ]] || die 'Fixture launcher is not a regular file.'; }
owned_base() { :; }
lock_base() { exec 9>"$TEST_DIRECTORY/lock"; flock -n 9 || die 'Fixture lock inherited or not released.'; }
ui_heading() { printf 'HEADING:%s\n' "$1"; }
ui_status_summary() { :; }
ui_section() { printf 'SECTION:%s\n' "$*"; }
ui_item() { printf '%s) %s\n' "$1" "$2"; }
ui_note() { printf '%s\n' "$*"; }
ui_warn() { printf '%s\n' "$*"; }
ui_prompt() { IFS= read -r -p "$2" "$1"; }
say() { printf '%s\n' "$*"; }
systemctl() { return 0; }
diagnose() {
    record diagnose
    if [[ ${FAIL_ACTION:-} == diagnose ]]; then
        false
        record UNSAFE_MUTATION_AFTER_FAILURE
    fi
}
show_export() { record "export $*"; }
show_v2rayn_export() { record "v2rayn $*"; }
show_clash_export() { record "clash $*"; }
subscription_links() { record "subscription-links $*"; }
subscription_status() { record subscription-status; }
subscription_refresh() { record subscription-refresh; }
subscription_enable() { record subscription-enable; }
subscription_off() { record subscription-off; }
group_command() { record "group $*"; }
prefix_command() { record "prefix $*"; }
change_setting() { record "setting $*"; }
import_certificate() { record import-cert; }
manager_check_update() { record check-update; }
manager_self_update() { record self-update; }
updater() { record "updater $*"; }
manager_rollback() { record manager-rollback; }
update_core() { record update-core; }
rollback() { record rollback; }
install_server() { record install; }
uninstall_server() { record uninstall; }
'''
        self.worker.write_text(prelude.lstrip() + '\n' + functions + '\nmain "$@"\n')

    def run_menu(self, answers='', *arguments, **settings):
        return subprocess.run(
            [BASH, str(self.worker), *arguments], input=answers, text=True,
            capture_output=True, encoding='utf-8', timeout=10,
            env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C.UTF-8',
                 'HOME': str(self.directory), 'TEST_DIRECTORY': str(self.directory),
                 'TEST_EVENTS': str(self.events), 'STATE_HELPER': str(HELPER), **settings})

    def actions(self):
        return self.events.read_text().splitlines()

    def installed_bundles(self, current='old'):
        """Two real fixture bundles behind a stable launcher, like a live upgrade."""
        template = self.worker.read_text()
        bundles = self.directory / 'base/manager-releases'
        for version in ('old', 'new'):
            directory = bundles / version
            directory.mkdir(parents=True)
            script = template.replace('MANAGER_VERSION=fixture', 'MANAGER_VERSION=' + version)
            script = script.replace('    record diagnose\n', '    record "diagnose-$MANAGER_VERSION"\n')
            script = script.replace('manager_self_update() { record self-update; }', r'''
manager_self_update() {
    record "self-update-$MANAGER_VERSION"
    ln -sfn "$BASE/manager-releases/new" "$MANAGER_CURRENT"
}
''')
            (directory / 'anytls-manager.sh').write_text(script)
        self.current_bundle = self.directory / 'base/manager-current'
        self.current_bundle.symlink_to(bundles / current)
        self.launcher = self.directory / 'absent-installed-launcher'
        self.launcher.write_text(r'''#!/usr/bin/env bash
# Managed by gz-anytls-launcher-v1
set -euo pipefail
printf 'launcher %s\n' "${*:-<menu>}" >> "$TEST_EVENTS"
directory=$(readlink -f -- "$TEST_DIRECTORY/base/manager-current")
exec bash "$directory/anytls-manager.sh" "$@"
''')
        self.worker = bundles / 'old/anytls-manager.sh'

    def test_no_arguments_enters_menu_and_zero_exits_without_running_actions(self):
        result = self.run_menu('0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('主菜单', result.stdout)
        self.assertIn('0) 退出', result.stdout)
        self.assertEqual(self.actions(), [])
        self.assertFalse((self.directory / 'lock').exists())

    def test_numeric_export_subscription_and_group_actions_return_to_main_menu(self):
        # Main export -> enabled group 2; subscription -> links -> group 1;
        # group manager -> add. Blank lines dismiss the action-result pause.
        result = self.run_menu('2\n2\n\n3\n3\n1\n\n4\n1\n\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), ['export hermes', 'subscription-links all athena', 'group add'])
        self.assertGreaterEqual(result.stdout.count('· 主菜单'), 4)
        self.assertNotIn('Fixture lock', result.stderr)

    def test_failed_child_keeps_errexit_and_releases_lock_for_the_next_action(self):
        result = self.run_menu('1\n\n2\n1\n\n0\n', FAIL_ACTION='diagnose')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), ['diagnose', 'export athena'])
        self.assertIn('退出码 1', result.stdout)
        self.assertNotIn('UNSAFE_MUTATION', self.events.read_text())
        self.assertNotIn('Fixture lock', result.stderr)

    def test_invalid_main_choices_do_not_execute_an_action(self):
        result = self.run_menu('unknown\n99\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), [])
        self.assertGreaterEqual(result.stdout.count('无效编号'), 2)

    def test_eof_at_main_pause_and_group_choice_exits_without_hanging(self):
        for answers, expected in [('', []), ('1\n', ['diagnose']), ('2\n', [])]:
            with self.subTest(answers=answers):
                self.events.write_text('')
                result = self.run_menu(answers)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.actions(), expected)

    def test_group_management_numbers_resolve_the_correct_scope_without_id_input(self):
        cases = [('1\n', 'group add'), ('2\n2\n', 'group rename apollo'),
                 ('3\n2\n', 'group rotate hermes'), ('4\n2\n', 'group disable hermes'),
                 ('5\n1\n', 'group enable apollo'), ('6\n2\n', 'group remove apollo')]
        for answers, expected in cases:
            with self.subTest(answers=answers):
                self.events.write_text('')
                result = self.run_menu(answers, 'groups')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.actions(), [expected])
                self.assertNotIn('请输入启用分组的 ID', result.stderr)

    def test_group_management_zero_eof_and_invalid_choices_do_not_mutate(self):
        for answers, successful in [('0\n', True), ('', True), ('99\n', False), ('3\n99\n', False)]:
            with self.subTest(answers=answers):
                self.events.write_text('')
                result = self.run_menu(answers, 'groups')
                self.assertEqual(result.returncode == 0, successful, result.stderr)
                self.assertEqual(self.actions(), [])

    def test_settings_and_updates_accept_number_choices_and_return_to_main(self):
        result = self.run_menu('5\n1\n\n6\n2\n\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), ['setting port', 'self-update'])
        self.assertGreaterEqual(result.stdout.count('· 主菜单'), 3)

    def test_public_git_source_menu_uses_defaults_without_key_prompt(self):
        result = self.run_menu('6\n8\n\n\n\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), [
            'updater git-source ' + str(self.directory / 'base') + ' JackieSung4ev/AnyHarbor main'])
        self.assertNotIn('私钥', result.stderr)

    def test_public_git_source_menu_keeps_entered_repository_and_branch(self):
        result = self.run_menu('6\n8\nExample/Public\nmaintenance/stable\n\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), [
            'updater git-source ' + str(self.directory / 'base') + ' Example/Public maintenance/stable'])

    def test_public_git_source_menu_eof_does_not_change_binding(self):
        result = self.run_menu('6\n8\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), [])

    def test_installed_menu_uses_latest_launcher_even_if_its_own_bundle_is_old(self):
        self.installed_bundles(current='new')
        result = self.run_menu('1\n\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), ['launcher diagnose', 'diagnose-new', 'launcher <menu>'])
        self.assertIn('AnyHarbor new · 主菜单', result.stdout)
        self.assertNotIn('diagnose-old', self.actions())

    def test_successful_upgrade_reloads_new_menu_and_does_not_keep_stale_self(self):
        self.installed_bundles()
        result = self.run_menu('6\n2\n\n1\n\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.actions(), ['launcher __menu-updates', 'self-update-old',
                                         'launcher <menu>', 'launcher diagnose', 'diagnose-new'])
        self.assertEqual(self.current_bundle.resolve().name, 'new')
        self.assertEqual(result.stdout.count('AnyHarbor old · 主菜单'), 1)
        self.assertGreaterEqual(result.stdout.count('AnyHarbor new · 主菜单'), 2)
        self.assertNotIn('Fixture lock', result.stderr)

    def test_installed_menu_refuses_unmanaged_launcher_without_executing_it(self):
        self.installed_bundles()
        self.launcher.write_text('#!/usr/bin/env bash\nprintf UNSAFE_LAUNCHER >> "$TEST_EVENTS"\n')
        result = self.run_menu('1\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('启动器标记异常', result.stderr)
        self.assertEqual(self.actions(), [])


if __name__ == '__main__':
    unittest.main()
