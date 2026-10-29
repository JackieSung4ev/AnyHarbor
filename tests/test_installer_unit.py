"""Black-box bootstrap checks; privileged cases require an isolated test runner.

Run privileged cases only in a disposable Debian container or Debian CI runner:
  GZ_INSTALLER_INTEGRATION=1 python3 -B -m unittest discover -s tests -p test_installer_unit.py
No production manager, service, package manager, or network request is executed.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'install.sh'
BASH = shutil.which('bash')
LINUX = sys.platform.startswith('linux') and BASH
ISOLATED_ROOT = (
    LINUX and os.geteuid() == 0
    and os.environ.get('GZ_INSTALLER_INTEGRATION') == '1'
    and (Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()
         or os.environ.get('GITHUB_ACTIONS') == 'true')
)


@unittest.skipUnless(LINUX, 'Requires Linux and Bash')
class InstallerPublicInterfaceTests(unittest.TestCase):
    def invoke(self, *arguments, drop_privileges=False):
        def become_nobody():
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)

        return subprocess.run(
            [BASH, str(ENTRY), *arguments], capture_output=True, text=True,
            encoding='utf-8', timeout=10,
            env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C'},
            preexec_fn=become_nobody if drop_privileges and os.geteuid() == 0 else None,
        )

    def test_help_works_without_root_or_setup(self):
        result = self.invoke('--help', drop_privileges=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('self-update', result.stdout)
        self.assertIn('--upgrade', result.stdout)
        self.assertIn('Git HTTPS', result.stdout)

    def test_unknown_argument_is_rejected(self):
        for arguments in (('--not-an-install-option',), ('--public',),
                          ('--upgrade', '--upgrade'), ('install',)):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertNotEqual(result.returncode, 0)
        self.assertIn('--help', result.stderr)

    def test_install_requires_root(self):
        result = self.invoke(drop_privileges=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('root', result.stderr)

    def test_upgrade_requires_root(self):
        for arguments in (('--upgrade',),):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments, drop_privileges=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('root', result.stderr)


@unittest.skipUnless(ISOLATED_ROOT,
                     'Requires explicit GZ_INSTALLER_INTEGRATION=1 in an isolated root runner')
class InstallerIsolatedTests(unittest.TestCase):
    def setUp(self):
        # Refuse to take over existing installs, credentials, or command wrappers.
        self.managed = Path('/opt/jackie-anytls')
        self.config = Path('/root/.ssh/gz-anytls.conf')
        self.cli = Path('/usr/local/sbin/any')
        self.legacy_cli = Path('/usr/local/sbin/jackie-anytls')
        for path in (self.managed, self.config, self.cli, self.legacy_cli):
            if os.path.lexists(path):
                self.fail('Refusing an existing path on the test runner: ' + str(path))

        temporary = tempfile.TemporaryDirectory(prefix='gz-installer-test-', dir='/opt')
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)
        self.source = self.scratch / 'source'
        self.source.mkdir()
        shutil.copy2(ENTRY, self.source / 'install.sh')
        shutil.copytree(ROOT / 'src', self.source / 'src')
        (self.source / 'tools').mkdir()
        shutil.copy2(ROOT / 'tools/build_release.py', self.source / 'tools/build_release.py')
        # Windows bind mounts can expose permissive source modes; the fixture is
        # deliberately a new root-owned checkout with normal trusted modes.
        for path in self.source.rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        self.events = self.scratch / 'events'
        self.events.touch()
        self.key = self.scratch / 'deploy_key'
        self.key.write_text('isolated fake key; never used for network authentication\n')
        self.key.chmod(0o600)
        self.created_directory('/root/.ssh', 0o700)
        self.created_directory('/run/systemd/system', 0o755)
        self.created_directory('/usr/local/sbin', 0o755)
        self.config.write_text('Host github.com\n    IdentityFile ' + str(self.key) + '\n')
        self.config.chmod(0o600)
        self.addCleanup(lambda: self.config.unlink(missing_ok=True))

        # The bootstrap intentionally fixes PATH. These disposable, previously
        # absent /usr/sbin wrappers take priority without replacing system tools.
        self.command('systemctl', 'exit "${TEST_SYSTEMD_STATUS:-0}"')
        self.command('git', 'exit 0')
        self.command('ssh', 'exit 0')
        self.command('ssh-keygen', 'exit "${TEST_KEY_STATUS:-0}"')
        self.command('dpkg-query',
                     '[[ ${TEST_NEEDS_APT:-0} == 1 ]] || printf "install ok installed"')
        self.command('apt-get',
                     'printf "apt %s\\n" "$*" >>"$TEST_EVENTS"\nexit "${TEST_APT_STATUS:-99}"')
        for name in ('curl', 'openssl', 'ss', 'flock', 'useradd', 'getent'):
            if not shutil.which(name, path='/usr/sbin:/usr/bin:/sbin:/bin'):
                self.command(name, 'exit 97')
        self.cli.write_text(
            '#!/bin/bash\nset -e\nprintf "cli %s\\n" "$*" >>"$TEST_EVENTS"\n'
            'case "$1" in\n'
            ' update-source-ssh|update-source-git) exit "${TEST_BIND_STATUS:-0}";;\n'
            ' status) exit "${TEST_STATUS_STATUS:-0}";;\n'
            'esac\n'
        )
        self.cli.chmod(0o700)
        self.addCleanup(self.cli.unlink)

        manager = self.source / 'src/anytls-manager.sh'
        version = re.search(r'^readonly MANAGER_VERSION=(\d+\.\d+\.\d+)$',
                            manager.read_text(), re.MULTILINE).group(1)
        manager.write_text(
            '#!/bin/bash\nset -euo pipefail\nreadonly MANAGER_VERSION=' + version + '\n'
            'printf "manager %s\\n" "$*" >>"$TEST_EVENTS"\n'
            'if [[ $1 == install ]]; then\n'
            ' read -r answer\n'
            ' printf "stdin %s\\n" "$answer" >>"$TEST_EVENTS"\n'
            'fi\n'
            'exit "${TEST_INSTALL_STATUS:-0}"\n'
        )
        self.builds_before = set(Path('/opt').glob('gz-anytls-install.*'))
        self.addCleanup(self.clean_builds)

    def created_directory(self, value, mode):
        path = Path(value)
        missing = []
        for current in (path, *path.parents):
            if current.exists():
                break
            missing.append(current)
        path.mkdir(parents=True, mode=mode, exist_ok=True)
        # Cleanups run in reverse order: child first, only if empty.
        for current in reversed(missing):
            self.addCleanup(current.rmdir)

    def command(self, name, body):
        path = Path('/usr/sbin') / name
        if os.path.lexists(path):
            self.fail('Refusing to replace a system command: ' + str(path))
        path.write_text('#!/bin/bash\n' + body + '\n')
        path.chmod(0o700)
        self.addCleanup(path.unlink)

    def clean_builds(self):
        for path in set(Path('/opt').glob('gz-anytls-install.*')) - self.builds_before:
            if path.is_symlink() or path.parent != Path('/opt'):
                raise AssertionError('Unexpected build path: ' + str(path))
            shutil.rmtree(path)

    def invoke(self, *arguments, input_text='interactive answer\n', **settings):
        return subprocess.run(
            [BASH, str(self.source / 'install.sh'), *arguments], input=input_text,
            capture_output=True, text=True, encoding='utf-8', timeout=30,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LC_ALL': 'C',
                 'TEST_EVENTS': str(self.events), **settings},
        )

    def assert_no_install(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('manager ', self.events.read_text())
        self.assertNotIn('cli ', self.events.read_text())

    def public_environment(self):
        self.config.unlink()
        self.key.unlink()
        # Simulate missing SSH tools without moving any real system binaries.
        # All invocations are also trapped by our previously absent wrappers.
        shell_env = self.scratch / 'no-ssh.bash'
        shell_env.write_text(
            'command() {\n'
            ' case "$*" in "-v ssh"|"-v ssh-keygen") return 1;; esac\n'
            ' builtin command "$@"\n'
            '}\n')
        for name in ('ssh', 'ssh-keygen'):
            Path('/usr/sbin', name).write_text(
                '#!/bin/bash\nprintf "unexpected ssh call\\n" >>"$TEST_EVENTS"\nexit 98\n')
        return {'BASH_ENV': str(shell_env)}

    def test_success_preserves_stdin_and_binds_public_source_after_install(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), [
            'manager install', 'stdin interactive answer',
            'cli update-source-git JackieSung4ev/AnyHarbor main',
            'cli status',
        ])


    def test_public_install_without_ssh_or_key_preserves_stdin_and_binds_https(self):
        settings = self.public_environment()
        for config_kind in ('missing', 'untrusted'):
            with self.subTest(config_kind=config_kind):
                if config_kind == 'untrusted':
                    self.config.symlink_to(self.scratch / 'nonexistent-private-config')
                self.events.write_text('')
                result = self.invoke(**settings)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.events.read_text().splitlines(), [
                    'manager install', 'stdin interactive answer',
                    'cli update-source-git JackieSung4ev/AnyHarbor main', 'cli status',
                ])
                self.assertNotIn('Deploy Key', result.stdout + result.stderr)
                self.assertFalse(self.key.exists())


    def test_existing_install_even_dangling_symlink_is_preserved(self):
        self.managed.symlink_to(self.scratch / 'missing')
        self.addCleanup(self.managed.unlink)
        result = self.invoke()
        self.assert_no_install(result)
        self.assertTrue(self.managed.is_symlink())
        self.assertIn('self-update', result.stderr)
        self.assertEqual(self.events.read_text(), '')


    def test_writable_source_is_rejected_before_apt_or_install(self):
        (self.source / 'src/anytls-runtime.sh').chmod(0o666)
        result = self.invoke(TEST_NEEDS_APT='1')
        self.assert_no_install(result)
        self.assertEqual(self.events.read_text(), '')


    def test_apt_failure_stops_before_install(self):
        result = self.invoke(TEST_NEEDS_APT='1', TEST_APT_STATUS='42')
        self.assert_no_install(result)
        self.assertEqual(self.events.read_text().splitlines(), ['apt update'])

    def test_corrupted_built_archive_is_not_executed(self):
        builder = self.source / 'tools/build_release.py'
        original = self.source / 'tools/original_builder.py'
        builder.rename(original)
        builder.write_text(
            'import json, runpy, sys\nfrom pathlib import Path\n'
            'build = runpy.run_path(str(Path(__file__).with_name("original_builder.py")))["build"]\n'
            'result = build(Path(sys.argv[sys.argv.index("--root") + 1]), '
            'Path(sys.argv[sys.argv.index("--output-dir") + 1]))\n'
            'Path(result["archive"]).write_bytes(b"corrupt archive")\n'
            'print(json.dumps(result))\n'
        )
        result = self.invoke()
        self.assert_no_install(result)
        self.assertIn('SHA256', result.stderr)

    def test_failed_manager_does_not_bind_or_report_success(self):
        result = self.invoke(TEST_INSTALL_STATUS='37')
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertEqual(self.events.read_text().splitlines(),
                         ['manager install', 'stdin interactive answer'])

    def existing_install(self):
        self.managed.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(self.managed))
        (self.managed / '.owner').write_text('jackie-anytls-manager-v1\n')
        state = self.managed / 'synthetic-state.json'
        state.write_text('{"password": "synthetic-existing-password", "enabled": false}\n')
        state.chmod(0o600)
        self.legacy_cli.write_text(
            '#!/bin/bash\n'
            'readonly BASE=/opt/jackie-anytls SERVICE=jackie-anytls.service\n'
            'printf "legacy %s\\n" "$*" >>"$TEST_EVENTS"\nexit 91\n')
        self.legacy_cli.chmod(0o700)
        self.addCleanup(lambda: self.legacy_cli.unlink(missing_ok=True))
        return state

    def test_upgrade_requires_existing_install_and_never_falls_back_to_install(self):
        for arguments in (('--upgrade',),):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments, TEST_NEEDS_APT='1')
                self.assert_no_install(result)
                self.assertIn('--upgrade', result.stderr)
                self.assertEqual(self.events.read_text(), '')
                self.assertFalse(self.managed.exists())

    def test_upgrade_rejects_foreign_owner_before_dependencies_or_manager(self):
        state = self.existing_install()
        before = state.read_bytes()
        (self.managed / '.owner').write_text('unrelated-installation\n')
        result = self.invoke('--upgrade', TEST_NEEDS_APT='1')
        self.assert_no_install(result)
        self.assertIn('归属标记', result.stderr)
        self.assertEqual(self.events.read_text(), '')
        self.assertEqual(state.read_bytes(), before)

    def test_upgrade_rejects_missing_or_foreign_manager(self):
        self.existing_install()
        self.legacy_cli.unlink()
        for kind in ('missing', 'foreign'):
            with self.subTest(kind=kind):
                if kind == 'foreign':
                    self.legacy_cli.write_text('#!/bin/bash\nexit 0\n')
                    self.legacy_cli.chmod(0o700)
                result = self.invoke('--upgrade', TEST_NEEDS_APT='1')
                self.assert_no_install(result)
                self.assertEqual(self.events.read_text(), '')

    def test_upgrade_preserves_state_without_ssh_setup_or_install(self):
        state = self.existing_install()
        before = state.read_bytes()
        result = self.invoke('--upgrade', input_text='', **self.public_environment())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), [
            'manager upgrade-manager',
            'cli update-source-git JackieSung4ev/AnyHarbor main',
            'cli status',
        ])
        self.assertEqual(state.read_bytes(), before)
        self.assertIn('更新完成', result.stdout)
        self.assertIn('未自动刷新订阅', result.stdout)

    def test_failed_upgrade_does_not_bind_or_report_success(self):
        state = self.existing_install()
        before = state.read_bytes()
        result = self.invoke('--upgrade', input_text='', TEST_INSTALL_STATUS='37')
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), ['manager upgrade-manager'])
        self.assertEqual(state.read_bytes(), before)
        self.assertNotIn('更新完成', result.stdout)
        self.assertIn('升级管理工具', result.stderr)


    def test_public_install_binding_failure_reports_install_completed(self):
        settings = self.public_environment()
        result = self.invoke(TEST_BIND_STATUS='43', **settings)
        self.assertEqual(result.returncode, 43, result.stdout + result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), [
            'manager install', 'stdin interactive answer',
            'cli update-source-git JackieSung4ev/AnyHarbor main',
        ])
        self.assertIn('安装已完成，绑定 Git HTTPS 更新源', result.stderr)
        self.assertNotIn('安装完成。', result.stdout)

    def test_public_upgrade_binding_failure_reports_upgrade_completed(self):
        state = self.existing_install()
        before = state.read_bytes()
        settings = self.public_environment()
        result = self.invoke('--upgrade', input_text='',
                             TEST_BIND_STATUS='43', **settings)
        self.assertEqual(result.returncode, 43, result.stdout + result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), [
            'manager upgrade-manager',
            'cli update-source-git JackieSung4ev/AnyHarbor main',
        ])
        self.assertEqual(state.read_bytes(), before)
        self.assertIn('管理工具已升级，绑定 Git HTTPS 更新源', result.stderr)
        self.assertNotIn('更新完成', result.stdout)

    def test_post_upgrade_binding_or_status_failure_reports_upgrade_already_completed(self):
        state = self.existing_install()
        before = state.read_bytes()
        for setting in ('TEST_BIND_STATUS', 'TEST_STATUS_STATUS'):
            with self.subTest(setting=setting):
                self.events.write_text('')
                result = self.invoke('--upgrade', input_text='', **{setting: '43'})
                self.assertEqual(result.returncode, 43, result.stdout + result.stderr)
                events = self.events.read_text().splitlines()
                self.assertEqual(events[0], 'manager upgrade-manager')
                self.assertEqual(len(events), 2 if setting == 'TEST_BIND_STATUS' else 3)
                self.assertNotIn('legacy ', self.events.read_text())
                self.assertNotIn('manager install', self.events.read_text())
                self.assertEqual(state.read_bytes(), before)
                self.assertNotIn('更新完成', result.stdout)
                self.assertIn('管理工具已升级', result.stderr)

    def bootstrap_git(self, status=0):
        """A failed clone still leaves an entry file; it must never be executed."""
        Path('/usr/sbin/git').write_text(
            '#!/bin/bash\nset -euo pipefail\n'
            '[[ $GIT_ALLOW_PROTOCOL == https && $GIT_CONFIG_NOSYSTEM == 1 ]]\n'
            '[[ $GIT_CONFIG_GLOBAL == /dev/null && $GIT_TERMINAL_PROMPT == 0 ]]\n'
            '[[ -z ${SSH_AUTH_SOCK:-} && -z ${GIT_SSH_COMMAND:-} && -z ${https_proxy:-} ]]\n'
            '[[ -z ${GIT_CONFIG_COUNT:-} && -z ${GITHUB_TOKEN:-} && -z ${BASH_ENV:-} ]]\n'
            '[[ "$*" == *"credential.helper="* && "$*" == *"http.sslVerify=true"* ]]\n'
            '[[ "$*" == *"http.followRedirects=false"* && "$*" == *"core.hooksPath=/dev/null"* ]]\n'
            '[[ "$*" == *"--no-recurse-submodules"* && "$*" == *"--template="* ]]\n'
            '[[ "$*" == *"https://github.com/JackieSung4ev/AnyHarbor.git"* ]]\n'
            'if read -r unexpected; then exit 92; fi\n'
            'destination=${!#}\n'
            '[[ $destination == /opt/AnyHarbor-source.*/source && ! -e $destination ]]\n'
            '[[ $HOME == "$(dirname "$destination")" && $(stat -c %a "$HOME") == 700 ]]\n'
            'printf "git clone\\n" >>' + str(self.events) + '\n'
            'mkdir -- "$destination"\n'
            'cat > "$destination/install.sh" <<\'ENTRY\'\n'
            '#!/bin/bash\nset -euo pipefail\n'
            'printf "entry %s\\n" "$*" >>' + str(self.events) + '\n'
            'read -r answer\n'
            'printf "stdin %s\\n" "$answer" >>' + str(self.events) + '\n'
            'ENTRY\n'
            'exit ' + str(status) + '\n')

    def invoke_bootstrap(self, *arguments, **settings):
        before = set(Path('/opt').glob('AnyHarbor-source.*'))

        def cleanup():
            for path in set(Path('/opt').glob('AnyHarbor-source.*')) - before:
                if path.is_symlink() or path.resolve().parent != Path('/opt'):
                    raise AssertionError('Unexpected source path: ' + str(path))
                shutil.rmtree(path)

        self.addCleanup(cleanup)
        return subprocess.run(
            [BASH, str(ROOT / 'bootstrap.sh'), *arguments], input='retained-input\n',
            capture_output=True, text=True, encoding='utf-8', timeout=15,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LC_ALL': 'C',
                 'TEST_EVENTS': str(self.events), **settings},
        )

    def test_bootstrap_isolates_git_and_preserves_interactive_input(self):
        self.bootstrap_git()
        result = self.invoke_bootstrap(
            SSH_AUTH_SOCK='/untrusted-agent', GIT_SSH_COMMAND='untrusted command',
            https_proxy='http://untrusted.example.test', GITHUB_TOKEN='fixture-token',
            GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.sslVerify', GIT_CONFIG_VALUE_0='false',
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.events.read_text().splitlines(),
                         ['git clone', 'entry ', 'stdin retained-input'])

    def test_bootstrap_partial_failed_clone_is_not_executed(self):
        self.bootstrap_git(status=17)
        result = self.invoke_bootstrap()
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), ['git clone'])
        self.assertIn('下载目录保留', result.stderr)

    def test_bootstrap_refuses_existing_install_and_missing_upgrade_target(self):
        self.bootstrap_git()
        missing = self.invoke_bootstrap('--upgrade')
        self.assertNotEqual(missing.returncode, 0)
        self.assertEqual(self.events.read_text(), '')
        self.managed.symlink_to(self.scratch / 'missing')
        self.addCleanup(self.managed.unlink)
        existing = self.invoke_bootstrap()
        self.assertNotEqual(existing.returncode, 0)
        self.assertEqual(self.events.read_text(), '')

    def test_bootstrap_upgrade_passes_explicit_operation_without_changing_state(self):
        state = self.existing_install()
        before = state.read_bytes()
        self.bootstrap_git()
        result = self.invoke_bootstrap('--upgrade')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.events.read_text().splitlines(),
                         ['git clone', 'entry --upgrade', 'stdin retained-input'])
        self.assertEqual(state.read_bytes(), before)

    def test_bootstrap_apt_failure_stops_before_clone(self):
        self.bootstrap_git()
        result = self.invoke_bootstrap(TEST_NEEDS_APT='1', TEST_APT_STATUS='42')
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), ['apt update'])

    def test_documented_download_does_not_execute_partial_script_and_preserves_stdin(self):
        blocks = re.findall(r'```bash\n(.*?)\n```', (ROOT / 'README.md').read_text(), re.DOTALL)
        commands = [block for block in blocks if 'curl ' in block and '/main/bootstrap.sh' in block]
        self.assertEqual(len(commands), 1, 'Expected one documented bootstrap command')
        self.command('curl',
                     'printf \'printf "downloaded script\\\\n" >>"$TEST_EVENTS"; '
                     'read -r answer; printf "stdin %%s\\\\n" "$answer" >>"$TEST_EVENTS"\\n\'\n'
                     'exit "${TEST_CURL_STATUS:-0}"')
        for status in (22, 0):
            with self.subTest(download_status=status):
                self.events.write_text('')
                result = subprocess.run(
                    [BASH, '-c', commands[0]], input='after-download\n', capture_output=True,
                    text=True, encoding='utf-8', timeout=10,
                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root',
                         'TEST_EVENTS': str(self.events), 'TEST_CURL_STATUS': str(status)},
                )
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                expected = [] if status else ['downloaded script', 'stdin after-download']
                self.assertEqual(self.events.read_text().splitlines(), expected)


if __name__ == '__main__':
    unittest.main()
