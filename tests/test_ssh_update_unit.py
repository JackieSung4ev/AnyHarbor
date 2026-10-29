"""Private and public Git update regressions, without network access or production data."""
import contextlib
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('ssh_update_helper', ROOT / 'src' / 'anytls-update.py')
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
RUN = subprocess.run
GIT = shutil.which('git')
BASH = (str(Path(GIT).parents[1] / 'bin' / 'bash.exe') if os.name == 'nt' and GIT
        else shutil.which('bash'))


def source_blobs(version='1.4.0'):
    values = {}
    for name in helper.FILES:
        if name.endswith('.sh'):
            values[name] = b'#!/usr/bin/env bash\nexit 0\n'
        elif name.endswith('.py'):
            values[name] = b'raise RuntimeError("Downloaded code must not execute during preparation")\n'
        else:
            values[name] = ('Fixture documentation: ' + name + '\n').encode()
    values['anytls-manager.sh'] = (
        '#!/usr/bin/env bash\nreadonly MANAGER_VERSION=' + version + '\nexit 0\n').encode()
    return values


def syntax_runner(args, *values, **kwargs):
    """Use Git Bash on Windows; do not replace actual candidate validation."""
    if args and args[0] == 'bash':
        args = [BASH, *args[1:]]
    return RUN(args, *values, **kwargs)


class SourceValidationTests(unittest.TestCase):
    def test_host_key_pin_matches_githubs_published_ed25519_fingerprint(self):
        host, kind, encoded = helper.GITHUB_HOST_KEY.strip().split()
        self.assertEqual((host, kind), ('github.com', 'ssh-ed25519'))
        digest = base64.b64encode(hashlib.sha256(base64.b64decode(encoded)).digest()).decode().rstrip('=')
        self.assertEqual(digest, '+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU')

    def test_repository_names_cannot_inject_transport_or_options(self):
        self.assertEqual(helper.repository('https://github.com/Example/AnyTLS.git'), 'Example/AnyTLS')
        for value in (None, 42, [], '-u/AnyTLS', 'owner/../repo', 'owner/name?x=1',
                      'ssh://evil.example/owner/repo', 'file:///tmp/repo',
                      'https://github.com@evil.example/owner/repo',
                      'https://token@github.com/owner/repo', 'owner/repo\nextra'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                helper.repository(value)

    def test_branches_reject_revision_expressions_and_command_options(self):
        self.assertEqual(helper.branch_name('main'), 'main')
        self.assertEqual(helper.branch_name('maintenance/stable'), 'maintenance/stable')
        for value in ('', '-upload-pack=evil', 'main\nother', 'main:other', 'main~1',
                      'main^{tree}', 'main..other', 'refs/heads/main.lock',
                      '../main', 'main//other', 'main@{0}', 'a b'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                helper.branch_name(value)

    def test_legacy_repository_binding_remains_https_and_ssh_can_be_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with mock.patch.object(helper, 'secure_path', side_effect=lambda p, directory=False: Path(p)):
                helper.bind_source(base, 'Example/AnyTLS')
                legacy = helper.load_source(base)
                self.assertEqual(legacy['repository'], 'Example/AnyTLS')
                self.assertNotEqual(legacy.get('transport'), 'ssh')
                with mock.patch.object(helper, 'private_key_path', return_value=Path('/root/.ssh/test_key')):
                    helper.bind_ssh_source(base, 'Example/AnyTLS', '/root/.ssh/test_key', 'main')
                ssh = json.loads((base / 'update-source.json').read_text())
                self.assertEqual(ssh['transport'], 'ssh')
                self.assertEqual(ssh['branch'], 'main')
                self.assertNotIn('PRIVATE KEY', json.dumps(ssh))
                helper.bind_source(base, 'Example/Public')
                restored = helper.load_source(base)
                self.assertEqual(restored['repository'], 'Example/Public')
                self.assertNotEqual(restored.get('transport'), 'ssh')

    def test_git_environment_discards_inherited_execution_and_authentication_hooks(self):
        hostile = {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.sshCommand',
                   'GIT_CONFIG_VALUE_0': 'untrusted command', 'GIT_SSH': '/evil/ssh',
                   'GIT_SSH_COMMAND': 'untrusted command', 'GIT_DIR': '/wrong/repo',
                   'GIT_OBJECT_DIRECTORY': '/wrong/objects', 'GIT_ALTERNATE_OBJECT_DIRECTORIES': '/wrong/objects',
                   'SSH_AUTH_SOCK': '/agent', 'SSH_ASKPASS': '/evil/askpass',
                   'BASH_ENV': '/evil/bashrc', 'LD_PRELOAD': '/evil/lib.so'}
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, hostile):
            scratch = Path(directory)
            env = helper.git_environment(scratch, scratch / 'key', scratch / 'known_hosts')
        for key, value in hostile.items():
            self.assertNotEqual(env.get(key), value, key)
        ssh = env['GIT_SSH_COMMAND']
        for option in ('StrictHostKeyChecking=yes', 'IdentitiesOnly=yes', 'BatchMode=yes'):
            self.assertIn(option, ssh)
        self.assertIn('/dev/null', ssh)
        self.assertEqual(env['GIT_CONFIG_NOSYSTEM'], '1')
        self.assertEqual(env['GIT_TERMINAL_PROMPT'], '0')

    def test_public_source_binding_replaces_ssh_credentials_without_reading_a_key(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'update-source.json').write_text(json.dumps({
                'repository': 'Example/Private', 'transport': 'ssh', 'branch': 'old',
                'key_file': '/missing/private-key'}))
            with mock.patch.object(helper, 'secure_path', side_effect=lambda p, directory=False: Path(p)), \
                    mock.patch.object(helper, 'private_key_path', side_effect=AssertionError('must not read keys')):
                result = helper.bind_git_source(base, 'https://github.com/Example/Public.git', 'stable')
                source = helper.load_source(base)
            self.assertEqual(source, {'repository': 'Example/Public', 'transport': 'git-https', 'branch': 'stable'})
            self.assertIn('HTTPS Git, branch stable', result)
            self.assertNotIn('key_file', (base / 'update-source.json').read_text())

    def test_public_source_binding_rejects_invalid_input_without_replacing_existing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            original = b'{"repository":"Example/Private","transport":"https"}\n'
            path = base / 'update-source.json'
            path.write_bytes(original)
            for repo, branch in [('https://token@github.com/Example/Public', 'main'),
                                 ('Example/Public', 'main:refs/heads/other')]:
                with self.subTest(repo=repo, branch=branch), self.assertRaises(ValueError):
                    helper.bind_git_source(base, repo, branch)
                self.assertEqual(path.read_bytes(), original)

    def test_public_environment_has_no_credentials_proxy_tls_overrides_or_inherited_git_settings(self):
        hostile = {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'url.file:///tmp/.insteadOf',
                   'GIT_CONFIG_VALUE_0': 'https://github.com/', 'GIT_CONFIG_PARAMETERS': 'hostile',
                   'GIT_CONFIG_GLOBAL': '/hostile/gitconfig', 'GIT_ASKPASS': '/hostile/askpass',
                   'GIT_SSL_NO_VERIFY': 'true', 'SSL_CERT_FILE': '/hostile/ca',
                   'CURL_CA_BUNDLE': '/hostile/ca', 'GIT_SSH_COMMAND': '/hostile/ssh',
                   'GIT_DIR': '/hostile/repo', 'GIT_OBJECT_DIRECTORY': '/hostile/objects',
                   'GIT_ALTERNATE_OBJECT_DIRECTORIES': '/hostile/objects',
                   'HTTP_PROXY': 'http://hostile', 'HTTPS_PROXY': 'http://hostile',
                   'ALL_PROXY': 'http://hostile', 'https_proxy': 'http://hostile',
                   'SSH_AUTH_SOCK': '/agent', 'GH_TOKEN': 'fixture', 'GITHUB_TOKEN': 'fixture',
                   'BASH_ENV': '/hostile/bashrc', 'LD_PRELOAD': '/hostile/lib.so'}
        with mock.patch.dict(os.environ, hostile):
            environment = helper.git_environment(Path('/isolated'))
        for key, value in hostile.items():
            self.assertNotEqual(environment.get(key), value, key)
        self.assertEqual(environment['GIT_ALLOW_PROTOCOL'], 'https')
        self.assertEqual(environment['GIT_CONFIG_NOSYSTEM'], '1')
        self.assertEqual(environment['GIT_TERMINAL_PROMPT'], '0')
        self.assertEqual(environment['HOME'], str(Path('/isolated')))
        self.assertNotIn('GIT_SSH_COMMAND', environment)
        self.assertNotIn('GIT_SSH_VARIANT', environment)

    def test_ssh_key_path_with_spaces_stays_one_argument(self):
        scratch = Path('/root/update staging')
        key = scratch / 'key with spaces'
        hosts = scratch / 'known_hosts'
        argv = shlex.split(helper.git_environment(scratch, key, hosts)['GIT_SSH_COMMAND'])
        self.assertEqual(argv[argv.index('-i') + 1], str(key))
        host_options = [arg for arg in argv if arg.startswith('UserKnownHostsFile=')]
        self.assertEqual(len(host_options), 1)
        self.assertEqual(shlex.split(host_options[0].split('=', 1)[1]), [str(hosts)])
        for option in ('PasswordAuthentication=no', 'KbdInteractiveAuthentication=no'):
            self.assertIn(option, argv)

    def test_key_path_rejects_relative_control_character_and_traversal_paths(self):
        for value in ('relative_key', '', '/root/.ssh/../key', '/root/key\nnext', '/root/key\x00', '/root/key%h'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                helper.private_key_path(value)

    def test_key_permissions_and_parent_permissions_are_enforced(self):
        original_stat = Path.stat
        original_is_symlink = Path.is_symlink
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'key'
            key.write_text('fixture, not a private key', encoding='utf-8')

            def filesystem_case(bad=None):
                def controlled_stat(path, *args, **kwargs):
                    result = original_stat(path, *args, **kwargs)
                    values = list(result)
                    values[0] = stat.S_IFMT(result.st_mode) | (0o700 if stat.S_ISDIR(result.st_mode) else 0o600)
                    values[4] = 0
                    if path == key and bad == 'readable':
                        values[0] |= 0o040
                    if path == key and bad == 'owner':
                        values[4] = 1
                    if path == key.parent and bad == 'parent':
                        values[0] |= 0o002
                    return os.stat_result(values)
                return controlled_stat

            with mock.patch.object(Path, 'stat', filesystem_case()):
                self.assertEqual(helper.private_key_path(str(key)), key)
            for bad in ('readable', 'owner', 'parent', 'link'):
                # Python versions implement is_symlink through different OS
                # entry points. Model this policy explicitly without changing
                # the real file type returned by stat.
                def is_symlink(path):
                    return (path == key and bad == 'link') or original_is_symlink(path)

                with self.subTest(case=bad), mock.patch.object(Path, 'stat', filesystem_case(bad)), \
                        mock.patch.object(Path, 'is_symlink', is_symlink):
                    with self.assertRaises(ValueError):
                        helper.private_key_path(str(key))

    def test_https_sources_keep_release_path_and_ssh_sources_use_git(self):
        base = Path('/fixture')
        with mock.patch.object(helper, 'load_source', return_value={'transport': 'https'}), \
                mock.patch.object(helper, 'release_metadata', return_value={'version': '1.4.1'}) as release, \
                mock.patch.object(helper, 'prepare_ssh') as ssh:
            self.assertEqual(helper.prepare(base, '1.4.0', check_only=True), '1.4.1')
            release.assert_called_once_with(base, '1.4.0', 'latest')
            ssh.assert_not_called()
        source = {'transport': 'ssh'}
        with mock.patch.object(helper, 'load_source', return_value=source), \
                mock.patch.object(helper, 'release_metadata') as release, \
                mock.patch.object(helper, 'prepare_ssh', return_value='candidate') as ssh:
            self.assertEqual(helper.prepare(base, '1.4.0'), 'candidate')
            ssh.assert_called_once_with(base, '1.4.0', source, 'latest', False)
            release.assert_not_called()

    def test_public_git_dispatch_never_uses_releases_or_ssh(self):
        source = {'transport': 'git-https'}
        with mock.patch.object(helper, 'load_source', return_value=source), \
                mock.patch.object(helper, 'release_metadata') as release, \
                mock.patch.object(helper, 'prepare_ssh') as ssh, \
                mock.patch.object(helper, 'prepare_git', return_value='candidate') as public:
            self.assertEqual(helper.prepare(Path('/fixture'), '1.4.0'), 'candidate')
            public.assert_called_once_with(Path('/fixture'), '1.4.0', source, 'latest', False)
            ssh.assert_not_called()
            release.assert_not_called()

    def test_public_source_cli_binding_and_display_do_not_require_a_private_key(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with mock.patch.object(helper, 'base_directory', return_value=base), \
                    mock.patch.object(helper, 'secure_path', side_effect=lambda p, directory=False: Path(p)), \
                    mock.patch.object(helper, 'private_key_path', side_effect=AssertionError('must not read keys')), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                helper.main(['git-source', str(base), 'Example/Public'])
                helper.main(['source', str(base)])
            self.assertEqual(output.getvalue().splitlines(), [
                'Example/Public (HTTPS Git, branch main)', 'Example/Public (HTTPS Git, branch main)'])

    def test_git_command_disables_hooks_submodules_and_other_protocols(self):
        completed = subprocess.CompletedProcess(['git'], 0, stdout=b'fixture', stderr=b'')
        with mock.patch.object(helper.subprocess, 'run', return_value=completed) as run:
            self.assertEqual(helper.git_call(['ls-tree', 'a' * 40], {}, Path('/fixture')), b'fixture')
        argv = run.call_args.args[0]
        for option in ('--literal-pathspecs', 'core.hooksPath=/dev/null', 'protocol.allow=never',
                       'protocol.ssh.allow=always', 'fetch.recurseSubmodules=false',
                       'submodule.recurse=false', 'fetch.fsckObjects=true'):
            self.assertIn(option, argv)
        self.assertIs(run.call_args.kwargs['stdin'], subprocess.DEVNULL)

    def test_git_error_does_not_echo_untrusted_remote_stderr(self):
        completed = subprocess.CompletedProcess(['git'], 1, stdout=b'',
                                                stderr=b'private error detail fixture')
        with mock.patch.object(helper.subprocess, 'run', return_value=completed):
            with self.assertRaises(ValueError) as caught:
                helper.git_call(['fetch'], {}, Path('/fixture'))
        self.assertNotIn('private error detail fixture', str(caught.exception))

    def test_public_git_command_enforces_https_validation_and_prevents_redirects_credentials_or_proxy(self):
        completed = subprocess.CompletedProcess(['git'], 0, stdout=b'fixture', stderr=b'')
        environment = helper.git_environment(Path('/isolated'))
        with mock.patch.object(helper.subprocess, 'run', return_value=completed) as run:
            helper.git_call(['fetch', 'https://github.com/Example/Public.git', 'refs/heads/main'],
                            environment, Path('/isolated/source.git'))
        argv = run.call_args.args[0]
        for option in ('protocol.allow=never', 'protocol.https.allow=always', 'http.sslVerify=true',
                       'http.followRedirects=false', 'http.proxy=', 'credential.helper=',
                       'http.extraHeader=', 'http.cookieFile=', 'http.saveCookies=false',
                       'core.hooksPath=/dev/null', 'fetch.recurseSubmodules=false', 'submodule.recurse=false'):
            self.assertIn(option, argv)
        self.assertNotIn('protocol.ssh.allow=always', argv)
        self.assertIs(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
        self.assertIs(run.call_args.kwargs['env'], environment)
        for protocol in ('file', 'git', 'http', 'ssh:https'):
            with self.subTest(protocol=protocol), self.assertRaises(ValueError):
                helper.git_call(['fetch'], {'GIT_ALLOW_PROTOCOL': protocol}, Path('/isolated'))


@unittest.skipUnless(BASH and Path(BASH).exists(), 'Bash is needed for actual syntax checks')
class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / 'candidate'
        self.blobs = source_blobs()
        patch = mock.patch.object(helper.subprocess, 'run', side_effect=syntax_runner)
        patch.start()
        self.addCleanup(patch.stop)

    def test_build_is_allowlisted_and_does_not_execute_source(self):
        self.assertEqual(helper.source_candidate(self.directory, self.blobs, '1.3.0'), '1.4.0')
        self.assertEqual({p.name for p in self.directory.iterdir()}, set(helper.ALL_FILES))
        manifest = helper.manifest_at(self.directory, '1.4.0', '1.3.0')
        for name, content in self.blobs.items():
            self.assertEqual((self.directory / name).read_bytes(), content)
            self.assertEqual(manifest['files'][name], hashlib.sha256(content).hexdigest())
        self.assertEqual(helper.verify(self.directory, '1.4.0', '1.3.0'), '1.4.0')

    def test_candidate_tampering_is_rejected(self):
        helper.source_candidate(self.directory, self.blobs, '1.3.0')
        (self.directory / 'README.txt').write_text('tampered\n', encoding='utf-8')
        with self.assertRaises(ValueError):
            helper.verify(self.directory, '1.4.0', '1.3.0')

    def test_downgrade_is_rejected(self):
        with self.assertRaises(ValueError):
            helper.source_candidate(self.directory, source_blobs('1.2.0'), '1.3.0')

    def test_malformed_or_extra_source_is_rejected(self):
        bad = []
        for content in (b'wrong\r\n', b'\xef\xbb\xbftext\n', b'\xff', b''):
            values = dict(self.blobs)
            values['README.txt'] = content
            bad.append(values)
        values = dict(self.blobs)
        values.pop('anytls-runtime.sh')
        bad.append(values)
        values = dict(self.blobs)
        values['state.json'] = b'{"do_not_package":"runtime data"}\n'
        bad.append(values)
        for index, values in enumerate(bad):
            with self.subTest(case=index), self.assertRaises((ValueError, UnicodeError)):
                helper.source_candidate(self.directory.parent / ('bad-' + str(index)), values, '1.3.0')

    def test_syntax_errors_fail_preparation(self):
        broken = dict(self.blobs)
        broken['anytls-state.py'] = b'def invalid syntax\n'
        with self.assertRaises((ValueError, SyntaxError)):
            helper.source_candidate(self.directory, broken, '1.3.0')

    def test_installed_comparison_uses_actual_files_and_rejects_tampering(self):
        base = self.directory.parent / 'installed'
        releases = base / 'manager-releases'
        releases.mkdir(parents=True, mode=0o700)
        active = releases / 'manager-fixture'
        helper.source_candidate(active, self.blobs, '1.3.0')
        pointer = base / 'manager-current'
        try:
            pointer.symlink_to(active, target_is_directory=True)
        except OSError as error:
            self.skipTest('Directory symlink creation unavailable: ' + str(error))
        original_stat = Path.stat
        original_lstat = Path.lstat

        def root_metadata(result):
            values = list(result)
            values[4] = 0
            if os.name == 'nt':
                values[0] = stat.S_IFMT(result.st_mode) | (0o700 if stat.S_ISDIR(result.st_mode) else 0o600)
            return os.stat_result(values)

        def root_owned(path, *args, **kwargs):
            return root_metadata(original_stat(path, *args, **kwargs))

        def root_owned_link(path, *args, **kwargs):
            return root_metadata(original_lstat(path, *args, **kwargs))

        # lstat does not necessarily delegate to Path.stat on every Python
        # version; model root ownership for both, retaining actual file types.
        with mock.patch.object(Path, 'stat', root_owned), mock.patch.object(Path, 'lstat', root_owned_link):
            self.assertTrue(helper.installed_sources_equal(base, self.blobs, '1.4.0'))
            changed = dict(self.blobs)
            changed['README.txt'] = b'new contents, same source version\n'
            self.assertFalse(helper.installed_sources_equal(base, changed, '1.4.0'))
            (active / 'README.txt').write_bytes(b'corrupted installed file\n')
            with self.assertRaises(ValueError):
                helper.installed_sources_equal(base, self.blobs, '1.4.0')


@unittest.skipUnless(GIT, 'Git is needed for real object extraction tests')
class GitObjectTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.bare = self.directory / 'repo.git'
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('GIT_', 'SSH_'))}
        self.env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                         'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                         'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'})
        RUN([GIT, 'init', '--bare', '--template=', str(self.bare)], env=self.env,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.blobs = source_blobs()
        self.calls = []
        patch = mock.patch.object(helper, 'git_call', side_effect=self.git_adapter)
        patch.start()
        self.addCleanup(patch.stop)

    def git(self, *args, data=None):
        return RUN([GIT, *args], cwd=self.bare, env=self.env, input=data,
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def git_adapter(self, args, environment, cwd):
        self.calls.append(list(args))
        return RUN([GIT, *args], cwd=cwd, env=self.env, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def commit(self, blobs=None, modes=None, extra=True):
        blobs = self.blobs if blobs is None else blobs
        modes = modes or {}
        entries = []
        for name, content in blobs.items():
            mode = modes.get(name, '100644')
            if mode == '160000':
                oid, kind = content.decode(), 'commit'
            else:
                oid, kind = self.git('hash-object', '-w', '--stdin', data=content).strip().decode(), 'blob'
            entries.append(f'{mode} {kind} {oid}\t{name}\n')
        tree = self.git('mktree', data=''.join(entries).encode()).strip().decode()
        root = [f'040000 tree {tree}\tsrc\n']
        if extra:
            # An untrusted remote build script and runtime files must never be extracted or executed.
            oid = self.git('hash-object', '-w', '--stdin', data=b'raise RuntimeError("must not execute")\n').strip().decode()
            root += [f'100644 blob {oid}\tbuild_release.py\n', f'100644 blob {oid}\tstate.json\n']
        root_tree = self.git('mktree', data=''.join(root).encode()).strip().decode()
        return self.git('commit-tree', root_tree, '-m', 'fixture').strip().decode()

    def read(self, commit):
        return helper.read_git_sources(self.bare, commit, self.env)

    def test_exact_commit_is_extracted_without_extra_files(self):
        first = self.commit()
        changed = dict(self.blobs)
        changed['README.txt'] = b'changed after first commit\n'
        second = self.commit(changed)
        self.git('update-ref', 'refs/heads/main', second)
        self.assertEqual(self.read(first), self.blobs)
        self.assertEqual(self.read(second), changed)
        self.assertFalse(any('checkout' in args or 'push' in args for args in self.calls))

    def test_symlink_in_allowlisted_source_is_rejected(self):
        commit = self.commit(modes={'README.txt': '120000'})
        with self.assertRaises(ValueError):
            self.read(commit)

    def test_missing_file_is_rejected(self):
        values = dict(self.blobs)
        values.pop('anytls-runtime.sh')
        with self.assertRaises(ValueError):
            self.read(self.commit(values))

    def test_submodule_in_allowlisted_source_is_rejected(self):
        commit = self.commit()
        values = dict(self.blobs)
        values['anytls-update.py'] = commit.encode()
        malicious = self.commit(values, modes={'anytls-update.py': '160000'})
        with self.assertRaises(ValueError):
            self.read(malicious)

    def test_oversized_source_is_rejected(self):
        values = dict(self.blobs)
        values['README.txt'] = b'x' * (helper.MAX_ARCHIVE + 1)
        with self.assertRaises(ValueError):
            self.read(self.commit(values))

    def test_revision_expression_is_not_accepted_as_a_commit(self):
        commit = self.commit()
        for value in ('HEAD', 'main', commit + ':src', commit + '^', '--all'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.read(value)


@unittest.skipUnless(BASH and Path(BASH).exists(), 'Bash is needed for actual syntax checks')
class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = {'repository': 'Example/AnyTLS', 'transport': 'ssh',
                       'branch': 'main', 'key_file': '/root/.ssh/test_key'}
        self.commit = 'e' * 40
        self.blobs = source_blobs()
        self.calls = []

        def git_call(args, environment, cwd):
            self.calls.append(args)
            return (self.commit + '\n').encode() if args[0] == 'rev-parse' else b''

        for patch in (mock.patch.object(helper, 'git_call', side_effect=git_call),
                      mock.patch.object(helper, 'read_git_sources', return_value=self.blobs),
                      mock.patch.object(helper, 'private_key_path', return_value=Path(self.source['key_file'])),
                      mock.patch.object(helper, 'secure_path', side_effect=lambda p, directory=False: Path(p)),
                      mock.patch.object(helper.subprocess, 'run', side_effect=syntax_runner)):
            patch.start()
            self.addCleanup(patch.stop)

    def prepare(self, unchanged=False, check_only=False, requested='latest'):
        with mock.patch.object(helper, 'installed_sources_equal', return_value=unchanged), \
                contextlib.redirect_stderr(io.StringIO()):
            return helper.prepare_ssh(self.base, '1.4.0', self.source, requested, check_only)

    def test_same_version_with_changed_content_prepares_update_and_records_commit(self):
        candidate = Path(self.prepare())
        self.assertTrue(candidate.is_dir())
        self.assertEqual(helper.manifest_at(candidate)['version'], '1.4.0')
        origin = json.loads((candidate.parent / 'origin.json').read_text())
        self.assertEqual(origin['commit'], self.commit)
        self.assertEqual(origin['branch'], 'main')
        self.assertNotIn('key_file', origin)
        fetch = [args for args in self.calls if args[0] == 'fetch']
        self.assertEqual(len(fetch), 1)
        self.assertEqual(fetch[0][-2:], ['git@github.com:Example/AnyTLS.git', 'refs/heads/main'])
        self.assertIn('--no-tags', fetch[0])

    def test_identical_content_is_noop_even_at_new_commit(self):
        self.assertEqual(self.prepare(unchanged=True), '')
        self.assertEqual(list((self.base / 'updates').iterdir()), [])

    def test_check_only_validates_but_leaves_no_candidate_or_runtime_changes(self):
        sentinel = self.base / 'state.json'
        sentinel.write_bytes(b'private runtime fixture, must stay unchanged')
        result = self.prepare(check_only=True)
        self.assertIn('1.4.0', result)
        self.assertIn(self.commit[:12], result)
        self.assertEqual(list((self.base / 'updates').iterdir()), [])
        self.assertEqual(sentinel.read_bytes(), b'private runtime fixture, must stay unchanged')

    def test_git_failure_does_not_create_ready_candidate(self):
        with mock.patch.object(helper, 'git_call', side_effect=ValueError('transport failed')):
            with self.assertRaises(ValueError):
                self.prepare()
        self.assertEqual(list((self.base / 'updates').iterdir()), [])

    def test_ssh_source_does_not_accept_release_version_argument(self):
        with self.assertRaises(ValueError):
            self.prepare(requested='1.4.0')
        self.assertFalse((self.base / 'updates').exists())


class PublicPreparationTests(PreparationTests):
    """Run the same no-op, syntax, failure and check-only guarantees over HTTPS."""

    def setUp(self):
        super().setUp()
        self.source = {'repository': 'Example/AnyTLS', 'transport': 'git-https', 'branch': 'main'}

    def prepare(self, unchanged=False, check_only=False, requested='latest'):
        with mock.patch.object(helper, 'installed_sources_equal', return_value=unchanged), \
                mock.patch.object(helper, 'private_key_path', side_effect=AssertionError('must not read keys')), \
                contextlib.redirect_stderr(io.StringIO()):
            return helper.prepare_git(self.base, '1.4.0', self.source, requested, check_only)

    def test_same_version_with_changed_content_prepares_update_and_records_commit(self):
        candidate = Path(self.prepare())
        self.assertTrue(candidate.is_dir())
        self.assertEqual(helper.manifest_at(candidate)['version'], '1.4.0')
        origin = json.loads((candidate.parent / 'origin.json').read_text())
        self.assertEqual(origin, {'repository': 'Example/AnyTLS', 'transport': 'git-https',
                                  'branch': 'main', 'commit': self.commit, 'version': '1.4.0'})
        fetch = [args for args in self.calls if args[0] == 'fetch']
        self.assertEqual(len(fetch), 1)
        self.assertEqual(fetch[0][-2:], ['https://github.com/Example/AnyTLS.git', 'refs/heads/main'])
        self.assertIn('--no-tags', fetch[0])

    def test_public_fetch_uses_no_hostkey_file_or_ssh_environment(self):
        calls = []

        def git_call(args, environment, cwd):
            calls.append(environment)
            self.assertFalse((Path(environment['HOME']) / 'known_hosts').exists())
            return (self.commit + '\n').encode() if args[0] == 'rev-parse' else b''

        with mock.patch.object(helper, 'git_call', side_effect=git_call):
            self.prepare(check_only=True)
        self.assertTrue(calls)
        for environment in calls:
            self.assertEqual(environment['GIT_ALLOW_PROTOCOL'], 'https')
            self.assertNotIn('GIT_SSH_COMMAND', environment)


if __name__ == '__main__':
    unittest.main()
