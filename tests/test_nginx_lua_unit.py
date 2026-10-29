"""Nginx Lua discovery guards; no Nginx configuration or Lua code is executed."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('nginx_lua_state', ROOT / 'src/anytls-state.py')
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


@unittest.skipUnless(os.name == 'posix', 'Production paths and permission semantics are POSIX.')
class NginxLuaTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.prefix = self.directory / 'nginx'
        self.binary = self.prefix / 'sbin/nginx'
        self.binary.parent.mkdir(parents=True)
        self.binary.write_text('not executed', encoding='utf-8')
        self.bad_metadata = {}
        actual_lstat = Path.lstat
        temp_ancestors = set(self.directory.parents)

        def metadata(path):
            info = actual_lstat(path)
            # CI runs unprivileged. Model the production root owner while retaining
            # real types/modes, except the host's shared temporary ancestors.
            mode = stat.S_IFDIR | 0o755 if path in temp_ancestors else info.st_mode
            uid, mode = self.bad_metadata.get(path, (0, mode))
            return types.SimpleNamespace(st_uid=uid, st_mode=mode)

        guard = mock.patch.object(Path, 'lstat', metadata)
        guard.start()
        self.addCleanup(guard.stop)
        runner = mock.patch.object(helper.subprocess, 'run')
        self.run = runner.start()
        self.addCleanup(runner.stop)
        self.configure('--prefix=' + str(self.prefix))

    def configure(self, arguments):
        self.run.return_value = subprocess.CompletedProcess(
            [], 0, '', 'nginx version: nginx/1.26.3\nconfigure arguments: ' + arguments + '\n')

    def library(self, prefix=None, layout='lib/lua'):
        tree = (prefix or self.prefix) / layout
        (tree / 'resty').mkdir(parents=True)
        (tree / 'resty/core.lua').write_text('return {}\n', encoding='utf-8')
        (tree / 'resty/lrucache.lua').write_text('return {}\n', encoding='utf-8')
        return tree

    def discover(self):
        return helper.nginx_lua_path(str(self.binary))

    def test_associated_complete_library_and_cli_output(self):
        tree = self.library()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            helper.main(['nginx-lua-path', str(self.binary)])
        self.assertEqual(output.getvalue(), str(tree) + '\n')
        self.run.assert_called_once_with([str(self.binary), '-V'], check=True,
                                         capture_output=True, text=True, timeout=10)

    def test_quoted_configure_options_and_binary_relative_fallback(self):
        tree = self.library()
        self.configure("--with-ld-opt='-Wl,-rpath,/opt/lib -Wl,-E' '--prefix=" + str(self.prefix) + "'")
        self.assertEqual(self.discover(), str(tree))
        self.configure('--with-http_ssl_module')
        self.assertEqual(self.discover(), str(tree))

    def test_openresty_sibling_library(self):
        prefix = self.directory / 'openresty/nginx'
        prefix.mkdir(parents=True)
        tree = self.library(prefix.parent, 'lualib')
        self.configure('--prefix=' + str(prefix))
        self.assertEqual(self.discover(), str(tree))

    def test_stock_nginx_leaves_defaults_and_ignores_unrelated_library(self):
        self.library(self.directory / 'unrelated')
        self.library(self.directory, 'lualib')
        self.assertEqual(self.discover(), '')

    def test_incomplete_tree_is_not_mixed_with_other_installation(self):
        tree = self.library()
        (tree / 'resty/lrucache.lua').unlink()
        self.library(self.prefix, 'lualib')
        with self.assertRaisesRegex(ValueError, 'Incomplete Nginx Lua library'):
            self.discover()

    def test_unsafe_prefixes_are_rejected_without_shell_execution(self):
        for prefix in ('relative/nginx', '/safe/../elsewhere', '/tmp/nginx;id', '/tmp/$HOME',
                       '/tmp/nginx path', '/tmp/nginx";include /etc/passwd;#'):
            with self.subTest(prefix=prefix):
                self.configure('--prefix=' + shlex.quote(prefix))
                with self.assertRaises(ValueError):
                    self.discover()
        self.run.assert_called_with([str(self.binary), '-V'], check=True,
                                    capture_output=True, text=True, timeout=10)

    def test_ambiguous_or_malformed_configure_output_is_rejected(self):
        for arguments in ('--prefix=/one --prefix=/two', "--prefix='/unterminated"):
            with self.subTest(arguments=arguments):
                self.configure(arguments)
                with self.assertRaises(ValueError):
                    self.discover()

    def test_writable_or_nonroot_module_and_ancestor_are_rejected(self):
        tree = self.library()
        sibling = tree / 'unrelated.lua'
        sibling.write_text('return {}\n', encoding='utf-8')
        for path, uid, mode in ((self.prefix, 0, stat.S_IFDIR | 0o775),
                                (tree, 1000, stat.S_IFDIR | 0o755),
                                (tree / 'resty/core.lua', 0, stat.S_IFREG | 0o666),
                                (sibling, 1000, stat.S_IFREG | 0o644)):
            with self.subTest(path=path):
                self.bad_metadata[path] = (uid, mode)
                with self.assertRaisesRegex(ValueError, 'root-owned'):
                    self.discover()
                self.bad_metadata.clear()

    def test_library_symlinks_are_rejected(self):
        tree = self.library()
        (tree / 'alias.lua').symlink_to(tree / 'resty/core.lua')
        with self.assertRaisesRegex(ValueError, 'root-owned'):
            self.discover()

    def test_unsafe_executable_is_rejected_before_running_nginx(self):
        self.bad_metadata[self.binary] = (1000, stat.S_IFREG | 0o755)
        with self.assertRaises(ValueError):
            self.discover()
        self.run.assert_not_called()

    def test_nginx_inspection_failures_are_explained(self):
        for error in (subprocess.CalledProcessError(1, ['nginx', '-V']),
                      subprocess.TimeoutExpired(['nginx', '-V'], 10)):
            with self.subTest(error=error):
                self.run.side_effect = error
                with self.assertRaisesRegex(ValueError, 'selected Nginx build'):
                    self.discover()


if __name__ == '__main__':
    unittest.main()
