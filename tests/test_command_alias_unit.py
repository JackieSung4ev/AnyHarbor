"""Exercise short-command ownership and rollback on temporary real files.

Only numeric owner IDs are simulated so the suite also runs without root.
Service/health helpers are doubles; no host service or command path is touched.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'src' / 'anytls-runtime.sh'
BASH = shutil.which('bash')
PRELUDE = r'''
set -euo pipefail
readonly BASE="$TEST_DIRECTORY/base" MANAGER="$TEST_DIRECTORY/bin/backend"
readonly SHORT_MANAGER="${SHORT_OVERRIDE:-$TEST_DIRECTORY/bin/short-command}"
readonly SERVICE=fixture.service HELPER_DIR="$TEST_DIRECTORY/helpers"
die() { printf '%s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
stat() {
    if [[ ${1:-} == -c && ${2:-} == %u ]]; then
        if [[ ${*: -1} == "$SHORT_MANAGER" ]]; then printf '%s\n' "${FAKE_SHORT_UID:-0}"
        else printf '0\n'; fi
    else command stat "$@"; fi
}
root_readonly() {
    [[ -e "$1" && ! -L "$1" && $(stat -c %u -- "$1") == 0 ]] || die "unsafe path: $1"
    (( (8#$(stat -c %a -- "$1") & 0022) == 0 )) || die "writable path: $1"
}
mktemp() {
    if [[ ${1:-} == /usr/local/sbin/.gz-anytls-restore-XXXXXXXX ]]; then
        command mktemp "$TEST_DIRECTORY/bin/.restore-XXXXXXXX"
    else command mktemp "$@"; fi
}
atomic_link() { ln -sfn -- "$1" "$2"; }
guard_generation() { [[ "$1" == "$BASE/releases/"* && -d "$1" ]] || die 'bad fixture generation'; }
current() { readlink -f -- "$BASE/current"; }
systemctl() { return 1; }
healthy() { return 0; }
source "$RUNTIME"
'''


@unittest.skipUnless(sys.platform.startswith('linux') and BASH, 'Requires Linux and Bash')
class ShortCommandTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix='short-command-')
        self.addCleanup(scratch.cleanup)
        self.directory = Path(scratch.name)
        self.base = self.directory / 'base'
        self.bin = self.directory / 'bin'
        self.bin.mkdir(mode=0o755)
        self.manager = self.bin / 'backend'
        self.short = self.bin / 'short-command'
        self.manager.write_text(
            '#!/bin/bash\n# Managed by gz-anytls-launcher-v1\nprintf "fixture launcher\\n"\n')
        self.manager.chmod(0o755)
        self.original_launcher = self.manager.read_bytes()
        (self.base / 'manager-releases').mkdir(parents=True)
        (self.base / 'manager-transactions').mkdir(mode=0o700)
        (self.base / 'releases/data').mkdir(parents=True)
        (self.base / 'current').symlink_to(self.base / 'releases/data')
        self.old = self.bundle('old')
        self.new = self.bundle('new')
        (self.base / 'manager-current').symlink_to(self.old)

    def bundle(self, name):
        directory = self.base / 'manager-releases' / name
        directory.mkdir(mode=0o700)
        for filename in ('anytls-manager.sh', 'anytls-state.py', 'anytls-subscription.sh',
                         'anytls-runtime.sh', 'anytls-update.py', 'manifest.json'):
            (directory / filename).write_text('fixture\n')
        return directory

    def invoke(self, code, **settings):
        return subprocess.run(
            [BASH, '-c', PRELUDE + '\n' + code], capture_output=True, text=True,
            encoding='utf-8', timeout=10,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                 'TEST_DIRECTORY': str(self.directory), 'RUNTIME': str(RUNTIME),
                 'OLD_BUNDLE': str(self.old), 'NEW_BUNDLE': str(self.new), **settings},
        )

    def succeed(self, code, **settings):
        result = self.invoke(code, **settings)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_install_is_idempotent_and_targets_stable_backend(self):
        self.succeed('manager_install_short_command')
        self.assertEqual(os.readlink(self.short), str(self.manager))
        inode = self.short.lstat().st_ino
        self.succeed('manager_install_short_command')
        self.assertEqual(self.short.lstat().st_ino, inode)
        self.assertEqual(self.manager.read_bytes(), self.original_launcher)

    def test_collisions_are_rejected_before_bundle_switch(self):
        for kind in ('file', 'foreign-link', 'dangling-link'):
            with self.subTest(kind=kind):
                if kind == 'file':
                    self.short.write_text('another program\n')
                elif kind == 'foreign-link':
                    self.short.symlink_to(self.old / 'anytls-manager.sh')
                else:
                    self.short.symlink_to(self.directory / 'missing')
                before = os.readlink(self.short) if self.short.is_symlink() else self.short.read_bytes()
                result = self.invoke('manager_switch_bundle "$NEW_BUNDLE" "$OLD_BUNDLE"')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.base / 'manager-current').resolve(), self.old)
                self.assertFalse(os.path.lexists(self.base / 'manager-previous'))
                self.assertEqual(self.manager.read_bytes(), self.original_launcher)
                after = os.readlink(self.short) if self.short.is_symlink() else self.short.read_bytes()
                self.assertEqual(before, after)
                self.short.unlink()

    def test_non_root_owned_link_is_not_adopted_or_removed(self):
        self.short.symlink_to(self.manager)
        result = self.invoke('manager_install_short_command', FAKE_SHORT_UID='1000')
        self.assertNotEqual(result.returncode, 0)
        result = self.succeed('manager_remove_short_command', FAKE_SHORT_UID='1000')
        self.assertIn(str(self.short), result.stderr)
        self.assertTrue(self.short.is_symlink())

    def test_other_path_command_blocks_install_even_behind_existing_alias(self):
        other_bin = self.directory / 'other-bin'
        other_bin.mkdir()
        other = other_bin / self.short.name
        other.write_text('#!/bin/bash\nprintf "foreign program\\n"\n')
        other.chmod(0o755)
        before = other.read_bytes()
        path = str(self.bin) + ':' + str(other_bin) + ':/usr/bin:/bin'
        for already_installed in (False, True):
            with self.subTest(already_installed=already_installed):
                if already_installed:
                    self.short.symlink_to(self.manager)
                result = self.invoke('manager_install_short_command', PATH=path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(str(other), result.stderr)
                self.assertEqual(other.read_bytes(), before)
                self.assertEqual(self.short.is_symlink(), already_installed)

    def test_writable_parent_is_rejected(self):
        self.bin.chmod(0o777)
        result = self.invoke('manager_install_short_command')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(os.path.lexists(self.short))

    def test_existing_launcher_early_return_still_creates_short_command(self):
        inode = self.manager.stat().st_ino
        self.succeed('manager_switch_bundle "$NEW_BUNDLE" "$OLD_BUNDLE"')
        self.assertEqual(self.manager.stat().st_ino, inode)
        self.assertEqual(self.manager.read_bytes(), self.original_launcher)
        self.assertEqual(os.readlink(self.short), str(self.manager))
        self.assertEqual((self.base / 'manager-current').resolve(), self.new)

    def test_failed_upgrade_restore_removes_only_new_short_command(self):
        result = self.succeed('''
transaction=$(manager_snapshot "$OLD_BUNDLE")
manager_switch_bundle "$NEW_BUNDLE" "$OLD_BUNDLE"
manager_restore_worker "$transaction"
printf '%s\n' "$transaction"
''')
        transaction = Path(result.stdout.strip())
        self.assertEqual((transaction / 'short-command-state').read_text(), 'absent\n')
        self.assertEqual((transaction / 'status').read_text(), 'restored\n')
        self.assertFalse(os.path.lexists(self.short))
        self.assertEqual((self.base / 'manager-current').resolve(), self.old)
        self.assertEqual(self.manager.read_bytes(), self.original_launcher)

    def test_existing_short_command_survives_restore(self):
        self.short.symlink_to(self.manager)
        inode = self.short.lstat().st_ino
        result = self.succeed('''
transaction=$(manager_snapshot "$OLD_BUNDLE")
manager_switch_bundle "$NEW_BUNDLE" "$OLD_BUNDLE"
manager_restore_worker "$transaction"
printf '%s\n' "$transaction"
''')
        transaction = Path(result.stdout.strip())
        self.assertEqual((transaction / 'short-command-state').read_text(), 'present\n')
        self.assertEqual(self.short.lstat().st_ino, inode)
        self.assertEqual(os.readlink(self.short), str(self.manager))

    def test_historical_transaction_without_marker_preserves_short_command(self):
        self.succeed('''
transaction=$(manager_snapshot "$OLD_BUNDLE")
rm -- "$transaction/short-command-state"
manager_switch_bundle "$NEW_BUNDLE" "$OLD_BUNDLE"
manager_restore_worker "$transaction"
''')
        self.assertEqual(os.readlink(self.short), str(self.manager))
        self.assertEqual((self.base / 'manager-current').resolve(), self.old)

    def test_restore_refuses_to_delete_foreign_replacement(self):
        result = self.invoke('''
transaction=$(manager_snapshot "$OLD_BUNDLE")
printf 'another program\n' >"$SHORT_MANAGER"
manager_restore_worker "$transaction"
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.short.read_text(), 'another program\n')

    def test_uninstall_removes_owned_link_and_preserves_foreign_file(self):
        self.short.symlink_to(self.manager)
        self.succeed('manager_remove_short_command')
        self.assertFalse(os.path.lexists(self.short))
        self.short.write_text('another program\n')
        result = self.succeed('manager_remove_short_command')
        self.assertIn(str(self.short), result.stderr)
        self.assertEqual(self.short.read_text(), 'another program\n')


if __name__ == '__main__':
    unittest.main()
