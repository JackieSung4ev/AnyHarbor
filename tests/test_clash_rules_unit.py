"""Deployment-local Clash rules: preserve accounts, formats, order and rollback safety."""
import contextlib
import copy
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


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


state = module('clash_rules_state', HELPER)
updater = module('clash_rules_updater', ROOT / 'src/anytls-update.py')
SOURCE_RULES = [
    'DOMAIN,login.example.test,Proxy',
    'DOMAIN-SUFFIX,example.test,DIRECT',
    'DOMAIN-KEYWORD,ads,REJECT',
    'DOMAIN-SUFFIX,example.test,Proxy',  # Keep the intentional earlier DIRECT exception.
    'IP-CIDR,192.0.2.0/24,Proxy,no-resolve',
    'IP-CIDR6,2001:db8::/32,DIRECT,no-resolve',
    'GEOIP,CN,DIRECT',
    'MATCH,Proxy',
]
CANONICAL_RULES = [rule.replace(',Proxy', ',PROXY') for rule in SOURCE_RULES]


def profile_rules(text):
    """Read only the generated scalar list; no YAML dependency in the test suite."""
    section = text.split('\nrules:\n', 1)[1]
    result = []
    for line in section.splitlines():
        if not line.strip():
            continue
        if not line.startswith('  - '):
            raise AssertionError('Unexpected generated rule line')
        scalar = line[4:]
        if scalar.startswith("'") and scalar.endswith("'"):
            scalar = scalar[1:-1].replace("''", "'")
        elif scalar.startswith('"'):
            scalar = json.loads(scalar)
        result.append(scalar)
    return result


class ClashRuleValidationTests(unittest.TestCase):
    def test_preserves_first_match_order_and_duplicate_policy_exceptions(self):
        original = copy.deepcopy(SOURCE_RULES)
        self.assertEqual(state.validate_clash_rules(SOURCE_RULES), CANONICAL_RULES)
        self.assertEqual(SOURCE_RULES, original)
        self.assertEqual(state.validate_clash_rules(CANONICAL_RULES), CANONICAL_RULES)

    def test_rejects_unbound_policies_providers_and_unsupported_rule_types(self):
        invalid = [
            'DOMAIN,example.test,OtherNode', 'DOMAIN,example.test,fallback-auto',
            'RULE-SET,remote-provider,PROXY', 'GEOSITE,cn,DIRECT',
            'PROCESS-NAME,example.exe,PROXY',
            'AND,((DOMAIN,example.test),(NETWORK,TCP)),PROXY',
            'DOMAIN,example.test,proxy', 'DOMAIN,example.test,DIRECT,no-resolve',
            'IP-CIDR,192.0.2.0/24,PROXY,src',
        ]
        for rule in invalid:
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                state.validate_clash_rules([rule, 'MATCH,PROXY'])

    def test_rejects_missing_or_early_catchall_and_non_proxy_final(self):
        cases = [[], {}, None, 'MATCH,PROXY', [None], [42],
                 ['DOMAIN,example.test,PROXY'], ['MATCH,DIRECT'], ['MATCH,REJECT'],
                 ['MATCH,PROXY', 'DOMAIN,example.test,DIRECT'],
                 ['MATCH,PROXY', 'MATCH,PROXY']]
        for rules in cases:
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                state.validate_clash_rules(rules)

    def test_rejects_invalid_networks_control_characters_and_yaml_injection(self):
        cases = ['IP-CIDR,999.0.0.0/24,DIRECT', 'IP-CIDR,192.0.2.0/99,DIRECT',
                 'IP-CIDR6,192.0.2.0/24,DIRECT', 'IP-CIDR,2001:db8::/32,DIRECT',
                 'DOMAIN,,DIRECT', 'DOMAIN,example.test\nproxies: [],DIRECT',
                 'DOMAIN,example.test\x00,DIRECT', 'DOMAIN,example.test\x1b,DIRECT',
                 'DOMAIN,example.test,PROXY,EXTRA']
        for rule in cases:
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                state.validate_clash_rules([rule, 'MATCH,PROXY'])

    def test_bounds_prevent_oversized_subscription_payloads(self):
        cases = [
            ['DOMAIN,a.example.test,DIRECT'] * 5000 + ['MATCH,PROXY'],
            ['DOMAIN-KEYWORD,' + 'a' * 512 + ',DIRECT', 'MATCH,PROXY'],
            ['DOMAIN-KEYWORD,' + 'a' * 480 + ',DIRECT'] * 600 + ['MATCH,PROXY'],
        ]
        for rules in cases:
            with self.subTest(count=len(rules)), self.assertRaises(ValueError):
                state.validate_clash_rules(rules)


class ClashRulesFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='anyharbor-clash-rules-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / 'state.json'
        state.main(['init', str(self.path), 'proxy.example.test', '8443'])
        initial = state.load(self.path)
        initial['tls_mode'], initial['tls_verify'] = 'imported', 'pki'
        initial['subscription'] = {'domain': 'sub.example.test', 'port': 9443}
        initial['groups'] = initial['groups'][:3]
        initial['groups'][1]['enabled'] = False
        state.write_json(self.path, initial)
        self.initial = state.load(self.path)
        self.input_path = self.directory / 'rules-input.json'
        self.input_path.write_text(json.dumps(SOURCE_RULES), encoding='utf-8')

    def command(self, command, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            state.main([command, str(self.path), *map(str, args)])
        return output.getvalue()

    def import_rules(self):
        self.command('clash-rules', 'import', self.input_path)

    def render(self, directory=None):
        with mock.patch.object(state, 'certificate_info', return_value='ab' * 32):
            state.render(directory or self.directory)

    def exports(self):
        names = ('nodes', 'v2rayn', 'subscriptions_v2rayn',
                 'shadowrocket', 'subscriptions_shadowrocket')
        return {str(p.relative_to(self.directory)): p.read_bytes()
                for name in names for p in (self.directory / name).iterdir()}


class ClashRulesStateTests(ClashRulesFixture):
    def test_import_show_reset_preserve_every_unrelated_state_value(self):
        self.assertEqual(self.command('get', 'clash_rule_count').strip(), '0')
        self.assertEqual(json.loads(self.command('clash-rules', 'show')), ['MATCH,PROXY'])
        self.import_rules()
        expected = copy.deepcopy(self.initial)
        expected['clash_rules'] = CANONICAL_RULES
        self.assertEqual(state.load(self.path), expected)
        self.assertEqual(self.command('get', 'clash_rule_count').strip(), str(len(CANONICAL_RULES)))
        before = self.path.read_bytes()
        self.assertEqual(json.loads(self.command('clash-rules', 'show')), CANONICAL_RULES)
        self.assertEqual(self.path.read_bytes(), before)
        self.command('clash-rules', 'reset')
        self.assertEqual(state.load(self.path), self.initial)

    def test_invalid_import_never_changes_saved_state(self):
        self.import_rules()
        before = self.path.read_bytes()
        cases = ['{bad json', json.dumps({'rules': SOURCE_RULES}),
                 json.dumps(['RULE-SET,remote-provider,PROXY', 'MATCH,PROXY']),
                 json.dumps(['DOMAIN,example.test,UNKNOWN', 'MATCH,PROXY']),
                 json.dumps([]), json.dumps(['x' * (2 * 1024 * 1024)])]
        for contents in cases:
            self.input_path.write_text(contents, encoding='utf-8')
            with self.subTest(size=len(contents)), self.assertRaises((ValueError, OSError)):
                self.import_rules()
            self.assertEqual(self.path.read_bytes(), before)
        for target in (self.directory / 'missing.json', self.directory):
            with self.subTest(path=target.name), self.assertRaises((ValueError, OSError)):
                self.command('clash-rules', 'import', target)
            self.assertEqual(self.path.read_bytes(), before)

    def test_symbolic_link_input_is_rejected_without_mutation(self):
        link = self.directory / 'linked.json'
        try:
            link.symlink_to(self.input_path)
        except OSError as exc:
            self.skipTest('Platform does not permit creating test symlinks: ' + str(exc))
        before = self.path.read_bytes()
        with self.assertRaises((ValueError, OSError)):
            self.command('clash-rules', 'import', link)
        self.assertEqual(self.path.read_bytes(), before)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'Requires POSIX FIFO support')
    def test_fifo_input_fails_without_waiting_for_a_writer(self):
        fifo = self.directory / 'rules.fifo'
        os.mkfifo(fifo)
        before = self.path.read_bytes()
        result = subprocess.run([sys.executable, '-B', str(HELPER), 'clash-rules',
                                 str(self.path), 'import', str(fifo)],
                                capture_output=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_rules_in_managed_state_are_rejected_on_load(self):
        for invalid in (None, [], ['MATCH,DIRECT'], ['RULE-SET,unknown,PROXY', 'MATCH,PROXY']):
            raw = copy.deepcopy(self.initial)
            raw['clash_rules'] = invalid
            with self.subTest(rules=invalid), self.assertRaises(ValueError):
                state.normalized(raw)

    def test_all_existing_and_new_groups_share_rules_without_sharing_accounts(self):
        self.render()
        before = self.exports()
        runtime_before = (self.directory / 'config.json').read_bytes()
        self.import_rules()
        self.render()
        self.assertEqual(self.exports(), before)
        self.assertEqual((self.directory / 'config.json').read_bytes(), runtime_before)
        new_identifier = self.command('group', 'add').strip()
        self.render()
        current = state.load(self.path)
        self.assertIn(new_identifier, {g['id'] for g in current['groups']})
        for group in current['groups']:
            path = self.directory / 'profiles' / (group['id'] + '.yaml')
            subscription = self.directory / 'subscriptions' / (group['token'] + '.yaml')
            if not group['enabled']:
                self.assertFalse(path.exists())
                self.assertFalse(subscription.exists())
                continue
            profile = path.read_text(encoding='utf-8')
            self.assertEqual(profile_rules(profile), CANONICAL_RULES)
            self.assertEqual(path.read_bytes(), subscription.read_bytes())
            self.assertIn(group['password'], profile)
            self.assertNotIn('      - DIRECT\n', profile)
            self.assertIn('allow-lan: false\n', profile)
            self.assertNotIn('external-controller:', profile)
            for other in current['groups']:
                if other['id'] != group['id']:
                    self.assertNotIn(other['password'], profile)
                    self.assertNotIn(other['token'], profile)

    def test_rule_import_and_reset_preserve_warp_schema_and_server_routes(self):
        self.command('group', 'egress', 'athena', 'warp')
        self.render()
        before = (self.directory / 'config.json').read_bytes()
        state_before = state.load(self.path)
        self.import_rules()
        self.render()
        self.assertEqual((self.directory / 'config.json').read_bytes(), before)
        self.assertEqual(state.load(self.path)['schema'], 3)
        self.assertIn('    udp: false\n', (self.directory / 'profiles/athena.yaml').read_text())
        self.command('clash-rules', 'reset')
        self.render()
        self.assertEqual(state.load(self.path), state_before)
        self.assertEqual((self.directory / 'config.json').read_bytes(), before)

    def test_core_rollback_carries_current_rules_and_does_not_resurrect_reset_rules(self):
        candidate = self.directory / 'historical.json'
        historical = copy.deepcopy(self.initial)
        historical['port'] = 9444
        state.write_json(candidate, historical)
        self.import_rules()
        state.main(['preserve-identity', str(self.path), str(candidate)])
        merged = state.load(candidate)
        self.assertEqual(merged['clash_rules'], CANONICAL_RULES)
        self.assertEqual(merged['port'], 9444)
        self.command('clash-rules', 'reset')
        state.main(['preserve-identity', str(self.path), str(candidate)])
        self.assertNotIn('clash_rules', state.load(candidate))
        self.assertEqual(state.load(candidate)['port'], 9444)


class ClashRulesUpgradeProtectionTests(ClashRulesFixture):
    def setUp(self):
        super().setUp()
        for name in ('sing-box', 'server.crt', 'server.key'):
            (self.directory / name).write_text('synthetic-' + name)
        self.render()
        self.candidate = self.directory / 'candidate'
        shutil.copytree(self.directory, self.candidate)

    def change_candidate(self, change):
        path = self.candidate / 'state.json'
        raw = state.load(path)
        change(raw)
        state.write_json(path, raw)

    def test_manager_upgrade_refuses_to_drop_change_or_reorder_rules(self):
        self.import_rules()
        self.render()
        for replacement in (None, ['MATCH,PROXY'],
                            [CANONICAL_RULES[1], CANONICAL_RULES[0], *CANONICAL_RULES[2:]]):
            def alter(raw):
                if replacement is None:
                    raw.pop('clash_rules', None)
                else:
                    raw['clash_rules'] = replacement
            self.change_candidate(alter)
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                updater.protect(self.directory, self.candidate)
        self.change_candidate(lambda raw: raw.update(clash_rules=CANONICAL_RULES))
        self.render(self.candidate)
        self.assertEqual(updater.protect(self.directory, self.candidate), 'same_runtime')

    def test_rule_transaction_allows_only_rule_changes_and_same_runtime(self):
        self.change_candidate(lambda raw: raw.update(clash_rules=CANONICAL_RULES))
        self.render(self.candidate)
        self.assertEqual(updater.protect(self.directory, self.candidate, allow_rules=True), 'same_runtime')
        saved = (self.candidate / 'state.json').read_bytes()
        mutations = [lambda raw: raw.update(server='other.example.test'),
                     lambda raw: raw.update(node_prefix='Other'),
                     lambda raw: raw['groups'][0].update(label='Other'),
                     lambda raw: raw['groups'][0].update(password='a' * 43),
                     lambda raw: raw['groups'][0].update(egress='warp'),
                     lambda raw: raw.update(unrelated_new_field='must-not-change')]
        for mutate in mutations:
            (self.candidate / 'state.json').write_bytes(saved)
            self.change_candidate(mutate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                updater.protect(self.directory, self.candidate, allow_rules=True)


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('bash'),
                     'Requires Linux and Bash; no root privileges are needed')
class ClashRulesTransactionTests(ClashRulesFixture):
    def setUp(self):
        super().setUp()
        for name in ('sing-box', 'server.crt', 'server.key'):
            (self.directory / name).write_text('synthetic-' + name)
        self.render()
        self.base = self.directory / 'managed'
        self.base.mkdir()
        (self.base / 'current').symlink_to(self.directory)
        self.events = self.directory / 'events'
        self.events.touch()
        self.worker = self.directory / 'manager-fixture.sh'
        renderer = self.directory / 'render-fixture.py'
        renderer.write_text('''
import importlib.util
import os
import sys
spec = importlib.util.spec_from_file_location('transaction_state', os.environ['STATE_HELPER'])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
helper.certificate_info = lambda *args: 'ab' * 32
helper.render(sys.argv[1])
''', encoding='utf-8')
        runtime = (ROOT / 'src/anytls-runtime.sh').read_text(encoding='utf-8')
        manager = (ROOT / 'src/anytls-manager.sh').read_text(encoding='utf-8')
        functions = []
        for text, names in ((runtime, ('manager_exports_equal', 'rules_commit_worker', 'rules_command')),
                            (manager, ('main',))):
            for name in names:
                functions.append(re.search(r'^' + name + r'\(\) \{\n.*?^\}\n', text,
                                           re.MULTILINE | re.DOTALL).group(0))
        prelude = r'''
#!/usr/bin/env bash
set -euo pipefail
SELF=$(readlink -f -- "${BASH_SOURCE[0]}")
BASE="$TEST_DIRECTORY/managed"
record() { printf '%s\n' "$*" >> "$TEST_DIRECTORY/events"; }
die() { printf '%s\n' "$*" >&2; exit 70; }
say() { printf '%s\n' "$*"; }
root_and_tools() { :; }
owned_base() { :; }
lock_base() { :; }
current() { readlink -f -- "$BASE/current"; }
py() { record "py:$1:${3:-}"; python3 "$STATE_HELPER" "$@"; }
updater() {
    record "updater:$1"
    if [[ ${FORCE_RUNTIME:-} == changed && $1 == protect-rules ]]; then
        printf 'changed_runtime\n'
    else python3 "$UPDATE_HELPER" "$@"; fi
}
clone_current() {
    local old; old=$(current)
    record clone
    WORK="$TEST_DIRECTORY/candidate"
    mkdir "$WORK"
    cp "$old/state.json" "$old/server.crt" "$old/server.key" "$old/sing-box" "$WORK/"
}
finalize_generation() {
    record render
    python3 "$TEST_DIRECTORY/render-fixture.py" "$WORK"
}
manager_roots() { :; }
manager_target_guard() { :; }
manager_active_bundle() { printf '%s\n' "$TEST_DIRECTORY/bundle"; }
manager_snapshot() {
    local transaction="$TEST_DIRECTORY/transaction"
    record snapshot
    mkdir "$transaction"
    current > "$transaction/current"
    if [[ -L "$BASE/previous" ]]; then readlink -f "$BASE/previous" > "$transaction/previous"
    else : > "$transaction/previous"; fi
    printf 'yes\n' > "$transaction/was-active"
    printf '%s\n' "$transaction"
}
manager_transaction_guard() { record guard-transaction; [[ -f "$1/current" ]]; }
guard_generation() { [[ -f "$1/state.json" ]]; }
atomic_link() {
    record "publish:${2##*/}"
    ln -s -- "$1" "$2.next"
    mv -Tf -- "$2.next" "$2"
}
healthy() { record healthy; [[ ${HEALTH_FAIL:-no} != yes ]]; }
systemctl() { record UNEXPECTED_SYSTEMCTL; exit 80; }
manager_restore_worker() {
    record restore
    atomic_link "$(cat "$1/current")" "$BASE/current"
    if [[ -s "$1/previous" ]]; then atomic_link "$(cat "$1/previous")" "$BASE/previous"
    else rm -f -- "$BASE/previous"; fi
    printf 'restored\n' > "$1/status"
}
ui_heading() { printf 'HEADING:%s\n' "$1"; }
ui_note() { printf '%s\n' "$*"; }
ui_item() { printf '%s) %s\n' "$1" "$2"; }
ui_prompt() { IFS= read -r -p "$2" "$1"; }
'''
        self.worker.write_text(prelude + '\n'.join(functions) + '\nmain "$@"\n', encoding='utf-8')

    def run_cli(self, *args, input_text='', **environment):
        result = subprocess.run(['bash', str(self.worker), *map(str, args)],
                                env={**os.environ, 'TEST_DIRECTORY': str(self.directory),
                                     'STATE_HELPER': str(HELPER),
                                     'UPDATE_HELPER': str(ROOT / 'src/anytls-update.py'),
                                     **environment},
                                input=input_text, capture_output=True, text=True, timeout=10)
        return result, self.events.read_text().splitlines()

    def test_import_publishes_checked_rules_and_keeps_service_running(self):
        before = self.path.read_bytes()
        with_spaces = self.directory / 'my rules.json'
        with_spaces.write_bytes(self.input_path.read_bytes())
        result, events = self.run_cli('rules', 'import', with_spaces)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        candidate = self.directory / 'candidate'
        self.assertEqual((self.base / 'current').resolve(), candidate)
        self.assertEqual((self.base / 'previous').resolve(), self.directory)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(state.load(candidate / 'state.json')['clash_rules'], CANONICAL_RULES)
        self.assertEqual(profile_rules((candidate / 'profiles/athena.yaml').read_text()), CANONICAL_RULES)
        expected_order = ['clone', 'py:clash-rules:import', 'render', 'updater:protect-rules',
                          'snapshot', 'guard-transaction', 'publish:previous', 'publish:current', 'healthy']
        position = -1
        for event in expected_order:
            position = events.index(event, position + 1)
        self.assertNotIn('UNEXPECTED_SYSTEMCTL', events)
        self.assertNotIn('restore', events)
        self.assertEqual((self.directory / 'transaction/status').read_text().strip(), 'complete')

    def test_failed_health_check_runs_caller_restore_after_worker_failure(self):
        before = self.path.read_bytes()
        result, events = self.run_cli('rules', 'import', self.input_path, HEALTH_FAIL='yes')
        self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
        self.assertLess(events.index('publish:current'), events.index('healthy'))
        self.assertLess(events.index('healthy'), events.index('restore'))
        self.assertEqual((self.base / 'current').resolve(), self.directory)
        self.assertFalse((self.base / 'previous').exists())
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual((self.directory / 'transaction/status').read_text().strip(), 'restored')
        self.assertNotIn('UNEXPECTED_SYSTEMCTL', events)

    def test_worker_rejects_runtime_change_before_any_pointer_is_published(self):
        transaction = self.directory / 'transaction'
        transaction.mkdir()
        (transaction / 'current').write_text(str(self.directory))
        (transaction / 'was-active').write_text('yes')
        candidate = self.directory / 'candidate'
        candidate.mkdir()
        shutil.copyfile(self.path, candidate / 'state.json')
        result, events = self.run_cli('__rules-commit', transaction, candidate, FORCE_RUNTIME='changed')
        self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
        self.assertIn('updater:protect-rules', events)
        self.assertFalse(any(event.startswith('publish:') for event in events))
        self.assertEqual((self.base / 'current').resolve(), self.directory)
        self.assertFalse((transaction / 'status').exists())

    def test_malformed_import_does_not_render_snapshot_or_publish(self):
        self.input_path.write_text('["RULE-SET,missing,PROXY", "MATCH,PROXY"]')
        before = self.path.read_bytes()
        result, events = self.run_cli('rules', 'import', self.input_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('py:clash-rules:import', events)
        self.assertNotIn('render', events)
        self.assertNotIn('snapshot', events)
        self.assertFalse(any(event.startswith('publish:') for event in events))
        self.assertEqual((self.base / 'current').resolve(), self.directory)
        self.assertEqual(self.path.read_bytes(), before)

    def test_no_argument_rules_menu_returns_without_starting_a_transaction(self):
        before = self.path.read_bytes()
        result, events = self.run_cli('rules', input_text='0\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('HEADING:', result.stdout)
        self.assertIn('MATCH,PROXY', result.stdout)
        self.assertNotIn('clone', events)
        self.assertNotIn('snapshot', events)
        self.assertEqual(self.path.read_bytes(), before)


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('bash'),
                     'Requires Linux and Bash; no root privileges are needed')
class ClashRulesRollbackTests(ClashRulesFixture):
    def test_default_prefix_cannot_roll_back_to_renderer_ignoring_custom_rules(self):
        self.import_rules()
        self.render()
        before = self.path.read_bytes()
        profile_before = (self.directory / 'profiles/athena.yaml').read_bytes()
        self.assertEqual(state.load(self.path)['node_prefix'], 'GZ')
        for name in ('server.crt', 'server.key'):
            (self.directory / name).write_text('synthetic-' + name)
        core = self.directory / 'sing-box'
        core.write_text('#!/bin/sh\nexit 0\n')
        core.chmod(0o700)
        target = self.directory / 'old-manager'
        target.mkdir()
        # Emulate the old renderer: unknown state fields survive normalization,
        # but client rules are ignored. The actual rollback comparison must catch it.
        (target / 'anytls-state.py').write_text('''
import importlib.util
import os
import sys
spec = importlib.util.spec_from_file_location('previous_state', os.environ['STATE_HELPER'])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
original = helper.group_documents
def old_documents(state, *args):
    legacy = dict(state)
    legacy.pop('clash_rules', None)
    return original(legacy, *args)
helper.group_documents = old_documents
helper.certificate_info = lambda *args: 'ab' * 32
helper.main(sys.argv[1:])
''', encoding='utf-8')
        runtime = (ROOT / 'src/anytls-runtime.sh').read_text(encoding='utf-8')
        functions = '\n'.join(re.search(r'^' + name + r'\(\) \{\n.*?^\}\n', runtime,
                                        re.MULTILINE | re.DOTALL).group(0)
                              for name in ('manager_exports_equal', 'manager_rollback'))
        script = r'''
set -euo pipefail
MANAGER_CURRENT="$TEST_DIRECTORY/current-manager"
MANAGER_PREVIOUS="$TEST_DIRECTORY/old-manager"
SELF="$TEST_DIRECTORY/should-not-execute.sh"
manager_roots() { :; }
manager_target_guard() { :; }
manager_pointer() { printf '%s\n' "$1"; }
current() { printf '%s\n' "$TEST_DIRECTORY"; }
clone_current() {
    WORK="$TEST_DIRECTORY/rollback-check"
    mkdir "$WORK"
    cp "$TEST_DIRECTORY/state.json" "$TEST_DIRECTORY/server.crt" \
       "$TEST_DIRECTORY/server.key" "$TEST_DIRECTORY/sing-box" "$WORK/"
}
py() { python3 "$STATE_HELPER" "$@"; }
updater() { python3 "$UPDATE_HELPER" "$@"; }
die() { printf '%s\n' "$*" >&2; exit 70; }
manager_snapshot() { touch "$TEST_DIRECTORY/UNSAFE_COMMIT"; printf 'unsafe\n'; }
say() { printf '%s\n' "$*"; }
'''
        result = subprocess.run(['bash', '-c', script + functions + '\nmanager_rollback\n'],
                                env={**os.environ, 'TEST_DIRECTORY': str(self.directory),
                                     'STATE_HELPER': str(HELPER),
                                     'UPDATE_HELPER': str(ROOT / 'src/anytls-update.py')},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 70, result.stdout + result.stderr)
        self.assertFalse((self.directory / 'UNSAFE_COMMIT').exists(), result.stderr)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual((self.directory / 'profiles/athena.yaml').read_bytes(), profile_before)


if __name__ == '__main__':
    unittest.main()
