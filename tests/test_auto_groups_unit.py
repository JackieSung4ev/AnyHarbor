"""Portable state regressions; run with Python's standard-library unittest."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock


HELPER = Path(__file__).resolve().parents[1] / 'src' / 'anytls-state.py'
spec = importlib.util.spec_from_file_location('anytls_state', HELPER)
state_helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state_helper)


class AutomaticGroupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'state.json'
        state_helper.main(['init', str(self.path), '203.0.113.8', '8443'])
        state = state_helper.load(self.path)
        state['node_prefix'] = 'GZ-SV02'
        state_helper.write_json(self.path, state)

    def add(self, *values):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            state_helper.main(['group', str(self.path), 'add', *values])
        return output.getvalue().strip()

    def test_random_add_persists_matching_id_and_preserves_existing_identity(self):
        before = state_helper.load(self.path)
        picked = []

        def choose(candidates):
            picked.append(candidates[-1])
            return candidates[-1]

        with mock.patch.object(state_helper.secrets, 'choice', side_effect=choose) as choice:
            identifier = self.add()
        choice.assert_called_once()
        after = state_helper.load(self.path)
        new_group = after['groups'].pop()
        self.assertEqual(before, after)
        self.assertEqual((identifier, new_group['label']), picked[0])
        self.assertEqual(identifier, new_group['id'])
        self.assertTrue(new_group['enabled'])
        old_credentials = {g[key] for g in before['groups'] for key in ('password', 'token')}
        self.assertNotIn(new_group['password'], old_credentials)
        self.assertNotIn(new_group['token'], old_credentials)
        self.assertNotEqual(new_group['password'], new_group['token'])

    def test_disabled_ids_and_case_insensitive_display_names_remain_reserved(self):
        state = state_helper.load(self.path)
        by_id = state_helper.edit_group(state, 'add', ['ares', 'Custom title'])
        by_title = state_helper.edit_group(state, 'add', ['retired', 'DIONYSUS'])
        by_id['enabled'] = by_title['enabled'] = False
        before = copy.deepcopy(state)
        with mock.patch.object(state_helper, 'AUTO_GROUP_NAMES', ('Ares', 'Dionysus', 'Hades')):
            with mock.patch.object(state_helper.secrets, 'choice', side_effect=lambda items: items[0]) as choice:
                new_group = state_helper.edit_group(state, 'add', [])
        self.assertEqual(choice.call_args.args[0], [('hades', 'Hades')])
        self.assertEqual((new_group['id'], new_group['label']), ('hades', 'Hades'))
        state['groups'].pop()
        self.assertEqual(state, before)

    def test_exhausted_names_use_an_unused_matching_numeric_suffix(self):
        state = state_helper.load(self.path)
        state_helper.edit_group(state, 'add', ['ares', 'Ares'])
        state_helper.edit_group(state, 'add', ['ares2', 'Ares2'])
        with mock.patch.object(state_helper, 'AUTO_GROUP_NAMES', ('Ares',)):
            new_group = state_helper.edit_group(state, 'add', [])
        self.assertEqual((new_group['id'], new_group['label']), ('ares3', 'Ares3'))
        state_helper.normalized(state)

    def test_hundred_group_limit_includes_disabled_and_preserves_file_on_failure(self):
        state = state_helper.load(self.path)
        state['groups'][0]['enabled'] = False
        original_groups = copy.deepcopy(state['groups'])
        while len(state['groups']) < 100:
            state_helper.edit_group(state, 'add', [])
        self.assertEqual(state['groups'][:len(original_groups)], original_groups)
        for field in ('id', 'password', 'token'):
            self.assertEqual(len({group[field] for group in state['groups']}), 100)
        self.assertEqual(len({group['label'].casefold() for group in state['groups']}), 100)
        state_helper.write_json(self.path, state_helper.normalized(state))
        before = self.path.read_bytes()
        for values in ((), ('overflow', 'Overflow')):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.add(*values)
            self.assertEqual(self.path.read_bytes(), before)

    def test_manual_add_keeps_supplied_name_and_rejects_bad_arguments_without_writes(self):
        before = state_helper.load(self.path)
        self.assertEqual(self.add('ops_east', 'Operations East'), 'ops_east')
        after = state_helper.load(self.path)
        new_group = after['groups'].pop()
        self.assertEqual((new_group['id'], new_group['label']), ('ops_east', 'Operations East'))
        self.assertEqual(after, before)
        saved = self.path.read_bytes()
        invalid = [('only_id',), ('x', 'X', 'extra'), ('', 'Empty ID'),
                   ('Uppercase', 'Invalid ID'), ('athena', 'Duplicate ID')]
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.add(*values)
            self.assertEqual(self.path.read_bytes(), saved)


if __name__ == '__main__':
    unittest.main()
