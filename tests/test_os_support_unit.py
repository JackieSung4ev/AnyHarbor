"""Supported apt distros stay aligned between the helper and both installers."""
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
import importlib.util
spec = importlib.util.spec_from_file_location('os_state', ROOT / 'src/anytls-state.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class AptOsSuiteTests(unittest.TestCase):
    def suite(self, identifier, version, quote='"'):
        temporary = tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False, newline='\n')
        self.addCleanup(lambda: Path(temporary.name).unlink(missing_ok=True))
        temporary.write('ID={q}{id}{q}\nVERSION_ID={q}{version}{q}\n'.format(
            q=quote, id=identifier, version=version))
        temporary.close()
        return helper.apt_os_suite(temporary.name)

    def test_debian_and_ubuntu_lts_map_to_cloudflare_suites(self):
        expected = {
            ('debian', '12'): 'bookworm',
            ('debian', '13'): 'trixie',
            ('ubuntu', '22.04'): 'jammy',
            ('ubuntu', '24.04'): 'noble',
            ('ubuntu', '26.04'): 'resolute',
        }
        self.assertEqual(helper.APT_OS_SUITES, expected)
        for key, suite in expected.items():
            with self.subTest(os=key):
                self.assertEqual(self.suite(*key), suite)
                self.assertEqual(self.suite(*key, quote=''), suite)

    def test_unsupported_releases_are_rejected_without_a_suite(self):
        for identifier, version in (('ubuntu', '20.04'), ('ubuntu', '24.10'),
                                    ('debian', '11'), ('centos', '9'), ('linuxmint', '22.04')):
            with self.subTest(os=(identifier, version)):
                with self.assertRaises(ValueError) as caught:
                    self.suite(identifier, version)
                self.assertIn('Ubuntu 22.04/24.04/26.04', str(caught.exception))

    def test_installer_allowlists_match_the_helper(self):
        pattern = '|'.join(identifier + ':' + version
                           for identifier, version in helper.APT_OS_SUITES)
        for name in ('bootstrap.sh', 'install.sh'):
            text = (ROOT / name).read_text(encoding='utf-8')
            self.assertIn(pattern, text, name)
            self.assertNotIn('ID="?debian"?', text, name)
            self.assertIn('require_supported_os', text, name)
        runtime = (ROOT / 'src/anytls-runtime.sh').read_text(encoding='utf-8')
        self.assertIn('py apt-suite', runtime)
        self.assertNotIn('仅支持 Debian 12/13', runtime)


if __name__ == '__main__':
    unittest.main()
