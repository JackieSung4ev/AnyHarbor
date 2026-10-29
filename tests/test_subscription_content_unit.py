"""Synthetic read-only content checks; no real subscription, credentials or network."""
import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HELPER = Path(__file__).resolve().parents[1] / 'src/anytls-state.py'
spec = importlib.util.spec_from_file_location('subscription_content_state', HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class InputBuffer(io.BytesIO):
    def close(self):
        self.submitted = self.getvalue()
        super().close()


class CurlProcess:
    def __init__(self, body, status=b'200', code=0):
        self.stdin = InputBuffer()
        self.stdout = io.BytesIO(body + b'\n' + status)
        self.returncode = None
        self.code = code
        self.killed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stdout.close()

    def wait(self, timeout=None):
        self.returncode = -9 if self.killed else self.code
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True


class SubscriptionContentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='gz-content-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.state_path = self.directory / 'state.json'
        helper.main(['init', str(self.state_path), 'proxy.example.test', '8443'])
        self.state = helper.load(self.state_path)
        self.state['groups'] = self.state['groups'][:3]
        self.state['groups'][1]['enabled'] = False
        self.state['tls_mode'], self.state['tls_verify'] = 'imported', 'pki'
        self.state['subscription'] = {'domain': 'sub.example.test', 'port': 9443}
        helper.write_json(self.state_path, self.state)
        with mock.patch.object(helper, 'certificate_info', return_value='ab' * 32):
            helper.render(self.directory)
        self.group = self.state['groups'][0]
        self.paths = {'s': self.directory / 'subscriptions' / (self.group['token'] + '.yaml'),
                      'v': self.directory / 'subscriptions_v2rayn' / (self.group['token'] + '.txt'),
                      'r': self.directory / 'subscriptions_shadowrocket' / (self.group['token'] + '.txt')}
        self.bodies = {route: path.read_bytes() for route, path in self.paths.items()}

    def snapshot(self):
        return {str(path.relative_to(self.directory)): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in self.directory.rglob('*') if path.is_file()}

    def invoke(self, identifier=None, responses=None, error=None, failure=False):
        before = self.snapshot()
        processes = responses if responses is not None else [CurlProcess(body) for body in self.bodies.values()]
        output = io.StringIO()
        arguments = ['check-subscriptions', str(self.directory)]
        if identifier is not None:
            arguments.append(identifier)
        with mock.patch.object(helper.subprocess, 'Popen', side_effect=error or processes) as request:
            with contextlib.redirect_stdout(output):
                if failure:
                    with self.assertRaises(helper.SubscriptionCheckError) as result:
                        helper.main(arguments)
                    output.write(str(result.exception))
                else:
                    helper.main(arguments)
        self.assertEqual(self.snapshot(), before)
        text = output.getvalue()
        for group in self.state['groups']:
            self.assertNotIn(group['password'], text)
            self.assertNotIn(group['token'], text)
        self.assertNotIn('https://', text)
        self.assertNotIn('v2rayn://', text)
        self.assertNotIn('anytls://', text)
        return text, request, processes

    def test_three_formats_and_default_sampling_are_read_only(self):
        text, request, processes = self.invoke()
        self.assertIn('athena', text)
        self.assertIn('默认采样一个启用组', text)
        self.assertIn('同组账号', text)
        self.assertIn('HTTPS /s：200', text)
        self.assertIn('HTTPS /v：200', text)
        self.assertIn('HTTPS /r：200', text)
        self.assertEqual(request.call_count, 3)
        decoded = base64.b64decode(self.bodies['v'].strip(), validate=True)
        self.assertTrue(decoded.startswith(b'v2rayn://anytls/'))
        payload = decoded.strip().split(b'/', 3)[3]
        account = json.loads(base64.urlsafe_b64decode(payload + b'=' * (-len(payload) % 4)))
        self.assertEqual(account['Password'], self.group['password'])
        self.assertTrue(base64.b64decode(self.bodies['r'].strip(), validate=True).startswith(b'anytls://'))
        for index, call in enumerate(request.call_args_list):
            args = call.args[0]
            self.assertEqual(args[:2], ['curl', '-q'])
            self.assertEqual(args[args.index('--noproxy') + 1], '*')
            self.assertEqual(args[args.index('--proto') + 1], '=https')
            self.assertEqual(args[args.index('--resolve') + 1], 'sub.example.test:9443:127.0.0.1')
            self.assertEqual(args[args.index('--max-time') + 1], '5')
            self.assertEqual(args[-2:], ['--config', '-'])
            self.assertNotIn('--location', args)
            self.assertNotIn('-k', args)
            self.assertNotIn('--insecure', args)
            self.assertNotIn(self.group['token'], ' '.join(args))
            self.assertEqual(call.kwargs['stderr'], subprocess.DEVNULL)
            route = ('s', 'v', 'r')[index]
            self.assertEqual(processes[index].stdin.submitted,
                             ('url = "https://sub.example.test:9443/' + route + '/' + self.group['token'] + '"\n').encode())

    def test_explicit_enabled_group_is_checked_alone(self):
        group = self.state['groups'][2]
        responses = [CurlProcess((self.directory / directory / (group['token'] + suffix)).read_bytes())
                     for directory, suffix in [('subscriptions', '.yaml'), ('subscriptions_v2rayn', '.txt'),
                                               ('subscriptions_shadowrocket', '.txt')]]
        text, _, _ = self.invoke('hermes', responses=responses)
        self.assertIn('组 hermes（显式指定组', text)
        self.assertNotIn('athena', text)
        for identifier in ('apollo', 'missing', '../athena', ''):
            with self.subTest(identifier=identifier):
                _, request, _ = self.invoke(identifier, failure=True)
                request.assert_not_called()

    def test_pin_mode_reads_only_public_certificate_for_expected_formats(self):
        self.state['tls_verify'] = 'pin'
        helper.write_json(self.state_path, self.state)
        certificate = b'-----BEGIN CERTIFICATE-----\nU1lOVEhFVElD\n-----END CERTIFICATE-----\n'
        fingerprint = 'ab' * 32
        with mock.patch.object(helper, 'certificate_info', return_value=fingerprint), \
                mock.patch.object(helper, 'call', return_value=certificate):
            helper.render(self.directory)
        self.bodies = {route: self.paths[route].read_bytes() for route in ('s', 'v')}
        with mock.patch.object(helper, 'call', side_effect=[certificate, ('sha256 Fingerprint=' + fingerprint).encode()]) as openssl:
            text, request, _ = self.invoke()
        self.assertIn('HTTPS /v：200', text)
        self.assertNotIn('HTTPS /r', text)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(openssl.call_count, 2)
        self.assertTrue(all('server.key' not in ' '.join(call.args[0]) for call in openssl.call_args_list))

    def test_clash_corruption_is_distinguished_locally_and_over_http(self):
        self.paths['s'].write_bytes(self.bodies['v'])
        text, request, _ = self.invoke(failure=True)
        self.assertIn('本地产物 /s 不是预期的 Clash YAML', text)
        request.assert_not_called()
        self.paths['s'].write_bytes(self.bodies['s'])
        text, _, _ = self.invoke(responses=[CurlProcess(self.bodies['v']), CurlProcess(self.bodies['v']),
                                          CurlProcess(self.bodies['r'])], failure=True)
        self.assertIn('HTTP 返回 /s 不是预期的 Clash YAML', text)

    def test_local_yaml_in_v_is_identified_before_any_request(self):
        self.paths['v'].write_bytes(self.bodies['s'])
        text, request, _ = self.invoke(failure=True)
        self.assertIn('本地产物 /v 正文为 YAML', text)
        request.assert_not_called()

    def test_http_yaml_in_v_is_distinguished_from_local_output(self):
        text, _, _ = self.invoke(responses=[CurlProcess(self.bodies['s']), CurlProcess(self.bodies['s']),
                                          CurlProcess(self.bodies['r'])], failure=True)
        self.assertIn('本地产物：', text)
        self.assertIn('HTTP 返回 /v 正文为 YAML', text)

    def test_shadowrocket_rejects_yaml_v2rayn_and_double_encoded_bodies(self):
        variants = [(self.bodies['s'], '正文为 YAML'),
                    (self.bodies['v'], '解码后不是 Shadowrocket / AnyTLS'),
                    (base64.b64encode(self.bodies['r']) + b'\n', '存在双重 Base64')]
        for body, expected in variants:
            for local in (True, False):
                with self.subTest(reason=expected, local=local):
                    self.paths['r'].write_bytes(body if local else self.bodies['r'])
                    processes = [CurlProcess(self.bodies['s']), CurlProcess(self.bodies['v']), CurlProcess(body)]
                    text, request, _ = self.invoke(responses=processes, failure=True)
                    self.assertIn('/r ' + expected, text)
                    if local:
                        request.assert_not_called()

    def test_shadowrocket_wrong_group_is_detected_without_disclosing_uri(self):
        other = self.state['groups'][2]
        body = (self.directory / 'subscriptions_shadowrocket' / (other['token'] + '.txt')).read_bytes()
        self.paths['r'].write_bytes(body)
        text, request, _ = self.invoke(failure=True)
        self.assertIn('本地产物 /r 内容与当前组', text)
        request.assert_not_called()
        self.paths['r'].write_bytes(self.bodies['r'])
        processes = [CurlProcess(self.bodies['s']), CurlProcess(self.bodies['v']), CurlProcess(body)]
        text, _, _ = self.invoke(responses=processes, failure=True)
        self.assertIn('HTTP 返回 /r 内容与当前组', text)

    def test_double_base64_and_title_pollution_are_rejected(self):
        variants = [(base64.b64encode(self.bodies['v']) + b'\n', '双重 Base64'),
                    (b'=== v2rayN subscription ===\n' + self.bodies['v'], '混入标题')]
        for body, expected in variants:
            for local in (True, False):
                with self.subTest(reason=expected, local=local):
                    self.paths['v'].write_bytes(body if local else self.bodies['v'])
                    responses = [CurlProcess(self.bodies['s']), CurlProcess(body), CurlProcess(self.bodies['r'])]
                    text, request, _ = self.invoke(responses=responses, failure=True)
                    self.assertIn(expected, text)
                    if local:
                        request.assert_not_called()

    def test_same_format_with_wrong_account_or_stale_body_is_rejected(self):
        other = self.state['groups'][2]
        body = (self.directory / 'subscriptions_v2rayn' / (other['token'] + '.txt')).read_bytes()
        self.paths['v'].write_bytes(body)
        text, request, _ = self.invoke(failure=True)
        self.assertIn('本地产物 /v 内容与当前组', text)
        request.assert_not_called()
        self.paths['v'].write_bytes(self.bodies['v'])
        text, _, _ = self.invoke(responses=[CurlProcess(self.bodies['s']), CurlProcess(body),
                                          CurlProcess(self.bodies['r'])], failure=True)
        self.assertIn('HTTP 返回 /v 内容与当前组', text)

    def test_connection_tls_and_redirect_failures_are_safe(self):
        for code, expected in [(7, '无法连接'), (28, '超时'), (60, '证书验证失败')]:
            with self.subTest(code=code):
                text, request, _ = self.invoke(responses=[CurlProcess(b'', code=code) for _ in range(3)], failure=True)
                self.assertIn(expected, text)
                self.assertEqual(request.call_count, 3)
        text, _, _ = self.invoke(responses=[CurlProcess(b'', b'302'), CurlProcess(b'', b'404'),
                                          CurlProcess(self.bodies['r'])], failure=True)
        self.assertIn('返回 302（未跟随跳转）', text)
        self.assertIn('返回 404', text)

    def test_sensitive_stderr_and_file_paths_never_escape(self):
        secret = 'https://sub.example.test:9443/v/' + self.group['token'] + ' ' + self.group['password']
        text, _, _ = self.invoke(error=OSError(secret), failure=True)
        self.assertIn('curl 执行异常', text)
        self.paths['v'].unlink()
        text, request, _ = self.invoke(failure=True)
        self.assertIn('本地订阅产物缺失', text)
        request.assert_not_called()

    def test_oversized_response_is_bounded_and_killed(self):
        process = CurlProcess(b'x' * (helper.SUBSCRIPTION_LIMIT + 100))
        text, _, _ = self.invoke(responses=[process, CurlProcess(self.bodies['v']),
                                          CurlProcess(self.bodies['r'])], failure=True)
        self.assertIn('响应超过大小限制', text)
        self.assertTrue(process.killed)

    def test_invalid_normalized_domain_is_rejected_before_network(self):
        self.state['subscription']['domain'] = 'sub.example.test\nurl = "https://elsewhere.invalid"'
        helper.write_json(self.state_path, self.state)
        text, request, _ = self.invoke(failure=True)
        self.assertIn('状态不可读取', text)
        request.assert_not_called()

    def test_cli_local_failure_is_nonzero_and_has_no_credentials(self):
        self.paths['v'].write_bytes(self.bodies['s'])
        before = self.snapshot()
        result = subprocess.run([sys.executable, '-B', str(HELPER), 'check-subscriptions', str(self.directory)],
                                capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('本地产物 /v 正文为 YAML', result.stderr)
        for group in self.state['groups']:
            self.assertNotIn(group['token'], result.stdout + result.stderr)
            self.assertNotIn(group['password'], result.stdout + result.stderr)
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
