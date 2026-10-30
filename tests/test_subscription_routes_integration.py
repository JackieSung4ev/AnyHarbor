#!/usr/bin/env python3
"""Real renderer + Nginx three-route HTTPS check in a disposable Debian container.

Run with GZ_ANYTLS_DISPOSABLE_TEST=1. Requires nginx, openssl, curl and util-linux.
No production data or public subscription URLs are used. The negative control
deliberately changes only its fixture /v alias to prove that a root-path 404
health probe alone cannot detect a subscription format routing error.
The fixture CA is trusted only within this test; no insecure TLS flag is used.
AnyTLS URI structure is verified here, not import in a real Shadowrocket device.
"""
import base64
import contextlib
import csv
import grp
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = 'jackie-anytls-sub'
RUNTIME = Path('/run/jackie-anytls-sub')
DOMAIN = 'subscription.example.test'
spec = importlib.util.spec_from_file_location('route_state', ROOT / 'src/anytls-state.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def checked(arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, timeout=20, **kwargs)
    if result.returncode:
        # Even fixture stderr may contain a URL or credential-bearing file path.
        raise AssertionError('Fixture command failed: ' + Path(str(arguments[0])).name
                             + ' (exit ' + str(result.returncode) + ')')
    return result


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def generate_nginx(base, config, port):
    environment = os.environ | {'FIXTURE_BASE': str(base), 'FIXTURE_CONFIG': str(config),
                                'FIXTURE_PORT': str(port), 'FIXTURE_DOMAIN': DOMAIN,
                                'SOURCE': str(ROOT / 'src/anytls-subscription.sh')}
    checked(['bash', '-c', r'''
set -euo pipefail
BASE="$FIXTURE_BASE"
source "$SOURCE"
die() { printf '%s\n' "$*" >&2; exit 1; }
subscription_write_config "$FIXTURE_CONFIG" "$FIXTURE_DOMAIN" "$FIXTURE_PORT"
'''], env=environment)


def generate_certificate(work, generation):
    """Create an isolated CA and server leaf, leaving all system trust untouched."""
    authority = work / 'fixture-ca.crt'
    authority_key = work / 'fixture-ca.key'
    checked(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
             '-nodes', '-days', '2', '-subj', '/CN=AnyHarbor route-test CA',
             '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
             '-keyout', str(authority_key), '-out', str(authority)])
    request, extensions = work / 'fixture-leaf.csr', work / 'fixture-leaf.ext'
    checked(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
             '-nodes', '-subj', '/CN=' + DOMAIN, '-keyout', str(generation / 'server.key'),
             '-out', str(request)])
    extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                          'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + DOMAIN + '\n')
    checked(['openssl', 'x509', '-req', '-in', str(request), '-CA', str(authority),
             '-CAkey', str(authority_key), '-CAcreateserial', '-days', '2',
             '-extfile', str(extensions), '-out', str(generation / 'server.crt')])
    return authority


def fetch(curl, url, **kwargs):
    """Keep even synthetic subscription URLs out of the child process argv."""
    return checked(curl + ['--config', '-'], input=('url = "' + url + '"\n').encode('ascii'), **kwargs)


def inspect_response(response):
    """Classify body content, not filename or MIME type."""
    if response.startswith(b'mixed-port:') and b'\nproxies:\n' in response:
        return 'clash-yaml'
    try:
        lines = base64.b64decode(response.strip(), validate=True).decode('utf-8').splitlines()
    except (ValueError, UnicodeError):
        return 'unknown'
    if lines and all(line.startswith('v2rayn://anytls/') for line in lines):
        return 'v2rayn-subscription'
    if lines and all(line.startswith('anytls://') for line in lines):
        return 'shadowrocket-subscription'
    return 'unknown'


def diagnose(generation, authority, expected, negative):
    """Run the real diagnostic with fixture CA trust and assert redacted output."""
    state = helper.load(generation / 'state.json')
    group = state['groups'][0]
    before = {str(path.relative_to(generation)): path.read_bytes()
              for path in generation.rglob('*') if path.is_file()}
    output, errors = io.StringIO(), io.StringIO()
    failure = None
    previous_ca = os.environ.get('CURL_CA_BUNDLE')
    # Trust only the temporary fixture CA; normal TLS/SNI validation
    # stays enabled. This is process-local and allowed only by the Docker gate.
    os.environ['CURL_CA_BUNDLE'] = str(authority)
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            try:
                helper.check_subscriptions(generation, 'athena')
            except helper.SubscriptionCheckError as exc:
                failure = str(exc)
    finally:
        if previous_ca is None:
            os.environ.pop('CURL_CA_BUNDLE', None)
        else:
            os.environ['CURL_CA_BUNDLE'] = previous_ca
    report = output.getvalue() + errors.getvalue() + (failure or '')
    assert 'HTTPS /s：200' in report
    assert 'HTTPS /r：200' in report
    if negative:
        assert failure is not None
        assert 'HTTP 返回 /v 正文为 YAML' in report
    else:
        assert failure is None
        assert 'HTTPS /v：200' in report
    for secret in (group['token'], group['password'], 'mixed-port:', 'v2rayn://anytls/', 'anytls://',
                   expected['clash'].decode(), expected['v2rayn'].decode().strip(),
                   expected['shadowrocket'].decode().strip(),
                   (generation / 'server.key').read_text()):
        assert secret not in report, 'The diagnostic exposed fixture credentials or response data.'
    after = {str(path.relative_to(generation)): path.read_bytes()
             for path in generation.rglob('*') if path.is_file()}
    assert after == before, 'The read-only diagnostic modified the fixture generation.'
    return {'diagnostic': 'rejected-v-yaml' if negative else 'three-routes-200',
            'diagnostic_redacts_credentials_and_body': True, 'diagnostic_read_only': True}


def serve(config, prefix, authority, port, urls, expected, generation, negative=False):
    arguments = ['runuser', '-u', ACCOUNT, '--', '/usr/sbin/nginx', '-e', 'stderr',
                 '-p', str(prefix) + '/', '-c', str(config)]
    checked(arguments + ['-t', '-q'])
    log_path = config.with_suffix('.runtime.log')
    with log_path.open('w+') as log:
        process = subprocess.Popen(arguments, stdout=log, stderr=log, start_new_session=True)
        try:
            curl = ['curl', '-q', '--silent', '--show-error', '--noproxy', '*',
                    '--proto', '=https', '--connect-timeout', '1', '--max-time', '3',
                    '--cacert', str(authority),
                    '--resolve', f'{DOMAIN}:{port}:127.0.0.1']
            for _ in range(30):
                if process.poll() is not None:
                    raise AssertionError('Fixture Nginx stopped unexpectedly; runtime log was not exposed.')
                health = subprocess.run(curl + ['--output', '/dev/null', '--write-out', '%{http_code}',
                                               f'https://{DOMAIN}:{port}/'], capture_output=True, timeout=4)
                if health.returncode == 0:
                    break
                time.sleep(0.1)
            assert health.returncode == 0 and health.stdout == b'404'
            results = {format_name: fetch(curl + ['--fail'], url).stdout for format_name, url in urls.items()}
            assert results['clash'] == expected['clash']
            assert results['shadowrocket'] == expected['shadowrocket']
            assert inspect_response(results['shadowrocket']) == 'shadowrocket-subscription'
            diagnostic = diagnose(generation, authority, expected, negative)
            if negative:
                assert results['v2rayn'] == expected['clash']
                assert inspect_response(results['v2rayn']) == 'clash-yaml'
                return {'case': 'wrong-v-alias-control', 'root_http': 404,
                        'same_body': True, 'v_body_kind': 'clash-yaml',
                        'root_probe_detected_problem': False, **diagnostic}
            assert results['v2rayn'] == expected['v2rayn']
            assert len(set(results.values())) == 3
            assert inspect_response(results['clash']) == 'clash-yaml'
            assert inspect_response(results['v2rayn']) == 'v2rayn-subscription'
            for format_name, url in urls.items():
                response = fetch(curl + ['--fail', '-A', 'Shadowrocket'], url).stdout
                assert response == expected[format_name]
            pid = int((RUNTIME / 'nginx.pid').read_text().strip())
            fields = Path('/proc', str(pid), 'status').read_text().splitlines()
            uid = int(next(line.split()[1] for line in fields if line.startswith('Uid:')))
            assert uid == pwd.getpwnam(ACCOUNT).pw_uid != 0
            return {'case': 'generated-product-config', 'root_http': 404, 'nonroot': True,
                    'same_token': True, 'same_body': False,
                    's_body_kind': 'clash-yaml', 'v_body_kind': 'v2rayn-subscription',
                    'r_body_kind': 'shadowrocket-subscription', 'verified_fixture_ca': True,
                    'shadowrocket_device_import_tested': False,
                    'user_agent_changes_format': False, **diagnostic}
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


def main():
    if (os.name != 'posix' or os.geteuid() != 0 or not Path('/.dockerenv').exists()
            or os.environ.get('GZ_ANYTLS_DISPOSABLE_TEST') != '1'):
        raise SystemExit('Run only as root in a disposable Docker container with GZ_ANYTLS_DISPOSABLE_TEST=1.')
    for command in ('nginx', 'openssl', 'curl', 'runuser', 'useradd', 'userdel', 'groupdel'):
        if not shutil.which(command):
            raise SystemExit('Missing prerequisite: ' + command)
    if RUNTIME.exists() or RUNTIME.is_symlink():
        raise SystemExit('Refusing an existing subscription runtime directory.')
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup(ACCOUNT)
        except KeyError:
            pass
        else:
            raise SystemExit('Refusing an existing subscription account or group.')
    checked(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
             '--shell', '/usr/sbin/nologin', ACCOUNT])
    user = pwd.getpwnam(ACCOUNT)
    try:
        RUNTIME.mkdir(mode=0o700)
        os.chown(RUNTIME, user.pw_uid, user.pw_gid)
        with tempfile.TemporaryDirectory(prefix='anyharbor-routes-', dir='/opt') as temporary:
            work = Path(temporary)
            work.chmod(0o755)
            base = work / 'manager'
            generation = base / 'releases/generated'
            generation.mkdir(parents=True)
            helper.main(['init', str(generation / 'state.json'), '203.0.113.9', '8443'])
            state = helper.load(generation / 'state.json')
            state['groups'] = state['groups'][:1]
            # Exercise percent encoding, distinct connection address/SNI, and
            # a UTF-8 display name without printing any generated URI.
            state['groups'][0]['password'] = 'Fixture@:/?#%+&= ' + 'Q' * 32
            state['groups'][0]['label'] = 'Athena / 華南 #1'
            state['sni'] = DOMAIN
            state['tls_mode'], state['tls_verify'] = 'imported', 'pki'
            state['clash_rules'] = ['DOMAIN-SUFFIX,example.test,PROXY',
                                    'GEOIP,CN,DIRECT', 'MATCH,PROXY']
            port = free_port()
            state['subscription'] = {'domain': DOMAIN, 'port': port}
            helper.write_json(generation / 'state.json', state)
            authority = generate_certificate(work, generation)
            previous_ca = helper.CA_BUNDLE
            try:
                helper.CA_BUNDLE = str(authority)
                helper.main(['render', str(generation)])
            finally:
                helper.CA_BUNDLE = previous_ca
            state = helper.load(generation / 'state.json')
            token = state['groups'][0]['token']
            expected = {'clash': (generation / 'subscriptions' / (token + '.yaml')).read_bytes(),
                        'v2rayn': (generation / 'subscriptions_v2rayn' / (token + '.txt')).read_bytes(),
                        'shadowrocket': (generation / 'subscriptions_shadowrocket' / (token + '.txt')).read_bytes()}
            assert expected['clash'].endswith(('rules:\n' + ''.join(
                '  - ' + rule + '\n' for rule in state['clash_rules'])).encode('utf-8'))
            share = base64.b64decode(expected['v2rayn'].strip(), validate=True).decode().strip()
            assert share.startswith('v2rayn://anytls/')
            payload = share.removeprefix('v2rayn://anytls/')
            record = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
            assert record['Password'] == state['groups'][0]['password']
            assert record['ConfigType'] == 11 and record['Address'] == '203.0.113.9'
            assert 'Cert' not in record
            shadowrocket = base64.b64decode(expected['shadowrocket'].strip(), validate=True)
            assert base64.b64encode(shadowrocket) == expected['shadowrocket'].strip()
            assert shadowrocket == (generation / 'shadowrocket/athena.txt').read_bytes()
            assert len(shadowrocket.splitlines()) == 1
            uri_text = shadowrocket.decode('ascii').strip()
            assert all(33 <= ord(character) <= 126 for character in uri_text)
            uri = urlsplit(uri_text)
            assert uri.scheme == 'anytls' and uri.hostname == '203.0.113.9' and uri.port == 8443
            assert unquote(uri.username) == state['groups'][0]['password'] and uri.password is None
            assert parse_qs(uri.query) == {'sni': [DOMAIN], 'insecure': ['0']}
            assert unquote(uri.fragment) == 'GZ AnyTLS · Athena / 華南 #1'
            assert uri.path == '/'
            urls = {}
            for format_name in ('clash', 'v2rayn', 'shadowrocket'):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    helper.main(['links', str(generation / 'state.json'), format_name, 'athena'])
                rows = list(csv.DictReader(io.StringIO(output.getvalue())))
                urls[format_name] = rows[0]['url']
            assert urls['clash'].endswith('/s/' + token)
            assert urls['v2rayn'].endswith('/v/' + token)
            assert urls['shadowrocket'].endswith('/r/' + token)
            (base / 'current').symlink_to(generation)
            for directory in (base, base / 'releases', generation):
                directory.chmod(0o751)
            for name in ('subscriptions', 'subscriptions_v2rayn', 'subscriptions_shadowrocket'):
                directory = generation / name
                os.chown(directory, 0, user.pw_gid)
                directory.chmod(0o750)
                for file in directory.iterdir():
                    os.chown(file, 0, user.pw_gid)
                    file.chmod(0o640)
            prefix = base / 'subscription'
            config = prefix / 'generated'
            config.mkdir(parents=True)
            for name in ('server.crt', 'server.key'):
                shutil.copy2(generation / name, config / name)
            generate_nginx(base, config, port)
            configuration = config / 'nginx.conf'
            before = configuration.read_text()
            results = [serve(configuration, prefix, authority, port, urls, expected, generation)]
            # Negative control affects only this temporary fixture configuration.
            wrong_alias = before.replace(f'alias {base}/current/subscriptions_v2rayn/$v2rayn_token.txt;',
                                         f'alias {base}/current/subscriptions/$v2rayn_token.yaml;')
            assert wrong_alias != before
            configuration.write_text(wrong_alias)
            results.append(serve(configuration, prefix, authority, port, urls, expected, generation, True))
            print(json.dumps(results, indent=2))
    finally:
        shutil.rmtree(RUNTIME)
        checked(['userdel', ACCOUNT])
        try:
            grp.getgrnam(ACCOUNT)
        except KeyError:
            pass
        else:
            checked(['groupdel', ACCOUNT])


if __name__ == '__main__':
    main()
