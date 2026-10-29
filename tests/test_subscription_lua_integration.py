#!/usr/bin/env python3
"""Manual root-only integration test in a disposable Debian container.

Install nginx, libnginx-mod-http-lua, openssl, curl, and util-linux, then run:
    GZ_ANYTLS_DISPOSABLE_TEST=1 python3 tests/test_subscription_lua_integration.py

Uses the real product Bash probe/config writer and Python discovery command.
A wrapper injects real dynamic Lua modules to model a statically linked build;
it does not reproduce the user's exact BaoTa binary or systemd sandbox.
The missing-library control changes one generated directive to a deliberately
wrong search path; stock and autodiscovery checks use unmodified product output.
This file intentionally does not match the *_unit.py test selection.
"""
import grp
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = 'jackie-anytls-sub'
RUNTIME = Path('/run/jackie-anytls-sub')
DOMAIN = 'subscription.example.test'
TOKEN = 'A' * 43


def checked(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20, **kwargs)
    if result.returncode:
        raise AssertionError(f'{args!r} exited {result.returncode}:\n'
                             f'{result.stdout}\n{result.stderr}')
    return result


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def generate(source, base, directory, binary, port):
    env = os.environ | {'TEST_SOURCE': str(source), 'TEST_BASE': str(base),
                        'TEST_DIRECTORY': str(directory), 'TEST_BINARY': str(binary),
                        'TEST_PORT': str(port), 'TEST_DOMAIN': DOMAIN}
    result = checked(['bash', '-c', '''set -euo pipefail
BASE="$TEST_BASE"
source "$TEST_SOURCE/anytls-subscription.sh"
die() { printf '%s\\n' "$*" >&2; exit 1; }
py() { python3 "$TEST_SOURCE/anytls-state.py" "$@"; }
path=$(subscription_nginx_lua_path "$TEST_DIRECTORY" "$TEST_BINARY" -e stderr)
subscription_write_config "$TEST_DIRECTORY" "$TEST_DOMAIN" "$TEST_PORT" "$path"
printf '%s' "$path"
'''], env=env)
    return result.stdout


def serve(binary, config, prefix, cert, port, expected_failure=False):
    args = ['runuser', '-u', ACCOUNT, '--', str(binary), '-e', 'stderr',
            '-p', str(prefix) + '/', '-c', str(config)]
    checked(args + ['-t', '-q'])
    log_path = config.with_suffix('.runtime.log')
    with log_path.open('w+') as log:
        process = subprocess.Popen(args, stdout=log, stderr=log, start_new_session=True)
        try:
            if expected_failure:
                result = process.wait(timeout=5)
                log.flush()
                log.seek(0)
                output = log.read()
                assert result != 0 and 'resty.core' in output, output
                return {'config_test': 0, 'runtime_exit': result,
                        'error': 'resty.core unavailable'}
            curl = ['curl', '-q', '--silent', '--show-error', '--noproxy', '*',
                    '--connect-timeout', '1', '--max-time', '2', '--cacert', str(cert),
                    '--resolve', f'{DOMAIN}:{port}:127.0.0.1']
            for attempt in range(30):
                if process.poll() is not None:
                    raise AssertionError(log_path.read_text())
                check = subprocess.run(curl + ['--output', '/dev/null', '--write-out',
                                               '%{http_code}', f'https://{DOMAIN}:{port}/'],
                                       capture_output=True, text=True, timeout=3)
                if check.returncode == 0:
                    break
                time.sleep(0.1)
            assert check.returncode == 0 and check.stdout == '404', check.stderr
            pid = (RUNTIME / 'nginx.pid').read_text().strip()
            status = Path('/proc', pid, 'status').read_text().splitlines()
            uid = next(line.split()[1] for line in status if line.startswith('Uid:'))
            assert int(uid) == pwd.getpwnam(ACCOUNT).pw_uid != 0
            for endpoint, expected in ((f'/s/{TOKEN}', 'proxies: []\n'),
                                       (f'/v/{TOKEN}', 'YW55dGxzOi8vdGVzdA==\n')):
                response = checked(curl + ['--fail', f'https://{DOMAIN}:{port}{endpoint}'])
                assert response.stdout == expected, response.stdout
            return {'config_test': 0, 'nonroot_uid': int(uid), 'root_https': 404,
                    'clash_subscription': 'passed', 'v2rayn_subscription': 'passed'}
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
        raise SystemExit('Run as root only in a disposable Docker container with '
                         'GZ_ANYTLS_DISPOSABLE_TEST=1.')
    nginx = Path('/usr/sbin/nginx')
    modules = [Path('/usr/lib/nginx/modules/ndk_http_module.so'),
               Path('/usr/lib/nginx/modules/ngx_http_lua_module.so')]
    for path in [nginx, *modules, Path('/usr/share/lua/5.1/resty/core.lua')]:
        if not path.is_file():
            raise SystemExit('Missing prerequisite: ' + str(path))
    for command in ['bash', 'runuser', 'useradd', 'userdel', 'openssl', 'curl']:
        if not shutil.which(command):
            raise SystemExit('Missing prerequisite: ' + command)
    if RUNTIME.exists() or RUNTIME.is_symlink():
        raise SystemExit('Refusing to reuse existing service runtime directory.')
    try:
        pwd.getpwnam(ACCOUNT)
    except KeyError:
        pass
    else:
        raise SystemExit('Refusing to reuse an existing service account.')
    try:
        grp.getgrnam(ACCOUNT)
    except KeyError:
        pass
    else:
        raise SystemExit('Refusing to reuse an existing service group.')
    checked(['useradd', '--system', '--user-group', '--no-create-home',
             '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', ACCOUNT])
    user = pwd.getpwnam(ACCOUNT)
    try:
        RUNTIME.mkdir(mode=0o700)
        os.chown(RUNTIME, user.pw_uid, user.pw_gid)
        with tempfile.TemporaryDirectory(prefix='gz-sub-lua-', dir='/opt') as temporary:
            work = Path(temporary)
            work.chmod(0o755)
            source = work / 'src'
            source.mkdir()
            for name in ['anytls-subscription.sh', 'anytls-state.py']:
                (source / name).write_text((ROOT / 'src' / name).read_text(), encoding='utf-8')
            base = work / 'manager'
            prefix = base / 'subscription'
            prefix.mkdir(parents=True)
            for directory in ['subscriptions', 'subscriptions_v2rayn']:
                (base / 'current' / directory).mkdir(parents=True)
            (base / 'current/subscriptions' / (TOKEN + '.yaml')).write_text('proxies: []\n')
            (base / 'current/subscriptions_v2rayn' / (TOKEN + '.txt')).write_text('YW55dGxzOi8vdGVzdA==\n')
            install = work / 'nginx'
            binary = install / 'sbin/nginx'
            binary.parent.mkdir(parents=True)
            library = install / 'lib/lua'
            library.parent.mkdir(parents=True)
            shutil.copytree('/usr/share/lua/5.1', library)
            loads = ' '.join('load_module ' + str(module) + ';' for module in modules)
            binary.write_text('#!/bin/sh\n'
                              'if [ "${1:-}" = -V ]; then\n'
                              '  printf "%s\\n" "nginx version: integration-wrapper" '
                              f'"configure arguments: --prefix={install}" >&2\n'
                              '  exit 0\nfi\n'
                              f'exec /usr/sbin/nginx -g {shlex.quote(loads)} "$@"\n')
            binary.chmod(0o755)
            results = []
            for label, selected, expected in [('stock', nginx, ''),
                                               ('lua_autodiscovery', binary, str(library))]:
                directory = prefix / label
                directory.mkdir(mode=0o750)
                os.chown(directory, 0, user.pw_gid)
                checked(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                         'ec_paramgen_curve:prime256v1', '-nodes', '-keyout',
                         str(directory / 'server.key'), '-out', str(directory / 'server.crt'),
                         '-days', '1', '-subj', '/CN=' + DOMAIN,
                         '-addext', 'subjectAltName=DNS:' + DOMAIN])
                port = free_port()
                discovered = generate(source, base, directory, selected, port)
                assert discovered == expected, (label, discovered, expected)
                config = directory / 'nginx.conf'
                content = config.read_text()
                if expected:
                    directive = f'lua_package_path "{library}/?.lua;{library}/?/init.lua";'
                    assert directive in content and ';;' not in content
                    before = directory / 'before-fix.conf'
                    # Explicitly wrong path is a negative control. Debian's compiled
                    # defaults can still find core even when LUA_PATH is overridden.
                    before.write_text(content.replace(directive,
                                      'lua_package_path "/nonexistent-gz-lua/?.lua";'))
                    before.chmod(0o644)
                    results.append({'case': 'lua_missing_library_control', **serve(
                        selected, before, prefix, directory / 'server.crt', port, True)})
                else:
                    assert 'lua_package_path' not in content
                assert not (directory / 'lua-probe.conf').exists()
                result = serve(selected, config, prefix, directory / 'server.crt', port)
                results.append({'case': label, 'discovered_library': discovered, **result})
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
