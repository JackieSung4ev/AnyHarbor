#!/usr/bin/env python3
"""Real AnyTLS/auth-user routing in an offline, disposable Linux container.

Run with GZ_ANYTLS_DISPOSABLE_TEST=1 and ANYHARBOR_TEST_SING_BOX pointing to a
verified official sing-box binary. This test never downloads or registers WARP.
The SOCKS fixture stands in for the official client's loopback proxy; Cloudflare
connectivity, client setup, public egress and Grok access are NOT tested here.
All credentials and certificates are generated under a temporary directory.
"""
import contextlib
import http.server
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('warp_route_state', ROOT / 'src/anytls-state.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
LOOPBACK = '127.0.0.1'
DOMAIN = 'anytls.example.test'
REMOTE_DOMAIN = 'unresolvable.example.test'
DIRECT_BODY, WARP_BODY = b'DIRECT_FIXTURE\n', b'WARP_FIXTURE\n'


def exact(connection, length):
    result = b''
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise ConnectionError('Fixture connection ended early.')
        result += chunk
    return result


def destination(connection, kind):
    if kind == 1:
        address = socket.inet_ntoa(exact(connection, 4))
    elif kind == 3:
        address = exact(connection, exact(connection, 1)[0]).decode('ascii')
    elif kind == 4:
        address = socket.inet_ntop(socket.AF_INET6, exact(connection, 16))
    else:
        raise AssertionError('Unexpected SOCKS address type.')
    return address, struct.unpack('!H', exact(connection, 2))[0]


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as listener:
        listener.bind((LOOPBACK, 0))
        return listener.getsockname()[1]


class HTTPFixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.received.append(self.path)
        self.send_response(200)
        self.send_header('Content-Length', str(len(DIRECT_BODY)))
        self.end_headers()
        self.wfile.write(DIRECT_BODY)

    def log_message(self, *_):
        pass


class SocksFixture(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            version, count = exact(self.request, 2)
            assert version == 5 and 0 in exact(self.request, count)
            self.request.sendall(b'\x05\x00')
            version, command, reserved, kind = exact(self.request, 4)
            assert (version, command, reserved) == (5, 1, 0)
            address, port = destination(self.request, kind)
            self.server.received.append((kind, address, port))
            self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
            request = b''
            while b'\r\n\r\n' not in request:
                request += exact(self.request, 1)
                assert len(request) <= 8192
            self.request.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '
                                 + str(len(WARP_BODY)).encode() + b'\r\n\r\n' + WARP_BODY)
        except (OSError, AssertionError) as exc:
            self.server.errors.append(type(exc).__name__)


class UDPFixture(socketserver.BaseRequestHandler):
    def handle(self):
        packet, connection = self.request
        self.server.received.append(packet)
        connection.sendto(packet, self.client_address)


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextlib.contextmanager
def serve(server):
    server.received, server.errors = [], []
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def checked(arguments):
    result = subprocess.run(arguments, capture_output=True, timeout=10)
    if result.returncode:
        raise AssertionError('Fixture command failed: ' + Path(arguments[0]).name
                             + ' (exit ' + str(result.returncode) + ').')
    return result


@contextlib.contextmanager
def core(binary, configuration, tcp_port):
    checked([binary, 'check', '-c', str(configuration)])
    with configuration.with_suffix('.log').open('wb') as log:
        process = subprocess.Popen([binary, 'run', '-c', str(configuration)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, 'The real core stopped unexpectedly.'
                try:
                    with socket.create_connection((LOOPBACK, tcp_port), timeout=0.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, 'The real core did not start its listener.'
                    time.sleep(0.05)
            yield process
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def client(directory, state, group, echo_port):
    tcp_port, udp_port = free_port(), free_port(socket.SOCK_DGRAM)
    configuration = directory / ('client-' + group['id'] + '.json')
    helper.write_json(configuration, {
        'log': {'level': 'warn'},
        'inbounds': [
            {'type': 'socks', 'tag': 'tcp', 'listen': LOOPBACK, 'listen_port': tcp_port},
            {'type': 'direct', 'tag': 'udp', 'listen': LOOPBACK, 'listen_port': udp_port,
             'network': 'udp', 'override_address': LOOPBACK, 'override_port': echo_port}],
        'outbounds': [{'type': 'anytls', 'tag': 'proxy', 'server': LOOPBACK,
                       'server_port': state['port'], 'password': group['password'],
                       'tls': {'enabled': True, 'server_name': DOMAIN, 'alpn': ['h2'],
                               'certificate_path': str(directory / 'server.crt')}}],
        'route': {'final': 'proxy'}})
    return configuration, tcp_port, udp_port


def http_via_socks(port, address, destination_port):
    with socket.create_connection((LOOPBACK, port), timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(b'\x05\x01\x00')
        assert exact(connection, 2) == b'\x05\x00'
        try:
            encoded = b'\x01' + ipaddress.IPv4Address(address).packed
        except ipaddress.AddressValueError:
            encoded = b'\x03' + bytes([len(address)]) + address.encode('ascii')
        connection.sendall(b'\x05\x01\x00' + encoded + struct.pack('!H', destination_port))
        version, status, reserved, kind = exact(connection, 4)
        assert (version, status, reserved) == (5, 0, 0), 'The test SOCKS request was rejected.'
        destination(connection, kind)
        connection.sendall(b'GET /probe HTTP/1.1\r\nHost: fixture.example.test\r\nConnection: close\r\n\r\n')
        response = b''
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
            assert len(response) <= 8192
        return response.partition(b'\r\n\r\n')[2]


def udp(port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(1)
        connection.sendto(message, (LOOPBACK, port))
        return connection.recv(4096)


def main():
    if os.environ.get('GZ_ANYTLS_DISPOSABLE_TEST') != '1' or not Path('/.dockerenv').exists():
        raise SystemExit('Run only in an explicitly opted-in disposable Docker container.')
    binary = os.environ.get('ANYHARBOR_TEST_SING_BOX') or shutil.which('sing-box')
    if not binary:
        raise SystemExit('Set ANYHARBOR_TEST_SING_BOX to a verified official sing-box binary.')
    version = checked([binary, 'version']).stdout.decode().splitlines()[0]
    results = []
    with tempfile.TemporaryDirectory(prefix='anyharbor-warp-route-') as temporary, contextlib.ExitStack() as stack:
        directory = Path(temporary)
        helper.main(['init', str(directory / 'state.json'), DOMAIN, str(free_port())])
        state = helper.load(directory / 'state.json')
        state['groups'] = state['groups'][:2]
        state['groups'][0]['egress'] = 'direct'
        state['groups'][1]['egress'] = 'warp'
        state['schema'] = 3
        helper.write_json(directory / 'state.json', state)
        helper.main(['certificate', str(directory)])
        helper.render(directory)
        state = helper.load(directory / 'state.json')
        direct_server = stack.enter_context(serve(http.server.ThreadingHTTPServer((LOOPBACK, 0), HTTPFixture)))
        echo = stack.enter_context(serve(socketserver.ThreadingUDPServer((LOOPBACK, 0), UDPFixture)))
        stack.enter_context(core(binary, directory / 'config.json', state['port']))
        clients = [client(directory, state, group, echo.server_address[1]) for group in state['groups']]
        for configuration, tcp_port, _ in clients:
            stack.enter_context(core(binary, configuration, tcp_port))
        direct, warp = clients
        target_port = direct_server.server_address[1]
        with serve(TCPServer((LOOPBACK, 40000), SocksFixture)) as socks:
            assert http_via_socks(direct[1], LOOPBACK, target_port) == DIRECT_BODY
            assert socks.received == []
            assert http_via_socks(warp[1], LOOPBACK, target_port) == WARP_BODY
            assert socks.received == [(1, LOOPBACK, target_port)]
            assert len(direct_server.received) == 1
            results.append('authenticated_groups_choose_different_egress_for_same_target')

            assert http_via_socks(warp[1], REMOTE_DOMAIN, 443) == WARP_BODY
            assert socks.received[-1] == (3, REMOTE_DOMAIN, 443)
            results.append('destination_domain_reaches_socks_without_local_dns_resolution')

            assert udp(direct[2], b'direct-udp-control') == b'direct-udp-control'
            assert echo.received == [b'direct-udp-control']
            try:
                udp(warp[2], b'warp-udp-must-not-leak')
            except (TimeoutError, ConnectionError, OSError):
                pass
            else:
                raise AssertionError('WARP UDP unexpectedly received a direct reply.')
            assert echo.received == [b'direct-udp-control']
            assert len(socks.received) == 2 and socks.errors == []
            results.append('warp_udp_rejected_while_direct_udp_remains_functional')

        # The destination is still reachable directly. A successful retry would
        # therefore expose a real fallback leak rather than an unavailable target.
        before = len(direct_server.received)
        try:
            response = http_via_socks(warp[1], LOOPBACK, target_port)
        except (TimeoutError, ConnectionError, OSError):
            response = b''
        assert response == b'' and len(direct_server.received) == before
        assert http_via_socks(direct[1], LOOPBACK, target_port) == DIRECT_BODY
        results.append('socks_outage_blocks_warp_without_direct_fallback_or_direct_group_outage')

        # Recovery must not need re-rendering or a service restart.
        with serve(TCPServer((LOOPBACK, 40000), SocksFixture)) as socks:
            assert http_via_socks(warp[1], LOOPBACK, target_port) == WARP_BODY
            assert len(socks.received) == 1 and socks.errors == []
        results.append('warp_proxy_recovery_resumes_new_connections')
    print(json.dumps({'core': version, 'passed': len(results), 'tests': results,
                      'limitations': 'Loopback SOCKS fixture; no official WARP daemon, registration, '
                                     'public connectivity, system routing or Grok test.'}, indent=2))


if __name__ == '__main__':
    main()
