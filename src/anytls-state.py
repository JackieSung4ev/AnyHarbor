#!/usr/bin/env python3
"""Validated state, client exports and loopback diagnostics for AnyHarbor.

No network listener or downloads run here; subscription diagnostics make only
read-only HTTPS requests to loopback. The Bash manager owns locking, permissions,
service activation and transactional generation changes.
"""
import base64
import copy
import csv
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
from urllib.parse import quote


DEFAULT_GROUPS = [('athena', 'Athena'), ('apollo', 'Apollo'),
                  ('hermes', 'Hermes'), ('artemis', 'Artemis'),
                  ('hestia', 'Hestia'), ('zeus', 'Zeus'),
                  ('hera', 'Hera'), ('poseidon', 'Poseidon'),
                  ('demeter', 'Demeter'), ('hephaestus', 'Hephaestus')]
AUTO_GROUP_NAMES = tuple(title for _, title in DEFAULT_GROUPS) + (
    'Aphrodite', 'Ares', 'Hades', 'Persephone', 'Dionysus', 'Hecate',
    'Nike', 'Iris', 'Selene', 'Helios', 'Eos', 'Gaia', 'Uranus', 'Cronus',
    'Rhea', 'Atlas', 'Prometheus', 'Epimetheus', 'Oceanus', 'Tethys',
    'Themis', 'Mnemosyne', 'Hyperion', 'Iapetus', 'Phoebe', 'Coeus',
    'Crius', 'Leto', 'Metis', 'Tyche')
OLD_GROUP_LABELS = dict(zip((identifier for identifier, _ in DEFAULT_GROUPS),
                           ['雅典娜', '阿波罗', '赫尔墨斯', '阿尔忒弥斯', '赫斯提亚',
                            '宙斯', '赫拉', '波塞冬', '德墨忒尔', '赫淮斯托斯']))
ID_RE = re.compile(r'[a-z][a-z0-9_-]{0,31}')
TOKEN_RE = re.compile(r'[A-Za-z0-9_-]{43}')
CA_BUNDLE = '/etc/ssl/certs/ca-certificates.crt'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def nginx_lua_path(binary):
    """Find only this Nginx installation's complete, root-controlled Lua tree."""
    def absolute(value):
        require(isinstance(value, str) and re.fullmatch(r'/[A-Za-z0-9/._-]+', value)
                and '..' not in value.split('/'), 'Unsafe Nginx installation path.')
        return Path(value)

    def trusted(path):
        info = path.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022
                and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                'Nginx Lua path must contain only root-owned, non-writable files/directories: ' + str(path))

    executable = absolute(binary)
    for path in (executable, *executable.parents):
        trusted(path)
    require(executable.is_file(), 'Nginx executable is not a regular file.')
    try:
        result = subprocess.run([str(executable), '-V'], check=True, capture_output=True,
                                text=True, timeout=10)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ValueError('Failed to inspect the selected Nginx build with -V.') from exc
    lines = (result.stdout + '\n' + result.stderr).splitlines()
    arguments = [line.partition(':')[2].strip() for line in lines
                 if line.startswith('configure arguments:')]
    require(len(arguments) <= 1, 'Ambiguous Nginx configure arguments.')
    prefixes = [word.partition('=')[2] for word in shlex.split(arguments[0] if arguments else '')
                if word.startswith('--prefix=')]
    require(len(prefixes) <= 1, 'Ambiguous Nginx installation prefix.')
    roots = [absolute(prefixes[0])] if prefixes else []
    roots.append(executable.parent.parent)
    candidates = []
    for root in roots:
        candidates.extend((root / 'lib/lua', root / 'lualib'))
        if root.name == 'nginx' and root.parent.name == 'openresty':
            candidates.append(root.parent / 'lualib')
    for candidate in dict.fromkeys(candidates):
        core = candidate / 'resty/core.lua'
        cache = candidate / 'resty/lrucache.lua'
        if not (core.exists() or core.is_symlink() or cache.exists() or cache.is_symlink()):
            continue
        require(core.is_file() and cache.is_file(),
                'Incomplete Nginx Lua library (resty.core and resty.lrucache must share one tree): ' + str(candidate))
        for path in (candidate, *candidate.parents):
            trusted(path)
        # Do not follow symlinks or accept writable modules, including unused ones:
        # Lua dependencies can import siblings beyond the two entry-point files.
        pending = [candidate]
        while pending:
            directory = pending.pop()
            for path in directory.iterdir():
                trusted(path)
                if path.is_dir():
                    pending.append(path)
        return str(candidate)
    return ''


def read_json(path):
    p = Path(path)
    require(not p.is_symlink(), 'Refusing a symbolic-link state file.')
    return json.loads(p.read_text(encoding='utf-8'))


def private_write(path, text):
    """Atomically replace one owned output; never follow a file symlink."""
    p = Path(path)
    require(not p.is_symlink(), 'Refusing a symbolic-link output file.')
    fd, temp = tempfile.mkstemp(prefix='.' + p.name + '-', dir=str(p.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as out:
            out.write(text)
        os.chmod(temp, 0o600)
        os.replace(temp, p)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def write_json(path, value):
    private_write(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def host(value):
    require(isinstance(value, str), 'Address must be a string.')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        require(1 <= len(value) <= 253 and '.' in value and
                all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part)
                    for part in value.split('.')) and
                not re.fullmatch(r'[0-9.]+', value),
                'Enter a public IPv4 address or DNS name, not a URL or IPv6 address.')
        return value.lower()
    require(address.version == 4, 'This release supports an IPv4 endpoint or DNS name.')
    return str(address)


def domain(value):
    value = host(value)
    require(not re.fullmatch(r'[0-9.]+', value), 'A DNS name is required here, not an IP address.')
    return value


def port(value):
    value = str(value)
    require(re.fullmatch(r'[0-9]{1,5}', value) is not None and
            1024 <= int(value) <= 65535, 'Port must be 1024..65535.')
    return int(value)


def group_id(value):
    require(isinstance(value, str) and ID_RE.fullmatch(value) is not None,
            'Group ID must start with a lowercase letter and contain 1..32 lowercase letters, digits, _ or -.')
    return value


def label(value):
    require(isinstance(value, str) and 1 <= len(value) <= 80 and
            value == value.strip() and
            all(not unicodedata.category(c).startswith('C') for c in value) and
            value[0] not in '=+-@', 'Group label must be 1..80 printable characters without surrounding spaces.')
    return value


def new_group(identifier, title):
    return {'id': group_id(identifier), 'label': label(title),
            'password': secrets.token_urlsafe(32), 'token': secrets.token_urlsafe(32),
            'enabled': True}


def node_prefix(value):
    require(isinstance(value, str) and 1 <= len(value) <= 32 and
            value == value.strip() and
            all(not unicodedata.category(c).startswith('C') for c in value) and
            value[0] not in '=+-@',
            'Node prefix must be 1..32 printable characters without surrounding spaces.')
    return value


def rotate(group):
    group['password'] = secrets.token_urlsafe(32)
    group['token'] = secrets.token_urlsafe(32)


def normalized(raw):
    require(isinstance(raw, dict), 'State must be an object.')
    state = copy.deepcopy(raw)
    if state.get('schema') == 1:
        password = state.pop('password', None)
        old_name = state.get('name', 'Jackie AnyTLS')
        state['groups'] = [{'id': 'legacy', 'label': '原有账号', 'password': password,
                            'token': secrets.token_urlsafe(32), 'enabled': True,
                            'node_name': old_name}]
        state['schema'] = 2
        state['tls_verify'] = 'pin'
        state['subscription'] = None
    require(state.get('schema') in (2, 3), 'Unsupported managed state schema.')
    state['node_prefix'] = node_prefix(state.get('node_prefix', 'GZ'))
    state['server'] = host(state['server'])
    state['sni'] = host(state['sni'])
    state['port'] = port(state['port'])
    require(state.get('tls_mode') in ('self-signed', 'imported'), 'Invalid certificate mode.')
    require(state.get('tls_verify') in ('pin', 'pki'), 'Invalid TLS verification mode.')
    require(state['tls_mode'] != 'self-signed' or state['tls_verify'] == 'pin',
            'Self-signed certificates require certificate pinning.')
    groups = state.get('groups')
    require(isinstance(groups, list) and 1 <= len(groups) <= 100, 'State must contain 1..100 groups.')
    identifiers, passwords, tokens = set(), set(), set()
    for group in groups:
        require(isinstance(group, dict), 'Invalid group record.')
        identifier = group_id(group.get('id'))
        label(group.get('label'))
        if 'node_name' in group:
            label(group['node_name'])
        password, token = group.get('password'), group.get('token')
        require(isinstance(password, str) and 32 <= len(password) <= 256 and
                all(not unicodedata.category(c).startswith('C') for c in password),
                'Invalid managed group password.')
        require(isinstance(token, str) and TOKEN_RE.fullmatch(token) is not None,
                'Invalid subscription token.')
        require(type(group.get('enabled')) is bool, 'Group enabled must be boolean.')
        require(group.get('egress', 'direct') in ('direct', 'warp'),
                'Group egress must be direct or warp.')
        require(identifier not in identifiers and password not in passwords and token not in tokens,
                'Duplicate group ID or credential.')
        identifiers.add(identifier)
        passwords.add(password)
        tokens.add(token)
    # Older managers ignore unknown group fields. Schema 3 makes them refuse
    # to render WARP identities instead of silently converting them to direct.
    # Keep this barrier even after the last WARP group is disabled or removed.
    if any(g.get('egress') == 'warp' for g in groups):
        state['schema'] = 3
    require(any(g['enabled'] for g in groups), 'At least one group must remain enabled.')
    subscription = state.get('subscription')
    if subscription is not None:
        require(isinstance(subscription, dict), 'Invalid subscription settings.')
        subscription['domain'] = domain(subscription['domain'])
        subscription['port'] = port(subscription['port'])
        require(subscription['port'] != state['port'], 'Subscription port conflicts with AnyTLS port.')
    else:
        state['subscription'] = None
    return state


def load(path):
    return normalized(read_json(path))


def active(state):
    return [group for group in state['groups'] if group['enabled']]


def selected_group(state, identifier=None, must_enable=True):
    if not identifier:
        choices = active(state)
        require(len(choices) == 1, 'More than one active group: specify a group ID.')
        return choices[0]
    group_id(identifier)
    found = next((g for g in state['groups'] if g['id'] == identifier), None)
    require(found is not None, 'Unknown group ID.')
    require(not must_enable or found['enabled'], 'This group is disabled.')
    return found


def group_export(raw, directory, group, format_name):
    """Read an already generated format without rendering or changing credentials."""
    base = Path(directory)
    if format_name == 'clash':
        path = base / 'profiles' / (group['id'] + '.yaml')
        if raw.get('schema') == 1 and group['id'] == 'legacy' and not path.exists():
            path = base / 'mihomo-profile.yaml'
    else:
        require(format_name in ('v2rayn', 'shadowrocket'),
                'Export format must be clash, v2rayn or shadowrocket.')
        if format_name == 'shadowrocket':
            require(normalized(raw)['tls_verify'] == 'pki', SHADOWROCKET_PIN_NOTICE)
        path = base / format_name / (group['id'] + '.txt')
    require(path.is_file() and not path.is_symlink(),
            format_name + ' export is missing or unsafe; update the manager before exporting this format.')
    return path.read_text(encoding='utf-8')


def call(arguments, data=None):
    return subprocess.check_output(arguments, input=data, stderr=subprocess.PIPE)


def certificate_info(cert, key, identity, mode):
    cert, key, identity = str(cert), str(key), host(identity)
    require(mode in ('pin', 'pki'), 'TLS verification mode must be pin or pki.')
    public = call(['openssl', 'x509', '-in', cert, '-pubkey', '-noout'])
    cert_public = call(['openssl', 'pkey', '-pubin', '-outform', 'DER'], public)
    key_public = call(['openssl', 'pkey', '-in', key, '-passin', 'pass:', '-pubout', '-outform', 'DER'])
    require(cert_public == key_public, 'Certificate/private key mismatch.')
    call(['openssl', 'x509', '-in', cert, '-checkend', '0', '-noout'])
    try:
        ipaddress.IPv4Address(identity)
        verify = '-verify_ip'
    except ValueError:
        verify = '-verify_hostname'
    command = ['openssl', 'verify', '-purpose', 'sslserver', verify, identity]
    if mode == 'pki':
        require(Path(CA_BUNDLE).is_file(), 'System CA bundle is missing; install ca-certificates.')
        command += ['-CAfile', CA_BUNDLE, '-untrusted', cert, cert]
    else:
        command += ['-partial_chain', '-CAfile', cert, cert]
    call(command)
    fingerprint = call(['openssl', 'x509', '-in', cert, '-noout', '-fingerprint', '-sha256'])
    fingerprint = fingerprint.decode().strip().split('=', 1)[1].replace(':', '').lower()
    require(re.fullmatch(r'[0-9a-f]{64}', fingerprint) is not None, 'Invalid certificate fingerprint.')
    return fingerprint


def output_directory(parent, name, suffix='.yaml'):
    directory = parent / name
    require(not directory.is_symlink(), 'Refusing a symbolic-link output directory.')
    directory.mkdir(mode=0o700, exist_ok=True)
    require(directory.is_dir(), 'Output path is not a directory.')
    # A rerender must remove stale tokens and disabled groups. Only owned outputs
    # in these dedicated directories may be deleted; no recursive deletion.
    for child in directory.iterdir():
        require(child.is_file() and not child.is_symlink() and child.suffix == suffix,
                'Unexpected file in a managed output directory.')
        child.unlink()
    os.chmod(directory, 0o700)
    return directory


def yaml_text(value):
    """Prefer plain strings; preserve exact text and type with single quotes."""
    plain = (re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_ ./·-]*', value) is not None
             and value == value.strip()
             and value.lower() not in {'y', 'yes', 'n', 'no', 'true', 'false',
                                       'on', 'off', 'null'}
             and re.match(r'^\d{4}-\d{1,2}-\d{1,2}', value) is None)
    if plain:
        # YAML implementations differ on implicit numeric types (notably
        # scientific notation). Quote conservatively; passwords are strings.
        numeric = value.replace('_', '')
        try:
            float(numeric)
        except ValueError:
            try:
                int(numeric, 0)
            except ValueError:
                return value
    return "'" + value.replace("'", "''") + "'"


def update_display_names(state):
    """Idempotent display-only migration; never rotate credentials."""
    if isinstance(state.get('name'), str):
        state['name'] = state['name'].replace('Jackie', 'GZ')
    for group in state['groups']:
        identifier = group['id']
        if group['label'] == OLD_GROUP_LABELS.get(identifier):
            group['label'] = dict(DEFAULT_GROUPS)[identifier]
        if identifier == 'legacy' and group['label'] == '原有账号':
            group['label'] = 'Legacy'
        if 'node_name' in group:
            group['node_name'] = group['node_name'].replace('Jackie', 'GZ')
            for old, new in zip(OLD_GROUP_LABELS.values(), dict(DEFAULT_GROUPS).values()):
                group['node_name'] = group['node_name'].replace(old, new)


def v2rayn_share(state, group, name, certificate):
    """Official v2rayN 7.22.6/7.25.6 inner format; no private key or skipped TLS."""
    payload = {'ConfigVersion': 4, 'ConfigType': 11, 'CoreType': 24,
               'Remarks': name, 'Address': state['server'], 'Port': state['port'],
               'Password': group['password'], 'StreamSecurity': 'tls',
               'Sni': state['sni'], 'Alpn': 'h2', 'Fingerprint': 'chrome',
               'AllowInsecure': 'false'}
    if state['tls_verify'] == 'pin':
        # A pcs parameter is parsed but not applied to AnyTLS by these versions.
        # Their supported Cert field becomes sing-box tls.certificate, with
        # certificate/hostname checks enabled. Export only the public leaf PEM.
        payload['Cert'] = certificate
    encoded = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return 'v2rayn://anytls/' + base64.urlsafe_b64encode(encoded).decode('ascii').rstrip('=')


SHADOWROCKET_PIN_NOTICE = ('Shadowrocket / AnyTLS：当前为证书固定模式；标准 AnyTLS URI '
                          '无法保留证书固定验证，因此不生成此格式。请使用可信域名证书（pki）。')


def shadowrocket_share(state, group, name):
    """Official AnyTLS URI fields only; never weaken certificate verification."""
    require(state['tls_verify'] == 'pki', SHADOWROCKET_PIN_NOTICE)
    address = state['server']
    try:
        if ipaddress.ip_address(address).version == 6:
            address = '[' + address + ']'
    except ValueError:
        pass  # The normalized state already validates domain names.
    return 'anytls://{}@{}:{}/?sni={}&insecure=0#{}'.format(
        quote(group['password'], safe=''), address, state['port'],
        quote(state['sni'], safe=''), quote(name, safe=''))


def group_documents(state, group, fingerprint, certificate):
    """Build the two formats without writing files or rotating credentials."""
    q = yaml_text
    name = group.get('node_name', state['node_prefix'] + ' AnyTLS · ' + group['label'])
    lines = ['proxies:', '  - name: ' + q(name), '    type: anytls',
             '    server: ' + q(state['server']), '    port: ' + str(state['port']),
             '    password: ' + q(group['password']), '    client-fingerprint: chrome',
             '    sni: ' + q(state['sni']), '    alpn:', '      - h2',
             '    udp: ' + ('false' if group.get('egress') == 'warp' else 'true'),
             '    skip-cert-verify: false']
    if state['tls_verify'] == 'pin':
        lines.append('    fingerprint: ' + q(fingerprint))
    node = '\n'.join(lines) + '\n'
    profile = 'mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: warning\n' + node
    profile += ('proxy-groups:\n  - name: PROXY\n    type: select\n'
                '    proxies:\n      - ' + q(name) + '\n      - DIRECT\n'
                'rules:\n  - MATCH,PROXY\n')
    share = v2rayn_share(state, group, name, certificate) + '\n'
    return node, profile, share


def render(directory):
    directory = Path(directory)
    state = load(directory / 'state.json')
    fingerprint = certificate_info(directory / 'server.crt', directory / 'server.key',
                                   state['sni'], state['tls_verify'])
    certificate = (call(['openssl', 'x509', '-in', str(directory / 'server.crt'),
                         '-outform', 'PEM']).decode('ascii')
                   if state['tls_verify'] == 'pin' else None)
    groups = active(state)
    config = {'log': {'level': 'warn', 'timestamp': True}, 'inbounds': [{
        'type': 'anytls', 'tag': 'anytls-in', 'listen': '0.0.0.0', 'listen_port': state['port'],
        'users': [{'name': g['id'], 'password': g['password']} for g in groups],
        'tls': {'enabled': True, 'alpn': ['h2'], 'min_version': '1.2',
                'certificate_path': str(directory / 'server.crt'),
                'key_path': str(directory / 'server.key')}
    }], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}
    if state['schema'] == 3:
        warp_users = [g['id'] for g in groups if g.get('egress') == 'warp']
        direct_users = [g['id'] for g in groups if g.get('egress', 'direct') == 'direct']
        rules = []
        if warp_users:
            config['outbounds'].append({'type': 'socks', 'tag': 'warp',
                                        'server': '127.0.0.1', 'server_port': 40000,
                                        'version': '5', 'network': 'tcp'})
            rules.extend([
                {'inbound': ['anytls-in'], 'auth_user': warp_users,
                 'network': 'udp', 'action': 'reject'},
                {'inbound': ['anytls-in'], 'auth_user': warp_users,
                 'network': 'tcp', 'action': 'route', 'outbound': 'warp'}])
        if direct_users:
            rules.append({'inbound': ['anytls-in'], 'auth_user': direct_users,
                          'action': 'route', 'outbound': 'direct'})
        # No resolver/sniff action: send domain destinations through SOCKS5.
        # Unknown/missing authenticated users must not inherit direct egress.
        rules.append({'action': 'reject'})
        config['route'] = {'rules': rules}
    profiles = output_directory(directory, 'profiles')
    nodes = output_directory(directory, 'nodes')
    subscriptions = output_directory(directory, 'subscriptions')
    v2rayn = output_directory(directory, 'v2rayn', '.txt')
    subscriptions_v2rayn = output_directory(directory, 'subscriptions_v2rayn', '.txt')
    shadowrocket = output_directory(directory, 'shadowrocket', '.txt')
    subscriptions_shadowrocket = output_directory(directory, 'subscriptions_shadowrocket', '.txt')
    for old in ('mihomo-profile.yaml', 'mihomo-node.yaml'):
        target = directory / old
        require(not target.is_symlink(), 'Refusing a symbolic-link compatibility export.')
        if target.exists():
            target.unlink()
    for group in groups:
        node, profile, share = group_documents(state, group, fingerprint, certificate)
        private_write(profiles / (group['id'] + '.yaml'), profile)
        private_write(nodes / (group['id'] + '.yaml'), node)
        private_write(subscriptions / (group['token'] + '.yaml'), profile)
        private_write(v2rayn / (group['id'] + '.txt'), share)
        private_write(subscriptions_v2rayn / (group['token'] + '.txt'),
                      base64.b64encode(share.encode('utf-8')).decode('ascii') + '\n')
        if state['tls_verify'] == 'pki':
            name = group.get('node_name', state['node_prefix'] + ' AnyTLS · ' + group['label'])
            anytls = shadowrocket_share(state, group, name) + '\n'
            private_write(shadowrocket / (group['id'] + '.txt'), anytls)
            private_write(subscriptions_shadowrocket / (group['token'] + '.txt'),
                          base64.b64encode(anytls.encode('utf-8')).decode('ascii') + '\n')
        if len(groups) == 1:
            private_write(directory / 'mihomo-profile.yaml', profile)
            private_write(directory / 'mihomo-node.yaml', node)
    write_json(directory / 'state.json', state)
    write_json(directory / 'config.json', config)


SUBSCRIPTION_LIMIT = 1024 * 1024


class SubscriptionCheckError(ValueError):
    """Only fixed diagnostic text belongs here: never a URL, body or file path."""


def subscription_body_check(body, route, expected, origin):
    """Check the wire format independently before comparing exact account output."""
    def yaml(data):
        return re.search(rb'(?m)^(?:proxies|mixed-port|proxy-groups|rules):', data) is not None

    if route == 's':
        if not yaml(body):
            raise SubscriptionCheckError(origin + ' /s 不是预期的 Clash YAML。')
    else:
        require(route in ('v', 'r'), 'Unknown subscription format.')
        prefix = b'v2rayn://anytls/' if route == 'v' else b'anytls://'
        name = 'v2rayN AnyTLS' if route == 'v' else 'Shadowrocket / AnyTLS'
        location = origin + ' /' + route
        if yaml(body):
            raise SubscriptionCheckError(location + ' 正文为 YAML，应为标准 Base64 订阅。')
        try:
            decoded = base64.b64decode(body.strip(), validate=True)
            require(base64.b64encode(decoded) == body.strip(), 'Noncanonical Base64.')
        except ValueError:
            raise SubscriptionCheckError(location + ' 不是有效的标准 Base64（可能损坏或混入标题）。') from None
        if not decoded.startswith(prefix):
            try:
                double_encoded = base64.b64decode(decoded.strip(), validate=True).startswith(prefix)
            except ValueError:
                double_encoded = False
            reason = '存在双重 Base64 编码' if double_encoded else '解码后不是 ' + name + ' 分享链接'
            raise SubscriptionCheckError(location + ' ' + reason + '。')
    if body != expected:
        raise SubscriptionCheckError(origin + ' /' + route + ' 内容与当前组的正确产物不匹配。')


def local_subscription_file(path):
    try:
        require(not path.parent.is_symlink() and path.is_file() and not path.is_symlink(), 'Unsafe output.')
        with path.open('rb') as source:
            data = source.read(SUBSCRIPTION_LIMIT + 1)
        require(len(data) <= SUBSCRIPTION_LIMIT, 'Oversized output.')
        return data
    except (OSError, ValueError):
        raise SubscriptionCheckError('本地订阅产物缺失、不安全或超过大小限制。') from None


def loopback_subscription(subscription, token, route):
    """Keep the secret URL on stdin, verify TLS/SNI, and never follow redirects."""
    resolve = '{}:{}:127.0.0.1'.format(subscription['domain'], subscription['port'])
    config = 'url = "https://{}:{}/{}/{}"\n'.format(
        subscription['domain'], subscription['port'], route, token).encode('ascii')
    arguments = ['curl', '-q', '--silent', '--show-error', '--noproxy', '*',
                 '--proto', '=https', '--resolve', resolve, '--connect-timeout', '3',
                 '--max-time', '5', '--max-filesize', str(SUBSCRIPTION_LIMIT),
                 '--write-out', '\n%{http_code}', '--config', '-']
    try:
        # Read at most the limit plus status trailer. Discard stderr completely:
        # curl errors can include the secret URL or response data. curl's own
        # max-time bounds the blocking read; oversized streams are killed early.
        with subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL) as process:
            try:
                process.stdin.write(config)
                process.stdin.close()
                data = process.stdout.read(SUBSCRIPTION_LIMIT + 5)
                if len(data) > SUBSCRIPTION_LIMIT + 4:
                    raise SubscriptionCheckError('HTTP /' + route + ' 响应超过大小限制。')
                code = process.wait(timeout=2)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    except (OSError, subprocess.SubprocessError):
        raise SubscriptionCheckError('HTTPS /' + route + ' 本机请求失败（连接、证书或 curl 执行异常）。') from None
    if code:
        reason = {7: '无法连接本机监听端口', 28: '连接或读取超时',
                  35: 'TLS 握手失败', 60: 'TLS 证书验证失败',
                  63: '响应超过大小限制'}.get(code, 'curl 请求失败')
        raise SubscriptionCheckError('HTTPS /' + route + ' ' + reason + '（curl ' + str(code) + '）。')
    body, separator, status = data.rpartition(b'\n')
    if not separator or re.fullmatch(rb'[0-9]{3}', status) is None:
        raise SubscriptionCheckError('HTTP /' + route + ' 返回状态无法识别。')
    if status != b'200':
        raise SubscriptionCheckError('HTTP /' + route + ' 返回 ' + status.decode('ascii') + '（未跟随跳转）。')
    return body


def check_subscriptions(directory, identifier=None):
    """Diagnose one enabled group; do not render, save state or refresh tokens."""
    try:
        directory = Path(directory)
        state = load(directory / 'state.json')
        require(state['subscription'] is not None, 'Subscription disabled.')
        if identifier is not None:
            group_id(identifier)
        group = selected_group(state, identifier) if identifier else active(state)[0]
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        raise SubscriptionCheckError('订阅检查失败：状态不可读取、订阅未启用，或指定组不存在/已停用。') from None
    print('订阅内容检查：组 {}（{}，仅检查本机 HTTPS，不代表公网可达）。'.format(
        group['id'], '默认采样一个启用组' if identifier is None else '显式指定组'))
    try:
        fingerprint, certificate = None, None
        if state['tls_verify'] == 'pin':
            cert = str(directory / 'server.crt')
            certificate = call(['openssl', 'x509', '-in', cert, '-outform', 'PEM']).decode('ascii')
            fingerprint = call(['openssl', 'x509', '-in', cert, '-noout', '-fingerprint', '-sha256'])
            fingerprint = fingerprint.decode('ascii').strip().split('=', 1)[1].replace(':', '').lower()
            require(re.fullmatch(r'[0-9a-f]{64}', fingerprint) is not None, 'Invalid fingerprint.')
        _, profile, share = group_documents(state, group, fingerprint, certificate)
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError):
        raise SubscriptionCheckError('本地证书或当前组数据无法验证，未请求订阅。') from None
    expected = {'s': profile.encode('utf-8'), 'v': base64.b64encode(share.encode('utf-8')) + b'\n'}
    paths = {'s': directory / 'subscriptions' / (group['token'] + '.yaml'),
             'v': directory / 'subscriptions_v2rayn' / (group['token'] + '.txt')}
    if state['tls_verify'] == 'pki':
        name = group.get('node_name', state['node_prefix'] + ' AnyTLS · ' + group['label'])
        share = shadowrocket_share(state, group, name) + '\n'
        expected['r'] = base64.b64encode(share.encode('utf-8')) + b'\n'
        paths['r'] = directory / 'subscriptions_shadowrocket' / (group['token'] + '.txt')
    for route in expected:
        subscription_body_check(local_subscription_file(paths[route]), route, expected[route], '本地产物')
    print('本地产物：所有支持格式、同组账号及当前配置一致。')
    failed = False
    for route in expected:
        try:
            body = loopback_subscription(state['subscription'], group['token'], route)
            subscription_body_check(body, route, expected[route], 'HTTP 返回')
            print('HTTPS /' + route + '：200，正文与本地正确产物一致。')
        except SubscriptionCheckError as exc:
            failed = True
            print(str(exc))
    if failed:
        raise SubscriptionCheckError('订阅内容检查未通过；没有刷新订阅、修改凭据或重载服务。')


def list_groups(state):
    print('ID\t分组\t状态\t出口')
    for group in state['groups']:
        print('{}\t{}\t{}\t{}'.format(group['id'], group['label'],
              'enabled' if group['enabled'] else 'disabled', group.get('egress', 'direct')))


def list_groups_ui(state):
    """Align the human menu, including the selected group egress."""
    def width(text):
        return sum(0 if unicodedata.combining(char) else
                   2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
                   for char in text)
    rows = [('ID', '分组', '状态', '出口')] + [
        (g['id'], g['label'], '已启用' if g['enabled'] else '已停用',
         'WARP · TCP' if g.get('egress') == 'warp' else '直连')
        for g in state['groups']]
    widths = [max(width(row[i]) for row in rows) for i in (0, 1, 2)]
    for row in rows:
        fields = [row[i] + ' ' * (widths[i] - width(row[i])) for i in (0, 1, 2)]
        print('  ' + '  '.join(fields + [row[3]]))


def automatic_group_name(state):
    # Disabled groups still own their identifiers and display names.
    identifiers = {group['id'] for group in state['groups']}
    titles = {group['label'].casefold() for group in state['groups']}
    for layer in range(1, 102):
        suffix = '' if layer == 1 else str(layer)
        candidates = [(name.lower() + suffix, name + suffix)
                      for name in AUTO_GROUP_NAMES
                      if name.lower() + suffix not in identifiers
                      and (name + suffix).casefold() not in titles]
        if candidates:
            return secrets.choice(candidates)
    raise ValueError('No unused automatic group name is available.')


def edit_group(state, action, values):
    if action == 'add':
        require(len(values) in (0, 2), 'Usage: group STATE add [ID LABEL]')
        require(len(state['groups']) < 100, 'Cannot add more than 100 groups.')
        identifier, title = values if values else automatic_group_name(state)
        require(not any(g['id'] == identifier for g in state['groups']), 'Group ID already exists.')
        group = new_group(identifier, title)
        state['groups'].append(group)
        return group
    require(len(values) == (2 if action in ('rename', 'egress') else 1), 'Wrong group command arguments.')
    group = selected_group(state, values[0], must_enable=False)
    if action == 'rename':
        group['label'] = label(values[1])
        group.pop('node_name', None)
    elif action == 'egress':
        require(values[1] in ('direct', 'warp'), 'Group egress must be direct or warp.')
        group['egress'] = values[1]
        if values[1] == 'warp':
            state['schema'] = 3
    elif action == 'rotate':
        rotate(group)
    elif action in ('disable', 'enable'):
        desired = action == 'enable'
        if group['enabled'] == desired:
            raise ValueError('Group is already {}; use rotate to replace credentials.'.format(
                'enabled' if desired else 'disabled'))
        if not desired:
            require(len(active(state)) > 1, 'Cannot disable the last active group.')
        rotate(group)
        group['enabled'] = desired
    elif action == 'remove':
        require(not group['enabled'] or len(active(state)) > 1, 'Cannot remove the last active group.')
        state['groups'].remove(group)
    else:
        raise ValueError('Unknown group command.')


def main(argv):
    require(bool(argv), 'Missing helper command.')
    command, *args = argv
    if command == 'validate':
        print(host(args[0]))
        print(port(args[1]))
    elif command in ('validate-domain', 'validate-prefix', 'validate-ip'):
        require(len(args) == 1, 'Validation requires exactly one value.')
        if command == 'validate-domain':
            print(domain(args[0]))
        elif command == 'validate-prefix':
            print(node_prefix(args[0]))
        else:
            address = ipaddress.ip_address(args[0])
            require(address.version == 4, 'An IPv4 address is required for IP test mode.')
            print(str(address))
    elif command == 'init':
        destination, address, listening_port = args
        state = {'schema': 2, 'server': host(address), 'sni': host(address),
                 'port': port(listening_port), 'name': 'GZ AnyTLS', 'node_prefix': 'GZ',
                 'tls_mode': 'self-signed', 'tls_verify': 'pin', 'version': '', 'sha256': '',
                 'groups': [new_group(identifier, title) for identifier, title in DEFAULT_GROUPS],
                 'subscription': None}
        write_json(destination, normalized(state))
    elif command == 'normalize':
        write_json(args[0], load(args[0]))
    elif command == 'branding':
        state = load(args[0])
        update_display_names(state)
        write_json(args[0], normalized(state))
    elif command == 'get':
        state, key = load(args[0]), args[1]
        subscription = state['subscription'] or {}
        derived = {'group_count': len(state['groups']), 'active_group_count': len(active(state)),
                   'warp_group_count': sum(g.get('egress') == 'warp' for g in state['groups']),
                   'active_warp_group_count': sum(g.get('egress') == 'warp' for g in active(state)),
                   'node_name_override_count': sum('node_name' in g for g in state['groups']),
                   'subscription_domain': subscription.get('domain', ''),
                   'subscription_port': subscription.get('port', 0),
                   'subscription_enabled': int(bool(subscription))}
        if key == 'password':
            value = selected_group(state)['password']
        else:
            value = derived[key] if key in derived else state[key]
        require(isinstance(value, (str, int)) and not isinstance(value, bool), 'Requested value is not scalar.')
        print(value)
    elif command == 'group-egress':
        require(len(args) == 2, 'Usage: group-egress STATE GROUP')
        print(selected_group(load(args[0]), args[1], must_enable=False).get('egress', 'direct'))
    elif command == 'edit':
        filename, action, *values = args
        state = load(filename)
        if action == 'port':
            state['port'] = port(values[0])
        elif action == 'server':
            state['server'] = host(values[0])
        elif action == 'prefix':
            require(len(values) == 1, 'Usage: edit STATE prefix NEW_PREFIX')
            state['node_prefix'] = node_prefix(values[0])
            for group in state['groups']:
                group.pop('node_name', None)
        elif action == 'password':
            rotate(selected_group(state))
        elif action == 'certificate':
            state['tls_mode'], state['tls_verify'] = 'self-signed', 'pin'
        elif action == 'import-cert':
            state['sni'] = host(values[0])
            state['tls_mode'] = 'imported'
            state['tls_verify'] = values[1] if len(values) > 1 else 'pin'
        elif action == 'version':
            state['version'], state['sha256'] = values
        elif action == 'subscription':
            state['subscription'] = {'domain': domain(values[0]),
                                     'port': port(values[1] if len(values) > 1 else '9443')}
        elif action == 'subscription-off':
            state['subscription'] = None
        else:
            raise ValueError('Unknown edit command.')
        write_json(filename, normalized(state))
    elif command == 'list-ui':
        require(len(args) == 1, 'Usage: list-ui STATE')
        list_groups_ui(load(args[0]))
    elif command in ('group-options', 'group-number'):
        required = 1 if command == 'group-options' else 2
        require(len(args) in (required, required + 1),
                'Usage: group-options STATE [enabled|disabled|all] or group-number STATE NUMBER [enabled|disabled|all]')
        scope = args[required] if len(args) > required else 'enabled'
        require(scope in ('enabled', 'disabled', 'all'), 'Group selection scope must be enabled, disabled or all.')
        groups = [group for group in load(args[0])['groups']
                  if scope == 'all' or group['enabled'] == (scope == 'enabled')]
        require(groups, 'No groups are available for this action.')
        if command == 'group-options':
            for number, group in enumerate(groups, 1):
                print('  {}) {} ({})'.format(number, group['label'], group['id']))
        else:
            require(re.fullmatch(r'[1-9][0-9]{0,2}', args[1]) is not None,
                    'Enter one of the displayed group numbers.')
            number = int(args[1])
            require(number <= len(groups), 'Group number is outside the displayed list.')
            print(groups[number - 1]['id'])
    elif command in ('list', 'group'):
        filename = args[0]
        state = load(filename)
        action = 'list' if command == 'list' else args[1]
        if action == 'list':
            list_groups(state)
        else:
            changed_group = edit_group(state, action, args[2:])
            write_json(filename, normalized(state))
            if action == 'add':
                print(changed_group['id'])
    elif command in ('links', 'links-all'):
        require(1 <= len(args) <= (3 if command == 'links' else 2),
                'Usage: links STATE [clash|v2rayn|shadowrocket] [GROUP] or links-all STATE [GROUP]')
        state = load(args[0])
        if command == 'links':
            format_name = args[1] if len(args) > 1 else 'clash'
            identifier = args[2] if len(args) > 2 else None
            require(format_name in ('clash', 'v2rayn', 'shadowrocket'),
                    'Subscription format must be clash, v2rayn or shadowrocket.')
            if format_name == 'shadowrocket':
                require(state['tls_verify'] == 'pki', SHADOWROCKET_PIN_NOTICE)
        else:
            format_name = 'all'
            identifier = args[1] if len(args) > 1 else None
        sub = state['subscription']
        require(sub is not None, 'HTTPS subscription is not configured. Export local group profiles first.')
        groups = [selected_group(state, identifier)] if identifier else active(state)

        def url(group, route):
            return 'https://{}:{}/{}/{}'.format(sub['domain'], sub['port'], route, group['token'])

        if format_name == 'all':
            reports = []
            for group in groups:
                report = '分组：{} ({})\nClash / Mihomo：\n{}\nv2rayN：\n{}'.format(
                    group['label'], group['id'], url(group, 's'), url(group, 'v'))
                if state['tls_verify'] == 'pki':
                    report += '\nShadowrocket / AnyTLS：\n' + url(group, 'r')
                reports.append(report)
            if state['tls_verify'] != 'pki':
                reports.append(SHADOWROCKET_PIN_NOTICE)
            print('\n\n'.join(reports))
        else:
            route = {'clash': 's', 'v2rayn': 'v', 'shadowrocket': 'r'}[format_name]
            writer = csv.writer(sys.stdout, lineterminator='\n')
            writer.writerow(['id', 'label', 'url'])
            for group in groups:
                writer.writerow([group['id'], group['label'], url(group, route)])
    elif command in ('export', 'export-v2rayn', 'export-shadowrocket', 'export-all'):
        require(len(args) in (2, 3), 'Usage: export[-v2rayn|-shadowrocket|-all] STATE DIRECTORY [GROUP]')
        raw = read_json(args[0])
        state = normalized(raw)
        group = selected_group(state, args[2] if len(args) > 2 else None)
        if command == 'export-all':
            # Read every supported format first; failures must not print partial credentials.
            clash = group_export(raw, args[1], group, 'clash')
            v2rayn = group_export(raw, args[1], group, 'v2rayn')
            extra = ('=== Shadowrocket / AnyTLS 分享链接 ===\n' +
                     group_export(raw, args[1], group, 'shadowrocket').rstrip('\n')
                     if state['tls_verify'] == 'pki' else SHADOWROCKET_PIN_NOTICE)
            print('分组：{} ({})\n\n=== Clash / Mihomo YAML ===\n{}\n\n'
                  '=== v2rayN 分享链接 ===\n{}\n\n{}'.format(
                      group['label'], group['id'], clash.rstrip('\n'), v2rayn.rstrip('\n'), extra))
        else:
            sys.stdout.write(group_export(raw, args[1], group,
                                          'clash' if command == 'export' else command.removeprefix('export-')))
    elif command == 'preserve-identity':
        current = load(args[0])
        candidate = load(args[1])
        candidate['groups'] = copy.deepcopy(current['groups'])
        candidate['subscription'] = copy.deepcopy(current['subscription'])
        candidate['node_prefix'] = current['node_prefix']
        candidate['schema'] = max(current['schema'], candidate['schema'])
        write_json(args[1], normalized(candidate))
    elif command == 'release':
        filename, wanted, architecture = args
        release = read_json(filename)
        tag = release.get('tag_name', '')
        version = tag[1:] if tag.startswith('v') else tag
        require(not release.get('draft') and not release.get('prerelease') and
                re.fullmatch(r'\d+\.\d+\.\d+', version), 'Not an official stable release.')
        require(wanted == 'latest' or version == wanted, 'Release version mismatch.')
        name = 'sing-box-{}-linux-{}.tar.gz'.format(version, architecture)
        assets = [a for a in release['assets'] if a['name'] == name]
        require(len(assets) == 1, 'No unique matching official asset.')
        asset = assets[0]
        url = 'https://github.com/SagerNet/sing-box/releases/download/v{}/{}'.format(version, name)
        digest = asset.get('digest', '')
        require(asset.get('browser_download_url') == url and re.fullmatch(r'sha256:[0-9a-f]{64}', digest),
                'Missing SHA256 digest or unexpected asset origin; refusing download.')
        print(version)
        print(url)
        print(digest[7:])
    elif command == 'extract':
        archive, destination, version, architecture = args
        member = 'sing-box-{}-linux-{}/sing-box'.format(version, architecture)
        with tarfile.open(archive, 'r:gz') as contents:
            matches = [item for item in contents.getmembers() if item.name == member]
            require(len(matches) == 1 and matches[0].isfile() and 0 < matches[0].size < 536870912,
                    'Unexpected binary inside archive.')
            with contents.extractfile(matches[0]) as source, open(destination, 'xb') as output:
                shutil.copyfileobj(source, output)
    elif command == 'certificate':
        directory = Path(args[0])
        identity = load(directory / 'state.json')['sni']
        try:
            ipaddress.IPv4Address(identity)
            san = 'IP:' + identity
        except ValueError:
            san = 'DNS:' + identity
        request = directory / 'cert-request.cnf'
        private_write(request, '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=server_ext\n'
                      '[dn]\nCN=' + identity + '\n[server_ext]\nsubjectAltName=' + san + '\n'
                      'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                      'extendedKeyUsage=serverAuth\n')
        try:
            call(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                  '-nodes', '-days', '825', '-config', str(request), '-keyout', str(directory / 'server.key'),
                  '-out', str(directory / 'server.crt')])
            os.chmod(directory / 'server.key', 0o600)
            os.chmod(directory / 'server.crt', 0o600)
        finally:
            request.unlink(missing_ok=True)
    elif command == 'nginx-lua-path':
        require(len(args) == 1, 'Usage: nginx-lua-path NGINX_BINARY')
        print(nginx_lua_path(args[0]))
    elif command == 'check-subscriptions':
        require(len(args) in (1, 2), 'Usage: check-subscriptions DIRECTORY [GROUP]')
        check_subscriptions(args[0], args[1] if len(args) > 1 else None)
    elif command == 'check-cert':
        require(len(args) in (3, 4), 'Usage: check-cert CERT KEY IDENTITY [pki|pin]')
        print(certificate_info(args[0], args[1], args[2], args[3] if len(args) > 3 else 'pki'))
    elif command == 'render':
        render(args[0])
    else:
        raise ValueError('Unknown helper command.')


if __name__ == '__main__':
    # Make stdout deterministic on hosts whose locale is C, including Chinese
    # group names. No credentials are included in exception messages.
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    try:
        main(sys.argv[1:])
    except subprocess.CalledProcessError as exc:
        print('Certificate or cryptographic validation failed ({}).'.format(
            Path(str(exc.cmd[0])).name), file=sys.stderr)
        sys.exit(1)
    except (ValueError, KeyError, IndexError, TypeError, OSError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        sys.exit(1)
