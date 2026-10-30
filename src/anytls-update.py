#!/usr/bin/env python3
"""Prepare verified manager releases or Git sources without executing downloaded code."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import zipfile

FILES = ('anytls-manager.sh', 'anytls-state.py', 'anytls-subscription.sh',
         'anytls-runtime.sh', 'anytls-update.py', 'README.txt', 'SOURCES.txt', 'TEST-RESULTS.txt')
ALL_FILES = set(FILES) | {'manifest.json', 'SHA256SUMS.txt'}
MAX_ARCHIVE = 2 * 1024 * 1024
MAX_EXPANDED = 8 * 1024 * 1024
SEMVER = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')
# GitHub publishes this host key at its official SSH key fingerprints page.
# A changed upstream key must be reviewed and shipped in a manager update.
GITHUB_HOST_KEY = ('github.com ssh-ed25519 '
                   'AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n')


def require(value, message):
    if not value:
        raise ValueError(message)


def version(value):
    require(isinstance(value, str) and SEMVER.fullmatch(value), 'Expected a stable X.Y.Z version.')
    return tuple(map(int, value.split('.')))


def repository(value):
    require(isinstance(value, str), 'Repository must be owner/repo or a GitHub URL.')
    value = value.strip()
    if value.startswith('https://'):
        parsed = urlsplit(value)
        require(parsed.netloc == 'github.com' and not parsed.query and not parsed.fragment,
                'Use a GitHub repository URL without credentials, query or fragment.')
        value = parsed.path.strip('/')
    if value.endswith('.git'):
        value = value[:-4]
    parts = value.split('/')
    require(len(parts) == 2 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?', parts[0])
            and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', parts[1]) and parts[1] not in ('.', '..'),
            'Use owner/repo or https://github.com/owner/repo for a trusted repository.')
    return '/'.join(parts)


def secure_path(path, directory=False):
    path = Path(path)
    require(not path.is_symlink() and (path.is_dir() if directory else path.is_file()),
            'Invalid managed file or directory: ' + str(path))
    info = path.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, 'Managed path is not root-owned/read-only: ' + str(path))
    return path


def base_directory(value):
    require(os.geteuid() == 0, 'Run manager maintenance as root.')
    base = Path(value)
    require(base.is_absolute(), 'Managed base must be absolute.')
    secure_path(base, True)
    marker = secure_path(base / '.owner')
    require(marker.read_text().strip() == 'jackie-anytls-manager-v1', 'Unrecognized managed installation.')
    return base


def write_json(path, value):
    path = Path(path)
    require(not path.is_symlink(), 'Refusing symbolic-link output.')
    fd, temporary = tempfile.mkstemp(prefix='.new-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def bind_source(base, value=None):
    path = base / 'update-source.json'
    if path.exists() or path.is_symlink():
        secure_path(path)
    if value is not None:
        write_json(path, {'repository': repository(value), 'transport': 'https'})
    require(path.is_file(), 'No repository bound. Run: any update-source OWNER/REPO')
    return repository(json.loads(secure_path(path).read_text(encoding='utf-8'))['repository'])


def branch_name(value):
    require(isinstance(value, str) and len(value) <= 100
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', value) is not None
            and '..' not in value and '//' not in value
            and all(part and not part.startswith('.') and not part.endswith(('.', '.lock'))
                    for part in value.split('/')),
            'Use a branch name such as main or stable; arbitrary revisions are not accepted.')
    return value


def private_key_path(value):
    require(isinstance(value, str) and value and '%' not in value
            and not any(ord(c) < 32 or ord(c) == 127 for c in value),
            'Invalid SSH private-key path.')
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts, 'SSH private-key path must be absolute.')
    for parent in reversed(path.parents):
        require(parent.is_dir() and not parent.is_symlink(), 'SSH key has an unsafe parent directory.')
        info = parent.stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022,
                'SSH key parent directories must be root-owned and not writable by other users.')
    require(path.is_file() and not path.is_symlink(), 'SSH private key must be a regular file.')
    info = path.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o077,
            'SSH private key must be root-owned with mode 0600 or stricter.')
    return path


def load_source(base):
    require((base / 'update-source.json').exists() or (base / 'update-source.json').is_symlink(),
            'No repository bound. Run: any update-source-git OWNER/REPO, '
            'any update-source-ssh OWNER/REPO PRIVATE_KEY or any update-source OWNER/REPO')
    path = secure_path(base / 'update-source.json')
    source = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(source, dict), 'Invalid update source.')
    source['repository'] = repository(source['repository'])
    source['transport'] = source.get('transport', 'https')
    require(source['transport'] in ('https', 'ssh', 'git-https'), 'Unsupported update transport.')
    if source['transport'] in ('ssh', 'git-https'):
        source['branch'] = branch_name(source['branch'])
    if source['transport'] == 'ssh':
        source['key_file'] = str(private_key_path(source['key_file']))
    return source


def bind_ssh_source(base, repo, key, branch='main'):
    value = {'repository': repository(repo), 'transport': 'ssh',
             'branch': branch_name(branch), 'key_file': str(private_key_path(key))}
    path = base / 'update-source.json'
    if path.exists() or path.is_symlink():
        secure_path(path)
    write_json(path, value)
    return value['repository'] + ' (SSH, branch ' + value['branch'] + ')'


def bind_git_source(base, repo, branch='main'):
    value = {'repository': repository(repo), 'transport': 'git-https',
             'branch': branch_name(branch)}
    path = base / 'update-source.json'
    if path.exists() or path.is_symlink():
        secure_path(path)
    write_json(path, value)
    return value['repository'] + ' (HTTPS Git, branch ' + value['branch'] + ')'


def git_environment(scratch, key=None, known_hosts=None):
    # Do not inherit SSH agents, proxy commands, Git configuration, alternate
    # object directories, hooks, credentials, or dynamic-loader environment.
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(scratch),
                   'XDG_CONFIG_HOME': str(Path(scratch) / 'no-config'), 'LC_ALL': 'C',
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null',
                   'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
                   'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_ATTR_NOSYSTEM': '1',
                   'GIT_PROTOCOL_FROM_USER': '0', 'GIT_OPTIONAL_LOCKS': '0',
                   'GIT_ALLOW_PROTOCOL': 'ssh' if key is not None else 'https'}
    if key is None:
        return environment
    require(known_hosts is not None, 'SSH updates require the pinned host-key file.')
    # OpenSSH parses -o values again after the shell. Quote the file inside its
    # own option syntax as well, so a space cannot mean a second host-key file.
    known_hosts_option = '"' + str(known_hosts).replace('\\', '\\\\').replace('"', '\\"') + '"'
    ssh = ['ssh', '-F', '/dev/null', '-i', str(key),
           '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
           '-o', 'PreferredAuthentications=publickey', '-o', 'PubkeyAuthentication=yes',
           '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
           '-o', 'GSSAPIAuthentication=no', '-o', 'HostbasedAuthentication=no',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'HostKeyAlgorithms=ssh-ed25519',
           '-o', 'UserKnownHostsFile=' + known_hosts_option, '-o', 'GlobalKnownHostsFile=/dev/null',
           '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'ClearAllForwardings=yes',
           '-o', 'PermitLocalCommand=no', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
           '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
           '-o', 'ConnectTimeout=15', '-o', 'ConnectionAttempts=1',
           '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2']
    environment.update({'GIT_SSH_COMMAND': shlex.join(ssh), 'GIT_SSH_VARIANT': 'ssh'})
    return environment


def git_call(args, environment, cwd):
    protocol = environment.get('GIT_ALLOW_PROTOCOL', 'ssh')
    require(protocol in ('ssh', 'https'), 'Unsupported Git protocol.')
    command = ['git', '--no-pager', '--literal-pathspecs',
               '-c', 'core.hooksPath=/dev/null', '-c', 'core.attributesFile=/dev/null',
               '-c', 'protocol.allow=never', '-c', 'protocol.' + protocol + '.allow=always',
               '-c', 'credential.helper=', '-c', 'http.proxy=',
               '-c', 'http.sslVerify=true', '-c', 'http.followRedirects=false',
               '-c', 'http.extraHeader=', '-c', 'http.cookieFile=', '-c', 'http.saveCookies=false',
               '-c', 'fetch.recurseSubmodules=false', '-c', 'submodule.recurse=false',
               '-c', 'fetch.fsckObjects=true', '-c', 'transfer.fsckObjects=true'] + list(args)
    try:
        result = subprocess.run(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError('Git source operation could not complete; check Git and network access.') from error
    require(result.returncode == 0,
            ('Git SSH operation failed; check the repository, branch and read-only deploy-key access. '
             if protocol == 'ssh' else
             'Public Git HTTPS operation failed; check repository visibility, branch and direct HTTPS access. ')
            + 'The running installation was not changed.')
    return result.stdout


def read_git_sources(bare, commit, environment):
    require(re.fullmatch(r'[0-9a-f]{40}', commit) is not None, 'Invalid fetched Git commit.')
    blobs = {}
    for name in FILES:
        expected = ('src/' + name).encode('ascii')
        record = git_call(['ls-tree', '-z', commit, '--', expected.decode('ascii')], environment, bare)
        entries = record.split(b'\0')
        require(len(entries) == 2 and not entries[1] and b'\t' in entries[0],
                'Missing or ambiguous source file: ' + name)
        header, path = entries[0].split(b'\t', 1)
        parts = header.split(b' ')
        require(len(parts) == 3 and parts[0] in (b'100644', b'100755') and parts[1] == b'blob'
                and re.fullmatch(rb'[0-9a-f]{40}', parts[2]) is not None and path == expected,
                'Source must be a regular Git blob, not a link or submodule: ' + name)
        oid = parts[2].decode('ascii')
        size_text = git_call(['cat-file', '-s', oid], environment, bare).strip()
        require(re.fullmatch(rb'[0-9]{1,10}', size_text) is not None,
                'Invalid Git source size: ' + name)
        size = int(size_text)
        require(0 < size <= MAX_ARCHIVE and sum(map(len, blobs.values())) + size <= MAX_ARCHIVE,
                'Git source exceeds the source-only package size limit.')
        data = git_call(['cat-file', 'blob', oid], environment, bare)
        require(len(data) == size, 'Git source size changed: ' + name)
        blobs[name] = data
    return blobs


def source_candidate(directory, blobs, current):
    require(set(blobs) == set(FILES), 'Source file list does not match the update protocol.')
    require(all(isinstance(data, bytes) and 0 < len(data) <= MAX_ARCHIVE for data in blobs.values())
            and sum(map(len, blobs.values())) <= MAX_ARCHIVE, 'Invalid source bundle size.')
    for name, data in blobs.items():
        require(b'\r' not in data and not data.startswith(b'\xef\xbb\xbf'),
                'Use UTF-8 without BOM and LF newlines: ' + name)
        data.decode('utf-8')
    actual = re.findall(r'^readonly MANAGER_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$',
                        blobs['anytls-manager.sh'].decode('utf-8'), re.M)
    require(len(actual) == 1, 'Expected one manager version in source.')
    wanted = actual[0]
    require(version(wanted) >= version(current), 'Source downgrade refused; use manager-rollback.')
    # Build locally with the installed protocol, never execute a downloaded
    # build script (including tools/build_release.py) to prepare an update.
    # Protocol 1 keeps state_schema=2 as its bootstrap compatibility contract:
    # the candidate can migrate an existing schema-2 installation. Runtime
    # state versions (including the WARP schema-3 barrier) are checked by the
    # state helper and protect(), not this legacy package transport constant.
    manifest = {'product': 'gz-anytls-manager', 'version': wanted, 'update_protocol': 1,
                'state_schema': 2, 'min_manager_version': '1.2.0',
                'files': {name: hashlib.sha256(blobs[name]).hexdigest() for name in FILES}}
    output = dict(blobs)
    output['manifest.json'] = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    output['SHA256SUMS.txt'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                                      for name, data in output.items()).encode('ascii')
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    for name, data in output.items():
        with (directory / name).open('xb') as stream:
            stream.write(data)
        os.chmod(directory / name, 0o700 if name.endswith('.sh') else 0o600)
    verify(directory, wanted, current)
    return wanted


def installed_sources_equal(base, blobs, current):
    pointer = base / 'manager-current'
    if not pointer.exists() and not pointer.is_symlink():
        return False
    require(pointer.is_symlink() and pointer.lstat().st_uid == 0, 'Invalid installed manager pointer.')
    releases = secure_path(base / 'manager-releases', True)
    active = pointer.resolve(strict=True)
    require(active.parent == releases.resolve(), 'Installed manager pointer is outside its managed directory.')
    secure_path(active, True)
    for name in ALL_FILES:
        secure_path(active / name)
    manifest = manifest_at(active, current)
    return manifest['files'] == {name: hashlib.sha256(data).hexdigest() for name, data in blobs.items()}


def prepare_ssh(base, current, source, requested='latest', check_only=False):
    return prepare_git(base, current, source, requested, check_only)


def prepare_git(base, current, source, requested='latest', check_only=False):
    require(requested == 'latest', 'Git source updates follow the bound branch; omit the version argument.')
    version(current)
    repo, branch = repository(source['repository']), branch_name(source['branch'])
    transport = source['transport']
    require(transport in ('ssh', 'git-https'), 'Unsupported Git source transport.')
    key = private_key_path(source['key_file']) if transport == 'ssh' else None
    label = 'SSH' if transport == 'ssh' else 'HTTPS Git'
    updates = base / 'updates'
    if not updates.exists() and not updates.is_symlink():
        updates.mkdir(mode=0o700)
    secure_path(updates, True)
    with tempfile.TemporaryDirectory(prefix='git-fetch-', dir=updates) as temporary:
        scratch = Path(temporary)
        known_hosts = None
        if key is not None:
            known_hosts = scratch / 'known_hosts'
            known_hosts.write_text(GITHUB_HOST_KEY, encoding='ascii')
            os.chmod(known_hosts, 0o600)
        template = scratch / 'empty-template'
        template.mkdir(mode=0o700)
        bare = scratch / 'source.git'
        environment = git_environment(scratch, key, known_hosts)
        url = ('git@github.com:' if key is not None else 'https://github.com/') + repo + '.git'
        git_call(['init', '--bare', '--template=' + str(template), str(bare)], environment, scratch)
        git_call(['fetch', '--depth=1', '--no-tags', '--no-recurse-submodules',
                  url, 'refs/heads/' + branch], environment, bare)
        commit = git_call(['rev-parse', '--verify', 'FETCH_HEAD^{commit}'], environment, bare).decode('ascii').strip()
        blobs = read_git_sources(bare, commit, environment)
        # Validate syntax and construct a complete package even for check-only;
        # neither path calls downloaded code or changes the running service.
        candidate = scratch / 'candidate'
        wanted = source_candidate(candidate, blobs, current)
        if installed_sources_equal(base, blobs, current):
            print('Manager source is unchanged at commit ' + commit[:12] + '.', file=sys.stderr)
            return ''
        if check_only:
            return wanted + ' (commit ' + commit[:12] + ')'
        staging = Path(tempfile.mkdtemp(prefix='candidate-', dir=updates))
        destination = staging / ('GZ-AnyTLS-Manager-' + wanted)
        os.replace(candidate, destination)
        write_json(staging / 'origin.json', {'repository': repo, 'transport': transport, 'branch': branch,
                                            'commit': commit, 'version': wanted})
        print('Prepared ' + label + ' source commit ' + commit[:12] + '; credentials have not been changed.', file=sys.stderr)
        return str(destination)


def fetch(url, destination, limit):
    # Fixed GitHub API/asset URLs only. Redirects must remain HTTPS; the archive
    # is subsequently checked against the digest supplied by the release API.
    result = subprocess.run(['curl', '-q', '--fail', '--silent', '--show-error', '--location',
                             '--proto', '=https', '--proto-redir', '=https',
                             '--connect-timeout', '15', '--max-time', '120', '--retry', '1',
                             '--max-filesize', str(limit), '-H', 'Accept: application/vnd.github+json',
                             url, '-o', str(destination)], check=False)
    require(result.returncode == 0, 'GitHub download failed; the running installation was not changed.')
    require(destination.is_file() and 0 < destination.stat().st_size <= limit, 'Download size is invalid.')


def release_metadata(base, current, requested='latest'):
    version(current)
    repo = bind_source(base)
    if requested != 'latest':
        requested = requested.removeprefix('v')
        version(requested)
    updates = base / 'updates'
    if not updates.exists() and not updates.is_symlink():
        updates.mkdir(mode=0o700)
    secure_path(updates, True)
    with tempfile.TemporaryDirectory(prefix='metadata-', dir=updates) as scratch:
        target = Path(scratch) / 'release.json'
        endpoint = 'latest' if requested == 'latest' else 'tags/v' + requested
        fetch('https://api.github.com/repos/' + repo + '/releases/' + endpoint, target, 1024 * 1024)
        release = json.loads(target.read_text(encoding='utf-8'))
    require(release.get('draft') is False and release.get('prerelease') is False,
            'Draft and prerelease updates are not accepted.')
    tag = release.get('tag_name', '')
    require(isinstance(tag, str) and tag.startswith('v'), 'Release tag must be vX.Y.Z.')
    wanted = tag[1:]
    version(wanted)
    require(requested == 'latest' or requested == wanted, 'Requested release/tag mismatch.')
    require(version(wanted) >= version(current), 'Downgrades are refused; use manager-rollback for a verified local previous manager.')
    name = 'GZ-AnyTLS-Manager-' + wanted + '.zip'
    assets = [a for a in release.get('assets', []) if a.get('name') == name]
    require(len(assets) == 1, 'Release must contain exactly one matching manager ZIP asset.')
    asset = assets[0]
    expected = 'https://github.com/' + repo + '/releases/download/' + tag + '/' + name
    url = asset.get('browser_download_url', '')
    parsed = urlsplit(url)
    parts = parsed.path.split('/')
    require(parsed.scheme == 'https' and parsed.netloc == 'github.com' and not parsed.query and not parsed.fragment
            and len(parts) == 7 and '/'.join(parts[1:3]).lower() == repo.lower()
            and '/'.join(parts[3:]) == 'releases/download/' + tag + '/' + name,
            'Release asset URL does not belong to the bound repository/tag.')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest', '')) is not None,
            'GitHub did not provide a SHA256 asset digest; refusing update.')
    require(type(asset.get('size')) is int and 0 < asset['size'] <= MAX_ARCHIVE,
            'Release ZIP exceeds the source-only package size limit.')
    return {'repository': repo, 'version': wanted, 'url': expected,
            'digest': asset['digest'][7:], 'size': asset['size'], 'tag': tag}


def manifest_at(directory, expected=None, current=None):
    directory = Path(directory)
    require(not directory.is_symlink() and directory.is_dir(), 'Invalid candidate directory.')
    require({p.name for p in directory.iterdir()} == ALL_FILES, 'Candidate file list does not match this update protocol.')
    for name in ALL_FILES:
        p = directory / name
        require(p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_ARCHIVE,
                'Invalid candidate member: ' + name)
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    require(manifest.get('product') == 'gz-anytls-manager' and manifest.get('update_protocol') == 1
            and manifest.get('state_schema') == 2, 'Unsupported manager product/update protocol/state schema.')
    wanted = manifest.get('version')
    version(wanted)
    require(expected is None or wanted == expected, 'Manifest version differs from the release tag.')
    minimum = manifest.get('min_manager_version')
    version(minimum)
    require(current is None or version(current) >= version(minimum), 'This update requires an intermediate manager upgrade.')
    hashes = manifest.get('files')
    require(isinstance(hashes, dict) and set(hashes) == set(FILES), 'Manifest file set is invalid.')
    for name, digest in hashes.items():
        require(re.fullmatch(r'[0-9a-f]{64}', digest) is not None
                and hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest,
                'Candidate checksum mismatch: ' + name)
    sums = {}
    for line in (directory / 'SHA256SUMS.txt').read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        require(match is not None and match[2] not in sums, 'Invalid or duplicate checksum entry.')
        sums[match[2]] = match[1]
    require(set(sums) == set(FILES) | {'manifest.json'}, 'Checksum file list mismatch.')
    require(all(hashlib.sha256((directory / n).read_bytes()).hexdigest() == d for n, d in sums.items()),
            'Checksum list mismatch.')
    script = (directory / 'anytls-manager.sh').read_text(encoding='utf-8')
    actual = re.findall(r'^readonly MANAGER_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$', script, re.M)
    require(actual == [wanted], 'Manager source version differs from manifest.')
    return manifest


def verify(directory, expected=None, current=None):
    directory = Path(directory)
    manifest = manifest_at(directory, expected, current)
    for name in FILES:
        data = (directory / name).read_bytes()
        require(b'\r\n' not in data and not data.startswith(b'\xef\xbb\xbf'), 'Use UTF-8 without BOM and LF newlines: ' + name)
        if name.endswith('.sh'):
            subprocess.run(['bash', '-n', str(directory / name)], check=True)
        elif name.endswith('.py'):
            compile(data, str(directory / name), 'exec')
    return manifest['version']


def unpack(archive, destination, metadata, current):
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == metadata['digest'],
            'GitHub asset SHA256 mismatch; no downloaded code was executed.')
    prefix = 'GZ-AnyTLS-Manager-' + metadata['version'] + '/'
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        names = [m.filename for m in members]
        require(len(names) == len(set(names)) and set(names) == {prefix + n for n in ALL_FILES},
                'ZIP paths, duplicate entries or extra files are invalid.')
        require(sum(m.file_size for m in members) <= MAX_EXPANDED, 'ZIP expanded size exceeds limit.')
        for member in members:
            kind = stat.S_IFMT(member.external_attr >> 16)
            require(not member.is_dir() and kind in (0, stat.S_IFREG)
                    and not member.flag_bits & 1 and member.file_size <= MAX_ARCHIVE,
                    'ZIP contains a link, special, encrypted or oversized member.')
        destination.mkdir(mode=0o700)
        for member in members:
            name = member.filename[len(prefix):]
            data = bundle.read(member)
            require(len(data) == member.file_size, 'ZIP member size mismatch.')
            with (destination / name).open('xb') as stream:
                stream.write(data)
            os.chmod(destination / name, 0o700 if name.endswith('.sh') else 0o600)
    return verify(destination, metadata['version'], current)


def prepare(base, current, requested='latest', check_only=False):
    source = load_source(base)
    if source['transport'] == 'ssh':
        return prepare_ssh(base, current, source, requested, check_only)
    if source['transport'] == 'git-https':
        return prepare_git(base, current, source, requested, check_only)
    metadata = release_metadata(base, current, requested)
    if metadata['version'] == current:
        print('Manager is already at version ' + current + '.', file=sys.stderr)
        return ''
    if check_only:
        return metadata['version']
    staging = Path(tempfile.mkdtemp(prefix='candidate-', dir=base / 'updates'))
    archive = staging / 'release.zip'
    fetch(metadata['url'], archive, MAX_ARCHIVE)
    require(archive.stat().st_size == metadata['size'], 'Release download size differs from API metadata.')
    candidate = staging / ('GZ-AnyTLS-Manager-' + metadata['version'])
    unpack(archive, candidate, metadata, current)
    write_json(staging / 'origin.json', metadata)
    return str(candidate)


def protect(old, new, allow_prefix=False, allow_rules=False):
    old, new = Path(old), Path(new)
    states = [json.loads((p / 'state.json').read_text(encoding='utf-8')) for p in (old, new)]
    before, after = states
    require(allow_rules or before.get('clash_rules') == after.get('clash_rules'),
            'Upgrade changed the server default Clash rules.')
    if allow_rules:
        require({k: v for k, v in before.items() if k != 'clash_rules'} ==
                {k: v for k, v in after.items() if k != 'clash_rules'},
                'Rules import changed unrelated managed state.')
    require(after.get('schema') in (2, 3) and before.get('schema') in (1, 2, 3),
            'Unsupported upgrade state schema.')
    require(not (before['schema'] == 3 and after['schema'] != 3),
            'Upgrade would remove the WARP state compatibility barrier.')
    require(after['schema'] == 3 or not any(g.get('egress') == 'warp' for g in after['groups']),
            'WARP groups require the state compatibility barrier.')
    keys = ('server', 'port', 'sni', 'tls_mode', 'version', 'sha256')
    require(all(before.get(k) == after.get(k) for k in keys), 'Upgrade changed endpoint/TLS/core metadata.')
    require(before.get('tls_verify', 'pin') == after.get('tls_verify'), 'Upgrade changed TLS verification mode.')
    require(before.get('subscription') == after.get('subscription'), 'Upgrade changed subscription settings.')
    require(allow_prefix or before.get('node_prefix', 'GZ') == after.get('node_prefix', 'GZ'),
            'Upgrade changed the server node prefix.')
    identity = lambda g: (g['id'], g['password'], g['token'], g['enabled'], g.get('egress', 'direct'))
    if before['schema'] in (2, 3):
        require(sorted(map(identity, before['groups'])) == sorted(map(identity, after['groups'])),
                'Upgrade changed group IDs, passwords, tokens, enabled flags or egress.')
    else:
        require(len(after['groups']) == 1 and after['groups'][0]['id'] == 'legacy'
                and after['groups'][0]['password'] == before['password'] and after['groups'][0]['enabled'] is True
                and after['groups'][0].get('egress', 'direct') == 'direct',
                'Legacy migration changed the existing account.')
    for name in ('sing-box', 'server.crt', 'server.key'):
        require(hashlib.sha256((old / name).read_bytes()).digest() == hashlib.sha256((new / name).read_bytes()).digest(),
                'Manager upgrade changed core/certificate/private key: ' + name)
    configs = []
    for path in (old, new):
        config = json.loads((path / 'config.json').read_text(encoding='utf-8'))
        for inbound in config.get('inbounds', []):
            tls = inbound.get('tls', {})
            for field, name in (('certificate_path', 'server.crt'), ('key_path', 'server.key')):
                if tls.get(field) == str(path / name):
                    tls[field] = '<managed-' + name + '>'
        configs.append(config)
    return 'same_runtime' if configs[0] == configs[1] else 'changed_runtime'


def main(args):
    require(bool(args), 'Missing update command.')
    command, *values = args
    if command == 'source':
        require(len(values) in (1, 2), 'Usage: source BASE [OWNER/REPO]')
        base = base_directory(values[0])
        if len(values) == 2:
            bind_source(base, values[1])
        source = load_source(base)
        detail = {'ssh': 'SSH', 'git-https': 'HTTPS Git'}.get(source['transport'])
        detail = detail + ', branch ' + source['branch'] if detail else 'HTTPS Release'
        print(source['repository'] + ' (' + detail + ')')
    elif command == 'ssh-source':
        require(len(values) in (3, 4), 'Usage: ssh-source BASE OWNER/REPO PRIVATE_KEY [BRANCH]')
        print(bind_ssh_source(base_directory(values[0]), values[1], values[2],
                              values[3] if len(values) == 4 else 'main'))
    elif command == 'git-source':
        require(len(values) in (2, 3), 'Usage: git-source BASE OWNER/REPO [BRANCH]')
        print(bind_git_source(base_directory(values[0]), values[1],
                              values[2] if len(values) == 3 else 'main'))
    elif command in ('check', 'prepare'):
        require(len(values) in (2, 3), 'Usage: check|prepare BASE CURRENT_VERSION [VERSION|latest]')
        result = prepare(base_directory(values[0]), values[1], values[2] if len(values) == 3 else 'latest', command == 'check')
        if result:
            print(result)
    elif command == 'verify':
        require(len(values) in (1, 2), 'Usage: verify DIRECTORY [VERSION]')
        print(verify(values[0], values[1] if len(values) == 2 else None))
    elif command in ('protect', 'protect-prefix', 'protect-rules'):
        require(len(values) == 2, 'Usage: protect OLD_GENERATION NEW_GENERATION')
        print(protect(*values, allow_prefix=command == 'protect-prefix',
                      allow_rules=command == 'protect-rules'))
    else:
        raise ValueError('Unknown update command.')


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main(sys.argv[1:])
    except (ValueError, KeyError, TypeError, OSError, UnicodeError,
            subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print('Update stopped: ' + str(error), file=sys.stderr)
        sys.exit(1)
