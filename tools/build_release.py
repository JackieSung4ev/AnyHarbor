#!/usr/bin/env python3
"""Build a source-only AnyHarbor release using the existing update allow-list."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile


FILES = (
    'anytls-manager.sh', 'anytls-state.py', 'anytls-subscription.sh',
    'anytls-runtime.sh', 'anytls-update.py',
    'README.txt', 'SOURCES.txt', 'TEST-RESULTS.txt',
)
SEMVER = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'
MAX_SOURCE_BYTES = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_sources(root):
    source = root / 'src'
    require(source.is_dir() and not source.is_symlink(), 'src must be a real directory.')
    blobs = {}
    for name in FILES:
        path = source / name
        require(path.is_file() and not path.is_symlink(), 'Missing or symbolic-link source: ' + name)
        data = path.read_bytes()
        require(0 < len(data) <= MAX_SOURCE_BYTES, 'Invalid source size: ' + name)
        require(b'\r' not in data, 'Use LF line endings, not CRLF: ' + name)
        text = data.decode('utf-8')
        require(not text.startswith('\ufeff'), 'UTF-8 BOM is not allowed: ' + name)
        blobs[name] = data
    require(sum(map(len, blobs.values())) <= MAX_SOURCE_BYTES, 'Source bundle is too large.')
    manager = blobs['anytls-manager.sh'].decode('utf-8')
    versions = re.findall(r'^readonly MANAGER_VERSION=(' + SEMVER + r')$', manager, re.MULTILINE)
    require(len(versions) == 1, 'Expected one strict readonly MANAGER_VERSION=X.Y.Z line.')
    return versions[0], blobs


def write_atomic(path, data):
    require(not path.is_symlink(), 'Refusing a symbolic-link output: ' + str(path))
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def build(root, output_dir=None, tag=None):
    root = Path(root).resolve()
    version, blobs = read_sources(root)
    expected_tag = 'v' + version
    require(tag is None or tag == expected_tag,
            'Tag must match the source version exactly: ' + expected_tag)
    manifest = {
        'product': 'gz-anytls-manager', 'version': version,
        'update_protocol': 1, 'state_schema': 2, 'min_manager_version': '1.2.0',
        'files': {name: sha256(data) for name, data in blobs.items()},
    }
    blobs['manifest.json'] = (json.dumps(manifest, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    blobs['SHA256SUMS.txt'] = ''.join(
        sha256(data) + '  ' + name + '\n' for name, data in blobs.items()
    ).encode('ascii')

    output = Path(output_dir) if output_dir else root / 'dist'
    require(not output.is_symlink(), 'Output directory must not be a symbolic link.')
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve()
    directory_name = 'GZ-AnyTLS-Manager-' + version
    archive = output / (directory_name + '.zip')
    require(not archive.is_symlink(), 'Refusing a symbolic-link archive.')
    fd, temporary = tempfile.mkstemp(prefix='.' + directory_name + '-', suffix='.zip', dir=output)
    os.close(fd)
    try:
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for name, data in blobs.items():
                info = zipfile.ZipInfo(directory_name + '/' + name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | (0o755 if name.endswith('.sh') else 0o644)) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                bundle.writestr(info, data)
        with zipfile.ZipFile(temporary) as bundle:
            expected = {directory_name + '/' + name for name in blobs}
            require(len(bundle.infolist()) == len(expected) and set(bundle.namelist()) == expected,
                    'Unexpected ZIP member list.')
            require(bundle.testzip() is None, 'ZIP CRC check failed.')
            for info in bundle.infolist():
                require(stat.S_ISREG(info.external_attr >> 16), 'ZIP member is not a regular file.')
                name = info.filename.split('/', 1)[1]
                require(bundle.read(info) == blobs[name], 'ZIP contents differ: ' + name)
            for name, digest in manifest['files'].items():
                require(sha256(bundle.read(directory_name + '/' + name)) == digest,
                        'ZIP manifest verification failed: ' + name)
        os.replace(temporary, archive)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    digest = sha256(archive.read_bytes())
    write_atomic(Path(str(archive) + '.sha256'), (digest + '  ' + archive.name + '\n').encode('ascii'))
    return {'version': version, 'tag': expected_tag, 'archive': str(archive),
            'sha256': digest, 'bytes': archive.stat().st_size, 'members': len(blobs)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--tag', help='Require the release tag to equal v plus MANAGER_VERSION.')
    parser.add_argument('--github-output', type=Path, help='Append safe build metadata for GitHub Actions.')
    args = parser.parse_args()
    result = build(args.root, args.output_dir, args.tag)
    if args.github_output:
        # All values are version-derived or controlled build paths, never source text.
        archive = Path(result['archive'])
        root = args.root.resolve()
        require(archive.is_relative_to(root), 'GitHub output archive must be inside the repository root.')
        values = {'version': result['version'], 'tag': result['tag'],
                  'archive': archive.relative_to(root).as_posix(), 'sha256': result['sha256']}
        require(all('\n' not in value and '\r' not in value for value in values.values()),
                'Invalid multiline GitHub output.')
        with args.github_output.open('a', encoding='utf-8', newline='\n') as stream:
            for key, value in values.items():
                stream.write(key + '=' + value + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError, zipfile.BadZipFile) as exc:
        print('Build failed: ' + str(exc), file=sys.stderr)
        sys.exit(1)
