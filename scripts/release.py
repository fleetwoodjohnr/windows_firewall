"""Validate a tag/artifact and publish a complete GitHub Release from CI."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from win_harden.version import VERSION
from win_harden.updates import REPOSITORY, parse_checksum, parse_release, version_tuple


def validate_tag(tag):
    version_tuple(VERSION)
    if tag != 'v' + VERSION:
        raise ValueError(f'Tag {tag!r} must equal v{VERSION}. Update win_harden/version.py before tagging.')


def validate_artifacts(folder, tag):
    validate_tag(tag)
    filename = f'WinHardenSetup-{VERSION}.exe'
    expected = {filename, filename + '.sha256', 'dependencies.json'}
    files = {p.name: p for p in folder.iterdir() if p.is_file()}
    if set(files) != expected:
        raise ValueError(f'Expected exactly {sorted(expected)}, found {sorted(files)}')
    exe = files[filename]
    if exe.stat().st_size == 0:
        raise ValueError('The installer is empty.')
    with exe.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    from types import SimpleNamespace
    parse_checksum(files[filename + '.sha256'].read_bytes(), SimpleNamespace(filename=filename, digest=digest))
    inventory = json.loads(files['dependencies.json'].read_text(encoding='utf-8-sig'))
    if not isinstance(inventory, list) or not inventory:
        raise ValueError('The dependency inventory is missing.')
    return files, digest


def canonical(release, tag):
    """Rewrite asset URLs to the form publishing will produce.

    A draft is not bound to its tag, so GitHub serves its assets under a
    temporary slug. Checking the draft's own URLs would reject every release.
    """
    assets = [{**asset, 'browser_download_url':
               f'https://github.com/{REPOSITORY}/releases/download/{tag}/{asset["name"]}'}
              for asset in release.get('assets', [])]
    return {**release, 'draft': False, 'assets': assets}


def api(path, method='GET', body=None):
    raw = None if body is None else json.dumps(body).encode()
    request = Request('https://api.github.com/repos/' + REPOSITORY + path, data=raw, method=method,
        headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                 'User-Agent': 'WinHarden-release'})
    with urlopen(request, timeout=60) as response:
        return json.load(response)


def publish(folder, tag):
    files, checksum = validate_artifacts(folder, tag)
    if os.environ.get('GITHUB_REPOSITORY') != REPOSITORY:
        raise ValueError('Release publishing is restricted to the official repository.')
    api('/git/ref/tags/' + tag)
    try:
        latest = api('/releases/latest')
    except HTTPError as exc:
        if exc.code != 404:
            raise
    else:
        latest_tag = latest.get('tag_name', '')
        if not latest_tag.startswith('v') or version_tuple(latest_tag[1:]) >= version_tuple(VERSION):
            raise ValueError('The new release must be newer than the latest public release.')
    # /releases/tags never returns drafts, so a rerun would post a duplicate.
    release = next((r for r in api('/releases?per_page=100') if r.get('tag_name') == tag), None)
    if release is None:
        release = api('/releases', 'POST', {
            'tag_name': tag, 'name': 'Windows Firewall & Hardening ' + VERSION,
            'draft': True, 'prerelease': False, 'generate_release_notes': True,
            'body': f'Download **WinHardenSetup-{VERSION}.exe** below and run the wizard on Windows 11 Intel/AMD x64. '
                    'Python and application dependencies are included. Existing settings and scan history are retained during upgrades. '
                    'This installer is unsigned; Windows may show Unknown publisher. '
                    'Verify the accompanying SHA-256 checksum before running a manually downloaded installer.'})
    if not release.get('draft'):
        raise ValueError('This release is already public. Publish a new version instead of replacing it.')
    subprocess.run(['gh', 'release', 'upload', tag, '--repo', REPOSITORY, '--clobber',
                    *(str(p) for p in files.values())], check=True)
    release = api('/releases/' + str(release['id']))
    assets = release.get('assets', [])
    if {a['name'] for a in assets} != set(files) or len(assets) != len(files):
        raise ValueError('The draft has missing or unexpected release assets.')
    for asset in assets:
        path = files[asset['name']]
        with path.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        if asset.get('state') != 'uploaded' or asset.get('size') != path.stat().st_size or asset.get('digest') != 'sha256:' + digest:
            raise ValueError('Uploaded asset failed verification: ' + asset['name'])
    candidate = parse_release(canonical(release, tag), '0.0.0')
    if candidate is None or candidate.digest != checksum:
        raise ValueError('The uploaded release cannot be consumed by the updater.')
    # All assets are validated before the release becomes discoverable.
    api('/releases/' + str(release['id']), 'PATCH', {'draft': False, 'make_latest': 'true'})
    # The published payload is the one clients parse. Withdraw it if it differs
    # from what was verified, so a bad release is never left discoverable.
    try:
        published = parse_release(api('/releases/' + str(release['id'])), '0.0.0')
        if published is None or published.digest != checksum:
            raise ValueError('The published release cannot be consumed by the updater.')
    except Exception:
        api('/releases/' + str(release['id']), 'PATCH', {'draft': True})
        raise
    print(release['html_url'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--validate-tag', action='store_true')
    parser.add_argument('--artifacts', type=Path)
    args = parser.parse_args()
    tag = os.environ.get('GITHUB_REF_NAME', '')
    if args.validate_tag:
        validate_tag(tag)
    elif args.artifacts:
        publish(args.artifacts, tag)
    else:
        parser.error('--validate-tag or --artifacts is required')
