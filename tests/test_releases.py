"""A release becomes public only after every uploaded asset is verified."""
import hashlib
import importlib.util
import json
from pathlib import Path
from urllib.error import HTTPError

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('release_script', ROOT / 'scripts' / 'release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


@pytest.fixture
def assets(tmp_path):
    name = f'WinHardenSetup-{release.VERSION}.exe'
    payload = b'MZ-complete-installer'
    (tmp_path / name).write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    (tmp_path / (name + '.sha256')).write_text(f'{digest}  {name}\n')
    (tmp_path / 'dependencies.json').write_text(json.dumps([{'name': 'PySide6', 'version': 'test'}]))
    return tmp_path


def uploaded(folder):
    return [dict(name=p.name, size=p.stat().st_size, state='uploaded',
        digest='sha256:' + hashlib.sha256(p.read_bytes()).hexdigest(),
        browser_download_url=f'https://github.com/{release.REPOSITORY}/releases/download/v{release.VERSION}/{p.name}')
        for p in folder.iterdir()]


def mock_publish(monkeypatch, assets, change=None, existing=(), on_publish=None):
    calls = []
    metadata = dict(id=42, draft=True, prerelease=False, tag_name='v' + release.VERSION,
        html_url='https://github.com/' + release.REPOSITORY + '/releases/tag/v' + release.VERSION,
        assets=uploaded(assets))
    if change:
        change(metadata)
    def api(path, method='GET', body=None):
        calls.append((path, method, body))
        if path.startswith('/releases/tags/') or path == '/releases/latest':
            raise HTTPError(path, 404, 'Missing', {}, None)
        if path.startswith('/releases?'):
            return existing
        if method == 'PATCH':
            metadata.update(body)
            if body.get('draft') is False:
                # Publishing binds the release to its tag, which is when GitHub
                # moves its assets off the draft's temporary slug.
                for asset in metadata['assets']:
                    asset['browser_download_url'] = (
                        f'https://github.com/{release.REPOSITORY}/releases/download/'
                        f'v{release.VERSION}/' + asset['name'])
                if on_publish:
                    on_publish(metadata)
        return metadata
    monkeypatch.setenv('GITHUB_REPOSITORY', release.REPOSITORY)
    monkeypatch.setattr(release, 'api', api)
    monkeypatch.setattr(release.subprocess, 'run', lambda args, check: calls.append(('upload', args, None)))
    return calls


def test_complete_release_is_published_after_upload_verification(monkeypatch, assets):
    calls = mock_publish(monkeypatch, assets)
    release.publish(assets, 'v' + release.VERSION)
    publish_at = calls.index(('/releases/42', 'PATCH', {'draft': False, 'make_latest': 'true'}))
    assert next(i for i, c in enumerate(calls) if c[0] == 'upload') < publish_at - 1
    assert next(c for c in calls if c[1] == 'POST')[2]['draft'] is True
    # The published payload is re-read, and nothing withdraws it.
    assert calls[publish_at + 1] == ('/releases/42', 'GET', None)
    assert not [c for c in calls if c[2] == {'draft': True}]


@pytest.mark.parametrize('change', [
    lambda d: d['assets'].pop(),
    lambda d: d['assets'][0].update(digest='sha256:' + '0' * 64),
    lambda d: d['assets'][0].update(size=0),
    lambda d: d.update(draft=False),
])
def test_bad_upload_never_publishes(monkeypatch, assets, change):
    calls = mock_publish(monkeypatch, assets, change)
    with pytest.raises(ValueError):
        release.publish(assets, 'v' + release.VERSION)
    assert not any(c[1] == 'PATCH' for c in calls)


def test_upload_failure_keeps_release_draft(monkeypatch, assets):
    calls = mock_publish(monkeypatch, assets)
    def fail(*args, **kwargs):
        raise RuntimeError('upload interrupted')
    monkeypatch.setattr(release.subprocess, 'run', fail)
    with pytest.raises(RuntimeError):
        release.publish(assets, 'v' + release.VERSION)
    assert not any(c[1] == 'PATCH' for c in calls)


def test_corrupt_local_installer_prevents_any_publish(monkeypatch, assets):
    calls = mock_publish(monkeypatch, assets)
    (assets / f'WinHardenSetup-{release.VERSION}.exe').write_bytes(b'changed')
    with pytest.raises(ValueError):
        release.publish(assets, 'v' + release.VERSION)
    assert calls == []


@pytest.mark.parametrize('tag', ['main', 'v1.1.0', 'v1.2.0-beta', '1.2.0'])
def test_mismatched_tags_cannot_release(tag):
    with pytest.raises(ValueError):
        release.validate_tag(tag)


def test_executable_metadata_and_installer_use_same_version():
    resource = importlib.util.spec_from_file_location('version_resource', ROOT / 'scripts' / 'version-info.py')
    module = importlib.util.module_from_spec(resource)
    resource.loader.exec_module(module)
    text = module.generate(release.VERSION)
    assert f"StringStruct('FileVersion', {release.VERSION!r})" in text
    assert 'filevers=' + repr(tuple(int(p) for p in release.VERSION.split('.')) + (0,)) in text
    installer = (ROOT / 'installer' / 'win-harden.iss').read_text()
    build = (ROOT / 'scripts' / 'build.ps1').read_text()
    assert '/DAppVersion=$version' in build
    assert '#define AppVersion' not in installer


def test_updater_page_is_in_frozen_imports():
    from tests.test_packaging import packaged_objects
    gui = next(n for n in packaged_objects() if n.kind == 'Analysis' and Path(n.args[0][0]).name == 'win-harden.py')
    assert 'win_harden.pages.updates' in gui.kwargs['hiddenimports']


def test_older_tag_cannot_replace_latest(monkeypatch, assets):
    calls = mock_publish(monkeypatch, assets)
    original = release.api
    def api(path, *args):
        if path == '/releases/latest':
            return {'tag_name': 'v9.0.0'}
        return original(path, *args)
    monkeypatch.setattr(release, 'api', api)
    with pytest.raises(ValueError, match='newer'):
        release.publish(assets, 'v' + release.VERSION)
    assert not any(c[1] in ('POST', 'PATCH') or c[0] == 'upload' for c in calls)


def test_draft_slug_urls_do_not_block_publishing(monkeypatch, assets):
    # A draft is not bound to its tag, so GitHub serves its assets under a
    # temporary slug. Publishing must still verify and complete.
    def slugged(metadata):
        for asset in metadata['assets']:
            asset['browser_download_url'] = (
                f'https://github.com/{release.REPOSITORY}/releases/download/untagged-9f8e7d6c/' + asset['name'])
    calls = mock_publish(monkeypatch, assets, change=slugged)
    release.publish(assets, 'v' + release.VERSION)
    assert ('/releases/42', 'PATCH', {'draft': False, 'make_latest': 'true'}) in calls
    assert not [c for c in calls if c[2] == {'draft': True}]


def test_existing_draft_is_reused_instead_of_duplicated(monkeypatch, assets):
    draft = dict(id=42, draft=True, tag_name='v' + release.VERSION)
    calls = mock_publish(monkeypatch, assets, existing=[draft])
    release.publish(assets, 'v' + release.VERSION)
    assert not [c for c in calls if c[1] == 'POST']


def test_published_release_is_withdrawn_when_unusable(monkeypatch, assets):
    # A release GitHub serves differently from what was verified must not be
    # left discoverable just because the draft checks passed.
    def break_on_publish(metadata):
        installer = f'WinHardenSetup-{release.VERSION}.exe'
        next(a for a in metadata['assets'] if a['name'] == installer)[
            'browser_download_url'] = 'https://evil.example/setup.exe'
    calls = mock_publish(monkeypatch, assets, on_publish=break_on_publish)
    with pytest.raises(ValueError):
        release.publish(assets, 'v' + release.VERSION)
    assert calls[-1] == ('/releases/42', 'PATCH', {'draft': True})
