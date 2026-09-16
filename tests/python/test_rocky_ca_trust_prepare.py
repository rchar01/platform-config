from __future__ import annotations

import hashlib
import importlib.util
import os
import ssl
import stat
import subprocess
import sys
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_helper(repo_root):
    loader = SourceFileLoader('rocky_ca_trust_prepare', str(repo_root / 'scripts/rocky-ca-trust-prepare'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def certificates(tmp_path_factory):
    directory = tmp_path_factory.mktemp('ca-fixtures')

    def openssl(*args):
        subprocess.run(['openssl', *args], cwd=directory, check=True, capture_output=True, timeout=30)

    for name in ('root', 'other'):
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                '-subj', f'/CN=Test {name}', '-keyout', f'{name}.key', '-out', f'{name}.crt',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Test issuer',
            '-keyout', 'issuer.key', '-out', 'issuer.csr')
    for name, ca, usage, days in (
        ('intermediate', 'TRUE', 'keyCertSign,cRLSign', '2'),
        ('leaf', 'FALSE', 'digitalSignature', '2'),
        ('wrong-usage', 'TRUE', 'cRLSign', '2'),
    ):
        (directory / 'extensions').write_text(f'basicConstraints=critical,CA:{ca}\nkeyUsage=critical,{usage}\n')
        openssl('x509', '-req', '-in', 'issuer.csr', '-CA', 'root.crt', '-CAkey', 'root.key',
                '-set_serial', '2', '-days', days, '-extfile', 'extensions', '-out', f'{name}.crt')
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=repo.example.test',
            '-keyout', 'server.key', '-out', 'server.csr')
    (directory / 'extensions').write_text(
        'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
        'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:repo.example.test\n'
    )
    openssl('x509', '-req', '-in', 'server.csr', '-CA', 'intermediate.crt', '-CAkey', 'issuer.key',
            '-set_serial', '3', '-days', '2', '-extfile', 'extensions', '-out', 'server.crt')
    return {path.stem: path.read_bytes() for path in directory.glob('*.crt')}


def fingerprint(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.decode())).hexdigest()


@pytest.fixture
def sandbox(repo_root, tmp_path, monkeypatch, certificates):
    helper = load_helper(repo_root)
    source = tmp_path / 'source'
    anchors = tmp_path / 'anchors'
    source.mkdir(mode=0o700)
    anchors.mkdir(mode=0o755)
    for name, content in certificates.items():
        (source / f'{name}.crt').write_bytes(content)
        (source / f'{name}.crt').chmod(0o600)
    monkeypatch.setattr(helper, 'ANCHORS', anchors)
    monkeypatch.setattr(helper, 'TLS_BUNDLE', tmp_path / 'tls-bundle.pem')
    monkeypatch.setattr(helper, 'LOCK', tmp_path / 'helper.lock')
    monkeypatch.setattr(helper, 'check_host', lambda hostname: None)

    # Model root ownership and trusted system ancestors outside the sandbox;
    # retain real file types, permissions, links and content within it.
    original_directory = helper.validate_directory
    original_file = helper.validate_file

    def root_info(info):
        values = list(info)
        if info.st_uid == os.getuid():
            values[4:6] = [0, 0]
        return os.stat_result(values)

    def directory_check(path):
        if path in tmp_path.parents:
            return
        info = root_info(path.lstat())
        helper.require(stat.S_ISDIR(info.st_mode), f'not a non-symlink directory: {path}')
        helper.require(info.st_uid == info.st_gid == 0, f'directory must be root:root: {path}')
        helper.require(not stat.S_IMODE(info.st_mode) & 0o022, f'unsafe directory: {path}')

    monkeypatch.setattr(helper, 'validate_directory', directory_check)
    monkeypatch.setattr(helper, 'validate_file', lambda info, path, mode=None: original_file(root_info(info), path, mode))
    monkeypatch.setattr(helper.os, 'fchown', lambda fd, uid, gid: None)
    calls = []
    real_command = helper.run_command

    def command(name, *args, **kwargs):
        calls.append((name, *args))
        if name == 'openssl':
            return real_command(name, *args, **kwargs)
        if name == 'update-ca-trust':
            helper.TLS_BUNDLE.write_bytes(b'\n'.join(p.read_bytes() for p in sorted(anchors.glob('*.crt'))))
            helper.TLS_BUNDLE.chmod(0o644)
        else:
            assert name in ('restorecon', 'matchpathcon'), (name, args)
        return b''

    monkeypatch.setattr(helper, 'run_command', command)
    args = ['--expected-hostname', 'node-01', '--root-file', str(source / 'root.crt'),
            '--root-fingerprint', fingerprint(certificates['root'])]
    extra = ['--intermediate-file', str(source / 'intermediate.crt'),
             '--intermediate-fingerprint', fingerprint(certificates['intermediate'])]
    return SimpleNamespace(helper=helper, source=source, anchors=anchors, args=args,
                           extra=extra, calls=calls, certificates=certificates,
                           directory_check=original_directory, file_check=original_file)


def snapshot(directory):
    return {
        str(p.relative_to(directory)): (p.lstat().st_mode, p.lstat().st_ino,
                                      p.lstat().st_mtime_ns, p.lstat().st_ctime_ns,
                                      p.read_bytes() if p.is_file() else None)
        for p in directory.rglob('*')
    }


@pytest.mark.parametrize('with_intermediate', [False, True])
def test_check_apply_check_and_repeat(sandbox, tmp_path, with_intermediate, capsys):
    s = sandbox
    args = s.args + (s.extra if with_intermediate else [])
    before = snapshot(tmp_path)
    assert s.helper.main(['check', *args]) == 1
    assert snapshot(tmp_path) == before
    assert not s.helper.LOCK.exists()
    assert s.helper.main(['apply', *args, '--confirm', 'node-01:ca-trust']) == 0
    assert len(list(s.anchors.glob('*.crt'))) == (2 if with_intermediate else 1)
    before = snapshot(s.anchors)
    assert s.helper.main(['check', *args]) == 0
    assert snapshot(s.anchors) == before
    assert s.helper.main(['apply', *args, '--confirm', 'node-01:ca-trust']) == 0
    assert snapshot(s.anchors) == before
    assert sum(c[0] == 'update-ca-trust' for c in s.calls) == 2
    assert 'SELECTED CA ANCHORS AND TLS BUNDLE READY' in capsys.readouterr().out


@pytest.mark.parametrize('extra', [
    ['--confirm', 'node-01:ca-trust'], ['--intermediate-file', '/root/inter.crt'],
    ['--intermediate-fingerprint', 'a' * 64], ['--intermediate-name', 'inter.crt'],
    ['--root-file', 'relative.crt'], ['--root-file', '/root/../elsewhere.crt'],
    ['--root-fingerprint', 'A' * 64], ['--root-name', '../escape.crt'],
    ['--expected-hostname', 'node-01 node-02'], ['--root', '/root/file.crt'],
])
def test_reject_invalid_arguments(sandbox, extra):
    with pytest.raises(SystemExit):
        sandbox.helper.parse_arguments(['check', *sandbox.args, *extra])


def test_apply_requires_confirmation_and_distinct_names(sandbox):
    s = sandbox
    with pytest.raises(SystemExit):
        s.helper.parse_arguments(['apply', *s.args])
    with pytest.raises(SystemExit):
        s.helper.parse_arguments(['apply', *s.args, '--confirm', 'different:ca-trust'])
    with pytest.raises(SystemExit):
        s.helper.parse_arguments(['check', *s.args, *s.extra, '--intermediate-name', 'platform-root-ca.crt'])


@pytest.mark.parametrize('kind', ['appended', 'garbage', 'leaf', 'wrong-usage', 'wrong-pin', 'expired', 'other', 'duplicate'])
def test_bad_certificate_stops_before_any_anchor(sandbox, monkeypatch, kind):
    s = sandbox
    data = s.certificates.get(kind, s.certificates['intermediate'])
    if kind == 'appended':
        data += s.certificates['other']
    if kind == 'garbage':
        data += b'garbage\n'
    if kind == 'duplicate':
        data = s.certificates['root']
    (s.source / 'intermediate.crt').write_bytes(data)
    extra = s.extra.copy()
    if kind in ('leaf', 'wrong-usage', 'expired', 'other', 'duplicate'):
        extra[-1] = fingerprint(data)
    if kind == 'wrong-pin':
        extra[-1] = '0' * 64
    if kind == 'expired':
        command = s.helper.run_command

        def future_verification(name, *args, **kwargs):
            if name == 'openssl' and args[0] == 'verify':
                args = ('verify', '-attime', str(int(time.time()) + 3 * 86400), *args[1:])
            return command(name, *args, **kwargs)

        monkeypatch.setattr(s.helper, 'run_command', future_verification)
    assert s.helper.main(['apply', *s.args, *extra, '--confirm', 'node-01:ca-trust']) == 1
    assert not list(s.anchors.iterdir())
    assert not any(c[0] in ('restorecon', 'update-ca-trust') for c in s.calls)


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo', 'writable', 'ancestor-symlink', 'ancestor-writable'])
def test_unsafe_sources_rejected_read_only(sandbox, tmp_path, kind):
    s = sandbox
    source = s.source / 'root.crt'
    if kind in ('symlink', 'fifo'):
        source.unlink()
        if kind == 'symlink':
            source.symlink_to(s.source / 'other.crt')
        else:
            os.mkfifo(source)
    elif kind == 'hardlink':
        os.link(source, s.source / 'alias.crt')
    elif kind == 'writable':
        source.chmod(0o666)
    elif kind == 'ancestor-symlink':
        moved = tmp_path / 'moved'
        s.source.rename(moved)
        s.source.symlink_to(moved, target_is_directory=True)
    else:
        s.source.chmod(0o777)
    assert s.helper.main(['check', *s.args]) == 1
    assert not s.helper.LOCK.exists()
    assert not list(s.anchors.iterdir())


@pytest.mark.parametrize('kind', ['different', 'symlink', 'hardlink', 'mode'])
def test_all_destinations_preflight_before_first_write(sandbox, kind):
    s = sandbox
    target = s.anchors / 'platform-intermediate-ca.crt'
    if kind == 'symlink':
        target.symlink_to(s.source / 'intermediate.crt')
    else:
        target.write_bytes(s.certificates['other' if kind == 'different' else 'intermediate'])
        target.chmod(0o644 if kind != 'mode' else 0o600)
        if kind == 'hardlink':
            os.link(target, s.anchors / 'extra.crt')
    assert s.helper.main(['apply', *s.args, *s.extra, '--confirm', 'node-01:ca-trust']) == 1
    assert not (s.anchors / 'platform-root-ca.crt').exists()
    assert not any(c[0] == 'update-ca-trust' for c in s.calls)


def test_refresh_failure_and_recovery(sandbox, monkeypatch, capsys):
    s = sandbox
    command = s.helper.run_command

    def fail_refresh(name, *args, **kwargs):
        if name == 'update-ca-trust':
            raise s.helper.PreparationError('injected refresh failure')
        return command(name, *args, **kwargs)

    monkeypatch.setattr(s.helper, 'run_command', fail_refresh)
    args = ['apply', *s.args, *s.extra, '--confirm', 'node-01:ca-trust']
    assert s.helper.main(args) == 1
    assert len(list(s.anchors.glob('*.crt'))) == 2
    assert s.helper.main(['check', *s.args, *s.extra]) == 1
    assert 'SELECTED CA ANCHORS AND TLS BUNDLE READY' not in capsys.readouterr().out
    monkeypatch.setattr(s.helper, 'run_command', command)
    assert s.helper.main(args) == 0


def test_stale_extracted_bundle_and_selinux_mismatch(sandbox, monkeypatch):
    s = sandbox
    assert s.helper.main(['apply', *s.args, *s.extra, '--confirm', 'node-01:ca-trust']) == 0
    s.helper.TLS_BUNDLE.write_bytes(s.certificates['root'])
    assert s.helper.main(['check', *s.args, *s.extra]) == 1
    command = s.helper.run_command

    def bad_label(name, *args, **kwargs):
        if name == 'matchpathcon':
            raise s.helper.PreparationError('incorrect SELinux label')
        return command(name, *args, **kwargs)

    monkeypatch.setattr(s.helper, 'run_command', bad_label)
    assert s.helper.main(['check', *s.args]) == 1


def test_extracted_bundle_label_mismatch_fails(sandbox, monkeypatch):
    s = sandbox
    assert s.helper.main(['apply', *s.args, '--confirm', 'node-01:ca-trust']) == 0
    command = s.helper.run_command

    def bad_bundle_label(name, *args, **kwargs):
        if name == 'matchpathcon' and args[-1] == str(s.helper.TLS_BUNDLE):
            raise s.helper.PreparationError('incorrect bundle SELinux label')
        return command(name, *args, **kwargs)

    monkeypatch.setattr(s.helper, 'run_command', bad_bundle_label)
    assert s.helper.main(['check', *s.args]) == 1


def test_production_lock_uses_root_controlled_run_directory(repo_root):
    helper = load_helper(repo_root)
    assert helper.LOCK.parent == Path('/run')
    helper.validate_ancestors(helper.LOCK)


def test_atomic_publication_refuses_racing_destination(sandbox, monkeypatch):
    s = sandbox
    cert = s.helper.prepare(s.helper.parse_arguments(['check', *s.args]))[0]
    link = os.link

    def racing_link(*args, **kwargs):
        cert.destination.write_bytes(b'concurrent owner\n')
        return link(*args, **kwargs)

    monkeypatch.setattr(s.helper.os, 'link', racing_link)
    with pytest.raises(FileExistsError):
        s.helper.publish(cert)
    assert cert.destination.read_bytes() == b'concurrent owner\n'
    assert not list(s.anchors.glob('.platform-ca-*'))


def test_apply_lock_contention_and_unsafe_lock(sandbox):
    s = sandbox
    with s.helper.apply_lock():
        assert s.helper.main(['apply', *s.args, '--confirm', 'node-01:ca-trust']) == 1
    s.helper.LOCK.unlink()
    s.helper.LOCK.symlink_to(s.source / 'root.crt')
    assert s.helper.main(['apply', *s.args, '--confirm', 'node-01:ca-trust']) == 1
    assert not list(s.anchors.iterdir())


def test_metadata_rejects_non_root_owner_and_hardlinks(sandbox):
    info = (sandbox.source / 'root.crt').stat()
    values = list(info)
    values[4:6] = [1234, 0]
    with pytest.raises(sandbox.helper.PreparationError, match='root:root'):
        sandbox.file_check(os.stat_result(values), Path('/root/example.crt'))


def test_existing_manual_crlf_anchor_is_retained(sandbox):
    s = sandbox
    target = s.anchors / 'signet-example.crt'
    target.write_bytes(s.certificates['root'].replace(b'\n', b'\r\n') + b'\r\n')
    target.chmod(0o644)
    before = snapshot(s.anchors)
    assert s.helper.main(['apply', *s.args, '--root-name', target.name, '--confirm', 'node-01:ca-trust']) == 0
    assert snapshot(s.anchors) == before


def test_partial_publication_requires_reviewed_rerun(sandbox, monkeypatch):
    s = sandbox
    publish = s.helper.publish

    def fail_second(certificate):
        if 'intermediate' in certificate.destination.name:
            raise OSError('injected publication failure')
        publish(certificate)

    monkeypatch.setattr(s.helper, 'publish', fail_second)
    args = ['apply', *s.args, *s.extra, '--confirm', 'node-01:ca-trust']
    assert s.helper.main(args) == 1
    assert len(list(s.anchors.glob('*.crt'))) == 1
    assert not any(c[0] == 'update-ca-trust' for c in s.calls)
    assert s.helper.main(['check', *s.args, *s.extra]) == 1
    monkeypatch.setattr(s.helper, 'publish', publish)
    assert s.helper.main(args) == 0


def test_apply_uses_fingerprint_verified_snapshot(sandbox):
    s = sandbox
    selected = s.helper.prepare(s.helper.parse_arguments(['check', *s.args]))
    (s.source / 'root.crt').write_bytes(s.certificates['other'])
    s.helper.apply(selected)
    assert selected[0].destination.read_bytes() == s.certificates['root']


def test_client_store_completes_leaf_only_chain_without_hostname_bypass(sandbox):
    s = sandbox

    def verify_leaf(hostname):
        return s.helper.run_command(
            'openssl', 'verify', '-no-CApath', '-no-CAstore',
            '-CAfile', str(s.helper.TLS_BUNDLE), '-purpose', 'sslserver',
            '-verify_hostname', hostname, data=s.certificates['server'],
        )

    assert s.helper.main(['apply', *s.args, '--confirm', 'node-01:ca-trust']) == 0
    with pytest.raises(s.helper.PreparationError, match='issuer certificate'):
        verify_leaf('repo.example.test')
    assert s.helper.main(['apply', *s.args, *s.extra, '--confirm', 'node-01:ca-trust']) == 0
    assert b'OK' in verify_leaf('repo.example.test')
    with pytest.raises(s.helper.PreparationError, match='hostname mismatch'):
        verify_leaf('wrong.example.test')


@pytest.mark.parametrize('failure', [None, 'hostname', 'os', 'root', 'selinux', 'tool', 'python'])
def test_host_baseline(repo_root, monkeypatch, failure):
    helper = load_helper(repo_root)
    monkeypatch.setattr(helper.os, 'geteuid', lambda: 1000 if failure == 'root' else 0)
    monkeypatch.setattr(helper.platform, 'freedesktop_os_release', lambda: {
        'ID': 'other' if failure == 'os' else 'rocky', 'VERSION_ID': '10.1',
    })
    monkeypatch.setattr(helper.sys, 'version_info', (3, 11) if failure == 'python' else (3, 12))
    monkeypatch.setattr(helper.shutil, 'which', lambda name, path: None if failure == 'tool' else '/usr/bin/' + name)

    def command(name, *args):
        if name == 'hostnamectl':
            return b'wrong-host' if failure == 'hostname' else b'node-01'
        assert name == 'getenforce'
        return b'Disabled' if failure == 'selinux' else b'Enforcing'

    monkeypatch.setattr(helper, 'run_command', command)
    if failure:
        with pytest.raises(helper.PreparationError):
            helper.check_host('node-01')
    else:
        helper.check_host('node-01')
