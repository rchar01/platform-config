"""Real filesystem transitions and shared activation exclusion in offline fixtures."""
import copy
import importlib.machinery
import importlib.util
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest

from test_openbao_failover_plan import HOSTS, NOW, plan, plans  # noqa: F401
from test_openbao_edge_guard import guard as edge_guard  # noqa: F401


@pytest.fixture
def guard(repo_root, plan, edge_guard, monkeypatch):
    loader = importlib.machinery.SourceFileLoader('failover_guard', str(
        repo_root / 'roles/openbao/files/platform-openbao-failover-guard'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    monkeypatch.setattr(module, 'ROOT', edge_guard.ROOT)
    # Reuse existing ownership translation harness; real modes/links/I/O remain.
    monkeypatch.setattr(module, '_directory', edge_guard._directory)
    monkeypatch.setattr(module.time, 'time', lambda: NOW)
    return module


def request(plan, host=HOSTS[0]):
    return {'plan': copy.deepcopy(plan), 'nonce': plan['nonce'], 'host': host}


def finish(guard, req):
    return guard.guard('finish', {**req, 'smoke_verified': True})


def test_absent_inspect_does_not_create_guard(guard):
    assert guard.guard('inspect', {'host': HOSTS[0]})['status'] == 'absent'
    assert not guard.ROOT.exists()


def test_success_arm_once_close_and_permanent_consumption(guard, plan, edge_guard):
    req = request(plan)
    guard.guard('claim', req)
    assert guard.guard('inspect', {'host': HOSTS[0]})['record']['plan'] == plan
    assert guard.guard('arm', req)['stop_authorized'] is True
    with pytest.raises(ValueError, match='once'):
        guard.guard('arm', req)
    guard.guard('prove', req)
    assert guard.guard('restore', req)['restore_authorized'] is True
    result = finish(guard, req)
    assert result['record']['outcome'] == 'proven'
    assert result['status'] == 'closed'
    assert not (guard.ROOT / 'active').exists()
    assert (guard.ROOT / 'consumed' / plan['plan_id']).exists()
    assert finish(guard, req)['changed'] is False
    assert guard.guard('restore', req)['restore_authorized'] is False
    assert guard.guard('inspect', {'host': HOSTS[0], 'plan_id': plan['plan_id']})['status'] == 'closed'
    with pytest.raises(ValueError, match='consumed'):
        guard.guard('claim', req)
    with pytest.raises(ValueError, match='consumed'):
        edge_guard.guard('acquire', 'haproxy', plan['plan_id'], 'f' * 32)
    edge_guard.guard('acquire', 'keepalived', 'e' * 32, 'f' * 32)


@pytest.mark.parametrize('phase', ['claimed', 'armed', 'failover-proven', 'restoring'])
def test_interrupted_phases_restore_after_ttl_without_another_stop(guard, plan, monkeypatch, phase):
    req = request(plan)
    guard.guard('claim', req)
    if phase != 'claimed':
        guard.guard('arm', req)
    if phase == 'failover-proven':
        guard.guard('prove', req)
    if phase == 'restoring':
        guard.guard('restore', req)
    monkeypatch.setattr(guard.time, 'time', lambda: NOW + 90000)
    with pytest.raises(ValueError, match='expired'):
        guard.guard('arm', req)
    guard.guard('restore', req)
    result = finish(guard, req)
    assert result['record']['outcome'] == ('proven' if phase == 'failover-proven' else 'failed')


@pytest.mark.parametrize('proved', [False, True])
def test_failed_proof_cannot_be_rewritten_as_success(guard, plan, proved):
    req = request(plan)
    guard.guard('claim', req)
    guard.guard('arm', req)
    if proved:
        guard.guard('prove', req)
    guard.guard('fail', req)
    with pytest.raises(ValueError):
        guard.guard('prove', req)
    guard.guard('restore', req)
    assert finish(guard, req)['record']['outcome'] == 'failed'


def test_peer_never_arms_and_partial_claim_closes_failed(guard, plan):
    req = request(plan, HOSTS[1])
    guard.guard('claim', req)
    with pytest.raises(ValueError, match='owner'):
        guard.guard('arm', req)
    guard.guard('restore', req)
    assert finish(guard, req)['record']['outcome'] == 'failed'


@pytest.mark.parametrize('activation_first', [True, False])
def test_shared_exclusion_never_unlocks_foreign_owner(guard, edge_guard, plan, activation_first):
    req = request(plan)
    if activation_first:
        edge_guard.guard('acquire', 'haproxy', 'e' * 32, 'f' * 32)
    else:
        guard.guard('claim', req)
    before = (guard.ROOT / 'active/owner.json').read_bytes()
    if activation_first:
        for action in ('inspect', 'claim', 'restore'):
            with pytest.raises(ValueError, match='foreign'):
                guard.guard(action, {'host': HOSTS[0]} if action == 'inspect' else req)
    else:
        with pytest.raises((OSError, ValueError)):
            edge_guard.guard('acquire', 'keepalived', 'e' * 32, 'f' * 32)
        with pytest.raises(ValueError):
            edge_guard.guard('release', 'haproxy', plan['plan_id'], plan['nonce'])
    assert (guard.ROOT / 'active/owner.json').read_bytes() == before


@pytest.mark.parametrize('field', ['nonce', 'host', 'plan'])
def test_request_must_match_retained_record(guard, plan, plans, field):
    req = request(plan)
    guard.guard('claim', req)
    changed = copy.deepcopy(req)
    if field == 'nonce':
        changed[field] = 'f' * 32
    elif field == 'host':
        changed[field] = HOSTS[1]
    else:
        changed['plan']['context']['private_sha'] = 'f' * 40
        changed['plan']['digest'] = plans.digest(changed['plan'])
    with pytest.raises(ValueError):
        guard.guard('restore', changed)
    assert guard.guard('inspect', {'host': HOSTS[0]})['status'] == 'claimed'


@pytest.mark.parametrize('relative', ['mutex', 'active/owner.json', 'consumed/PLAN'])
@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'mode', 'malformed', 'duplicate', 'owner'])
def test_unsafe_records_fail_closed(guard, plan, tmp_path, monkeypatch, relative, kind):
    req = request(plan)
    guard.guard('claim', req)
    path = guard.ROOT / relative.replace('PLAN', plan['plan_id'])
    if kind == 'symlink':
        path.unlink()
        path.symlink_to(tmp_path / 'missing')
    elif kind == 'hardlink':
        os.link(path, tmp_path / 'link')
    elif kind == 'mode':
        path.chmod(0o644)
    elif kind == 'owner':
        original = guard.os.fstat

        def wrong_owner(fd):
            value = list(original(fd))
            value[4] = 12345
            return os.stat_result(value)

        monkeypatch.setattr(guard.os, 'fstat', wrong_owner)
    elif relative == 'mutex':
        # Mutex has no JSON payload; test the bounded regular-file requirement.
        path.write_bytes(b'x' * (guard.RECORD_BYTES + 1))
    else:
        path.write_text('{' if kind == 'malformed' else '{"schema":1,"schema":1}')
    with pytest.raises((OSError, ValueError)):
        guard.guard('restore', req)
    assert (guard.ROOT / 'active').exists()


@pytest.mark.parametrize('phase', ['owner', 'consumed', 'transition'])
def test_interrupted_publication_retains_exclusion(guard, plan, monkeypatch, phase):
    req = request(plan)
    original = guard._write
    if phase == 'transition':
        guard.guard('claim', req)

    def interrupt(path, value, replace=False):
        if ((phase == 'owner' and path.name == 'owner.json')
                or (phase == 'consumed' and path.parent.name == 'consumed') or replace):
            raise OSError('simulated interruption')
        return original(path, value, replace)

    monkeypatch.setattr(guard, '_write', interrupt)
    with pytest.raises(OSError, match='interruption'):
        guard.guard('arm' if phase == 'transition' else 'claim', req)
    monkeypatch.setattr(guard, '_write', original)
    assert (guard.ROOT / 'active').is_dir()
    if phase == 'transition':
        # No successful arm response => no caller stop. The surviving claimed
        # record can only be used by recovery, which never invokes arm.
        guard.guard('restore', req)
        assert finish(guard, req)['record']['outcome'] == 'failed'
    else:
        with pytest.raises(ValueError):
            guard.guard('restore', req)


def test_finish_requires_restore_and_boolean_smoke(guard, plan):
    req = request(plan)
    guard.guard('claim', req)
    with pytest.raises(ValueError):
        finish(guard, req)
    guard.guard('restore', req)
    for value in (False, 'true', 1, None):
        with pytest.raises(ValueError):
            guard.guard('finish', {**req, 'smoke_verified': value})
    assert (guard.ROOT / 'active').exists()


def test_concurrent_claims_and_arms_have_one_winner(guard, plan):
    req = request(plan)

    def attempt(action):
        try:
            return guard.guard(action, req)
        except (OSError, ValueError):
            return None

    for action in ('claim', 'arm'):
        with ThreadPoolExecutor(max_workers=4) as workers:
            results = list(workers.map(attempt, [action] * 4))
        winners = [value for value in results if value is not None]
        assert len(winners) == 1
        assert winners[0]['stop_authorized'] is (action == 'arm')


@pytest.mark.parametrize('kind', ['symlink', 'permissions', 'unknown-entry'])
def test_unsafe_root_fails_without_repair(guard, plan, tmp_path, kind):
    if kind == 'symlink':
        guard.ROOT.symlink_to(tmp_path)
    else:
        guard.ROOT.mkdir(mode=0o700)
        if kind == 'permissions':
            guard.ROOT.chmod(0o755)
        else:
            (guard.ROOT / 'unknown').write_text('retain me')
    with pytest.raises((OSError, ValueError)):
        guard.guard('claim', request(plan))
    assert not (guard.ROOT / 'active').exists()


def test_closed_publication_before_release_is_repeatable_without_fault(guard, plan, monkeypatch):
    req = request(plan)
    guard.guard('claim', req)
    guard.guard('arm', req)
    guard.guard('restore', req)
    original = Path.unlink

    def interrupt(path, *args, **kwargs):
        if path.name == 'owner.json':
            raise OSError('interrupted release')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'unlink', interrupt)
    with pytest.raises(OSError, match='interrupted'):
        finish(guard, req)
    assert guard.guard('inspect', {'host': HOSTS[0]})['status'] == 'closed'
    with pytest.raises(ValueError, match='verification-only'):
        guard.guard('arm', req)
    monkeypatch.setattr(Path, 'unlink', original)
    assert finish(guard, req)['record']['outcome'] == 'failed'
    assert not (guard.ROOT / 'active').exists()


def test_partial_cluster_recovery_leaves_absent_hosts_unclaimed(guard, plan, monkeypatch, tmp_path):
    roots = {host: tmp_path / host for host in HOSTS}
    for host in HOSTS[:2]:
        monkeypatch.setattr(guard, 'ROOT', roots[host])
        guard.guard('claim', request(plan, host))
    for host in HOSTS:
        monkeypatch.setattr(guard, 'ROOT', roots[host])
        result = guard.guard('inspect', {'host': host, 'plan_id': plan['plan_id']})
        if result['status'] == 'absent':
            assert host == HOSTS[2]
            continue
        assert result['record']['phase'] == 'claimed'
        guard.guard('restore', request(plan, host))
        assert finish(guard, request(plan, host))['record']['outcome'] == 'failed'
    assert not roots[HOSTS[2]].exists()


def test_failed_atomic_write_leaves_pending_record_and_blocks_all_recovery(guard, plan, monkeypatch):
    req = request(plan)
    guard.guard('claim', req)

    def interrupted_rename(*args):
        raise OSError('interrupted rename')

    monkeypatch.setattr(guard.os, 'rename', interrupted_rename)
    with pytest.raises(OSError, match='interrupted'):
        guard.guard('arm', req)
    assert any(p.name.startswith('.pending-') for p in (guard.ROOT / 'consumed').iterdir())
    with pytest.raises(ValueError, match='incomplete'):
        guard.guard('restore', req)


def test_actual_root_namespace_filesystem_state_machine(repo_root, namespace_root_runner, plan):
    # Real root ownership and file safety checks, with only the fixed storage
    # root substituted in this in-process test. Production CLI has no override.
    source = f'''
import importlib.machinery, importlib.util, pathlib, tempfile
loader = importlib.machinery.SourceFileLoader('guard', {str(repo_root / 'roles/openbao/files/platform-openbao-failover-guard')!r})
spec = importlib.util.spec_from_loader(loader.name, loader)
g = importlib.util.module_from_spec(spec)
loader.exec_module(g)
with tempfile.TemporaryDirectory(dir='/tmp') as directory:
    root = pathlib.Path(directory)
    g.ROOT = root / 'edge'
    original = g._directory
    g._directory = lambda path, private=False: original(path, private) if path.is_relative_to(root) else None
    g.time.time = lambda: {NOW}
    req = {request(plan)!r}
    assert g.guard('inspect', {{'host': 'bao-1'}})['status'] == 'absent'
    g.guard('claim', req)
    assert (g.ROOT / 'active/owner.json').stat().st_uid == 0
    assert g.guard('arm', req)['stop_authorized']
    g.guard('fail', req)
    g.guard('restore', req)
    result = g.guard('finish', dict(req, smoke_verified=True))
    assert result['record']['outcome'] == 'failed'
    assert not (g.ROOT / 'active').exists()
    assert (g.ROOT / 'consumed' / req['plan']['plan_id']).is_file()
'''
    namespace_root_runner.run(['python3', '-c', source], timeout=15).assert_success()
