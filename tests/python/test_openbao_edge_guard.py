"""Fast filesystem guard tests and isolated edge-orchestration action doubles."""

import importlib.machinery
import importlib.util
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml


HELPER = 'roles/openbao/files/platform-openbao-edge-guard'
PLAN = 'a' * 32
NONCE = 'b' * 32


@pytest.fixture
def guard(repo_root, tmp_path, monkeypatch):
    loader = importlib.machinery.SourceFileLoader('edge_guard', str(repo_root / HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    monkeypatch.setattr(module, 'ROOT', tmp_path / 'edge')
    monkeypatch.setattr(module.os, 'geteuid', lambda: 0)
    # Isolate tests under tmp_path without host root or changes to /var/lib.
    # Translate the test user's ownership only; retain all real type/mode/link checks.
    uid, gid = os.getuid(), os.getgid()
    original_lstat, original_fstat = Path.lstat, os.fstat

    def owned(info):
        values = list(info)
        if info.st_uid == uid:
            values[4] = 0
        if info.st_gid == gid:
            values[5] = 0
        return os.stat_result(values)

    monkeypatch.setattr(Path, 'lstat', lambda path: owned(original_lstat(path)))
    monkeypatch.setattr(os, 'fstat', lambda fd: owned(original_fstat(fd)))
    directory = module._directory
    monkeypatch.setattr(module, '_directory', lambda path, private=False:
                        directory(path, private) if path.is_relative_to(tmp_path) else None)
    return module


def test_guard_release_retains_consumed_plan_after_success_or_rollback(guard):
    guard.guard('acquire', 'haproxy', PLAN, NONCE)
    owner = json.loads((guard.ROOT / 'active/owner.json').read_text())
    assert owner == {'operation': 'haproxy', 'plan_id': PLAN, 'nonce': NONCE}
    guard.guard('release', 'haproxy', PLAN, NONCE)
    assert not (guard.ROOT / 'active').exists()
    assert (guard.ROOT / 'consumed' / PLAN).exists()
    with pytest.raises(ValueError, match='already consumed'):
        guard.guard('acquire', 'haproxy', PLAN, 'c' * 32)
    guard.guard('acquire', 'keepalived', 'd' * 32, 'c' * 32)


@pytest.mark.parametrize('operation,plan,nonce', [
    ('keepalived', 'c' * 32, 'd' * 32),
    ('haproxy', PLAN, 'd' * 32),
    ('haproxy', PLAN, NONCE),
])
def test_guard_conflict_never_replaces_owner(guard, operation, plan, nonce):
    guard.guard('acquire', 'haproxy', PLAN, NONCE)
    before = (guard.ROOT / 'active/owner.json').read_bytes()
    with pytest.raises((OSError, ValueError)):
        guard.guard('acquire', operation, plan, nonce)
    assert (guard.ROOT / 'active/owner.json').read_bytes() == before


@pytest.mark.parametrize('operation,plan,nonce', [
    ('keepalived', PLAN, NONCE), ('haproxy', 'c' * 32, NONCE),
    ('haproxy', PLAN, 'c' * 32),
])
def test_guard_release_requires_exact_owner(guard, operation, plan, nonce):
    guard.guard('acquire', 'haproxy', PLAN, NONCE)
    with pytest.raises(ValueError, match='another invocation'):
        guard.guard('release', operation, plan, nonce)
    assert (guard.ROOT / 'active/owner.json').exists()


def test_guard_interruption_keeps_incomplete_lock(guard, monkeypatch):
    original = guard._file

    def interrupt(path, flags):
        if path.name == 'owner.json':
            raise OSError('interrupted write')
        return original(path, flags)

    monkeypatch.setattr(guard, '_file', interrupt)
    with pytest.raises(OSError, match='interrupted'):
        guard.guard('acquire', 'haproxy', PLAN, NONCE)
    monkeypatch.setattr(guard, '_file', original)
    with pytest.raises(FileExistsError):
        guard.guard('acquire', 'keepalived', 'c' * 32, 'd' * 32)
    assert (guard.ROOT / 'active').is_dir()


def test_guard_concurrent_edge_routes_have_one_winner(guard):
    def acquire(index):
        try:
            guard.guard('acquire', 'haproxy' if index % 2 else 'keepalived',
                        str(index) * 32, str(index + 1) * 32)
            return True
        except (OSError, ValueError):
            return False

    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(acquire, range(1, 5)))
    assert sum(results) == 1
    assert len(list((guard.ROOT / 'consumed').iterdir())) == 1


def test_guard_requires_root_and_has_no_runtime_path_override(guard, monkeypatch):
    monkeypatch.setattr(guard.os, 'geteuid', lambda: 1000)
    with pytest.raises(ValueError, match='root is required'):
        guard.guard('acquire', 'haproxy', PLAN, NONCE)
    with pytest.raises(TypeError):
        guard.guard('acquire', 'haproxy', PLAN, NONCE, root='/tmp')
    assert not guard.ROOT.exists()


@pytest.mark.parametrize('kind', ['symlink', 'writable', 'wrong-owner'])
def test_guard_rejects_unsafe_root(guard, tmp_path, monkeypatch, kind):
    if kind == 'symlink':
        guard.ROOT.symlink_to(tmp_path, target_is_directory=True)
    else:
        guard.ROOT.mkdir(mode=0o700)
        if kind == 'writable':
            guard.ROOT.chmod(0o777)
        else:
            original = Path.lstat

            def other_owner(path):
                info = list(original(path))
                if path == guard.ROOT:
                    info[4] = 12345
                return os.stat_result(info)

            monkeypatch.setattr(Path, 'lstat', other_owner)
    with pytest.raises(ValueError, match='unsafe guard directory'):
        guard.guard('acquire', 'haproxy', PLAN, NONCE)
    assert not (guard.ROOT / 'active').exists()


@pytest.mark.parametrize('record', ['mutex', 'active/owner.json', 'consumed/' + PLAN])
def test_guard_rejects_symlink_records(guard, tmp_path, record):
    guard.guard('acquire', 'haproxy', PLAN, NONCE)
    path = guard.ROOT / record
    destination = tmp_path / 'untouched'
    destination.write_text('untouched')
    path.unlink()
    path.symlink_to(destination)
    with pytest.raises((OSError, ValueError)):
        guard.guard('release', 'haproxy', PLAN, NONCE)
    assert destination.read_text() == 'untouched'
    assert (guard.ROOT / 'active').exists()


@pytest.mark.parametrize('action,operation,plan,nonce', [
    ('recover', 'haproxy', PLAN, NONCE), ('acquire', 'rolling', PLAN, NONCE),
    ('acquire', 'haproxy', '../other', NONCE), ('acquire', 'haproxy', PLAN, 'A' * 32),
])
def test_guard_rejects_invalid_input_without_writes(guard, action, operation, plan, nonce):
    with pytest.raises(ValueError):
        guard.guard(action, operation, plan, nonce)
    assert not guard.ROOT.exists()


@pytest.mark.parametrize('operation', ['haproxy', 'keepalived'])
def test_edge_playbook_preflight_plan_guard_contract(repo_root, operation):
    path = repo_root / f'playbooks/maintenance/openbao-{operation}-activate.yml'
    source = path.read_text()
    assert source.count(f'include_tasks: tasks/openbao-{operation}-preflight.yml') == 2
    assert source.index('tasks/openbao-edge-acquire.yml') < source.index('Requalify exact')
    verify = next(task for play in yaml.safe_load(source) for task in play['tasks']
                  if 'openbao_activation_plan' in task)
    assert verify['no_log'] is True
    assert verify['run_once'] is True
    assert verify['openbao_activation_plan']['action'] == 'verify'
    assert verify['openbao_activation_plan']['plan'] == '{{ openbao_edge_prepared.plan }}'
    preflight = yaml.safe_load((path.parent / f'tasks/openbao-{operation}-preflight.yml').read_text())
    assert not preflight[0].get('run_once', False)
    assert any("== 'plan' or" in gate for gate in preflight[0]['ansible.builtin.assert']['that'])
    for play in yaml.safe_load(source)[1:]:
        assert play['gather_facts'] is False
        assert play['tasks'][0]['ansible.builtin.meta'] == 'end_play'


# These doubles test orchestration, not the independently owned plugin's provenance policy.
EDGE_ACTION = '''
import hashlib
import json
import uuid
from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        variables = task_vars or {}
        args = self._task.args
        action = self._task.action.rsplit('.', 1)[-1]
        root = Path(variables['openbao_test_root'])
        result = {'changed': False}
        if action == 'edge_plan':
            evidence = args['evidence']
            digest = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
            if args['action'] == 'verify':
                if args['plan']['evidence'] != evidence:
                    return dict(result, failed=True, msg='evidence changed after approval')
                return result
            if args['mode'] == 'ci' and not args['path']:
                return dict(result, failed=True, msg='CI requires plan and provenance')
            plan = {'operation': args['operation'], 'evidence': evidence,
                    'plan_id': uuid.uuid4().hex, 'digest': digest}
            if args['path']:
                path = Path(args['path'])
                if args['mode'] == 'plan':
                    path.write_text(json.dumps(plan))
                else:
                    plan = json.loads(path.read_text())
                    if plan['evidence'] != evidence:
                        return dict(result, failed=True, msg='evidence changed after approval')
            approval = 'activate-openbao-' + args['operation'] + '|' + plan['plan_id'] + '|' + plan['digest']
            return dict(result, plan=plan, approval=approval)
        assert action == 'edge_guard'
        argv = args['argv']
        phase, operation, plan, nonce = argv[-4:]
        host = variables.get('item', variables['inventory_hostname'])
        assert phase in ('acquire', 'release')
        lock = root / (host + '-edge-lock')
        consumed = root / (host + '-consumed-' + plan)
        owner = {'operation': operation, 'plan_id': plan, 'nonce': nonce}
        if phase == 'acquire':
            if host in variables.get('test_guard_conflict', []) or lock.exists() or consumed.exists():
                return dict(result, failed=True, msg='guard conflict')
            lock.write_text(json.dumps(owner))
            consumed.write_text(json.dumps(owner))
        else:
            assert json.loads(lock.read_text()) == owner
            lock.unlink()
        with (root / 'guard-events.jsonl').open('a') as stream:
            stream.write(json.dumps({'phase': phase, 'host': host}) + '\\n')
        return dict(result, changed=True, rc=0)
'''


def shadow_edge_tasks(repo_root, root, operation):
    """Copy only affected sources; real commands must never reach /var/lib in fixtures."""
    maintenance = root / 'playbooks/maintenance'
    tasks = maintenance / 'tasks'
    tasks.mkdir(parents=True, exist_ok=True)
    plugin_dir = root / 'action_plugins'
    plugin_dir.mkdir(exist_ok=True)
    for name in ('edge_plan', 'edge_guard'):
        (plugin_dir / (name + '.py')).write_text(EDGE_ACTION)
    source_dir = repo_root / 'playbooks/maintenance'
    paths = [source_dir / f'openbao-{operation}-activate.yml',
             source_dir / f'tasks/openbao-{operation}-preflight.yml']
    paths += list((source_dir / 'tasks').glob('openbao-edge-*.yml'))
    for path in paths:
        source = path.read_text().replace('openbao_activation_plan:', 'ansible.legacy.edge_plan:')
        if path.name in ('openbao-edge-acquire.yml', 'openbao-edge-release.yml'):
            source = source.replace('ansible.builtin.command:', 'ansible.legacy.edge_guard:')
            # The mock inspects argv only; no target interpreter or lookup is executed.
            source = source.replace("{{ hostvars[item].ansible_facts.python.executable }}", 'python3')
            source = source.replace("{{ ansible_facts.python.executable }}", 'python3')
            source = source.replace("{{ lookup('ansible.builtin.file', playbook_dir ~ '/../../roles/openbao/files/platform-openbao-edge-guard') }}",
                                    'isolated-guard-double')
        if operation == 'haproxy':
            # Bootstrap shadows publish ansible_facts via set_fact, whose higher
            # precedence would hide normal module fact updates. Match that boundary.
            source = source.replace('ansible.builtin.service_facts:',
                                    "ansible.builtin.set_fact:\n"
                                    "    ansible_facts: >-\n"
                                    "      {{ ansible_facts | combine({'services': {"
                                    "'haproxy.service': {'status': 'disabled'}, "
                                    "'keepalived.service': {'status': 'disabled'}}}, recursive=true) }}")
        else:
            for name in ('setup', 'service_facts', 'systemd_service'):
                source = source.replace(f'ansible.builtin.{name}:', f'ansible.legacy.{name}:')
            source = source.replace('ansible.builtin.pause:\n                seconds:',
                                    'ansible.legacy.election_pause:\n                seconds:')
        (maintenance / path.relative_to(source_dir)).write_text(source)
    return maintenance / f'openbao-{operation}-activate.yml'
