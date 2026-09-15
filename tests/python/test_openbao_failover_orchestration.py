"""Run the fixed plays with real plan/guard transitions and offline target I/O.

The doubles translate only ownership/storage and source identity, simulate time,
service and network observations. They do not establish live VRRP or TLS health.
"""
from __future__ import annotations

import json
import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from ansible_test_helpers import run_playbook

HOSTS = ['bao-1', 'bao-2', 'bao-3']
PLAYBOOK = 'playbooks/maintenance/openbao-haproxy-failover.yml'

ACTION = r'''
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch
from ansible.plugins.action import ActionBase

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        v = dict(task_vars or {})
        root = Path(v['openbao_test_root'])
        host = v['inventory_hostname']
        action = self._task.action.rsplit('.', 1)[-1]
        args = self._task.args
        def event(phase, **extra):
            with (root / ('events-' + host + '.jsonl')).open('a') as f:
                f.write(json.dumps(dict(host=host, phase=phase, **extra)) + '\n')
        def out(stdout='', **extra):
            return dict(changed=False, rc=0, stdout=stdout, stdout_lines=stdout.splitlines(), **extra)
        stopped = (root / 'stopped').exists()
        clock = root / ('clock-' + host)
        if action == 'setup':
            return dict(changed=False, ansible_facts={})
        if action == 'pause':
            if 'prompt' in args:
                event('approval')
                # Exact approval comparison in production tasks remains real.
                return dict(changed=False, user_input=v.get('test_approval', args['prompt'].removeprefix('Type exactly ')))
            event('wait', seconds=int(args['seconds']), offset=v.get('openbao_failover_settle_offset'))
            clock.write_text(str((float(clock.read_text()) if clock.exists() else 100.0) + int(args['seconds'])))
            return dict(changed=False)
        if action == 'systemd_service':
            assert args == dict(name='haproxy.service', state=args['state'])
            assert host == 'bao-1'
            state = args['state']
            event(state)
            if state == 'stopped':
                (root / 'stopped').touch()
            elif state == 'started':
                if v.get('test_restore_failure'):
                    return dict(failed=True, msg='offline start failure')
                (root / 'stopped').unlink(missing_ok=True)
            else:
                raise AssertionError(args)
            if state == 'stopped' and v.get('test_stop_unreachable'):
                return dict(unreachable=True, msg='lost stop response')
            return dict(changed=True, state=state)
        if action == 'stat':
            checksum = v['test_keepalived_checksum'] if args['path'].endswith('keepalived.conf') else 'c' * 64
            if v.get('test_config_drift') and (root / 'bao-1/active').exists():
                checksum = 'd' * 64
            return dict(changed=False, stat=dict(exists=True, isreg=True, islnk=False, uid=0, checksum=checksum))
        assert action == 'command', (action, args)
        argv = list(map(str, args['argv']))
        if argv[:2] == ['/usr/bin/python3', '-c']:
            if len(argv) == 3:
                return out(clock.read_text() if clock.exists() else '100.0')
            phase = argv[-1]
            request = json.loads(args['stdin'])
            event(phase)
            if v.get('test_claim_failure') == host and phase == 'claim':
                return dict(changed=False, rc=1, stdout='')
            if v.get('test_restore_peer_unreachable') == host and phase == 'restore':
                return dict(unreachable=True, msg='offline peer unreachable')
            if v.get('test_inspect_unreachable') == host and phase == 'inspect':
                return dict(unreachable=True, msg='offline inspection unreachable')
            g = {'__name__': 'offline_guard'}
            exec(compile(argv[2], '<real failover guard>', 'exec'), g)
            g['ROOT'] = root / host
            uid, gid = os.getuid(), os.getgid()
            lstat, fstat = Path.lstat, os.fstat
            def owned(info):
                fields = list(info)
                if fields[4] == uid: fields[4] = 0
                if fields[5] == gid: fields[5] = 0
                return os.stat_result(fields)
            directory = g['_directory']
            g['_directory'] = lambda path, private=False: directory(path, private) if path.is_relative_to(root) else None
            with patch('os.geteuid', lambda: 0), patch.object(Path, 'lstat', lambda p: owned(lstat(p))), patch('os.fstat', lambda fd: owned(fstat(fd))):
                try:
                    result = g['guard'](phase, request)
                except (ValueError, OSError) as e:
                    return dict(changed=False, rc=1, stdout='', msg=str(e))
            return out(json.dumps(result))
        event('probe', argv=argv, stopped=stopped)
        if argv[0] == 'ip':
            if stopped and v.get('test_proof_fault') == 'unreachable' and host == 'bao-3':
                return dict(unreachable=True, msg='offline address unreachable')
            owner = 'bao-2' if stopped else 'bao-1'
            if stopped and v.get('test_proof_fault') == 'same-owner': owner = 'bao-1'
            owners = [owner]
            if stopped and v.get('test_proof_fault') == 'duplicate': owners.append('bao-3')
            return out(json.dumps([dict(ifname='eth0', addr_info=[dict(local='192.0.2.200')] if host in owners else [])]))
        if argv[0] == 'systemctl':
            if argv[2] == 'haproxy.service' and stopped:
                assert host == 'bao-1', 'intentional fault must inspect only the stopped owner'
                assert argv[1] in {'is-active', 'is-enabled'}
                fault = v.get('test_stop_observation', '')
                if fault == 'unreachable':
                    return dict(unreachable=True, msg='offline stopped service observation unreachable')
                if fault == 'unknown':
                    return dict(changed=False, rc=4, stdout='unknown')
                if argv[1] == 'is-active':
                    stdout, rc = ('active', 0) if fault == 'still-active' else ('inactive', 3)
                    if fault == 'failed': stdout = 'failed'
                    if fault == 'inactive-wrong-rc': rc = 0
                    return dict(changed=False, rc=rc, stdout=stdout, stdout_lines=[stdout])
                if fault == 'disabled':
                    return dict(changed=False, rc=1, stdout='disabled', stdout_lines=['disabled'])
                return out('enabled')
            return out('active' if argv[1] == 'is-active' else 'enabled')
        if argv[0] == 'getent':
            return out('192.0.2.200 STREAM bao.example.invalid')
        if argv[0] == 'curl':
            if '--output' in argv:
                assert not stopped, 'all-HAProxy smoke ran during intentional fault'
                return out('200')
            body = dict(initialized=True, sealed=False, standby=False, cluster_id='test-cluster')
            if stopped and v.get('test_proof_fault') == 'identity': body['cluster_id'] = 'foreign'
            if stopped and v.get('test_proof_fault') == 'tls':
                return dict(failed=True, rc=60, msg='offline strict TLS failure')
            return out(json.dumps(body) + '\n200 192.0.2.200')
        raise AssertionError(argv)
'''

PLAN_ACTION = r'''
import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch
root = Path(__file__).parents[1]
sys.path.insert(0, str(root / 'plugins/module_utils'))
spec = importlib.util.spec_from_file_location('real_failover_action', root / 'plugins/action/openbao_failover_plan.py')
real = importlib.util.module_from_spec(spec)
spec.loader.exec_module(real)
class ActionModule(real.ActionModule):
    def run(self, tmp=None, task_vars=None):
        def source(path):
            return ('a' * 40, 'ansible.cfg') if str(path).endswith('ansible.cfg') else ('b' * 40, 'hosts.yml')
        with patch.object(real.plans.base, 'source_identity', source):
            return super().run(tmp, task_vars)
'''


@pytest.fixture
def orchestration(repo_root, isolated_test_dir, test_environment):
    root = isolated_test_dir
    fixture = repo_root / 'tests/fixtures/openbao-vip-smoke'
    for directory in ('playbooks/maintenance/tasks', 'playbooks/tasks', 'action_plugins',
                      'plugins/action', 'plugins/module_utils', 'roles/openbao/files',
                      'roles/keepalived_vip/templates'):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for source in (repo_root / 'playbooks/maintenance/tasks').glob('openbao-failover-*.yml'):
        text = source.read_text()
        for name in ('command', 'pause', 'stat', 'systemd_service', 'setup'):
            text = text.replace(f'ansible.builtin.{name}:', f'ansible.legacy.{name}:')
        (root / 'playbooks/maintenance/tasks' / source.name).write_text(text)
    text = (repo_root / PLAYBOOK).read_text().replace('ansible.builtin.setup:', 'ansible.legacy.setup:')
    (root / PLAYBOOK).write_text(text)
    for name in ('openbao-smoke.yml', 'openbao-vip-status.yml', 'openbao-vip-sample.yml'):
        text = (repo_root / 'playbooks/tasks' / name).read_text()
        for action in ('command', 'pause'):
            text = text.replace(f'ansible.builtin.{action}:', f'ansible.legacy.{action}:')
        (root / 'playbooks/tasks' / name).write_text(text)
    shutil.copytree(fixture / 'roles', root / 'roles', dirs_exist_ok=True)
    shutil.copyfile(repo_root / 'roles/keepalived_vip/tasks/validate_lifecycle.yml',
                    root / 'roles/keepalived_vip/tasks/validate_lifecycle.yml')
    shutil.copyfile(repo_root / 'roles/keepalived_vip/templates/keepalived.conf.j2',
                    root / 'roles/keepalived_vip/templates/keepalived.conf.j2')
    for relative in ('roles/openbao/files/platform-openbao-failover-guard',
                     'plugins/action/openbao_failover_plan.py',
                     'plugins/module_utils/platform_openbao_failover_plan.py',
                     'plugins/module_utils/platform_openbao_activation_plan.py'):
        shutil.copyfile(repo_root / relative, root / relative)
    for name in ('command', 'pause', 'setup', 'stat', 'systemd_service'):
        (root / 'action_plugins' / f'{name}.py').write_text(ACTION)
    (root / 'action_plugins/openbao_failover_plan.py').write_text(PLAN_ACTION)
    inventory = yaml.safe_load((fixture / 'inventory.yml').read_text())
    variables = inventory['all']['vars']
    variables.update(platform_environment='fixture', openbao_haproxy_enabled=True,
                     openbao_haproxy_service_enabled=True, openbao_haproxy_service_state='started',
                     openbao_status_request_timeout=5,
                     keepalived_vip_preempt_delay=60, keepalived_vip_script_interval=1,
                     keepalived_vip_script_rise=2, keepalived_vip_script_fall=1,
                     keepalived_vip_script_timeout=1, keepalived_vip_script_name='ready',
                     keepalived_vip_script_path='/fixture/check', keepalived_vip_script_user='fixture',
                     keepalived_vip_script_group='fixture', keepalived_vip_router_id='{{ inventory_hostname }}',
                     test_keepalived_checksum="{{ lookup('ansible.builtin.template', playbook_dir ~ '/../../roles/keepalived_vip/templates/keepalived.conf.j2') | hash('sha256') }}")
    for n, host in enumerate(HOSTS):
        inventory['all']['children']['openbao']['hosts'][host] = dict(keepalived_vip_instances=[dict(
            name='OPENBAO', interface='eth0', virtual_router_id=51, priority=150-n*10,
            source_address=f'192.0.2.{11+n}', peers=[f'192.0.2.{11+i}' for i in range(3) if i != n],
            vip='192.0.2.200/24')])
    (root / 'inventory.yml').write_text(yaml.safe_dump(inventory))
    environment = dict(test_environment, ANSIBLE_FORCE_COLOR='0', ANSIBLE_ROLES_PATH=str(root / 'roles'),
                       ANSIBLE_ACTION_PLUGINS=str(root / 'action_plugins'))
    with tempfile.TemporaryDirectory(prefix='failover-orchestration-', dir='/tmp') as directory:
        yield root, environment, Path(directory) / 'plan.json'


def run(command_runner, fixture, mode, variables=None, limit='openbao', omit_path=False):
    root, environment, path = fixture
    arguments = {'openbao_test_root': str(root), 'openbao_tls_ca_src': '/fixture/ca.crt',
                 'openbao_failover_mode': mode}
    if mode != 'recover' and not omit_path:
        arguments['openbao_failover_plan_path'] = str(path)
    arguments.update(variables or {})
    return run_playbook(command_runner, root / PLAYBOOK, inventory=root / 'inventory.yml',
                        limit=limit, environment=environment, timeout=90, extra_vars=(arguments,))


def events(fixture):
    return [json.loads(line) for path in fixture[0].glob('events-*.jsonl')
            for line in path.read_text().splitlines()]


def records(fixture):
    return [json.loads(path.read_text()) for path in sorted(fixture[0].glob('bao-*/consumed/*'))]


def summaries(result):
    """Extract the real sanitized debug payloads from the default YAML callback."""
    import re
    reports = [yaml.safe_load(block) for block in re.findall(
        r'(?m)^    msg:\n((?:        [^\n]*\n)+)', result.stdout)
        if 'failover_test_result:' in block]
    assert reports, result.stdout
    return reports


def configure_ci(fixture, mode='plan', pipeline='42'):
    fixture[1].update(CI='true', CI_PIPELINE_SOURCE='web', CI_COMMIT_REF_PROTECTED='true',
                      CI_DEFAULT_BRANCH='main', CI_COMMIT_BRANCH='main', CI_COMMIT_SHA='b' * 40,
                      CI_PROJECT_ID='41', CI_PIPELINE_ID=pipeline, CI_JOB_MANUAL='true',
                      CI_JOB_IMAGE='registry.invalid/tool@sha256:' + 'c' * 64,
                      CI_JOB_NAME='fixture-haproxy-failover-' + mode)


def seed_retained(repo_root, fixture, phase, *, hosts=HOSTS, expired=False):
    """Real interrupted guard transitions; no service command is used to seed."""
    root, _, path = fixture
    plan = json.loads(path.read_text())
    if expired:
        plan['created'] -= 90000
        plan['expires'] -= 90000
        body = {k: v for k, v in plan.items() if k != 'digest'}
        plan['digest'] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':'),
                                                  ensure_ascii=True).encode()).hexdigest()
    guard: dict[str, Any] = {'__name__': 'seed_guard'}
    exec(compile((repo_root / 'roles/openbao/files/platform-openbao-failover-guard').read_text(),
                 '<real seed guard>', 'exec'), guard)
    uid, gid = os.getuid(), os.getgid()
    lstat, fstat = Path.lstat, os.fstat
    def owned(info):
        fields = list(info)
        if fields[4] == uid:
            fields[4] = 0
        if fields[5] == gid:
            fields[5] = 0
        return os.stat_result(fields)
    directory = guard['_directory']
    guard['_directory'] = lambda p, private=False: directory(p, private) if p.is_relative_to(root) else None
    with patch('os.geteuid', lambda: 0), patch.object(Path, 'lstat', lambda p: owned(lstat(p))), \
            patch('os.fstat', lambda fd: owned(fstat(fd))), patch('time.time', lambda: plan['created']):
        for host in hosts:
            guard['ROOT'] = root / host
            request = dict(host=host, plan=plan, nonce=plan['nonce'])
            guard['guard']('claim', request)
            if phase != 'claimed' and host == plan['owner']:
                guard['guard']('arm', request)
            if phase == 'failover-proven':
                guard['guard']('prove', request)
            if phase == 'restoring':
                guard['guard']('restore', request)
    if phase != 'claimed':
        (root / 'stopped').touch()


def test_read_only_plan_then_one_stop_and_closed_replay(orchestration, command_runner):
    plan_result = run(command_runner, orchestration, 'plan').assert_success()
    assert len(summaries(plan_result)) == 3
    assert all(s['failover_elapsed_seconds'] is None and s['transaction_elapsed_seconds'] is None
               for s in summaries(plan_result))
    assert not records(orchestration)
    assert not any(e['phase'] == 'approval' for e in events(orchestration))
    test_result = run(command_runner, orchestration, 'test').assert_success()
    assert all(0 < s['failover_elapsed_seconds'] < s['transaction_elapsed_seconds']
               for s in summaries(test_result))
    assert [r['phase'] for r in records(orchestration)] == ['closed'] * 3
    assert [r['outcome'] for r in records(orchestration)] == ['proven'] * 3
    assert not list(orchestration[0].glob('bao-*/active'))
    before = events(orchestration)
    assert [e['host'] for e in before if e['phase'] == 'stopped'] == ['bao-1']
    assert [e['host'] for e in before if e['phase'] == 'started'] == ['bao-1']
    replay_result = run(command_runner, orchestration, 'test').assert_success()
    assert len(summaries(replay_result)) == 3
    assert all(s['failover_elapsed_seconds'] is None and s['transaction_elapsed_seconds'] is None
               for s in summaries(replay_result))
    assert len([e for e in events(orchestration) if e['phase'] == 'stopped']) == 1
    assert len([e for e in events(orchestration) if e['phase'] == 'started']) == 1


@pytest.mark.parametrize('fault', ['same-owner', 'duplicate', 'identity', 'tls', 'unreachable'])
def test_failed_proof_restores_owner_but_stays_failed(orchestration, command_runner, fault):
    run(command_runner, orchestration, 'plan').assert_success()
    result = run(command_runner, orchestration, 'test', {'test_proof_fault': fault})
    result.assert_failure()
    assert 'recovery_result: passed' in result.stdout
    assert 'failover_test_result: failed' in result.stdout
    assert len(summaries(result)) == 3
    assert all(s['failover_elapsed_seconds'] is None and s['transaction_elapsed_seconds'] > 0
               for s in summaries(result))
    assert [r['phase'] for r in records(orchestration)] == ['closed'] * 3
    assert [r['outcome'] for r in records(orchestration)] == ['failed'] * 3
    assert [e['host'] for e in events(orchestration) if e['phase'] == 'started'] == ['bao-1']
    run(command_runner, orchestration, 'test').assert_failure()
    assert len([e for e in events(orchestration) if e['phase'] == 'stopped']) == 1


@pytest.mark.parametrize('variables', [
    {'test_stop_unreachable': True}, {'test_restore_peer_unreachable': 'bao-3'},
])
def test_post_stop_unreachable_still_attempts_reachable_owner_restore(orchestration, command_runner, variables):
    run(command_runner, orchestration, 'plan').assert_success()
    run(command_runner, orchestration, 'test', variables).assert_failure()
    assert [e['host'] for e in events(orchestration) if e['phase'] == 'started'] == ['bao-1']
    assert not (orchestration[0] / 'stopped').exists()


@pytest.mark.parametrize('fault', ['still-active', 'disabled', 'failed', 'inactive-wrong-rc', 'unknown', 'unreachable'])
def test_bad_actual_stop_observation_restores_owner_without_proof(orchestration, command_runner, fault):
    run(command_runner, orchestration, 'plan').assert_success()
    result = run(command_runner, orchestration, 'test', {'test_stop_observation': fault})
    result.assert_failure()
    assert 'recovery_result: passed' in result.stdout
    assert len(summaries(result)) == 3
    assert all(s['failover_test_result'] == 'failed' and s['failover_elapsed_seconds'] is None
               for s in summaries(result))
    observed = events(orchestration)
    assert [e['host'] for e in observed if e['phase'] == 'started'] == ['bao-1']
    assert not any(e['phase'] == 'prove' for e in observed)
    assert not any(e['phase'] == 'probe' and e['stopped'] and e['argv'][0] == 'ip' for e in observed)
    assert {r['outcome'] for r in records(orchestration)} == {'failed'}
    assert {r['phase'] for r in records(orchestration)} == {'closed'}


def test_partial_claim_cleanup_never_claims_missing_peer(orchestration, command_runner):
    run(command_runner, orchestration, 'plan').assert_success()
    run(command_runner, orchestration, 'test', {'test_claim_failure': 'bao-3'}).assert_failure()
    assert len(records(orchestration)) == 2
    assert all(r['phase'] == 'closed' and r['outcome'] == 'failed' for r in records(orchestration))
    assert not (orchestration[0] / 'bao-3').exists()
    assert not any(e['phase'] == 'stopped' for e in events(orchestration))


def test_later_recovery_without_artifact_restores_retained_owner(orchestration, command_runner):
    run(command_runner, orchestration, 'plan').assert_success()
    run(command_runner, orchestration, 'test', {'test_restore_failure': True}).assert_failure()
    assert (orchestration[0] / 'stopped').exists()
    orchestration[2].unlink()
    result = run(command_runner, orchestration, 'recover').assert_success()
    assert 'recovery_result: passed' in result.stdout
    assert len(summaries(result)) == 3
    assert all(s['failover_elapsed_seconds'] is None and s['transaction_elapsed_seconds'] is None
               for s in summaries(result))
    assert not (orchestration[0] / 'stopped').exists()
    assert len([e for e in events(orchestration) if e['phase'] == 'stopped']) == 1
    assert all(r['phase'] == 'closed' for r in records(orchestration))


@pytest.mark.parametrize('phase', ['claimed', 'armed', 'failover-proven', 'restoring'])
def test_expired_interrupted_record_recovery_never_stops_again(repo_root, orchestration, command_runner, phase):
    run(command_runner, orchestration, 'plan').assert_success()
    seed_retained(repo_root, orchestration, phase, expired=True)
    orchestration[2].unlink()
    result = run(command_runner, orchestration, 'recover').assert_success()
    assert 'recovery_result: passed' in result.stdout
    assert not any(e['phase'] in {'arm', 'stopped', 'claim'} for e in events(orchestration))
    assert len(records(orchestration)) == 3
    assert all(r['phase'] == 'closed' for r in records(orchestration))
    assert {r['outcome'] for r in records(orchestration)} == ({'proven'} if phase == 'failover-proven' else {'failed'})


def test_partial_armed_state_blocks_without_claim_or_start(repo_root, orchestration, command_runner):
    run(command_runner, orchestration, 'plan').assert_success()
    seed_retained(repo_root, orchestration, 'armed', hosts=HOSTS[:2])
    run(command_runner, orchestration, 'recover').assert_failure()
    assert not any(e['phase'] in {'started', 'arm', 'claim'} for e in events(orchestration))
    assert (orchestration[0] / 'stopped').exists()


def test_different_fresh_artifact_blocks_retained_arm_until_artifact_free_recovery(
    repo_root, orchestration, command_runner,
):
    root, _, old_path = orchestration
    run(command_runner, orchestration, 'plan').assert_success()
    old_id = json.loads(old_path.read_text())['plan_id']
    fresh_path = old_path.with_name('different-fresh-plan.json')
    run(command_runner, orchestration, 'plan', {'openbao_failover_plan_path': str(fresh_path)}).assert_success()
    assert json.loads(fresh_path.read_text())['plan_id'] != old_id
    seed_retained(repo_root, orchestration, 'armed')
    assert [r['phase'] for r in records(orchestration)] == ['armed', 'claimed', 'claimed']
    retained = {path: path.read_bytes() for path in root.glob('bao-*/**/*') if path.is_file()}

    blocked = run(command_runner, orchestration, 'test', {'openbao_failover_plan_path': str(fresh_path)})
    blocked.assert_failure()
    assert 'TASK [Require the artifact to name the already discovered active transaction]' in blocked.stdout
    assert 'TASK [Select the reviewed artifact identity for consumed-result inspection]' not in blocked.stdout
    assert not any(e['phase'] in {'claim', 'arm', 'stopped', 'started'} for e in events(orchestration))
    assert {path: path.read_bytes() for path in root.glob('bao-*/**/*') if path.is_file()} == retained
    assert (root / 'stopped').exists()

    old_path.unlink()
    fresh_path.unlink()
    recovered = run(command_runner, orchestration, 'recover').assert_success()
    reports = summaries(recovered)
    assert len(reports) == 3
    assert all(s['recovery_result'] == 'passed' and s['failover_test_result'] == 'failed' for s in reports)
    assert not any(e['phase'] in {'claim', 'arm', 'stopped'} for e in events(orchestration))
    assert [e['host'] for e in events(orchestration) if e['phase'] == 'started'] == ['bao-1']
    assert not (root / 'stopped').exists()
    assert all(r['phase'] == 'closed' and r['outcome'] == 'failed' and r['plan']['plan_id'] == old_id
               for r in records(orchestration))


def test_real_pause_rejects_non_tty_approval(orchestration, command_runner):
    run(command_runner, orchestration, 'plan').assert_success()
    approval = orchestration[0] / 'playbooks/maintenance/tasks/openbao-failover-approval.yml'
    approval.write_text(approval.read_text().replace('ansible.legacy.pause:', 'ansible.builtin.pause:'))
    run(command_runner, orchestration, 'test').assert_failure()
    assert not records(orchestration)
    assert not any(e['phase'] == 'stopped' for e in events(orchestration))


def test_normal_300_second_preempt_delay_is_fully_observed(orchestration, command_runner):
    variables = {'keepalived_vip_preempt_delay': 300}
    run(command_runner, orchestration, 'plan', variables).assert_success()
    result = run(command_runner, orchestration, 'test', variables).assert_success()
    waits = [e for e in events(orchestration) if e['phase'] == 'wait'
             and e['offset'] is not None and e['host'] == 'bao-1']
    assert [e['offset'] for e in waits] == list(range(0, 309, 10))
    assert sum(e['seconds'] for e in waits) == 309
    assert len(summaries(result)) == 3
    assert all(s['failover_elapsed_seconds'] == 12.0 and s['transaction_elapsed_seconds'] == 325.0
               for s in summaries(result))


def test_ci_protected_fault_and_later_pipeline_recovery(orchestration, command_runner):
    configure_ci(orchestration)
    run(command_runner, orchestration, 'plan').assert_success()
    configure_ci(orchestration, 'test')
    run(command_runner, orchestration, 'test', {'test_restore_failure': True}).assert_failure()
    assert (orchestration[0] / 'stopped').exists()
    configure_ci(orchestration, 'recover', pipeline='43')
    run(command_runner, orchestration, 'recover').assert_success()
    assert not any(e['phase'] == 'approval' for e in events(orchestration))
    assert len([e for e in events(orchestration) if e['phase'] == 'stopped']) == 1
    assert all(r['phase'] == 'closed' for r in records(orchestration))


def test_ci_closed_replay_never_stops_again(orchestration, command_runner):
    configure_ci(orchestration)
    run(command_runner, orchestration, 'plan').assert_success()
    configure_ci(orchestration, 'test')
    run(command_runner, orchestration, 'test').assert_success()
    result = run(command_runner, orchestration, 'test').assert_success()
    assert len([e for e in events(orchestration) if e['phase'] == 'stopped']) == 1
    assert len([e for e in events(orchestration) if e['phase'] == 'started']) == 1
    assert not any(e['phase'] == 'approval' for e in events(orchestration))
    assert all(s['failover_elapsed_seconds'] is None for s in summaries(result))


def test_ci_partial_claim_cleanup_in_test_job_never_claims_missing_peer(orchestration, command_runner):
    configure_ci(orchestration)
    run(command_runner, orchestration, 'plan').assert_success()
    configure_ci(orchestration, 'test')
    result = run(command_runner, orchestration, 'test', {'test_claim_failure': 'bao-3'})
    result.assert_failure()
    assert 'recovery_result: passed' in result.stdout
    assert len(records(orchestration)) == 2
    assert all(r['phase'] == 'closed' and r['outcome'] == 'failed' for r in records(orchestration))
    assert not (orchestration[0] / 'bao-3').exists()
    assert not any(e['phase'] == 'stopped' for e in events(orchestration))


@pytest.mark.parametrize('mode', ['plan', 'test'])
@pytest.mark.parametrize('path', ['', 'relative/plan.json', None, 17])
def test_plan_and_test_require_absolute_artifact_before_inspection(orchestration, command_runner, mode, path):
    result = run(command_runner, orchestration, mode, {'openbao_failover_plan_path': path})
    result.assert_failure()
    assert not events(orchestration)
    assert not records(orchestration)


@pytest.mark.parametrize('mode', ['plan', 'test'])
def test_plan_and_test_reject_missing_artifact_before_inspection(orchestration, command_runner, mode):
    run(command_runner, orchestration, mode, omit_path=True).assert_failure()
    assert not events(orchestration)


@pytest.mark.parametrize('mode,path', [('recover', '/tmp/plan.json'), ('recover', 'relative.json'),
                                       ('recover', None), ('verify', '/tmp/plan.json')])
def test_invalid_mode_or_recovery_artifact_never_inspects(orchestration, command_runner, mode, path):
    run(command_runner, orchestration, mode, {'openbao_failover_plan_path': path}).assert_failure()
    assert not events(orchestration)


@pytest.mark.parametrize('variable,value', [
    ('openbao_status_request_timeout', 0), ('openbao_status_request_timeout', 6),
    ('openbao_status_retries', 0), ('openbao_status_retries', 11),
    ('openbao_status_retry_delay', -1), ('openbao_status_retry_delay', 3),
    ('openbao_status_stability_observations', 1), ('openbao_status_stability_observations', 4),
    ('openbao_status_stability_delay', 0), ('openbao_status_stability_delay', 3),
    ('openbao_status_request_timeout', True), ('openbao_status_retries', '10'),
])
def test_status_timing_envelope_rejects_out_of_bounds_before_inspection(
    orchestration, command_runner, variable, value,
):
    result = run(command_runner, orchestration, 'plan', {variable: value})
    result.assert_failure()
    assert 'Failover status timing must meet its per-field budget' in result.stdout
    assert not events(orchestration)
    assert not orchestration[2].exists()


@pytest.mark.parametrize('values', [(1, 1, 0, 2, 1), (5, 10, 2, 3, 2)])
def test_status_timing_envelope_accepts_boundaries_including_zero_retry_delay(
    orchestration, command_runner, values,
):
    variables = dict(zip(('openbao_status_request_timeout', 'openbao_status_retries',
                          'openbao_status_retry_delay', 'openbao_status_stability_observations',
                          'openbao_status_stability_delay'), values))
    run(command_runner, orchestration, 'plan', variables).assert_success()
    assert orchestration[2].is_file()
    assert not records(orchestration)


@pytest.mark.parametrize('variable,value', [
    ('keepalived_vip_preempt_delay', 61), ('keepalived_vip_advert_interval', 2),
    ('keepalived_vip_script_interval', 2), ('keepalived_vip_script_fall', 2),
    ('keepalived_vip_script_rise', 3), ('openbao_status_request_timeout', 4),
    ('openbao_status_retries', 9), ('openbao_status_retry_delay', 0),
    ('openbao_status_stability_observations', 3), ('openbao_status_stability_delay', 2),
])
def test_timing_envelope_rejects_in_range_nonfirst_host_drift(
    orchestration, command_runner, variable, value,
):
    inventory = orchestration[0] / 'inventory.yml'
    data = yaml.safe_load(inventory.read_text())
    data['all']['children']['openbao']['hosts']['bao-3'][variable] = value
    inventory.write_text(yaml.safe_dump(data))
    run(command_runner, orchestration, 'plan').assert_failure()
    assert not events(orchestration)
    assert not orchestration[2].exists()


@pytest.mark.parametrize('limit', [None, 'bao-1', 'openbao,other'])
def test_inexact_selection_never_inspects_or_mutates(orchestration, command_runner, limit):
    run(command_runner, orchestration, 'test', limit=limit).assert_failure()
    assert not events(orchestration)


@pytest.mark.parametrize('variables', [
    {'test_approval': 'yes'}, {'test_config_drift': True}, {'test_inspect_unreachable': 'bao-3'},
])
def test_pre_stop_failures_never_stop(orchestration, command_runner, variables):
    run(command_runner, orchestration, 'plan').assert_success()
    run(command_runner, orchestration, 'test', variables).assert_failure()
    assert not any(e['phase'] == 'stopped' for e in events(orchestration))


def test_production_fixed_service_and_shared_oracles(repo_root):
    files = [repo_root / PLAYBOOK, repo_root / 'playbooks/tasks/openbao-smoke.yml',
             *(repo_root / 'playbooks/maintenance/tasks').glob('openbao-failover-*.yml')]
    services = []
    def walk(tasks):
        for task in tasks:
            for branch in ('tasks', 'block', 'rescue', 'always'):
                walk(task.get(branch, []))
            if 'ansible.builtin.systemd_service' in task:
                services.append(task['ansible.builtin.systemd_service'])
    for path in files:
        walk(yaml.safe_load(path.read_text()))
    assert sorted(services, key=lambda s: s['state']) == [
        {'name': 'haproxy.service', 'state': 'started'}, {'name': 'haproxy.service', 'state': 'stopped'}]
    assert 'openbao-vip-status.yml' in (repo_root / 'playbooks/maintenance/tasks/openbao-failover-test.yml').read_text()
    assert 'tasks/openbao-smoke.yml' in (repo_root / 'playbooks/openbao-smoke.yml').read_text()
    assert '../../tasks/openbao-smoke.yml' in (
        repo_root / 'playbooks/maintenance/tasks/openbao-failover-full-smoke.yml').read_text()
    assert not (repo_root / 'playbooks/maintenance/tasks/openbao-failover-smoke.yml').exists()
