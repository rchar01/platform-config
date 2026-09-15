"""Offline failover identity/TTL contract; no repositories committed or hosts used."""
import copy
import importlib.util
import tempfile
from pathlib import Path

import pytest

HOSTS = ['bao-1', 'bao-2', 'bao-3']
NOW = 1800000000
CONTEXT = {'config_sha': 'a' * 40, 'private_sha': 'b' * 40, 'inventory': 'hosts.yml',
           'environment': 'fixture', 'lane': 'operator', 'project': '', 'pipeline': '',
           'image': '', 'plan_job': ''}
EVIDENCE = {'vip': '192.0.2.42', 'nodes': {h: {'healthy': True} for h in HOSTS}}


@pytest.fixture
def plans(repo_root, monkeypatch):
    monkeypatch.syspath_prepend(str(repo_root / 'plugins/module_utils'))
    import platform_openbao_failover_plan
    return platform_openbao_failover_plan


@pytest.fixture
def plan(plans):
    with tempfile.TemporaryDirectory(prefix='failover-plan-', dir='/tmp') as directory:
        return plans.prepare('plan', str(Path(directory) / 'plan.json'), HOSTS,
                             copy.deepcopy(CONTEXT), HOSTS[0], copy.deepcopy(EVIDENCE), now=NOW)


def test_exclusive_private_publication_and_test_roundtrip(plans):
    with tempfile.TemporaryDirectory(prefix='failover-plan-', dir='/tmp') as directory:
        path = Path(directory) / 'plan.json'
        plan = plans.prepare('plan', str(path), HOSTS, CONTEXT, HOSTS[0], EVIDENCE, now=NOW)
        assert path.stat().st_mode & 0o777 == 0o600
        assert plans.prepare('test', str(path), HOSTS, CONTEXT, HOSTS[0], EVIDENCE, now=NOW) == plan
        before = path.read_bytes()
        with pytest.raises(FileExistsError):
            plans.prepare('plan', str(path), HOSTS, CONTEXT, HOSTS[0], EVIDENCE, now=NOW)
        assert path.read_bytes() == before
        assert plan['expires'] - plan['created'] == 1800


@pytest.mark.parametrize('now', [NOW - 1, NOW + 1800, NOW + 90000])
def test_expired_fault_rejected_but_retained_recovery_allowed(plans, plan, now):
    with pytest.raises(plans.PlanError, match='expired'):
        plans.validate(plan, 'test', HOSTS, CONTEXT, HOSTS[0], EVIDENCE, now=now)
    assert plans.prepare('recover', '', HOSTS, CONTEXT, plan=plan, now=now) == plan


@pytest.mark.parametrize('field,value', [
    ('config_sha', 'c' * 40), ('private_sha', 'c' * 40), ('inventory', 'other.yml'),
    ('environment', 'other'), ('lane', 'unknown'), ('project', '42'),
    ('image', 'tool@sha256:' + 'd' * 64), ('plan_job', 'other-haproxy-failover-plan'),
])
@pytest.mark.parametrize('mode', ['test', 'recover'])
def test_current_identity_drift_fails_both_routes(plans, plan, field, value, mode):
    with pytest.raises(plans.PlanError):
        plans.validate(plan, mode, HOSTS, {**CONTEXT, field: value}, HOSTS[0], EVIDENCE, now=NOW)


def ci(mode='plan'):
    return {'CI': 'true', 'CI_PIPELINE_SOURCE': 'web', 'CI_COMMIT_REF_PROTECTED': 'true',
            'CI_DEFAULT_BRANCH': 'main', 'CI_COMMIT_BRANCH': 'main',
            'CI_COMMIT_SHA': CONTEXT['private_sha'], 'CI_PROJECT_ID': '41', 'CI_PIPELINE_ID': '42',
            'CI_JOB_IMAGE': 'registry.invalid/tool@sha256:' + 'c' * 64,
            'CI_JOB_NAME': 'fixture-haproxy-failover-' + mode, 'CI_JOB_MANUAL': 'true'}


@pytest.fixture
def source_context(plans, monkeypatch):
    calls = []

    def identity(path):
        calls.append(str(path))
        return (CONTEXT['config_sha'], 'ansible.cfg') if str(path) == 'config' else (CONTEXT['private_sha'], 'hosts.yml')

    monkeypatch.setattr(plans.base, 'source_identity', identity)
    return calls


def test_fixed_ci_jobs_same_pipeline_fault_later_pipeline_restore(plans, plan, source_context):
    contexts = {mode: plans.context('config', 'private', 'fixture', mode, env=ci(mode))
                for mode in ('plan', 'test', 'recover')}
    cleanup = plans.context('config', 'private', 'fixture', 'recover', env=ci('test'))
    assert contexts['plan'] == contexts['test'] == contexts['recover'] == cleanup
    assert source_context == ['config', 'private'] * 4
    plan['context'] = contexts['plan']
    plan['digest'] = plans.digest(plan)
    later = {**contexts['recover'], 'pipeline': '43'}
    with pytest.raises(plans.PlanError):
        plans.validate(plan, 'test', HOSTS, later, HOSTS[0], EVIDENCE, now=NOW)
    assert plans.validate(plan, 'recover', HOSTS, later, now=NOW + 90000) == plan


@pytest.mark.parametrize('pipeline', ['42', '43'])
def test_manual_test_job_can_validate_expired_retained_plan_for_restore_only(
        plans, plan, source_context, pipeline):
    plan['context'] = plans.context('config', 'private', 'fixture', 'plan', env=ci())
    plan['digest'] = plans.digest(plan)
    current = plans.context('config', 'private', 'fixture', 'recover',
                            env={**ci('test'), 'CI_PIPELINE_ID': pipeline})
    assert plans.prepare('recover', '', HOSTS, current, plan=plan, now=NOW + 90000) == plan
    with pytest.raises(plans.PlanError, match='expired'):
        plans.validate(plan, 'test', HOSTS, current, HOSTS[0], EVIDENCE, now=NOW + 90000)
    if pipeline == '42':
        assert plans.validate(plan, 'test', HOSTS, current, HOSTS[0], EVIDENCE, now=NOW) == plan
    else:
        with pytest.raises(plans.PlanError, match='identity changed'):
            plans.validate(plan, 'test', HOSTS, current, HOSTS[0], EVIDENCE, now=NOW)


@pytest.mark.parametrize('field,value', [
    ('config_sha', 'c' * 40), ('private_sha', 'c' * 40), ('inventory', 'other.yml'),
    ('environment', 'other'), ('project', '99'),
    ('image', 'registry.invalid/tool@sha256:' + 'd' * 64),
    ('plan_job', 'other-haproxy-failover-plan'),
])
def test_test_job_recovery_still_binds_retained_identity(plans, plan, source_context, field, value):
    plan['context'] = plans.context('config', 'private', 'fixture', 'plan', env=ci())
    plan['digest'] = plans.digest(plan)
    current = plans.context('config', 'private', 'fixture', 'recover', env=ci('test'))
    with pytest.raises(plans.PlanError, match='identity changed'):
        plans.validate(plan, 'recover', HOSTS, {**current, field: value}, now=NOW + 90000)
    with pytest.raises(plans.PlanError, match='identity changed'):
        plans.validate(plan, 'recover', HOSTS, CONTEXT, now=NOW + 90000)


@pytest.mark.parametrize('job', ['recover', 'test-extra', 'recover-extra', 'activate'])
def test_fresh_test_context_rejects_recovery_and_other_suffixes(plans, source_context, job):
    with pytest.raises(plans.PlanError, match='Expected fixed'):
        plans.context('config', 'private', 'fixture', 'test', env=ci(job))


@pytest.mark.parametrize('key,value', [
    ('CI', 'false'), ('CI_PIPELINE_SOURCE', 'push'), ('CI_COMMIT_REF_PROTECTED', 'false'),
    ('CI_COMMIT_BRANCH', 'feature'), ('CI_COMMIT_SHA', 'd' * 40), ('CI_PROJECT_ID', '0'),
    ('CI_PIPELINE_ID', '01'), ('CI_JOB_IMAGE', 'tool:latest'), ('CI_JOB_MANUAL', 'false'),
    ('CI_JOB_MANUAL', ''),
    ('CI_JOB_NAME', 'fixture-haproxy-failover-plan'), ('CI_JOB_NAME', 'fixture-haproxy-activate'),
    ('CI_JOB_NAME', 'fixture-haproxy-failover-test-extra'), ('CI_JOB_NAME', '-haproxy-failover-test'),
])
@pytest.mark.parametrize('mode,job', [('test', 'test'), ('recover', 'recover'), ('recover', 'test')])
def test_protected_manual_lane_required(plans, source_context, key, value, mode, job):
    with pytest.raises(plans.PlanError):
        plans.context('config', 'private', 'fixture', mode, env={**ci(job), key: value})


@pytest.mark.parametrize('field,value', [
    ('schema', True), ('operation', 'haproxy'), ('nonce', '../bad'), ('owner', 'bao-4'),
    ('service', 'keepalived.service'), ('hosts', HOSTS[:2]), ('hosts', [HOSTS[0]] * 3),
    ('evidence', {}), ('created', True), ('expires', NOW + 1801),
])
def test_resigned_malformed_plans_rejected(plans, plan, field, value):
    plan[field] = value
    plan['digest'] = plans.digest(plan)
    with pytest.raises(plans.PlanError):
        plans.validate_shape(plan)


def test_exact_owner_evidence_hosts_and_json_types(plans, plan):
    for hosts, owner, evidence in [(HOSTS, HOSTS[1], EVIDENCE),
                                   (HOSTS, HOSTS[0], {'changed': True}),
                                   (HOSTS[::-1], HOSTS[0], EVIDENCE)]:
        with pytest.raises(plans.PlanError):
            plans.validate(plan, 'test', hosts, CONTEXT, owner, evidence, now=NOW)
    evidence = copy.deepcopy(EVIDENCE)
    evidence['nodes'][HOSTS[0]]['healthy'] = 1
    with pytest.raises(plans.PlanError):
        plans.validate(plan, 'test', HOSTS, CONTEXT, HOSTS[0], evidence, now=NOW)


def test_recovery_requires_target_plan_and_fresh_fault_requires_file(plans, plan):
    with pytest.raises(plans.PlanError):
        plans.prepare('recover', '/tmp/expired-artifact', HOSTS, CONTEXT, plan=plan)
    with pytest.raises(plans.PlanError):
        plans.prepare('test', '', HOSTS, CONTEXT, plan=plan)


@pytest.mark.parametrize('mode', ['plan', 'test'])
def test_plan_and_fresh_test_require_explicit_path(plans, mode):
    with pytest.raises(plans.PlanError):
        plans.prepare(mode, '', HOSTS, CONTEXT, HOSTS[0], EVIDENCE, now=NOW)


def test_private_plan_duplicate_and_symlink_rejection(plans, tmp_path):
    path = tmp_path / 'plan'
    path.write_text('{"schema":1,"schema":1}')
    path.chmod(0o600)
    with pytest.raises(plans.PlanError, match='duplicate'):
        plans.read_plan(str(path))
    link = tmp_path / 'link'
    link.symlink_to(path)
    with pytest.raises(OSError):
        plans.read_plan(str(link))


def test_action_returns_exact_owner_approval_and_private_result(repo_root, plans, plan, monkeypatch):
    from ansible.plugins.action import ActionBase
    from types import SimpleNamespace

    spec = importlib.util.spec_from_file_location('failover_action_test', repo_root / 'plugins/action/openbao_failover_plan.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(ActionBase, 'run', lambda *args: {})
    monkeypatch.setattr(module.plans, 'context', lambda *args: CONTEXT)
    monkeypatch.setattr(module.plans.base.time, 'time', lambda: NOW)
    action = object.__new__(module.ActionModule)
    action._task = SimpleNamespace(check_mode=False, args={'action': 'verify', 'mode': 'test',
                                  'plan': plan, 'owner': HOSTS[0], 'evidence': EVIDENCE})
    variables = {'groups': {'openbao': HOSTS}, 'ansible_inventory_sources': ['fixture.yml'],
                 'platform_environment': 'fixture'}
    result = action.run(task_vars=variables)
    assert not result.get('failed'), result
    assert result['_ansible_no_log'] is True
    assert result['nonce'] == plan['nonce']
    assert result['approval'] == f"test-openbao-haproxy-failover|bao-1|{','.join(HOSTS)}|{plan['digest']}"
    action._task.args['owner'] = HOSTS[1]
    assert action.run(task_vars=variables)['failed'] is True
    action._task.check_mode = True
    assert action.run(task_vars=variables)['failed'] is True
