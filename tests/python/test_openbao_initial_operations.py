from __future__ import annotations

import pytest

from test_openbao_preparation_operations import HOSTS, inventory, launcher  # noqa: F401


PREFIX = ['inventory', 'connectivity', 'openbao-initial-preflight']
ROUTES = {
    'openbao-pki-request-plan': [],
    'openbao-pki-request': ['openbao-pki-request'],
    'openbao-pki-activate-plan': [],
    'openbao-pki-activate': ['openbao-pki-activate'],
    'openbao-bootstrap-start': ['openbao-bootstrap-start'],
    'openbao-bootstrap-complete-plan': ['openbao-bootstrap-complete-check'],
    'openbao-bootstrap-complete': ['openbao-bootstrap-complete-check', 'openbao-bootstrap-complete'],
}


def cohort():
    data = inventory()
    members = [dict(name=host, node_id=host, address=f'192.0.2.{i}', dns=f'{host}.test')
               for i, host in enumerate(HOSTS, 1)]
    data['_meta']['hostvars'] = {host: {'openbao_cluster_members': members} for host in HOSTS}
    return data


def run(launcher, operation='openbao-pki-request', **kwargs):
    kwargs.setdefault('data', cohort())
    kwargs.setdefault('extra', ('--node', HOSTS[0]) if operation.startswith('openbao-pki-') else ())
    return launcher(operation, **kwargs)


@pytest.mark.parametrize('operation', ROUTES)
def test_exact_initial_phase_contract(launcher, operation):
    result, calls = run(launcher, operation)
    result.assert_success()
    assert 'Overall: PASS' in result.stdout
    assert [call['phase'] for call in calls] == PREFIX + ROUTES[operation]
    limit = HOSTS[0] if operation.startswith('openbao-pki-') else 'openbao'
    assert calls[1]['args'][2] == limit
    for call in calls[2:]:
        args = call['args']
        assert args[args.index('--limit') + 1] == limit
        assert ('--check' in args) == (call['phase'] == 'openbao-bootstrap-complete-check')
        assert ('--diff' in args) == ('--check' in args)
        if call['phase'] != 'openbao-initial-preflight':
            name = call['phase'].removesuffix('-check')
            folder = 'maintenance/' if name.startswith('openbao-bootstrap-') else ''
            assert args[2].endswith(f'/playbooks/{folder}{name}.yml')


@pytest.mark.parametrize('operation,phase', [(op, phase) for op in ROUTES for phase in PREFIX + ROUTES[op]])
def test_every_gate_requires_complete_selected_evidence(launcher, operation, phase):
    result, calls = run(launcher, operation, phase=phase, fault='missing')
    result.assert_failure()
    assert calls[-1]['phase'] == phase
    assert 'Overall: FAIL' in result.stdout


@pytest.mark.parametrize('fault', ['extra', 'duplicate', 'exit', 'failures', 'unreachable', 'rescued', 'ignored', 'ok', 'changed'])
@pytest.mark.parametrize('phase', ['openbao-initial-preflight', 'openbao-bootstrap-complete-check'])
def test_readonly_gates_fail_closed(launcher, phase, fault):
    result, calls = run(launcher, 'openbao-bootstrap-complete', phase=phase, fault=fault)
    result.assert_failure()
    assert calls[-1]['phase'] == phase


@pytest.mark.parametrize('group', ['rke2_cluster', 'rke2_servers', 'rke2_agents', 'registry', 'registry_clients',
                                   'gitlab', 'gitlab_runners', 'monitoring', 'bastion', 'k8s_bastion',
                                   'load_balancers', 'haproxy', 'openbao_storage'])
def test_unselected_member_service_collision_blocks_pki(launcher, group):
    data = cohort()
    data[group] = {'hosts': [HOSTS[-1]]}
    result, calls = run(launcher, data=data)
    result.assert_failure()
    assert [call['phase'] for call in calls] == ['inventory']


@pytest.mark.parametrize('case', ['partial', 'nonrocky', 'missing-map', 'different-map', 'group-collision',
                                  'bad-meta', 'bad-hostvars', 'bad-host', 'bad-name'])
def test_full_canonical_cohort_required_before_ping(launcher, case):
    data = cohort()
    if case == 'partial': data['bao_nodes']['hosts'] = HOSTS[:2]
    if case == 'nonrocky': data['rocky']['hosts'] = HOSTS[:2]
    if case == 'missing-map': data['_meta']['hostvars'].pop(HOSTS[-1])
    if case == 'different-map': data['_meta']['hostvars'][HOSTS[-1]] = {'openbao_cluster_members': []}
    if case == 'group-collision': data[HOSTS[0]] = {}
    if case == 'bad-meta': data['_meta'] = None
    if case == 'bad-hostvars': data['_meta']['hostvars'] = []
    if case == 'bad-host': data['_meta']['hostvars'][HOSTS[-1]] = None
    if case == 'bad-name': data['_meta']['hostvars'][HOSTS[-1]]['openbao_cluster_members'][0]['name'] = None
    result, calls = run(launcher, data=data)
    result.assert_failure()
    assert len(calls) == 1
    assert 'Traceback' not in result.stderr


@pytest.mark.parametrize('extra', [(), ('--node', 'all'), ('--node', 'bao*'), ('--node', 'bao-a,bao-b'),
                                  ('--node', 'foreign'), ('--node', 'bao-a', '--plan', '/tmp/plan'),
                                  ('--node', 'bao-a', '--ttl', '7200'), ('--node', 'bao-a', '--request-id', 'a' * 32)])
def test_pki_has_only_literal_node_selector(launcher, extra):
    result, calls = run(launcher, extra=extra)
    result.assert_failure()
    assert len(calls) <= 1


@pytest.mark.parametrize('operation', ROUTES)
def test_ci_only(launcher, operation):
    result, calls = run(launcher, operation, ci='false')
    result.assert_failure()
    assert not calls


@pytest.mark.parametrize('controller', [{'openbao_pki_request_ttl_seconds': 7200}, {'openbao_bootstrap_ready': True},
                                      {'openbao_status_token_src': '/tmp/token'}, {'ansible_connection': 'local'}])
def test_only_transport_json_before_inventory(launcher, controller):
    result, calls = run(launcher, controller=controller)
    result.assert_failure()
    assert not calls


def test_transport_snapshot_and_selected_key_coverage(launcher):
    result, _ = run(launcher, tamper=True, controller={'platform_ci_ssh_private_key_files': {HOSTS[0]: '/tmp/key'}})
    result.assert_success()


@pytest.mark.parametrize('operation', ['openbao-pki-request', 'openbao-bootstrap-start', 'openbao-bootstrap-complete'])
def test_incomplete_transport_key_coverage(launcher, operation):
    result, calls = run(launcher, operation, controller={'platform_ci_ssh_private_key_files': {HOSTS[-1]: '/tmp/key'}})
    result.assert_failure()
    assert len(calls) == 1


@pytest.mark.parametrize('operation', ['openbao-bootstrap-start', 'openbao-bootstrap-complete-plan', 'openbao-bootstrap-complete'])
def test_bootstrap_forbids_node_and_arbitrary_flags(launcher, operation):
    result, calls = run(launcher, operation, extra=('--node', HOSTS[0]))
    result.assert_failure()
    assert not calls
