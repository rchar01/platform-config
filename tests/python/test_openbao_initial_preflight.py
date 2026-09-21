from __future__ import annotations

import hashlib
import json
import shutil

import pytest
import yaml


@pytest.fixture
def initial_preflight(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir
    project = root / 'project'
    plays = project / 'playbooks'
    plays.mkdir(parents=True)
    shutil.copy(repo_root / 'playbooks/openbao-initial-preflight.yml', plays)
    for role in ('openbao', 'pki_host_local_certificate'):
        shutil.copytree(repo_root / 'roles' / role, project / 'roles' / role)
    actions = root / 'actions'
    actions.mkdir()
    shutil.copy(repo_root / 'tests/fixtures/openbao-initial/target_io.py', actions)
    # Map only remote observations into the sandbox; retain controller source
    # pinning, all assertions, real includes, and default/inventory resolution.
    for role, names in {
        'openbao': ['initial_pki_preflight.yml', 'custody.yml'],
        'pki_host_local_certificate': ['filesystem_preflight.yml', 'response_preflight.yml'],
    }.items():
        for name in names:
            path = project / 'roles' / role / 'tasks' / name
            tasks = yaml.safe_load(path.read_text())
            for task in tasks:
                if task.get('delegate_to') == 'localhost':
                    continue
                for module in ('stat', 'command', 'systemd_service'):
                    if f'ansible.builtin.{module}' in task:
                        task['target_io'] = task.pop(f'ansible.builtin.{module}')
            path.write_text(yaml.safe_dump(tasks, sort_keys=False))
    target = root / 'target'
    source = repo_root / 'roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle'
    helper = target / 'usr/local/libexec/platform-pki-host-local-lifecycle'
    helper.parent.mkdir(parents=True)
    shutil.copy(source, helper)
    helper.chmod(0o755)
    listener = target / 'etc/openbao/listener.hcl'
    listener.parent.mkdir(parents=True)
    listener.write_text('synthetic adapter-authenticated listener\n')
    listener.chmod(0o640)
    (target / 'var/lib/platform-config').mkdir(parents=True)
    ca = root / 'config/openbao/validation-ca.pem'
    ca.parent.mkdir(parents=True)
    ca.write_text('public reviewed fixture CA\n')
    ca.chmod(0o600)
    names = ['policy', 'requesters.allowed_signers', 'approvers.allowed_signers', 'responses.allowed_signers']
    sources, paths, digests = {}, {}, {}
    for name in names:
        file = root / 'config/pki-source/pki/csr-trust' / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(f'reviewed public fixture {name}\n')
        file.chmod(0o600)
        sources[name] = str(file)
        paths[name] = f'/var/lib/platform-config/pki/openbao/trust/fixture-v1/{name}'
        dest = target / paths[name].lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(file, dest)
        digests[name] = hashlib.sha256(file.read_bytes()).hexdigest()
    group = yaml.safe_load((repo_root / 'inventories/dev/group_vars/openbao.yml.example').read_text())
    group.update(dict(
        openbao_orchestration_ready=True, openbao_enabled=True,
        openbao_tls_ca_src=str(ca), openbao_tls_ca_sha256=hashlib.sha256(ca.read_bytes()).hexdigest(),
        platform_environment='dev', openbao_status_token_src=str(ca.parent / 'dev/status.token'),
        pki_host_local_certificate_transport='filesystem', pki_host_local_certificate_inventory_sha256='a' * 64,
        pki_host_local_certificate_response_principal='signer.test', pki_host_local_certificate_trust_id='fixture-v1',
        pki_host_local_certificate_trust_sources=sources, pki_host_local_certificate_trust_paths=paths,
        pki_host_local_certificate_trust_sha256=digests, pki_host_local_certificate_filesystem_owner_uid=1234,
        pki_host_local_certificate_filesystem_exchange_root='/var/lib/platform-config/exchange',
        pki_host_local_certificate_reviewed_ca_source=str(ca),
        pki_host_local_certificate_reviewed_ca_sha256=hashlib.sha256(ca.read_bytes()).hexdigest(),
        pki_host_local_certificate_reviewed_ca_mode='0644', pki_host_local_certificate_minimum_remaining_lifetime_seconds=1,
        pki_host_local_certificate_rollback_seconds=1209600,
        ansible_connection='local', ansible_become=False, fixture_target=str(target),
        fixture_calls=str(root / 'calls.jsonl'), fixture_scenario={},
    ))
    hosts = {f'openbao-example-0{i}': yaml.safe_load(
        (repo_root / f'inventories/dev/host_vars/openbao-example-0{i}.yml.example').read_text()) for i in range(1, 4)}
    inv = root / 'hosts.yml'

    def run(action='pki-request', overrides=None, scenario=None, check=False, host_overrides=None):
        values = {**group, **(overrides or {}), 'fixture_scenario': scenario or {}}
        inv.write_text(yaml.safe_dump({'all': {'vars': values, 'children': {
            'openbao': {'hosts': {host: {**values, **(host_overrides or {}).get(host, {})} for host, values in hosts.items()}},
            'rocky': {'hosts': dict.fromkeys(hosts, {})},
        }}}))
        return command_runner.run([
            'ansible-playbook', '-i', inv, plays / 'openbao-initial-preflight.yml',
            '--limit', 'openbao-example-01' if action.startswith('pki-') else 'openbao',
            '--extra-vars', json.dumps({'openbao_initial_action': action}), *( ['--check'] if check else []),
        ], environment={'CI': 'true', 'ANSIBLE_ROLES_PATH': str(project / 'roles'),
                        'ANSIBLE_ACTION_PLUGINS': f'{actions}:{repo_root / "plugins/action"}',
                        'PLATFORM_INFRASTRUCTURE_CONFIG_DIR': str(root / 'config')}, timeout=90)
    return run, target, group, root, project


def snapshot(path):
    return {str(file.relative_to(path)): (file.read_bytes(), file.stat().st_mode)
            for file in path.rglob('*') if file.is_file()}


@pytest.mark.parametrize('action', ['pki-request', 'pki-activate', 'bootstrap-start', 'bootstrap-complete'])
def test_shipped_initial_preflight_is_readonly(initial_preflight, action):
    run, target, _, root, _ = initial_preflight
    before = snapshot(target)
    result = run(action)
    result.assert_success()
    assert 'changed=0' in result.stdout
    assert snapshot(target) == before
    # No status token exists: binding here does not read it. Only the completion
    # play's existing status role reads token bytes under no_log.
    assert not (root / 'config/openbao/dev/status.token').exists()


@pytest.mark.parametrize('scenario', [{'active': 'active'}, {'unit': 'enabled'}, {'authentication_failed': True},
                                       {'status': ['invalid', 'none']}])
def test_shipped_activation_preflight_rejects_unsafe_observations(initial_preflight, scenario):
    run, target, *_ = initial_preflight
    before = snapshot(target)
    run('pki-activate', scenario=scenario).assert_failure()
    assert snapshot(target) == before


@pytest.mark.parametrize('status', [['complete', 'none'], ['recovery-required', 'recover'],
                                  ['not-activated', 'recover'], ['rolled-back', 'recover'],
                                  ['activating', 'complete-local-validation']])
def test_existing_response_replay_recovery_contract_is_admitted(initial_preflight, status):
    run, target, *_ = initial_preflight
    before = snapshot(target)
    result = run('pki-activate', scenario={'status': status})
    result.assert_success()
    assert 'changed=0' in result.stdout
    assert snapshot(target) == before


@pytest.mark.parametrize('case', ['helper-drift', 'helper-symlink', 'missing-trust', 'trust-drift', 'controller-trust-drift',
                                 'leaf-present', 'exchange-mode', 'ca-drift'])
def test_real_artifact_failures_are_retained(initial_preflight, case):
    run, target, group, root, _ = initial_preflight
    helper = target / 'usr/local/libexec/platform-pki-host-local-lifecycle'
    trust = target / group['pki_host_local_certificate_trust_paths']['policy'].lstrip('/')
    if case == 'helper-drift': helper.write_text('drift\n')
    if case == 'helper-symlink':
        helper.rename(helper.with_name('other'))
        helper.symlink_to(helper.with_name('other'))
    if case == 'missing-trust': trust.unlink()
    if case == 'trust-drift': trust.write_text('drift\n')
    if case == 'controller-trust-drift': (root / 'config/pki-source/pki/csr-trust/policy').write_text('drift\n')
    if case == 'leaf-present':
        leaf = target / 'etc/openbao/tls/tls.key'
        leaf.parent.mkdir()
        leaf.write_text('retained synthetic leaf\n')
    if case == 'exchange-mode':
        exchange = target / 'var/lib/platform-config/exchange'
        exchange.mkdir(mode=0o777)
        exchange.chmod(0o777)
    if case == 'ca-drift': (root / 'config/openbao/validation-ca.pem').write_text('drift\n')
    before = snapshot(target)
    run().assert_failure()
    assert snapshot(target) == before


@pytest.mark.parametrize('overrides', [
    {'pki_host_local_certificate_transport': 'gitlab'}, {'pki_host_local_certificate_operation': 'renew'},
    {'openbao_pki_request_ttl_seconds': '7200'}, {'openbao_pki_request_ttl_seconds': True},
    {'openbao_pki_request_ttl_seconds': 0}, {'openbao_pki_request_ttl_seconds': 604801},
    {'openbao_tls_ca_src': '/tmp/other-ca'}, {'pki_host_local_certificate_reviewed_ca_sha256': 'b' * 64},
])
def test_real_initial_input_rejections(initial_preflight, overrides):
    run, target, *_ = initial_preflight
    before = snapshot(target)
    run(overrides=overrides).assert_failure()
    assert snapshot(target) == before


def test_completion_token_binding_and_preflight_check_rejection(initial_preflight):
    run, *_ = initial_preflight
    run('bootstrap-complete', overrides={'openbao_status_token_src': '/tmp/other-token'}).assert_failure()
    run(check=True).assert_failure()


def test_unselected_member_identity_must_be_canonical(initial_preflight):
    run, target, *_ = initial_preflight
    before = snapshot(target)
    result = run(host_overrides={'openbao-example-03': {'openbao_node_dns': 'foreign.test'}})
    result.assert_failure()
    assert 'Validate initial deployment pinned CA bytes' not in result.stdout
    assert snapshot(target) == before


def test_explicit_inventory_ttl_admitted_by_real_preflight(initial_preflight):
    run, target, *_ = initial_preflight
    before = snapshot(target)
    result = run(overrides={'openbao_pki_request_ttl_seconds': 7200})
    result.assert_success()
    assert 'changed=0' in result.stdout
    assert snapshot(target) == before


def test_trust_source_cannot_select_other_identical_public_file(initial_preflight):
    run, target, group, root, _ = initial_preflight
    alternate = root / 'other/policy'
    alternate.parent.mkdir()
    shutil.copy(root / 'config/pki-source/pki/csr-trust/policy', alternate)
    sources = {**group['pki_host_local_certificate_trust_sources'], 'policy': str(alternate)}
    before = snapshot(target)
    result = run(overrides={'pki_host_local_certificate_trust_sources': sources})
    result.assert_failure()
    assert 'Inspect public controller trust bytes' not in result.stdout
    assert snapshot(target) == before
