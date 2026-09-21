from __future__ import annotations

import json
import shutil

import pytest
import yaml

from test_pki_host_local_request_helper import request_scenario  # noqa: F401


@pytest.fixture
def request_play(repo_root, isolated_test_dir, request_scenario):
    root = isolated_test_dir
    scenario = request_scenario
    role = root / 'roles/pki_host_local_certificate'
    shutil.copytree(repo_root / 'roles/pki_host_local_certificate', role)
    # Keep the real entry validation and the real filesystem request command and
    # result validation. This test isolates request creation from trust deployment
    # and exchange export; the native helper creates/signs the actual request.
    native = yaml.safe_load((role / 'tasks/filesystem_request.yml').read_text())
    tasks = [{'ansible.builtin.import_tasks': 'validate_target_local.yml'}] + [
        task for task in native if task['name'] in (
            'Create or authenticate the filesystem schema-2 request', 'Validate filesystem request result')]
    (role / 'tasks/request_publish.yml').write_text(yaml.safe_dump(tasks))
    (role / 'meta/main.yml').write_text('---\ndependencies: []\n')
    play = root / 'request.yml'
    shutil.copy(repo_root / 'playbooks/openbao-pki-request.yml', play)
    trust = scenario.state / 'trust/reviewed-v1'
    trust.parent.mkdir(parents=True)
    scenario.state.chmod(0o700)
    trust.parent.chmod(0o700)
    shutil.copytree(scenario.trust, trust)
    lock = scenario.state / 'lock'
    lock.touch(mode=0o600)
    group = yaml.safe_load((repo_root / 'inventories/dev/group_vars/openbao.yml.example').read_text())
    group.update(dict(
        ansible_connection='local', ansible_become=False,
        openbao_node_dns='bao.test', openbao_node_address='192.0.2.10',
        pki_host_local_certificate_transport='filesystem',
        pki_host_local_certificate_inventory_sha256='a' * 64,
        pki_host_local_certificate_response_principal='test-response',
        pki_host_local_certificate_trust_id='reviewed-v1',
        pki_host_local_certificate_trust_paths={name: str(trust / name) for name in scenario.trust_digests},
        pki_host_local_certificate_trust_sources={name: str(scenario.trust / name) for name in scenario.trust_digests},
        pki_host_local_certificate_trust_sha256=scenario.trust_digests,
        pki_host_local_certificate_request_helper_path=str(scenario.helper),
        pki_host_local_certificate_request_signing_key_path=str(scenario.signing_key),
        pki_host_local_certificate_state_root=str(scenario.state),
        pki_host_local_certificate_pending_root=str(scenario.pending),
        pki_host_local_certificate_filesystem_exchange_root=str(scenario.work / 'exchange'),
        pki_host_local_certificate_filesystem_owner_uid=1234,
        pki_host_local_certificate_minimum_remaining_lifetime_seconds=1,
    ))
    inv = root / 'inventory.yml'

    def run(ttl=None, check=False):
        values = dict(group)
        if ttl is not None:
            values['openbao_pki_request_ttl_seconds'] = ttl
        inv.write_text(yaml.safe_dump({'all': {'children': {'openbao': {
            'vars': values, 'hosts': {'test-target': {}},
        }}}}))
        return scenario.runner.run([
            'ansible-playbook', '-i', inv, play, '--limit', 'test-target', *( ['--check'] if check else []),
        ], environment={'ANSIBLE_ROLES_PATH': str(root / 'roles')}, timeout=45)
    return run, scenario


@pytest.mark.parametrize('ttl', [None, 7200])
def test_real_request_uses_inventory_ttl_or_preserved_default(request_play, ttl):
    run, scenario = request_play
    result = run(ttl)
    result.assert_success()
    requests = list(scenario.pending.glob('*/request'))
    assert len(requests) == 1
    fields = dict(line.split('=', 1) for line in requests[0].read_text().splitlines())
    assert int(fields['expires_epoch']) - int(fields['created_epoch']) == (3600 if ttl is None else ttl)
    assert fields['service'] == 'openbao-test-target'
    assert fields['operation'] == 'issue'
    assert (requests[0].parent / 'tls.key').is_file()
    assert 'PRIVATE KEY' not in result.stdout + result.stderr


@pytest.mark.parametrize('ttl', ['7200', True, 0, 604801])
def test_invalid_ttl_rejected_before_native_request(request_play, ttl):
    run, scenario = request_play
    run(ttl).assert_failure()
    assert not scenario.pending.exists()


def test_request_check_mode_rejected_before_native_request(request_play):
    run, scenario = request_play
    run(check=True).assert_failure()
    assert not scenario.pending.exists()


def test_operator_make_keeps_typed_ttl(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir
    environment = root / 'environment'
    environment.write_text(':\n')
    inventory = root / 'inventory'
    inventory.write_text('[openbao]\nbao-test\n')
    capture = root / 'capture'
    capture.write_text('#!/usr/bin/env python3\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n')
    capture.chmod(0o755)
    result = command_runner.run([
        'make', 'openbao-pki-request-publish', 'ENV=dev', 'LIMIT=bao-test', 'REQUEST_TTL_SECONDS=7200',
        f'ENV_FILE={environment}', f'INVENTORY={inventory}', 'IN_CONTAINER=env', f'ANSIBLE_PLAYBOOK={capture}',
    ]).assert_success()
    line = next(line for line in result.stdout.splitlines() if line.startswith('["-i"'))
    args = json.loads(line)
    assert json.loads(args[args.index('-e') + 1]) == {'openbao_pki_request_ttl_seconds': 7200}
