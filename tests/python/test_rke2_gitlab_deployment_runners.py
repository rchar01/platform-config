from __future__ import annotations

import hashlib
import json
import shutil
import tomllib
from pathlib import Path

import pytest
import yaml

ROLE = 'rke2_gitlab_deployment_runners'
PREFIX = 'rke2_gitlab_deployment_runner_'


def variables(root):
    ca = root / 'ca.pem'
    ca.write_text('-----BEGIN CERTIFICATE-----\nsynthetic-offline-fixture\n-----END CERTIFICATE-----\n')
    instances = []
    for profile in ('apps', 'platform'):
        token = root / (profile + '.token')
        token.write_text('glrt-synthetic-' + profile)
        token.chmod(0o600)
        instances.append(dict(profile=profile, name=profile + '-runner',
                              manager_namespace=profile + '-managers', job_namespace=profile + '-jobs',
                              token_src=str(token)))
    return {
        ROLE: instances,
        PREFIX + 'gitlab_url': 'https://gitlab.example.test',
        PREFIX + 'tls_ca_cert_src': str(ca),
        PREFIX + 'tls_ca_cert_sha256': hashlib.sha256(ca.read_bytes()).hexdigest(),
        PREFIX + 'job_image': 'registry.example.test/tools:v1@sha256:' + 'a' * 64,
        PREFIX + 'acceptance_namespace': 'apps-acceptance',
        PREFIX + 'platform_acceptance_namespace': 'platform-canary',
        PREFIX + 'egress': [{'address': '192.0.2.10', 'ports': [443, 6443]}],
    }


@pytest.fixture
def harness(repo_root, isolated_test_dir, command_runner, namespace_root_runner):
    root = isolated_test_dir
    fixture = root / 'fixture'
    fixture.mkdir()
    (fixture / 'manifests').mkdir()
    roles = root / 'roles'
    target = roles / ROLE
    shutil.copytree(repo_root / 'roles' / ROLE, target)
    # Shadow only fixed target filesystem/transport boundaries. Task chains,
    # conditions, templates and validators remain the production code.
    for path in (target / 'tasks').glob('*.yml'):
        text = path.read_text().replace('/var/lib/rancher/rke2/server/manifests', str(fixture / 'manifests'))
        text = text.replace('/var/lib/rancher/rke2/bin/kubectl', str(fixture / 'kubectl'))
        if path.name == 'paths.yml':
            for parent in ('/var/lib/rancher/rke2/server', '/var/lib/rancher/rke2', '/var/lib/rancher', '/var/lib', '/var', '/'):
                text = text.replace('    - ' + parent + '\n', '    - ' + str(fixture) + '\n')
        path.write_text(text)
    shutil.copy(repo_root / 'tests/python/fixtures/deployment_runner_kubectl.py', fixture / 'kubectl')
    (fixture / 'kubectl').chmod(0o755)
    inventory = root / 'inventory.yml'
    inventory.write_text(yaml.safe_dump({'all': {'children': {
        'rke2_cluster': {'children': {'rke2_servers': {}, 'rke2_agents': {}}},
        'rke2_servers': {'hosts': {'server': {'ansible_connection': 'local'}}},
        'rke2_agents': {'hosts': {'worker': {}}},
    }}}))
    config = variables(root)

    def run(*, smoke=False, check=False, settings=None, limit=None, timeout=240, tasks_from=None):
        play = yaml.safe_load((repo_root / 'playbooks' / (ROLE.replace('_', '-') + ('-smoke' if smoke else '') + '.yml')).read_text())
        play[0]['become'] = False
        if tasks_from:
            play[0].pop('roles', None)
            play[0]['tasks'] = [{'ansible.builtin.include_role': {
                'name': ROLE, 'tasks_from': tasks_from, 'defaults_from': 'unused',
            }}]
        playbook = root / 'playbook.yml'
        playbook.write_text(yaml.safe_dump(play))
        args = ['ansible-playbook', '-i', inventory, playbook, '-e', json.dumps(config if settings is None else settings)]
        if check:
            args.append('--check')
        if limit:
            args += ['--limit', limit]
        return namespace_root_runner.run(args, environment={
            'ANSIBLE_ROLES_PATH': str(roles), 'DEPLOYMENT_RUNNER_FIXTURE': str(fixture),
        }, timeout=timeout)

    return root, fixture, config, run


def test_empty_defaults_both_entry_points_are_noops(harness):
    _, fixture, _, run = harness
    for smoke in (False, True):
        result = run(smoke=smoke, settings={}).assert_success()
        assert 'changed=0' in result.stdout
    assert not (fixture / 'calls.jsonl').exists()
    assert not list((fixture / 'manifests').iterdir())


def test_real_convergence_check_idempotence_render_and_read_only_smoke(harness):
    _, fixture, config, run = harness
    run(check=True).assert_success()
    assert not (fixture / 'state.json').exists()
    assert not list((fixture / 'manifests').iterdir())
    assert all('get' in json.loads(line) for line in (fixture / 'calls.jsonl').read_text().splitlines())
    applied = run().assert_success()
    assert 'glrt-synthetic' not in applied.stdout + applied.stderr
    state = json.loads((fixture / 'state.json').read_text())
    assert len([v for v in state.values() if v['kind'] == 'Namespace']) == 5
    assert not any(v['kind'] == 'CustomResourceDefinition' for v in state.values())
    assert not any('platform-canary' == v['metadata']['name'] for v in state.values() if v['kind'] == 'Namespace')
    assert len([v for v in state.values() if v['kind'] == 'ValidatingAdmissionPolicy']) == 2
    assert len([v for v in state.values() if v['kind'] == 'ValidatingAdmissionPolicyBinding']) == 2
    for obj in state.values():
        if obj['kind'] in ('Role', 'ClusterRole'):
            for rule in obj['rules']:
                assert '*' not in rule['verbs'] + rule['resources'] + rule['apiGroups']
        if obj['kind'] == 'ServiceAccount':
            assert obj['automountServiceAccountToken'] is True
    policies = [v for v in state.values() if v['kind'] == 'NetworkPolicy']
    assert len(policies) == 4
    for policy in policies:
        assert 'ingress' not in policy['spec']
        assert policy['spec']['policyTypes'] == ['Ingress', 'Egress']
        assert policy['spec']['egress'][1]['to'] == [{'ipBlock': {'cidr': '192.0.2.10/32'}}]
        assert policy['spec']['egress'][0]['to'][0]['namespaceSelector']['matchLabels'] == {'kubernetes.io/metadata.name': 'kube-system'}
    for profile in ('apps', 'platform'):
        release = 'rke2-gitlab-' + profile
        chart = yaml.safe_load((fixture / 'manifests' / (release + '.yaml')).read_text())
        values = yaml.safe_load(chart['spec']['valuesContent'])
        runner = tomllib.loads(values['runners']['config'])['runners'][0]
        executor = runner['kubernetes']
        assert values['rbac']['create'] is False and values['serviceAccount']['create'] is False
        assert values['serviceAccount']['name'] == release
        assert executor['automount_service_account_token'] is True
        assert executor['namespace'] == profile + '-jobs'
        assert executor['service_account'] == release + '-job'
        assert 'services_limit' not in executor  # Docker-only, ignored by Kubernetes.
        assert executor['allowed_services'] == ['!']
        assert executor['allowed_images'] == [config[PREFIX + 'job_image']]
        assert executor['namespace_overwrite_allowed'] == executor['service_account_overwrite_allowed'] == ''
        assert executor['cap_drop'] == ['ALL'] and executor['privileged'] is False
        assert 'glrt-synthetic' not in json.dumps(chart)
    # Admission is not retroactive. An independently shaped, already-existing
    # job exercises fresh Pod inspection and UID-bound ephemeral dry-run UPDATE.
    defaults = yaml.safe_load((fixture.parent / 'roles' / ROLE / 'defaults/main.yml').read_text())
    state['pod/apps-jobs/existing-job'] = {
        'apiVersion': 'v1', 'kind': 'Pod',
        'metadata': {'name': 'existing-job', 'namespace': 'apps-jobs', 'uid': 'existing-job-uid', 'resourceVersion': '7'},
        'spec': {'serviceAccountName': 'rke2-gitlab-apps-job', 'containers': [
            {'name': 'helper', 'image': defaults[PREFIX + 'helper_image']},
            {'name': 'build', 'image': config[PREFIX + 'job_image']},
        ], 'initContainers': [{'name': 'init-permissions', 'image': defaults[PREFIX + 'helper_image']}]},
    }
    (fixture / 'state.json').write_text(json.dumps(state))
    for check in (False, True):
        result = run(check=check).assert_success()
        assert 'changed=0' in result.stdout
    before = (fixture / 'state.json').read_bytes()
    calls_before = len((fixture / 'calls.jsonl').read_text().splitlines())
    result = run(smoke=True, check=True).assert_success()
    assert 'changed=0' in result.stdout
    assert (fixture / 'state.json').read_bytes() == before
    calls = [json.loads(line) for line in (fixture / 'calls.jsonl').read_text().splitlines()[calls_before:]]
    assert all('get' in call or 'auth' in call or 'status' in call or '--dry-run=server' in call for call in calls)
    assert any('--subresource=ephemeralcontainers' in call for call in calls)
    assert all('-o=jsonpath={.metadata}' in call for call in calls if 'Secret' in call)
    token_reads = [call for call in calls if 'secret' in call]
    assert len(token_reads) == 3
    assert all(any(arg.startswith('-o=go-template=') for arg in call) for call in token_reads)
    assert any('customresourcedefinitions.apiextensions.k8s.io/runnerchecks.acceptance.platform.example' in call for call in calls)
    (fixture / 'leak-auth').touch()
    run(smoke=True).assert_failure()


def test_invalid_inputs_fail_before_api_or_credentials(harness, command_runner):
    root, fixture, config, run = harness
    cases = [
        {ROLE: {}}, {ROLE: config[ROLE][:1]},
        {ROLE: [config[ROLE][0] | {'extra': True}, config[ROLE][1]]},
        {ROLE: [config[ROLE][0], config[ROLE][1] | {'profile': 'apps'}]},
        {ROLE: [config[ROLE][0] | {'job_namespace': 'kube-owned'}, config[ROLE][1]]},
        {ROLE: [config[ROLE][0] | {'job_namespace': 'gitlab-runner'}, config[ROLE][1]]},
        {PREFIX + 'acceptance_namespace': 'apps-jobs'},
        {PREFIX + 'job_image': 'https://registry.example.test/tools@sha256:' + 'a' * 64},
        {PREFIX + 'egress': []},
        {PREFIX + 'egress': [{'address': '192.0.2.0/24', 'ports': [443]}]},
        {PREFIX + 'egress': [{'address': '256.0.2.1', 'ports': [443]}]},
        {PREFIX + 'egress': [{'address': '192.0.2.1', 'ports': [True]}]},
        {PREFIX + 'egress': [{'address': '192.0.2.1', 'ports': [65536]}]},
        {PREFIX + 'egress': [{'address': '192.0.2.1', 'ports': [443], 'cidr': '0.0.0.0/0'}]},
        {PREFIX + 'clone_url': 'https://user:password@gitlab.example.test'},
        {PREFIX + 'chart_repo_ca_src': '/synthetic/not-read.pem'},
    ]
    # Batch through the real validator task file in one Ansible process, with
    # independent expected-failure blocks; no task-position extraction.
    defaults = yaml.safe_load((root / 'roles' / ROLE / 'defaults/main.yml').read_text())
    tasks = []
    for index, patch in enumerate(cases[1:], 1):
        selected = defaults | config | patch
        resolved = {k.removeprefix(PREFIX): v for k, v in selected.items() if k.startswith(PREFIX)}
        tasks.append({'name': 'Invalid case ' + str(index), 'block': [
            {'ansible.builtin.set_fact': {'_deployment_runner_config': selected}},
            {'ansible.builtin.include_tasks': str(root / 'roles' / ROLE / 'tasks/validate.yml'), 'vars': {
                '_dr': resolved, '_dr_instances': selected[ROLE], '_dr_leader': 'server',
            }},
            {'ansible.builtin.set_fact': {'unexpected_pass': True}},
        ], 'rescue': [{'ansible.builtin.debug': {'msg': 'expected rejection'}}]})
    tasks.append({'ansible.builtin.assert': {'that': 'not unexpected_pass | default(false)'}})
    # The complete entry point separately covers the list type gate.
    run(settings=config | cases[0]).assert_failure()
    playbook = root / 'invalid.yml'
    playbook.write_text(yaml.safe_dump([{'hosts': 'rke2_servers', 'gather_facts': False, 'tasks': tasks}]))
    command_runner.run(['ansible-playbook', '-i', root / 'inventory.yml', playbook], timeout=120).assert_success()
    assert not (fixture / 'calls.jsonl').exists()


@pytest.mark.parametrize('foreign', ['namespace', 'role', 'secret', 'helmchart', 'static', 'symlink',
                                   'validatingadmissionpolicy', 'validatingadmissionpolicybinding'])
def test_foreign_ownership_fails_before_writes(harness, foreign):
    _, fixture, _, run = harness
    if foreign in ('static', 'symlink'):
        path = fixture / 'manifests/rke2-gitlab-apps.yaml'
        if foreign == 'symlink':
            path.symlink_to(fixture / 'outside')
        else:
            path.write_text('kind: HelmChart\nmetadata: {}\n')
            path.chmod(0o644)
    else:
        kinds = {
            'namespace': ('Namespace', 'apps-managers', ''),
            'role': ('Role', 'rke2-gitlab-platform', 'platform-jobs'),
            'secret': ('Secret', 'rke2-gitlab-platform-token', 'platform-managers'),
            'helmchart': ('HelmChart', 'rke2-gitlab-platform', 'kube-system'),
            'validatingadmissionpolicy': ('ValidatingAdmissionPolicy', 'rke2-gitlab-platform-job-pods', ''),
            'validatingadmissionpolicybinding': ('ValidatingAdmissionPolicyBinding', 'rke2-gitlab-platform-job-pods', ''),
        }
        kind, name, ns = kinds[foreign]
        (fixture / 'state.json').write_text(json.dumps({foreign + '/' + ns + '/' + name: {
            'kind': kind, 'metadata': {'name': name, 'namespace': ns, 'labels': {}},
        }}))
    run(check=True).assert_failure()
    if (fixture / 'calls.jsonl').exists():
        assert all('get' in json.loads(line) for line in (fixture / 'calls.jsonl').read_text().splitlines())


def test_complete_server_scope_and_coherence_precede_all_io(harness):
    root, fixture, config, run = harness
    inventory = yaml.safe_load((root / 'inventory.yml').read_text())
    hosts = inventory['all']['children']['rke2_servers']['hosts']
    hosts['second'] = {'ansible_connection': 'local'}
    (root / 'inventory.yml').write_text(yaml.safe_dump(inventory, sort_keys=False))
    run(limit='server', check=True).assert_failure()
    assert not (fixture / 'calls.jsonl').exists()
    hosts['second']['rke2_bootstrap_host'] = 'second'
    (root / 'inventory.yml').write_text(yaml.safe_dump(inventory, sort_keys=False))
    run(check=True).assert_failure()
    assert not (fixture / 'calls.jsonl').exists()
    del hosts['second']['rke2_bootstrap_host']
    inventory['all']['vars'] = config
    hosts['second'][PREFIX + 'acceptance_namespace'] = 'different-acceptance'
    (root / 'inventory.yml').write_text(yaml.safe_dump(inventory, sort_keys=False))
    run(settings={}, check=True).assert_failure()
    assert not (fixture / 'calls.jsonl').exists()
    del hosts['second'][PREFIX + 'acceptance_namespace']
    (root / 'inventory.yml').write_text(yaml.safe_dump(inventory, sort_keys=False))
    # A safe, role-owned source is still forbidden on a secondary server.
    path = fixture / 'manifests/rke2-gitlab-apps.yaml'
    path.write_text(yaml.safe_dump({
        'apiVersion': 'helm.cattle.io/v1', 'kind': 'HelmChart',
        'metadata': {'name': 'rke2-gitlab-apps', 'namespace': 'kube-system', 'labels': {
            'app.kubernetes.io/managed-by': 'platform-config',
            'app.kubernetes.io/part-of': 'rke2-gitlab-deployment-runners',
            'app.kubernetes.io/component': 'apps',
        }},
    }))
    path.chmod(0o644)
    run(check=True).assert_failure()
    assert not (fixture / 'calls.jsonl').exists()


@pytest.mark.parametrize('smoke', [False, True])
def test_overlapping_server_agent_topology_rejected_before_target_io(harness, smoke):
    root, fixture, _, run = harness
    inventory = yaml.safe_load((root / 'inventory.yml').read_text())
    inventory['all']['children']['rke2_agents']['hosts']['server'] = {}
    (root / 'inventory.yml').write_text(yaml.safe_dump(inventory))
    # Poison the later path boundary so a missing topology check cannot advance
    # to credential/API reads. The rejection must come from topology validation.
    (fixture / 'manifests').rmdir()
    result = run(smoke=smoke, check=True).assert_failure()
    assert 'disjoint' in result.stdout
    assert "groups['rke2_servers'] | intersect(groups['rke2_agents'])" in result.stdout
    assert 'Inspect fixed RKE2 manifest ancestors' not in result.stdout
    assert 'Inspect bounded controller source' not in result.stdout
    assert not (fixture / 'calls.jsonl').exists()


@pytest.mark.parametrize('topology', ['coherent', 'missing-agent', 'missing-server', 'unroled-extra', 'empty', 'absent'])
def test_declared_cluster_equals_complete_role_union_validation_only(harness, topology):
    root, fixture, config, run = harness
    inventory = yaml.safe_load((root / 'inventory.yml').read_text())
    children = inventory['all']['children']
    if topology == 'missing-agent':
        children['rke2_cluster'] = {'hosts': {'server': {}}}
    elif topology == 'missing-server':
        children['rke2_cluster'] = {'hosts': {'worker': {}}}
    elif topology == 'unroled-extra':
        children['rke2_cluster']['hosts'] = {'unroled': {}}
    elif topology == 'empty':
        children['rke2_cluster'] = {'hosts': {}}
    elif topology == 'absent':
        del children['rke2_cluster']
    (root / 'inventory.yml').write_text(yaml.safe_dump(inventory))
    defaults = yaml.safe_load((root / 'roles' / ROLE / 'defaults/main.yml').read_text())
    selected = defaults | config
    result = run(tasks_from='validate', check=True, settings=selected | {
        '_deployment_runner_config': selected,
        '_dr': {key.removeprefix(PREFIX): value for key, value in selected.items() if key.startswith(PREFIX)},
        '_dr_instances': selected[ROLE], '_dr_leader': 'server',
    })
    if topology == 'coherent':
        result.assert_success()
        assert 'changed=0' in result.stdout
    else:
        result.assert_failure()
        assert 'rke2_cluster' in result.stdout
    assert 'Inspect fixed RKE2 manifest ancestors' not in result.stdout
    assert 'Inspect bounded controller source' not in result.stdout
    assert not (fixture / 'calls.jsonl').exists()


def test_network_policy_api_roundtrip_preserves_semantic_empty_rules(harness, command_runner):
    root, fixture, _, _ = harness
    objects = [
        {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
         'metadata': {'name': name, 'namespace': 'apps-jobs'},
         'spec': {'podSelector': {}, 'ingress': ingress, 'egress': [
             {'to': [{'ipBlock': {'cidr': '192.0.2.10/32'}}], 'ports': [{'port': 443}]},
         ]}}
        for name, ingress in [('deny-ingress', []), ('allow-ingress', [{}])]
    ]
    play = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False, 'tasks': [
        {'ansible.builtin.command': {
            'argv': [str(fixture / 'kubectl'), 'create', '-f', '-'],
            'stdin': '{{ item | to_json }}',
        }, 'loop': objects},
    ]}]
    path = root / 'network-policy-roundtrip.yml'
    path.write_text(yaml.safe_dump(play))
    command_runner.run(['ansible-playbook', '-i', 'localhost,', path],
                       environment={'DEPLOYMENT_RUNNER_FIXTURE': str(fixture)}).assert_success()
    state = json.loads((fixture / 'state.json').read_text())
    denied = state['networkpolicy/apps-jobs/deny-ingress']['spec']
    allowed = state['networkpolicy/apps-jobs/allow-ingress']['spec']
    assert 'ingress' not in denied
    assert allowed['ingress'] == [{}]
    for spec in (denied, allowed):
        assert spec['policyTypes'] == ['Ingress', 'Egress']
        assert spec['podSelector'] == {}
        assert spec['egress'][0]['ports'] == [{'port': 443, 'protocol': 'TCP'}]


def test_reviewed_repo_ca_exact_bytes_clone_override_and_bad_digest(harness, command_runner):
    root, fixture, config, _ = harness
    role = root / 'roles' / ROLE
    defaults = yaml.safe_load((role / 'defaults/main.yml').read_text())
    selected = defaults | config
    dr = {k.removeprefix(PREFIX): v for k, v in selected.items() if k.startswith(PREFIX)}
    pem = root / 'repo-ca.pem'
    content = b'-----BEGIN CERTIFICATE-----\r\nsynthetic-repo-fixture\r\n-----END CERTIFICATE-----\r\n'
    pem.write_bytes(content)
    dr.update(chart_repo_ca_src=str(pem), chart_repo_ca_sha256=hashlib.sha256(content).hexdigest(),
              chart_repo='https://charts.example.test:8443/repository/runner/',
              clone_url='https://clone.example.test:8443/')
    play = [{'hosts': 'localhost', 'gather_facts': False, 'connection': 'local', 'vars': {
        '_dr': dr, '_dr_runner': config[ROLE][0], '_dr_release': 'rke2-gitlab-apps',
        '_dr_material': {}, '_dr_repo_ca': '{{ _dr_material.repo_ca }}',
        '_dr_source': {'key': 'repo_ca', 'src': str(pem), 'sha': dr['chart_repo_ca_sha256'], 'token': False},
    }, 'tasks': [
        {'ansible.builtin.include_tasks': str(role / 'tasks/source.yml')},
        {'ansible.builtin.copy': {
            'content': '{{ lookup("ansible.builtin.template", ' + json.dumps(str(role / 'templates/helmchart.yaml.j2')) + ') }}',
            'dest': str(root / 'rendered.yml'), 'mode': '0600',
        }},
    ]}]
    path = root / 'ca-render.yml'
    path.write_text(yaml.safe_dump(play))
    command_runner.run(['ansible-playbook', '-i', 'localhost,', path]).assert_success()
    chart = yaml.safe_load((root / 'rendered.yml').read_text())
    assert chart['spec']['repoCA'].encode() == content
    assert chart['spec']['repo'] == dr['chart_repo']
    values = yaml.safe_load(chart['spec']['valuesContent'])
    assert tomllib.loads(values['runners']['config'])['runners'][0]['clone_url'] == dr['clone_url']
    play[0]['vars']['_dr_source']['sha'] = '0' * 64
    path.write_text(yaml.safe_dump(play))
    command_runner.run(['ansible-playbook', '-i', 'localhost,', path]).assert_failure()
    assert not (fixture / 'calls.jsonl').exists()
