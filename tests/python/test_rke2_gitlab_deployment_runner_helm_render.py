"""Optional real-chart qualification using explicitly supplied, verified artifacts.

Never downloads artifacts. Ordinary offline pytest runs skip this module unless
both PLATFORM_CONFIG_TEST_HELM and PLATFORM_CONFIG_TEST_GITLAB_RUNNER_CHART are set.
"""
import hashlib
import json
import os
import tomllib
from pathlib import Path

import pytest
import yaml

from test_rke2_gitlab_deployment_runners import PREFIX, ROLE, variables


@pytest.mark.parametrize('profile', ['apps', 'platform'])
def test_chart_0883_real_render_matches_manager_smoke(repo_root, isolated_test_dir, command_runner, profile):
    helm = os.environ.get('PLATFORM_CONFIG_TEST_HELM')
    chart = os.environ.get('PLATFORM_CONFIG_TEST_GITLAB_RUNNER_CHART')
    if not helm and not chart:
        pytest.skip('requires verified local Helm 4.2.2 and gitlab-runner 0.88.3 artifacts')
    assert helm and chart and Path(helm).is_file() and Path(chart).is_file()
    assert hashlib.sha256(Path(chart).read_bytes()).hexdigest() == 'e1d1bfafb3592f7bac1c730a25c04afe672303ad66722f9f6775e60783652627'
    version = command_runner.run([helm, 'version', '--template', '{{ .Version }}']).assert_success()
    assert version.stdout.strip() == 'v4.2.2'
    metadata = yaml.safe_load(command_runner.run([helm, 'show', 'chart', chart]).assert_success().stdout)
    assert metadata['name'] == 'gitlab-runner' and metadata['version'] == '0.88.3'

    root = isolated_test_dir
    role = repo_root / 'roles' / ROLE
    defaults = yaml.safe_load((role / 'defaults/main.yml').read_text())
    config = variables(root)
    dr = {key.removeprefix(PREFIX): value for key, value in (defaults | config).items() if key.startswith(PREFIX)}
    runner = next(item for item in config[ROLE] if item['profile'] == profile)
    release = 'rke2-gitlab-' + profile
    playbook = root / 'render.yml'
    playbook.write_text(yaml.safe_dump([{
        'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
        'vars': {'_dr': dr, '_dr_runner': runner, '_dr_release': release},
        'tasks': [{'ansible.builtin.copy': {
            'content': '{{ lookup("ansible.builtin.template", ' + json.dumps(str(role / 'templates/helmchart.yaml.j2')) + ') }}',
            'dest': str(root / 'helmchart.yml'), 'mode': '0600',
        }}],
    }]))
    command_runner.run(['ansible-playbook', '-i', 'localhost,', playbook]).assert_success()
    helmchart = yaml.safe_load((root / 'helmchart.yml').read_text())
    values = yaml.safe_load(helmchart['spec']['valuesContent'])
    values_path = root / 'values.yml'
    values_path.write_text(helmchart['spec']['valuesContent'])
    rendered = command_runner.run([helm, 'template', release, chart, '--namespace', runner['manager_namespace'],
                                   '--kube-version', '1.35.0', '--values', values_path]).assert_success()
    objects = [obj for obj in yaml.safe_load_all(rendered.stdout) if obj]
    assert not any(obj['kind'] in ('Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding', 'ServiceAccount', 'Secret')
                   for obj in objects)
    deployments = [obj for obj in objects if obj['kind'] == 'Deployment']
    configmaps = [obj for obj in objects if obj['kind'] == 'ConfigMap']
    assert len(deployments) == len(configmaps) == 1
    deployment, configmap = deployments[0], configmaps[0]
    assert deployment['metadata']['name'] == configmap['metadata']['name'] == release
    spec = deployment['spec']['template']['spec']
    container = spec['containers'][0]
    assert spec['serviceAccountName'] == release
    assert spec['automountServiceAccountToken'] is True
    assert container['image'] == dr['manager_image']
    assert container['securityContext'] == values['securityContext']
    assert container['resources'] == values['resources']
    assert spec['affinity'] == values['affinity']
    executor = tomllib.loads(configmap['data']['config.template.toml'])['runners'][0]['kubernetes']
    assert executor['namespace'] == runner['job_namespace']
    assert executor['service_account'] == release + '-job'
    assert executor['automount_service_account_token'] is True
    assert executor['image'] == dr['job_image']
    assert executor['helper_image'] == dr['helper_image']

    # Chart 0.88.3 omits replicas. Model Kubernetes 1.35 SetDefaults_Deployment
    # (one replica), plus synthetic API readiness, without changing any rendered
    # field. The production smoke assertion still requires replicas == 1.
    deployment['spec'].setdefault('replicas', 1)
    deployment['metadata']['generation'] = 1
    deployment['status'] = {'observedGeneration': 1, 'updatedReplicas': 1, 'availableReplicas': 1}
    playbook.write_text(yaml.safe_dump([{
        'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
        'vars': {'_dr': dr, '_dr_release': release, '_dr_live_chart': {'stdout': json.dumps(helmchart)},
                 '_dr_manager_resources': {'results': [{'stdout': json.dumps(deployment)}, {'stdout': json.dumps(configmap)}]}},
        'tasks': [{'ansible.builtin.import_tasks': str(role / 'tasks/verify_manager.yml')}],
    }]))
    command_runner.run(['ansible-playbook', '-i', 'localhost,', playbook, '--check']).assert_success()
