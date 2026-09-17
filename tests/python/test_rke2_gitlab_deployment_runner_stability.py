import json

import pytest
import yaml


@pytest.mark.parametrize('first,second,success', [(7, 7, True), (7, 8, False), (7, 6, False), (-1, -1, False)])
def test_manager_stability_accepts_only_unchanged_nonnegative_counts(
    repo_root, isolated_test_dir, command_runner, first, second, success,
):
    def sample(count):
        return {'stdout': json.dumps({'items': [{
            'metadata': {'name': 'manager', 'uid': 'same-pod'},
            'spec': {'nodeName': 'worker', 'serviceAccountName': 'rke2-gitlab-apps'},
            'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}],
                       'containerStatuses': [{'name': 'manager', 'ready': True, 'restartCount': count,
                                              'state': {'running': {}}}]},
        }]})}

    inventory = isolated_test_dir / 'inventory.yml'
    inventory.write_text(yaml.safe_dump({'all': {'children': {
        'rke2_servers': {'hosts': {'server': {'ansible_connection': 'local'}}},
        'rke2_agents': {'hosts': {'worker': {}}},
    }}}))
    playbook = isolated_test_dir / 'stability.yml'
    playbook.write_text(yaml.safe_dump([{
        'hosts': 'rke2_servers', 'gather_facts': False,
        'vars': {'_dr_release': 'rke2-gitlab-apps', '_dr_pods_first': sample(first), '_dr_pods_second': sample(second)},
        'tasks': [{'ansible.builtin.import_tasks': str(
            repo_root / 'roles/rke2_gitlab_deployment_runners/tasks/verify_manager_stability.yml')}],
    }]))
    result = command_runner.run(['ansible-playbook', '-i', inventory, playbook, '--check'])
    if success:
        result.assert_success()
        assert 'changed=0' in result.stdout
    else:
        result.assert_failure()
