"""Native CEL is live-qualified by the role, not by the protocol double here."""
from __future__ import annotations

import json

import pytest
import yaml

from test_rke2_gitlab_deployment_runners import PREFIX, ROLE, harness  # noqa: F401


@pytest.fixture
def admission(harness, command_runner):
    root, fixture, config, run = harness
    role = root / 'roles' / ROLE
    defaults = yaml.safe_load((role / 'defaults/main.yml').read_text())
    dr = {k.removeprefix(PREFIX): v for k, v in (defaults | config).items() if k.startswith(PREFIX)}
    play = [{'hosts': 'localhost', 'gather_facts': False, 'connection': 'local',
             'vars': {'_dr': dr, '_dr_instances': config[ROLE]}, 'tasks': [
                 {'ansible.builtin.copy': {
                     'content': '{{ lookup("ansible.builtin.template", ' + json.dumps(str(role / 'templates/resources.yaml.j2')) + ') }}',
                     'dest': str(root / 'objects.yml'), 'mode': '0600',
                 }},
                 {'ansible.builtin.copy': {
                     'content': '{{ lookup("ansible.builtin.template", ' + json.dumps(str(role / 'templates/admission-probes.yaml.j2')) + ') }}',
                     'dest': str(root / 'probes.yml'), 'mode': '0600',
                 }, 'vars': {'_dr_runner': config[ROLE][0], '_dr_release': 'rke2-gitlab-apps'}},
             ]}]
    path = root / 'render-admission.yml'
    path.write_text(yaml.safe_dump(play))
    command_runner.run(['ansible-playbook', '-i', 'localhost,', path]).assert_success()
    objects = list(yaml.safe_load_all((root / 'objects.yml').read_text()))
    state = {}
    for obj in objects:
        if obj['kind'] in ('Secret', 'HelmChart'):
            continue
        obj['metadata'].update(uid='fixture-' + obj['metadata']['name'], resourceVersion='1')
        if obj['kind'] == 'ValidatingAdmissionPolicy':
            obj['metadata']['generation'] = 1
            obj['status'] = {'observedGeneration': 1, 'typeChecking': {}}
        key = '/'.join((obj['kind'].lower(), obj['metadata'].get('namespace', ''), obj['metadata']['name']))
        state[key] = obj
    (fixture / 'state.json').write_text(json.dumps(state))
    settings = config | {
        '_dr': dr, '_dr_instances': config[ROLE], '_dr_objects': list(yaml.safe_load_all((root / 'objects.yml').read_text())),
        '_dr_kubectl': [str(fixture / 'kubectl'), '--request-timeout=30s'],
        '_dr_job_pods': {'apps': [], 'platform': []},
    }
    probes = yaml.safe_load((root / 'probes.yml').read_text())
    return fixture, state, settings, probes, run


def test_fixed_native_policy_render_contract_and_probe_cases(admission):
    _, state, settings, probes, _ = admission
    dr = settings['_dr']
    policies = [obj for obj in state.values() if obj['kind'] == 'NetworkPolicy']
    assert len(policies) == 4
    for policy in policies:
        assert 'ingress' not in policy['spec']
        assert policy['spec']['policyTypes'] == ['Ingress', 'Egress']
    for profile in ('apps', 'platform'):
        namespace = state[f'namespace//{profile}-jobs']
        for mode in ('enforce', 'audit', 'warn'):
            assert namespace['metadata']['labels']['pod-security.kubernetes.io/' + mode] == 'baseline'
            assert namespace['metadata']['labels']['pod-security.kubernetes.io/' + mode + '-version'] == 'v1.35'
        name = 'rke2-gitlab-' + profile + '-job-pods'
        policy = state['validatingadmissionpolicy//' + name]
        binding = state['validatingadmissionpolicybinding//' + name]
        selector = {'matchLabels': {'kubernetes.io/metadata.name': profile + '-jobs'}}
        assert policy['apiVersion'] == binding['apiVersion'] == 'admissionregistration.k8s.io/v1'
        assert policy['spec']['failurePolicy'] == 'Fail'
        assert policy['spec']['matchConstraints'] == {
            'matchPolicy': 'Exact', 'namespaceSelector': selector, 'objectSelector': {},
            'resourceRules': [{'apiGroups': [''], 'apiVersions': ['v1'], 'operations': ['CREATE', 'UPDATE'],
                               'resources': ['pods', 'pods/ephemeralcontainers'], 'scope': 'Namespaced'}],
        }
        assert binding['spec'] == {
            'policyName': name, 'validationActions': ['Deny'],
            'matchResources': {'matchPolicy': 'Exact', 'namespaceSelector': selector, 'objectSelector': {}},
        }
        expressions = [v['expression'] for v in policy['spec']['validations']]
        assert expressions == [
            f'object.spec.serviceAccountName == "rke2-gitlab-{profile}-job"',
            'object.spec.containers.size() == 2 && '
            f"object.spec.containers.exists(c, c.name == 'build' && c.image == {json.dumps(dr['job_image'])}) && "
            f"object.spec.containers.exists(c, c.name == 'helper' && c.image == {json.dumps(dr['helper_image'])})",
            '!has(object.spec.initContainers) || (object.spec.initContainers.size() <= 1 && '
            "object.spec.initContainers.all(c, c.name == 'init-permissions' && "
            f"c.image == {json.dumps(dr['helper_image'])} && !has(c.restartPolicy)))",
            '!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.size() == 0',
        ]
        assert all(v['reason'] == 'Forbidden' for v in policy['spec']['validations'])
        assert policy['metadata']['labels']['app.kubernetes.io/component'] == profile
        assert binding['metadata']['labels'] == policy['metadata']['labels']
    cases = {probe['name']: probe for probe in probes}
    assert set(cases) == {'valid-no-init', 'valid-init-permissions', 'wrong-account', 'missing-helper', 'service',
                          'unpinned-build', 'unpinned-helper', 'other-init', 'unpinned-init', 'sidecar-init'}
    assert cases['valid-no-init']['message'] == cases['valid-init-permissions']['message'] == ''
    assert cases['wrong-account']['pod']['spec']['serviceAccountName'] == 'default'
    assert len(cases['service']['pod']['spec']['containers']) == 3
    assert cases['service']['pod']['spec']['containers'][2]['image'] == dr['helper_image']
    assert '@' not in cases['unpinned-build']['pod']['spec']['containers'][0]['image']
    assert '@' not in cases['unpinned-helper']['pod']['spec']['containers'][1]['image']
    assert cases['other-init']['pod']['spec']['initContainers'][0]['name'] == 'init-build-uid-gid-collector'
    assert cases['sidecar-init']['pod']['spec']['initContainers'][0]['restartPolicy'] == 'Always'


@pytest.mark.parametrize('failure', ['admission-off', 'admission-unrelated-denial', 'admission-warning', 'scope-drift'])
def test_read_only_admission_proof_fails_closed(admission, failure):
    fixture, state, settings, _, run = admission
    if failure == 'scope-drift':
        state['validatingadmissionpolicybinding//rke2-gitlab-apps-job-pods']['spec']['validationActions'] = ['Warn']
        (fixture / 'state.json').write_text(json.dumps(state))
    else:
        (fixture / failure).touch()
    before = (fixture / 'state.json').read_bytes()
    run(tasks_from='admission', settings=settings, check=True).assert_failure()
    assert (fixture / 'state.json').read_bytes() == before
    assert not list((fixture / 'manifests').iterdir())
    assert all('get' in call or '--dry-run=server' in call
               for call in map(json.loads, (fixture / 'calls.jsonl').read_text().splitlines()))


def test_failed_admission_gate_blocks_full_role_publication(admission):
    fixture, _, settings, _, run = admission
    (fixture / 'admission-off').touch()
    run(settings={k: v for k, v in settings.items() if not k.startswith('_')}).assert_failure()
    # Real convergence reached the native gate after reconciling its prerequisites,
    # but neither manager source may be published when rejection is unproved.
    calls = list(map(json.loads, (fixture / 'calls.jsonl').read_text().splitlines()))
    assert any('--dry-run=server' in call for call in calls)
    assert not list((fixture / 'manifests').iterdir())
    state = json.loads((fixture / 'state.json').read_text())
    assert len([v for v in state.values() if v['kind'] == 'ValidatingAdmissionPolicyBinding']) == 2


def test_existing_incompatible_job_pod_is_rejected_before_any_write(admission):
    fixture, state, settings, probes, run = admission
    pod = next(p['pod'] for p in probes if p['name'] == 'service')
    pod['metadata'].update(name='old-incompatible-job', uid='old-uid', resourceVersion='1')
    state['pod/apps-jobs/old-incompatible-job'] = pod
    (fixture / 'state.json').write_text(json.dumps(state))
    before = (fixture / 'state.json').read_bytes()
    run(settings={k: v for k, v in settings.items() if not k.startswith('_')}, check=True).assert_failure()
    assert (fixture / 'state.json').read_bytes() == before
    assert not list((fixture / 'manifests').iterdir())
    assert all('get' in call for call in map(json.loads, (fixture / 'calls.jsonl').read_text().splitlines()))
