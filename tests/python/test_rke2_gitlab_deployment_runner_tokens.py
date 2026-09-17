import base64
import copy
import json
import os
from pathlib import Path

import pytest
import yaml

from test_rke2_gitlab_deployment_runner_admission import admission  # noqa: F401
from test_rke2_gitlab_deployment_runners import ROLE, harness  # noqa: F401


def token_secret(name, namespace, token):
    return {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': namespace},
            'type': 'Opaque', 'data': {'runner-token': base64.b64encode(token.encode()).decode(),
                                      'runner-registration-token': ''}}


def assert_redacted(result, tokens):
    output = result.stdout + result.stderr
    for token in tokens:
        assert token not in output
        assert base64.b64encode(token.encode()).decode() not in output


@pytest.mark.parametrize('reuse', ['same-new-value', 'legacy-apps', 'legacy-platform'])
def test_controller_token_reuse_rejected_before_first_write(admission, reuse):
    fixture, state, settings, _, run = admission
    paths = {item['profile']: Path(item['token_src']) for item in settings[ROLE]}
    assert paths['apps'] != paths['platform']
    if reuse == 'same-new-value':
        paths['platform'].write_bytes(paths['apps'].read_bytes())
    else:
        selected = paths[reuse.removeprefix('legacy-')].read_text()
        state['secret/gitlab-runner/rke2-gitlab-runner-token'] = token_secret(
            'rke2-gitlab-runner-token', 'gitlab-runner', selected)
        (fixture / 'state.json').write_text(json.dumps(state))
    before = (fixture / 'state.json').read_bytes()
    result = run(tasks_from='converge', settings=settings | {'_deployment_runner_smoke': False}).assert_failure()
    assert 'Reconcile externally owned namespaces accounts policy and RBAC' not in result.stdout
    assert (fixture / 'state.json').read_bytes() == before
    assert not list((fixture / 'manifests').iterdir())
    assert_redacted(result, [path.read_text() for path in paths.values()])
    calls = list(map(json.loads, (fixture / 'calls.jsonl').read_text().splitlines())) if (fixture / 'calls.jsonl').exists() else []
    if reuse == 'same-new-value':
        assert calls == []
    else:
        assert len(calls) == 1
        start = calls[0].index('get')
        assert ['get', 'secret', 'rke2-gitlab-runner-token', '-n', 'gitlab-runner'] == calls[0][start:start + 5]
        assert '--ignore-not-found' in calls[0]


def test_complete_smoke_rejects_installed_token_reuse_without_controller_files(admission):
    fixture, state, settings, _, run = admission
    reused_token = 'glrt-' + ('a' * 32)  # Deliberately synthetic fixture value.
    for obj in settings['_dr_objects']:
        if obj['kind'] not in ('Secret', 'HelmChart'):
            continue
        obj = copy.deepcopy(obj)
        if obj['kind'] == 'Secret' and obj['metadata']['name'].endswith('-token'):
            obj.update(type='Opaque', data=token_secret('', '', reused_token)['data'])
        state['/'.join((obj['kind'].lower(), obj['metadata']['namespace'], obj['metadata']['name']))] = obj
    (fixture / 'state.json').write_text(json.dumps(state))
    for item in settings[ROLE]:
        Path(item['token_src']).unlink()
    Path(settings['_dr']['tls_ca_cert_src']).unlink()
    before = (fixture / 'state.json').read_bytes()
    result = run(smoke=True, check=True, settings={k: v for k, v in settings.items() if not k.startswith('_')}).assert_failure()
    assert 'Require two distinct canonical nonempty deployment token values' in result.stdout
    assert 'Inspect bounded controller source' not in result.stdout
    assert (fixture / 'state.json').read_bytes() == before
    assert_redacted(result, [reused_token])
    calls = list(map(json.loads, (fixture / 'calls.jsonl').read_text().splitlines()))
    projections = [call for call in calls if any(arg.startswith('-o=go-template=') for arg in call)]
    assert len(projections) == 2
    assert all('get' in call for call in calls)


def test_installed_token_shape_and_isolation_matrix_is_read_only_and_redacted(admission, command_runner):
    fixture, _, settings, _, _ = admission
    root = fixture.parent
    apps = token_secret('rke2-gitlab-apps-token', 'apps-managers', 'glrt-installed-apps')
    platform = token_secret('rke2-gitlab-platform-token', 'platform-managers', 'glrt-installed-platform')
    legacy = token_secret('rke2-gitlab-runner-token', 'gitlab-runner', 'glrt-installed-legacy')
    cases = [('absent-legacy', apps, platform, None, True), ('separate-legacy', apps, platform, legacy, True),
             ('empty-legacy', apps, platform, token_secret('rke2-gitlab-runner-token', 'gitlab-runner', ''), True)]
    for token in ['glrt-installed-apps', 'glrt-installed-platform']:
        cases.append(('legacy-reuse', apps, platform, token_secret('rke2-gitlab-runner-token', 'gitlab-runner', token), False))
    for value in ['', 'not-a-runner-token', 'glrt-whitespace\n', 'glrt-' + 'x' * 508]:
        cases.append(('bad-token', token_secret('rke2-gitlab-apps-token', 'apps-managers', value), platform, None, False))
    cases.append(('missing-new-secret', None, platform, None, False))
    for field, value in [('type', 'kubernetes.io/service-account-token'), ('kind', 'ConfigMap'), ('apiVersion', 'v2')]:
        bad = copy.deepcopy(apps)
        bad[field] = value
        cases.append(('bad-shape', bad, platform, None, False))
    for mutation in [{'runner-registration-token': 'YQ=='}, {'extra': ''}, {'runner-token': 'Z2xydC14='},
                     {'runner-token': 'Z2xydC14eB=='},
                     {'runner-token': '!!!!'}, {'runner-token': 'A' * 688}]:
        bad = copy.deepcopy(apps)
        bad['data'].update(mutation)
        cases.append(('bad-data', bad, platform, None, False))
    malformed_legacy = copy.deepcopy(legacy)
    del malformed_legacy['data']['runner-token']
    cases.append(('malformed-legacy', apps, platform, malformed_legacy, False))
    replaced_token = copy.deepcopy(malformed_legacy)
    replaced_token['data']['unexpected'] = base64.b64encode(b'synthetic-unexpected-secret-value').decode()
    cases.append(('legacy-token-key-replaced', apps, platform, replaced_token, False))
    for data in [None, {}, {'runner-token': None, 'runner-registration-token': ''}]:
        malformed = copy.deepcopy(legacy)
        malformed['data'] = data
        cases.append(('legacy-empty-or-null-data', apps, platform, malformed, False))
    missing_data = copy.deepcopy(legacy)
    del missing_data['data']
    cases.append(('legacy-missing-data', apps, platform, missing_data, False))

    tasks = []
    snapshots = []
    for index, (name, app_secret, platform_secret, legacy_secret, valid) in enumerate(cases):
        state = {key: obj for key, obj in [
            ('secret/apps-managers/rke2-gitlab-apps-token', app_secret),
            ('secret/platform-managers/rke2-gitlab-platform-token', platform_secret),
            ('secret/gitlab-runner/rke2-gitlab-runner-token', legacy_secret),
        ] if obj is not None}
        snapshots.append(state)
        tasks.extend([
            {'name': 'Set synthetic API snapshot', 'ansible.builtin.copy': {
                'content': json.dumps(state), 'dest': str(fixture / 'state.json'), 'mode': '0600'}, 'no_log': True},
            {'ansible.builtin.set_fact': {'rejected': False}},
            {'name': f'Identity case {index} {name}', 'block': [
                {'ansible.builtin.include_role': {'name': ROLE, 'tasks_from': 'token_identity', 'defaults_from': 'unused'}},
            ], 'rescue': [{'ansible.builtin.set_fact': {'rejected': True}}]},
            {'ansible.builtin.assert': {'that': f'rejected == {not valid}'}},
        ])
    playbook = root / 'token-matrix.yml'
    playbook.write_text(yaml.safe_dump([{
        'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
        'vars': {'_dr_instances': settings[ROLE], '_dr_kubectl': settings['_dr_kubectl'], '_deployment_runner_smoke': True},
        'tasks': tasks,
    }]))
    # There are deliberately no controller credential files for this entire matrix.
    for item in settings[ROLE]:
        Path(item['token_src']).unlink()
    Path(settings['_dr']['tls_ca_cert_src']).unlink()
    result = command_runner.run(['ansible-playbook', '-i', 'localhost,', playbook], timeout=120, environment={
        'ANSIBLE_ROLES_PATH': str(root / 'roles'), 'DEPLOYMENT_RUNNER_FIXTURE': str(fixture),
    }).assert_success()
    assert_redacted(result, ['glrt-installed-apps', 'glrt-installed-platform', 'glrt-installed-legacy'])
    assert_redacted(result, ['synthetic-unexpected-secret-value'])
    assert json.loads((fixture / 'state.json').read_text()) == snapshots[-1]
    calls = list(map(json.loads, (fixture / 'calls.jsonl').read_text().splitlines()))
    allowed = {('apps-managers', 'rke2-gitlab-apps-token'), ('platform-managers', 'rke2-gitlab-platform-token'),
               ('gitlab-runner', 'rke2-gitlab-runner-token')}
    for call in calls:
        assert 'get' in call and 'secret' in call and '--ignore-not-found' in call
        assert (call[call.index('-n') + 1], call[call.index('secret') + 1]) in allowed
        assert any(arg.startswith('-o=go-template=') for arg in call)


def test_bounded_token_printer_with_real_go_template_engine(repo_root, isolated_test_dir, command_runner):
    # Reuse the already verified optional Helm binary only as a local Go-template
    # engine. This checks the production printer independently of fake kubectl.
    helm = os.environ.get('PLATFORM_CONFIG_TEST_HELM')
    if not helm:
        pytest.skip('requires an already verified local Helm binary; never downloads')
    root = isolated_test_dir
    chart = root / 'printer-chart'
    (chart / 'templates').mkdir(parents=True)
    (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: token-printer-test\nversion: 0.0.0\n')
    printer = (repo_root / 'roles' / ROLE / 'templates/token-secret.gotmpl').read_text()
    (chart / 'templates/projection.yaml').write_text(
        '{{ range .Values.cases }}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n'
        '  name: projection-{{ .id }}\ndata:\n  projection: \'{{ with .secret }}'
        + printer + '{{ end }}\'\n{{ end }}\n')
    valid = token_secret('test', 'test', 'glrt-printer-synthetic')
    extra = copy.deepcopy(valid)
    extra['data']['unexpected'] = 'private-not-for-output'
    oversized = token_secret('test', 'test', 'glrt-' + 'x' * 600)
    wrong_type = copy.deepcopy(valid)
    wrong_type['type'] = 'kubernetes.io/service-account-token'
    empty = token_secret('test', 'test', '')
    missing_token = copy.deepcopy(valid)
    del missing_token['data']['runner-token']
    missing_registration = copy.deepcopy(valid)
    del missing_registration['data']['runner-registration-token']
    replaced_token = copy.deepcopy(missing_token)
    replaced_token['data']['unexpected'] = 'private-not-for-output'
    replaced_registration = copy.deepcopy(missing_registration)
    replaced_registration['data']['unexpected'] = 'private-not-for-output'
    missing_data = copy.deepcopy(valid)
    del missing_data['data']
    empty_data = copy.deepcopy(valid)
    empty_data['data'] = {}
    null_data = copy.deepcopy(valid)
    null_data['data'] = None
    null_token = copy.deepcopy(valid)
    null_token['data']['runner-token'] = None
    null_registration = copy.deepcopy(valid)
    null_registration['data']['runner-registration-token'] = None
    specimens = [valid, extra, oversized, wrong_type, empty, missing_token, missing_registration,
                 replaced_token, replaced_registration, missing_data, empty_data, null_data, null_token, null_registration]
    values = root / 'printer-values.yml'
    values.write_text(yaml.safe_dump({'cases': [
        {'id': index, 'secret': secret} for index, secret in enumerate(specimens)
    ]}))
    result = command_runner.run([helm, 'template', 'printer', chart, '--values', values]).assert_success()
    rendered = list(yaml.safe_load_all(result.stdout))
    observed = {obj['metadata']['name']: obj['data']['projection'] for obj in rendered}
    expected = {f'projection-{index}': 'invalid' for index in range(len(specimens))}
    expected.update({'projection-0': 'token:' + valid['data']['runner-token'], 'projection-4': 'token:'})
    assert observed == expected
    assert all(len(value) <= 690 for value in observed.values())
    assert 'private-not-for-output' not in result.stdout + result.stderr
