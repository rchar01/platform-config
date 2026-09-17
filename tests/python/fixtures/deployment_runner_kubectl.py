#!/usr/bin/env python3
"""Offline API-shaped state store; never contacts Kubernetes or GitLab."""
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

root = Path(os.environ['DEPLOYMENT_RUNNER_FIXTURE'])
state_path = root / 'state.json'
state = json.loads(state_path.read_text()) if state_path.exists() else {}
args = sys.argv[1:]
with (root / 'calls.jsonl').open('a') as stream:
    stream.write(json.dumps(args) + '\n')


def option(flag, default=''):
    return args[args.index(flag) + 1] if flag in args else default


def key(kind, name, namespace=''):
    return '/'.join((kind.lower(), namespace, name))


def put(obj):
    metadata = obj['metadata']
    metadata.setdefault('uid', 'fixture-' + metadata['name'])
    metadata.setdefault('resourceVersion', '1')
    if obj['kind'] == 'NetworkPolicy':
        # Kubernetes v1.35 networking/v1 defaults and JSON omitempty semantics.
        # Do not recursively remove empty objects: ingress: [{}] allows traffic.
        spec = obj['spec']
        spec.setdefault('podSelector', {})
        if not spec.get('policyTypes'):
            spec['policyTypes'] = ['Ingress'] + (['Egress'] if spec.get('egress') else [])
        for direction in ('ingress', 'egress'):
            if not spec.get(direction):
                spec.pop(direction, None)
            for rule in spec.get(direction, []):
                for port in rule.get('ports', []):
                    port.setdefault('protocol', 'TCP')
    if obj['kind'] == 'ValidatingAdmissionPolicy':
        metadata.setdefault('generation', 1)
        obj.setdefault('status', {'observedGeneration': metadata['generation'], 'typeChecking': {}})
    state[key(obj['kind'], metadata['name'], metadata.get('namespace', ''))] = obj


def admission_denial(pod):
    """Protocol double only: this models the fixed shape, NOT Kubernetes CEL."""
    if (root / 'admission-off').exists():
        return ''
    for policy in state.values():
        if policy['kind'] != 'ValidatingAdmissionPolicy':
            continue
        name = policy['metadata']['name']
        ns = policy['spec']['matchConstraints']['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name']
        if pod['metadata']['namespace'] != ns:
            continue
        if key('ValidatingAdmissionPolicyBinding', name) not in state:
            continue
        validations = policy['spec']['validations']
        account = json.loads(validations[0]['expression'].split(' == ')[1])
        build_image, helper_image = [json.loads(v) for v in re.findall(r'c.image == ("[^"]+")', validations[1]['expression'])]
        spec = pod['spec']
        containers = spec.get('containers', [])
        init = spec.get('initContainers', [])
        checks = [
            spec.get('serviceAccountName') == account,
            len(containers) == 2 and any(c['name'] == 'build' and c['image'] == build_image for c in containers)
            and any(c['name'] == 'helper' and c['image'] == helper_image for c in containers),
            len(init) <= 1 and all(c['name'] == 'init-permissions' and c['image'] == helper_image
                                  and 'restartPolicy' not in c for c in init),
            not spec.get('ephemeralContainers'),
        ]
        for check, validation in zip(checks, validations):
            if not check:
                if (root / 'admission-unrelated-denial').exists():
                    return 'unrelated admission or transport failure'
                return f"ValidatingAdmissionPolicy '{name}' with binding '{name}' denied request: {validation['message']}"
    return ''


# Simulate only Helm's observed outputs, from the actual Ansible-published values.
for path in (root / 'manifests').glob('rke2-gitlab-*.yaml'):
    chart = yaml.safe_load(path.read_text())
    put(chart)
    release = chart['metadata']['name']
    ns = chart['spec']['targetNamespace']
    values = yaml.safe_load(chart['spec']['valuesContent'])
    metadata = {
        'name': release, 'namespace': ns, 'generation': 1,
        'labels': {'app.kubernetes.io/managed-by': 'Helm'},
        'annotations': {'meta.helm.sh/release-name': release, 'meta.helm.sh/release-namespace': ns},
    }
    spec = {
        'serviceAccountName': values['serviceAccount']['name'],
        'automountServiceAccountToken': values['automountServiceAccountToken'],
        'affinity': values['affinity'],
        'containers': [{
            'image': 'docker.io/gitlab/gitlab-runner:' + values['image']['tag'],
            'imagePullPolicy': 'Always', 'securityContext': values['securityContext'],
            'resources': values['resources'],
        }],
        'volumes': [
            {'name': 'projected-secrets', 'projected': {'sources': [{'secret': {'name': values['runners']['secret']}}]}},
            {'name': 'custom-certs', 'secret': {'secretName': values['certsSecretName']}},
        ],
    }
    put({'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': metadata,
         'spec': {'replicas': 1, 'template': {'spec': spec}},
         'status': {'observedGeneration': 1, 'updatedReplicas': 1, 'availableReplicas': 1}})
    put({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata,
         'data': {'config.template.toml': values['runners']['config']}})
    put({'apiVersion': 'batch/v1', 'kind': 'Job',
         'metadata': {'name': 'helm-install-' + release, 'namespace': 'kube-system'},
         'status': {'conditions': [{'type': 'Complete', 'status': 'True'}]}})
    put({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': release + '-pod', 'namespace': ns},
         'spec': spec | {'nodeName': 'worker'},
         'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}],
                    'containerStatuses': [{'ready': True, 'restartCount': 0, 'state': {'running': {}}}]}})

if 'get' in args and 'auth' not in args:
    pos = args.index('get')
    kind, name = args[pos + 1:pos + 3]
    ns = option('-n')
    result: dict[str, Any] | None
    if kind == 'pods':
        result = {'items': [v for k, v in state.items() if k.startswith('pod/' + ns + '/')]}
    else:
        result = state.get(key(kind, name, ns))
    if result is None:
        sys.exit(0 if '--ignore-not-found' in args else 1)
    if result.get('kind') == 'ValidatingAdmissionPolicy' and (root / 'admission-warning').exists():
        result['status']['typeChecking'] = {'expressionWarnings': [{'warning': 'synthetic CEL type warning'}]}
    if any(arg.startswith('-o=go-template=') for arg in args):
        # Model the fixed bounded authentication printer, not a general Go-template engine.
        data = result.get('data')
        if not isinstance(data, dict):
            data = {}
        known_keys = len(data) == 2 and all(key in ('runner-token', 'runner-registration-token') for key in data)
        valid = (result.get('apiVersion') == 'v1' and result.get('kind') == 'Secret'
                 and result.get('type') == 'Opaque' and known_keys
                 and isinstance(data['runner-token'], str) and isinstance(data['runner-registration-token'], str)
                 and data['runner-registration-token'] == ''
                 and len(data['runner-token']) <= 684)
        print('token:' + data['runner-token'] if valid else 'invalid', end='')
    else:
        print(json.dumps(result['metadata'] if '-o=jsonpath={.metadata}' in args else result))
elif '--dry-run=server' in args:
    if 'patch' in args:
        patch = json.loads(option('-p'))
        name = args[args.index('pod') + 1]
        obj = state[key('pod', name, option('-n'))]
        assert patch['metadata']['uid'] == obj['metadata']['uid']
        assert patch['metadata']['resourceVersion'] == obj['metadata']['resourceVersion']
        obj['spec'].update(patch['spec'])
    else:
        obj = json.load(sys.stdin)
    with (root / 'dry-runs.jsonl').open('a') as stream:
        stream.write(json.dumps(obj) + '\n')
    denied = admission_denial(obj)
    if denied:
        print(denied, file=sys.stderr)
        sys.exit(1)
    print(json.dumps(obj))
elif ('create' in args or 'replace' in args) and 'auth' not in args:
    obj = json.load(sys.stdin)
    k = key(obj['kind'], obj['metadata']['name'], obj['metadata'].get('namespace', ''))
    if 'create' in args and k in state:
        sys.exit(1)
    if 'replace' in args and (k not in state or obj['metadata']['resourceVersion'] != state[k]['metadata']['resourceVersion']):
        sys.exit(1)
    put(obj)
    state_path.write_text(json.dumps(state))
elif 'auth' in args:
    pos = args.index('can-i')
    verb, resource = args[pos + 1:pos + 3]
    raw, _, name = resource.partition('/')
    resource, _, group = raw.partition('.')
    identity = next(a.removeprefix('--as=') for a in args if a.startswith('--as='))
    _, _, identity_ns, sa = identity.split(':')
    ns = option('-n')
    allowed = False
    for binding in state.values():
        if binding['kind'] not in ('RoleBinding', 'ClusterRoleBinding'):
            continue
        if binding['kind'] == 'RoleBinding' and binding['metadata']['namespace'] != ns:
            continue
        if not any(s['name'] == sa and s.get('namespace') == identity_ns for s in binding['subjects']):
            continue
        ref = binding['roleRef']
        role = state[key(ref['kind'], ref['name'], ns if ref['kind'] == 'Role' else '')]
        for rule in role['rules']:
            if ((verb in rule['verbs'] or '*' in rule['verbs'])
                    and (resource in rule['resources'] or '*' in rule['resources'])
                    and (group in rule['apiGroups'] or '*' in rule['apiGroups'])
                    and ('resourceNames' not in rule or name in rule['resourceNames'])):
                allowed = True
    if (root / 'leak-auth').exists():
        allowed = True
    print('yes' if allowed else 'no')
    sys.exit(0 if allowed else 1)
elif 'rollout' in args:
    print('deployment successfully rolled out')
else:
    raise AssertionError(args)
