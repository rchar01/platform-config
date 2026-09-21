"""Disposable preparer only: real signed client stages, never host-I/O stubs.

Reuse crypto construction from the Python suite, not its fake native activation
fixture. Only the explicit archive roots below may cross to the Rocky target.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from dataclasses import replace

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jinja2 import Environment, StrictUndefined

REPO = Path('/workspace')
sys.path.insert(0, str(REPO / 'tests/python'))
from conftest import CommandRunner  # noqa: E402
from test_alloy_initial_activation import inventory  # noqa: E402
from test_pki_host_local_client_staging import issue_response, replace_request, signed  # noqa: E402
from test_pki_host_local_lifecycle_helper import (  # noqa: E402
    REQUEST_ID, TARGET, digest, lifecycle_case, private_dir, private_file, record, result_json,
)

HELPER = Path('/usr/local/libexec/platform-alloy-initial-activate')
LIFECYCLE = HELPER.with_name('platform-pki-host-local-lifecycle')
ARTIFACT = Path('/usr/local/bin/platform-pki')
STATE = Path('/var/lib/platform-config/pki/alloy/process-owner')
CONTEXT = Path('/etc/alloy/pki/initial-activation.json')
SNAPSHOT = CONTEXT.with_name('inventory.yml')
CONFIG = Path('/etc/alloy/config.alloy')
DROPIN = Path('/etc/systemd/system/alloy.service.d/platform.conf')


def put(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    return private_file(path, data, mode)


def boundary():
    # Native fixed paths, with no PLATFORM_* testing environment or fake tools.
    return json.loads(subprocess.check_output([
        sys.executable, '-I', str(HELPER), 'boundary', '--config', str(CONTEXT),
    ], timeout=30))


def main():
    assert os.geteuid() == 0 and Path('/workspace/tests').is_dir()
    os.umask(0o077)
    put(HELPER, (REPO / 'roles/grafana_alloy/files/platform-alloy-initial-activate').read_bytes(), 0o755)
    put(LIFECYCLE, (REPO / 'roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle').read_bytes(), 0o755)
    artifact = Path(sys.argv[1]).read_bytes()
    assert artifact.startswith(b'#!') and b'PK\x03\x04' in artifact
    put(ARTIFACT, artifact, 0o755)
    private_dir(STATE)
    private_file(STATE / 'lock', b'')
    runner = CommandRunner(REPO, dict(os.environ))
    writers, cases = {}, {}
    for name in ('loki', 'mimir'):
        base = lifecycle_case.__wrapped__(REPO, private_dir(Path('/tmp') / name), runner)
        writer = {
            'service': name + '-writer', 'trust_id': 'reviewed-v1',
            'state_root': f'/var/lib/platform-config/pki/alloy/{name}',
            'pending_root': f'/etc/alloy/pki/{name}/tls-pending',
            'versions_root': f'/etc/alloy/pki/{name}/tls-versions',
            'ca_file': f'/etc/alloy/pki/{name}-server-ca.crt',
            'ca_sha256': digest(base.reviewed_ca),
        }
        put(Path(writer['ca_file']), base.reviewed_ca.read_bytes(), 0o644)
        shutil.copytree(base.state, writer['state_root'])
        shutil.copytree(base.pending_root, writer['pending_root'])
        private_dir(Path(writer['versions_root']))
        writers[name] = writer
        cases[name] = replace(base, state=Path(writer['state_root']),
                              pending_root=Path(writer['pending_root']),
                              pending=Path(writer['pending_root']) / REQUEST_ID,
                              versions_root=Path(writer['versions_root']))
    values = yaml.safe_load((REPO / 'roles/grafana_alloy/defaults/main.yml').read_text())
    values.update(grafana_alloy_config_path=str(CONFIG), grafana_alloy_environment='test',
                  grafana_alloy_vm_name=TARGET, grafana_alloy_ip='192.0.2.1', grafana_alloy_platform_role='vm')
    for name, writer in writers.items():
        prefix = 'grafana_alloy_loki_' if name == 'loki' else 'grafana_alloy_prometheus_remote_write_'
        for key, value in {
            'url': f'https://{name}.example.invalid/api/push', 'server_name': f'{name}.example.invalid',
            'ca_file': writer['ca_file'],
            'client_cert_file': writer['versions_root'] + '/' + REQUEST_ID + '/fullchain.crt',
            'client_key_file': writer['versions_root'] + '/' + REQUEST_ID + '/tls.key',
        }.items():
            values[prefix + key] = value
    templates = Environment(undefined=StrictUndefined, trim_blocks=True, keep_trailing_newline=True)
    templates.filters['to_json'] = json.dumps
    for path, template, mode in ((CONFIG, 'config.alloy.j2', 0o640), (DROPIN, 'alloy.service.override.conf.j2', 0o644)):
        put(path, templates.from_string((REPO / 'roles/grafana_alloy/templates' / template).read_text()).render(values), mode)
    put(SNAPSHOT, inventory(writers, dict.fromkeys(writers, '0' * 64)))
    context = {
        'schema': 1, 'target': TARGET, 'inventory_path': str(SNAPSHOT), 'inventory_sha256': digest(SNAPSHOT),
        'platform_pki_path': str(ARTIFACT), 'platform_pki_sha256': digest(ARTIFACT),
        'lifecycle_helper_path': str(LIFECYCLE), 'lifecycle_helper_sha256': digest(LIFECYCLE),
        'config_path': str(CONFIG), 'dropin_path': str(DROPIN), 'state_root': str(STATE),
        'package_nevra': 'alloy-0:1.18.1-1.x86_64', 'writers': writers,
    }
    put(CONTEXT, json.dumps(context))
    boundaries = boundary()
    # Prove request-ID normalization breaks the signing/config dependency cycle.
    original = CONFIG.read_bytes()
    put(CONFIG, original.replace(REQUEST_ID.encode(), b'3' * 32), 0o640)
    assert boundary() == boundaries
    put(CONFIG, original, 0o640)
    put(SNAPSHOT, inventory(writers, boundaries))
    context['inventory_sha256'] = digest(SNAPSHOT)
    put(CONTEXT, json.dumps(context))
    for name, case in cases.items():
        writer = writers[name]
        replace_request(case, service=writer['service'], inventory_sha256=digest(SNAPSHOT))
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Telemetry'),
            x509.NameAttribute(NameOID.COMMON_NAME, name + '.sender.test'),
        ])
        key = serialization.load_pem_private_key((case.pending / 'tls.key').read_bytes(), None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA384())
        issue_response(case, subject=subject, csr=csr)
        source = case.root / 'response-source'
        response = case.module.parse_record((source / 'response').read_bytes(), case.module.RESPONSE_V2_FIELDS, 'fixture')
        response.update(service=writer['service'], inventory_sha256=digest(SNAPSHOT))
        private_file(source / 'response', record(case.module.RESPONSE_V2_FIELDS, response))
        signed(case, source / 'response', case.module.RESPONSE_NAMESPACE_V2)
        exported = case.module.parse_record((source / 'artifact').read_bytes(), case.module.ARTIFACT_FIELDS, 'fixture')
        exported.update(service=writer['service'], source_response_sha256=digest(source / 'response'),
                        source_response_signature_sha256=digest(source / 'response.sig'))
        private_file(source / 'artifact', record(case.module.ARTIFACT_FIELDS, exported))
        common = ['--service', writer['service'], '--service-adapter', 'client-stage-v1', '--trust-id', 'reviewed-v1']
        ingress = Path(result_json(case.run([*case.common('target-response-prepare'), *common]))['ingress_dir'])
        for filename in case.module.RESPONSE_NAMES:
            private_file(ingress / filename, (source / filename).read_bytes())
        result_json(case.run([*case.common('target-response-install'), *common,
                             '--subject-cn', name + '.sender.test', '--subject-ou', 'Telemetry',
                             '--subject-o', 'Example', '--subject-c', 'US', '--validity-days', '397',
                             '--minimum-remaining-lifetime-seconds', '1']))
    with tarfile.open('/tmp/native-fixture.tar', 'w') as archive:
        for path in (CONFIG, CONFIG.parent / 'pki', DROPIN, STATE.parent, HELPER, LIFECYCLE, ARTIFACT):
            archive.add(path, arcname=str(path).lstrip('/'))
    print(f'Prepared real signed stages; normalized boundaries verified; zipapp SHA-256 {digest(ARTIFACT)}')


if __name__ == '__main__':
    main()
