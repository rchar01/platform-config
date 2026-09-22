"""Assertions inside the disposable Rocky systemd target; standard library only."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import stat
import subprocess
import time

HERE = Path(__file__).resolve().parent
HELPER = '/usr/local/libexec/platform-alloy-initial-activate'
CONTEXT = Path('/etc/alloy/pki/initial-activation.json')
STATE = Path('/var/lib/platform-config/pki/alloy/process-owner')
CONFIG = Path('/etc/alloy/config.alloy')
INVENTORY = CONTEXT.with_name('inventory.yml')
NEVRA = 'alloy-0:1.18.1-1.x86_64'


def run(*args, ok=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=100)
    if ok:
        assert result.returncode == 0, (args, result.returncode, result.stdout, result.stderr)
    return result


def action(name, status, changed=False):
    result = run(HELPER, name, '--config', str(CONTEXT))
    value = json.loads(result.stdout)
    assert value == {'schema': 1, 'status': status, 'changed': changed}, value
    return value


def rejected(reason, fault=None):
    argv = ([HELPER, 'activate', '--config', str(CONTEXT)] if fault is None else
            ['/usr/bin/python3', '-I', str(HERE / 'fault.py'), fault])
    result = run(*argv, ok=False)
    assert result.returncode == (91 if fault == 'after-journal' else 1), result
    assert not result.stdout and reason in result.stderr, result
    return result


def service():
    output = run('/usr/bin/systemctl', 'show', 'alloy.service', '--no-pager',
                 '--property=ActiveState,UnitFileState,MainPID,InvocationID,ExecMainStartTimestampMonotonic,NRestarts').stdout
    return dict(line.split('=', 1) for line in output.splitlines())


def stopped():
    value = service()
    assert (value['ActiveState'], value['UnitFileState'], value['MainPID']) == ('inactive', 'disabled', '0'), value


def snapshot(*roots):
    result = {}
    for root in roots:
        root = Path(root)
        for path in [root, *sorted(root.rglob('*'))]:
            info = path.lstat()
            assert not path.is_symlink(), path
            data = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
            result[str(path)] = (info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
                                 info.st_ino, info.st_mtime_ns, data)
    return result


def inputs():
    return snapshot('/etc/alloy', '/etc/systemd/system/alloy.service.d',
                    '/var/lib/platform-config/pki/alloy/loki', '/var/lib/platform-config/pki/alloy/mimir',
                    HELPER, '/usr/local/libexec/platform-pki-host-local-lifecycle', '/usr/local/bin/platform-pki')


def receipt(status):
    assert {p.name for p in STATE.iterdir()} == {'lock', 'journal.json', status + '.json'}
    for path in STATE.iterdir():
        info = path.stat()
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
    value = json.loads((STATE / (status + '.json')).read_bytes())
    assert value['schema'] == 1 and value['status'] == status
    evidence = value['evidence']
    assert set(evidence['writers']) == {'loki', 'mimir'}
    assert evidence['package_nevra'] == NEVRA
    assert set(evidence['rpm_files']) == {'/usr/bin/alloy', '/usr/lib/systemd/system/alloy.service'}
    assert len({w['certificate_spki_sha256'] for w in evidence['writers'].values()}) == 2
    assert 'PRIVATE KEY' not in (STATE / (status + '.json')).read_text()


def reset_disposable_case():
    # Harness isolation only, never an example of supported lifecycle recovery.
    # Keep all authenticated inputs and stage inodes; discard only verified failed
    # receipts in this disposable container before the next independent scenario.
    stopped()
    receipt('failed')
    for name in ('journal.json', 'failed.json'):
        (STATE / name).unlink()
    assert {p.name for p in STATE.iterdir()} == {'lock'}


def main():
    assert os.geteuid() == 0
    assert not any(k.startswith(('PLATFORM_ALLOY_INITIAL_', 'PLATFORM_PKI_LIFECYCLE_TEST')) for k in os.environ)
    assert 'VERSION_ID="10.' in Path('/etc/os-release').read_text()
    assert run('/usr/bin/rpm', '-q', '--qf', '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}', 'alloy').stdout == NEVRA
    assert 'version v1.18.1' in run('/usr/bin/alloy', '--version').stdout
    # Assert actual support command output contracts before exercising the helper.
    manifest = run('/usr/bin/rpm', '-q', '--qf', '%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEDIGESTS}\n]', 'alloy').stdout
    assert manifest.splitlines()[0] == '8'
    assert all('\t' in line for line in manifest.splitlines()[1:])
    run('/usr/bin/alloy', 'validate', str(CONFIG))
    stopped()
    baseline = inputs()
    state_before = snapshot(STATE)
    action('check', 'prepared')
    refused = run(HELPER, 'renewal-preflight', '--config', str(CONTEXT), '--writer', 'loki', ok=False)
    assert refused.returncode == 1 and not refused.stdout
    assert inputs() == baseline and snapshot(STATE) == state_before
    print('PASS: native RPM/unit/config validation and read-only prepared check', flush=True)

    context_bytes = CONTEXT.read_bytes()
    for name, path, data, rebind, reason in (
        ('boundary', CONFIG, CONFIG.read_bytes() + b'\n', False, 'signed boundary mismatch'),
        ('inventory', INVENTORY, INVENTORY.read_bytes() + b'# drift\n', False, 'inventory digest mismatch'),
        ('rehashed inventory', INVENTORY, INVENTORY.read_bytes() + b'# drift\n', True, 'request inventory mismatch'),
    ):
        original = path.read_bytes()
        try:
            path.write_bytes(data)
            if rebind:
                context = json.loads(context_bytes)
                context['inventory_sha256'] = hashlib.sha256(data).hexdigest()
                CONTEXT.write_text(json.dumps(context))
            before, process_before, unit_before = inputs(), snapshot(STATE), service()
            rejected(reason)
            stopped()
            assert inputs() == before and snapshot(STATE) == process_before and service() == unit_before
            print(f'PASS: tampered {name} rejected before enable/start; sources unchanged', flush=True)
        finally:
            path.write_bytes(original)
            CONTEXT.write_bytes(context_bytes)
    baseline = inputs()
    start = time.monotonic()
    failure = rejected('verified inactive and disabled', 'readiness')
    assert 'paused actual ready Alloy' in failure.stderr and 'resumed Alloy before native rollback' in failure.stderr
    assert time.monotonic() - start >= 9
    stopped()
    receipt('failed')
    assert inputs() == baseline
    records = snapshot(STATE)
    rejected('automatic reuse forbidden')
    action('recover', 'failed')
    assert snapshot(STATE) == records and inputs() == baseline
    print('PASS: native readiness timeout rolled back to disabled/inactive; failed receipt; no source changes', flush=True)

    reset_disposable_case()
    unit_before = service()
    rejected('exit after durable journal', 'after-journal')
    assert {p.name for p in STATE.iterdir()} == {'lock', 'journal.json'}
    stopped()
    assert service() == unit_before
    action('status', 'recovery-required')
    rejected('interrupted intent requires recover')
    action('recover', 'failed', True)
    stopped()
    receipt('failed')
    records = snapshot(STATE)
    action('recover', 'failed')
    assert snapshot(STATE) == records and inputs() == baseline
    print('PASS: interruption after journal recovered stop-only with failed receipt, never success', flush=True)

    reset_disposable_case()
    action('check', 'prepared')
    action('activate', 'complete', True)
    active = service()
    assert active['ActiveState'] == 'active' and active['UnitFileState'] == 'enabled' and int(active['MainPID']) > 1
    assert Path('/proc/' + active['MainPID'] + '/exe').resolve() == Path('/usr/bin/alloy')
    connection = http.client.HTTPConnection('127.0.0.1', 12345, timeout=2)
    try:
        connection.request('GET', '/-/ready')
        response = connection.getresponse()
        assert response.status == 200 and len(response.read(4097)) <= 4096
    finally:
        connection.close()
    receipt('complete')
    records = snapshot(STATE)
    for name in ('activate', 'check', 'status', 'recover'):
        action(name, 'complete')
        assert snapshot(STATE) == records and service() == active and inputs() == baseline
    print('PASS: actual enable/start, native HTTP 200, complete receipt and four no-restart/no-write replays', flush=True)
    context = json.loads(CONTEXT.read_bytes())
    receipt_hash = hashlib.sha256((STATE / 'complete.json').read_bytes()).hexdigest()
    for writer in ('loki', 'mimir'):
        result = run(HELPER, 'renewal-preflight', '--config', str(CONTEXT), '--writer', writer)
        value = json.loads(result.stdout)
        assert not result.stderr and value['status'] == 'predecessor-verified' and value['changed'] is False
        assert value['writer'] == writer and value['target'] == context['target']
        assert value['initial_receipt_sha256'] == receipt_hash
        assert value['inventory_sha256'] == context['inventory_sha256']
        assert set(value['writers']) == {'loki', 'mimir'}
        for name, observed in value['writers'].items():
            assert observed['service'] == context['writers'][name]['service']
            assert observed['remaining_lifetime_seconds'] > 0
        assert snapshot(STATE) == records and service() == active and inputs() == baseline
    print('PASS: both native renewal preflights bound the initial predecessor without writes or restarts', flush=True)


if __name__ == '__main__':
    main()
