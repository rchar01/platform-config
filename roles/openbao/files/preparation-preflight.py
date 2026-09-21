"""Read-only preparation guard. No installation, service actions or recovery."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect(path, owners=(0,)):
    require(isinstance(path, str) and path.startswith('/') and path != '/'
            and os.path.normpath(path) == path and not path.startswith('//'), 'unsafe path')
    target = Path(path)
    info = None
    for component in [*reversed(target.parents), target]:
        try:
            info = component.lstat()
        except FileNotFoundError:
            return None
        require(not stat.S_ISLNK(info.st_mode), 'symlink in preparation path')
        require(not info.st_mode & 0o022, 'writable preparation path')
        if component != target:
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0, 'unsafe path ancestor')
    assert info is not None
    require(info.st_uid in owners, 'unsafe preparation owner')
    require(stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
            'unsafe preparation object')
    return info


def empty(path, owners=(0,)):
    info = inspect(path, owners)
    if info is not None:
        require(stat.S_ISDIR(info.st_mode) and not any(Path(path).iterdir()), 'nonpristine storage or PKI state')


def guard(values):
    for unit in ('openbao.service', 'haproxy.service', 'keepalived.service'):
        result = subprocess.run(['systemctl', 'show', '--all', unit,
                                 '--property=LoadState,ActiveState,SubState,UnitFileState'],
                                capture_output=True, text=True, check=False)
        rows = result.stdout.splitlines()
        require(len(rows) == 4 and all('=' in row for row in rows), 'incomplete service observation')
        state = dict(row.split('=', 1) for row in rows)
        require(set(state) == {'LoadState', 'ActiveState', 'SubState', 'UnitFileState'}, 'invalid service observation')
        require(not result.stderr and result.returncode in (0, 4), 'service inspection failed')
        require(state['LoadState'] in ('not-found', 'loaded', 'masked')
                and state['ActiveState'] == 'inactive' and state['SubState'] == 'dead'
                and state['UnitFileState'] in ('', 'disabled', 'masked', 'static'), 'service is not inactive and disabled')
        for root in ('/etc/systemd/system', '/run/systemd/system', '/run/systemd/generator'):
            require(not os.path.lexists(f'{root}/multi-user.target.wants/{unit}'), 'retained service enablement')

    for path in {values['marker'], values['rolling'], '/var/lib/platform-config/openbao-bootstrap.json',
                 '/var/lib/platform-config/openbao-rolling-transaction',
                 '/var/lib/platform-config/openbao-edge-guard',
                 '/etc/openbao/tls/tls.crt', '/etc/openbao/tls/tls.key'}:
        require(inspect(path) is None, 'retained lifecycle or leaf state')
    for path in ('/etc/openbao', '/etc/openbao/tls', '/etc/haproxy', '/etc/keepalived', '/etc/containers/systemd'):
        info = inspect(path)
        require(info is None or stat.S_ISDIR(info.st_mode), 'preparation directory is not a directory')
    for path in [*values['artifacts'], '/etc/openbao/listener.hcl', '/etc/openbao/openbao.hcl',
                 '/etc/openbao/audit.hcl', '/etc/openbao/tls/ca.crt']:
        info = inspect(path)
        require(info is None or stat.S_ISREG(info.st_mode), 'preparation artifact is not a regular file')
    for path in values['mounts']:
        info = inspect(path, (0, 100))
        require(info is not None and stat.S_ISDIR(info.st_mode), 'approved mount is absent')
        result = subprocess.run(['findmnt', '--mountpoint', path, '--noheadings', '--output', 'TARGET'],
                                capture_output=True, text=True, check=False)
        require(result.returncode == 0 and result.stdout.strip() == path and not result.stderr,
                'approved path is not a separate mount')
    empty(values['data'], (0, 100))
    empty(values['pending'])
    empty(values['versions'])
    state = inspect(values['state'])
    if state is not None:
        require(stat.S_ISDIR(state.st_mode) and state.st_uid == 0
                and {p.name for p in Path(values['state']).iterdir()} == {'lock', 'trust'},
                'only authenticated trust-only lifecycle state may be replayed')

    helper = '/usr/local/libexec/platform-pki-host-local-lifecycle'
    info = inspect(helper)
    if info is not None:
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o755
                and hashlib.sha256(Path(helper).read_bytes()).hexdigest() == values['helper_sha256'],
                'installed lifecycle helper is not exact')
    require(info is not None or (not values['stage'] and state is None
                                and not os.path.lexists('/etc/openbao/listener.hcl')),
            'staging or retained state requires the installed lifecycle helper')
    return {'helper': info is not None}


if __name__ == '__main__':
    try:
        print(json.dumps(guard(json.loads(sys.argv[1]))))
    except (ValueError, OSError, KeyError, TypeError) as error:
        sys.exit(f'OpenBao preparation rejected: {error}')
