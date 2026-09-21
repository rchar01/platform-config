#!/usr/bin/env python3
"""Create disposable direct-file cases and snapshot them without following links."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


ROOT = Path('/etc/platform-test-loki/preflight')


def prepare(cases):
    ROOT.mkdir(parents=True, mode=0o755)
    for case in cases:
        parent = ROOT / case / 'direct'
        parent.mkdir(parents=True, mode=0o755)
        for name in ('ca.crt', 'client.crt', 'client.key'):
            shutil.copyfile(Path('/etc/platform-test-pki') / name, parent / name)
            (parent / name).chmod(0o600 if name.endswith('.key') else 0o644)
        key = parent / 'client.key'
        ca = parent / 'ca.crt'
        if case == 'missing-key':
            key.unlink()
        elif case == 'missing-ca':
            ca.unlink()
        elif case == 'directory':
            ca.unlink()
            ca.mkdir()
        elif case == 'fifo':
            key.unlink()
            os.mkfifo(key, 0o600)
        elif case == 'symlink-leaf':
            cert = parent / 'client.crt'
            cert.rename(parent / 'real.crt')
            cert.symlink_to('real.crt')
        elif case == 'hardlink':
            os.link(key, parent / 'linked.key')
        elif case == 'key-public':
            key.chmod(0o644)
        elif case in ('file-uid', 'file-gid'):
            os.chown(key, 12345 if case == 'file-uid' else 0, 12345 if case == 'file-gid' else 0)
        elif case in ('ancestor-uid', 'ancestor-gid'):
            os.chown(parent, 12345 if case == 'ancestor-uid' else 0, 12345 if case == 'ancestor-gid' else 0)
        elif case == 'ancestor-group-write':
            parent.chmod(0o775)
        elif case == 'ancestor-other-write':
            parent.chmod(0o757)
        elif case == 'ancestor-symlink':
            parent.rename(parent.with_name('real'))
            parent.symlink_to('real', target_is_directory=True)
        elif case in ('empty-ca', 'empty-key'):
            (ca if case == 'empty-ca' else key).write_bytes(b'')
        elif case not in ('good-ca', 'good-mtls'):
            raise ValueError(f'unknown fixture case: {case}')


def snapshot():
    paths = [ROOT, Path('/etc/alloy/config.alloy'),
             Path('/etc/systemd/system/alloy.service.d/platform.conf')]
    for parent, directories, files in os.walk(ROOT, followlinks=False):
        paths.extend(Path(parent) / name for name in sorted(directories + files))
    result = {}
    for path in sorted(paths):
        info = path.lstat()
        record = {name: getattr(info, name) for name in
                  ('st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_ino', 'st_size', 'st_mtime_ns')}
        if stat.S_ISREG(info.st_mode):
            record['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(info.st_mode):
            record['target'] = os.readlink(path)
        result[str(path)] = record
    lifecycle = subprocess.check_output([
        'systemctl', 'show', 'alloy.service',
        '--property=ActiveState,SubState,UnitFileState,MainPID,ExecMainStartTimestampMonotonic,FragmentPath,NeedDaemonReload',
    ], text=True, timeout=5)
    if 'ActiveState=active\n' not in lifecycle or 'SubState=running\n' not in lifecycle:
        raise AssertionError('full-role preflight requires the active native baseline')
    if 'FragmentPath=/usr/lib/systemd/system/alloy.service\n' not in lifecycle:
        raise AssertionError('not the qualified native RPM unit')
    result['lifecycle'] = lifecycle
    result['rpm'] = subprocess.check_output([
        'rpm', '-q', '--qf', '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}', 'alloy',
    ], text=True, timeout=5)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        prepare(json.loads(sys.argv[2]))
    elif sys.argv[1] == 'snapshot':
        snapshot()
    else:
        raise ValueError('unknown fixture operation')
