"""Sandbox only target I/O; execute the production preparation guard unchanged."""
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any
from types import SimpleNamespace


def execute(code, values, root, scenario):
    root = Path(root)

    class TargetPath(PurePosixPath):
        def local(self):
            return root / str(self).lstrip('/')

        def lstat(self):
            info = self.local().lstat()
            fields = list(info)
            # Controller-owned fixtures represent root-owned target files.
            fields[4] = fields[5] = 0
            return os.stat_result(fields)

        def iterdir(self):
            return (self / entry.name for entry in self.local().iterdir())

        def read_bytes(self):
            return self.local().read_bytes()

    def run(argv, **kwargs):
        assert kwargs == dict(capture_output=True, text=True, check=False)
        if argv[0] == 'systemctl':
            state = scenario.get('service', 'absent')
            states = {
                'absent': ('not-found', 'inactive', 'dead', ''),
                'stopped': ('loaded', 'inactive', 'dead', 'disabled'),
                'masked': ('masked', 'inactive', 'dead', 'masked'),
                'active': ('loaded', 'active', 'running', 'enabled'),
                'enabled': ('loaded', 'inactive', 'dead', 'enabled'),
                'failed': ('loaded', 'failed', 'failed', 'disabled'),
            }
            output = ''.join(f'{key}={value}\n' for key, value in zip(
                ('LoadState', 'ActiveState', 'SubState', 'UnitFileState'), states[state]))
            if scenario.get('incomplete'): output = output.splitlines()[0]
            return SimpleNamespace(returncode=0, stdout=output, stderr='')
        assert argv[:2] == ['findmnt', '--mountpoint'], argv
        return SimpleNamespace(returncode=int(scenario.get('unmounted', False)), stdout=argv[2] + '\n', stderr='')

    namespace: dict[str, Any] = {'__name__': 'fixture_guard'}
    exec(compile(code, '<shipped-preparation-guard>', 'exec'), namespace)
    namespace.update(Path=TargetPath, subprocess=SimpleNamespace(run=run), os=SimpleNamespace(path=SimpleNamespace(
        normpath=os.path.normpath, lexists=lambda path: os.path.lexists(root / path.lstrip('/')))))
    return namespace['guard'](values)
