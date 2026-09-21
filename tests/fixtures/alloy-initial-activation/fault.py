"""Fault injection around unmodified helper code, at native fixed paths.

No replacements for RPM, systemctl, Alloy, crypto, native validation, or HTTP.
The pause makes the actual Alloy HTTP socket time out; resume precedes rollback.
"""

import http.client
import os
import runpy
import signal
import subprocess
import sys
import time

HELPER = '/usr/local/libexec/platform-alloy-initial-activate'
mode = sys.argv[1]
assert mode in ('after-journal', 'readiness')
paused = None


def trace(frame, event, arg):
    global paused
    if frame.f_code.co_filename != HELPER:
        return None
    if event == 'call':
        if mode == 'after-journal' and frame.f_code.co_name == 'crash' and frame.f_locals['point'] == 'after-journal':
            print('FAULT: exit after durable journal, before enable/start', file=sys.stderr, flush=True)
            os._exit(91)
        if mode == 'readiness' and frame.f_code.co_name == 'ready':
            # First prove this is the real, live native endpoint, then suspend it.
            for attempt in range(30):
                connection = http.client.HTTPConnection('127.0.0.1', 12345, timeout=1)
                try:
                    connection.request('GET', '/-/ready')
                    response = connection.getresponse()
                    if response.status == 200 and len(response.read(4097)) <= 4096:
                        break
                except OSError:
                    pass
                finally:
                    connection.close()
                time.sleep(0.1)
            else:
                raise AssertionError('Native readiness never reached HTTP 200 before fault')
            paused = int(subprocess.check_output([
                '/usr/bin/systemctl', 'show', '--property=MainPID', '--value', 'alloy.service',
            ], timeout=10))
            assert paused > 1
            os.kill(paused, signal.SIGSTOP)
            print('FAULT: paused actual ready Alloy process', file=sys.stderr, flush=True)
        if frame.f_code.co_name == 'stop' and paused is not None:
            os.kill(paused, signal.SIGCONT)
            paused = None
            print('FAULT: resumed Alloy before native rollback', file=sys.stderr, flush=True)
    return trace


sys.argv = [HELPER, 'activate', '--config', '/etc/alloy/pki/initial-activation.json']
sys.settrace(trace)
try:
    runpy.run_path(HELPER, run_name='__main__')
finally:
    sys.settrace(None)
    if paused is not None:
        os.kill(paused, signal.SIGCONT)
