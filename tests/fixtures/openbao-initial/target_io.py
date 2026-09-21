"""Sandbox target I/O only; the shipped Ansible includes and assertions execute."""
import hashlib
import json
from pathlib import Path

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = dict(self._task.args)
        variables = task_vars or {}
        target = Path(variables['fixture_target'])
        scenario = variables.get('fixture_scenario', {})
        log = Path(variables['fixture_calls'])
        with log.open('a') as stream:
            stream.write(json.dumps(args) + '\n')
        if 'path' in args:
            original = args['path']
            args['path'] = str(target / original.lstrip('/'))
            result = self._execute_module(module_name='ansible.builtin.stat', module_args=args, task_vars=variables)
            metadata = result.get('stat', {})
            assert isinstance(metadata, dict)
            if metadata.get('exists'):
                metadata.update(uid=0, gid=1000 if original == '/etc/openbao/listener.hcl' else 0,
                                pw_name='root', gr_name='root')
            return result
        if 'name' in args:
            assert args == {'name': 'openbao.service'}, args
            return dict(changed=False, status=dict(ActiveState=scenario.get('active', 'inactive'),
                                                  UnitFileState=scenario.get('unit', 'masked')))
        argv = args['argv']
        if argv[0] == '/usr/bin/realpath':
            return dict(changed=False, rc=0, stdout=argv[-1], stderr='')
        command = argv[1]
        if scenario.get('authentication_failed'):
            return dict(failed=True, msg='fixture authentication rejection')
        if command == 'openbao-custody':
            assert '--service-adapter' in argv and '--bootstrap-marker-path' in argv
            result = dict(schema='2', kind='platform-config-openbao-tls-custody',
                          custody='dormant', request_id='none',
                          host_cert_path='/etc/openbao/tls/tls.crt', host_key_path='/etc/openbao/tls/tls.key',
                          container_cert_path='/openbao/config/tls/tls.crt', container_key_path='/openbao/config/tls/tls.key',
                          artifact_sha256='none', certificate_sha256='none', spki_sha256='none', chain_sha256='none',
                          fullchain_sha256='none', listener_sha256=hashlib.sha256((target / 'etc/openbao/listener.hcl').read_bytes()).hexdigest())
        elif command == 'target-status':
            assert '--trust-id' in argv and '--minimum-remaining-lifetime-seconds' in argv
            status, action = scenario.get('status', ['request-pending', 'await-response'])
            result = dict(schema='2', kind='platform-config-target-local-certificate-status',
                          service=argv[argv.index('--service') + 1], target=argv[argv.index('--target') + 1],
                          request_id='a' * 32, status=status, required_action=action)
        else:
            raise AssertionError(f'Unexpected mutating or unknown command: {argv}')
        return dict(changed=False, rc=0, stdout=json.dumps(result), stderr='')
