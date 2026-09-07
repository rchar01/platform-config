"""Fail-closed action doubles: no connections, subprocesses, DNS, or services."""

import json
from pathlib import Path

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        variables = task_vars or {}
        host = variables["inventory_hostname"]
        action = self._task.action.rsplit(".", 1)[-1]
        args = self._task.args
        sample = variables.get("openbao_vip_sample", 0)
        event = {
            "host": host, "action": action, "sample": sample, "args": args,
            "delegate": self._task.delegate_to, "become": self._task.become,
            "check_mode": self._task.check_mode,
        }
        root = Path(variables["openbao_test_root"])
        with (root / f"vip-{host}.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event) + "\n")
        if action == "vip_pause":
            assert set(args) == {"seconds"}
            return {"changed": False}
        assert action == "command", action
        assert set(args) == {"argv"}, args
        # command's module argument spec coerces argv elements (YAML -4 is int).
        argv = [str(value) for value in args["argv"]]
        kind = argv[0]
        fault = variables.get("vip_test_fault", "")
        target = host == variables.get("vip_test_host", "bao-3")
        result = {"changed": False, "rc": 0}
        stdout = ""
        if kind == "systemctl":
            assert argv[1] in {"is-active", "is-enabled"}, argv
            assert argv[2] in {"haproxy.service", "keepalived.service"}, argv
            stdout = "active" if argv[1] == "is-active" else "enabled"
            if target and argv[2] == "keepalived.service":
                if fault == "service-unreachable":
                    return {"unreachable": True, "msg": "offline service unreachable"}
                if fault == argv[1]:
                    stdout = "inactive" if argv[1] == "is-active" else "disabled"
                if fault == "service-error":
                    result.update(rc=3, failed=True, msg="offline systemctl error")
        elif kind == "ip":
            assert argv == ["ip", "-j", "-4", "address", "show"], argv
            if target and fault == "address-unreachable":
                return {"unreachable": True, "msg": "offline address unreachable"}
            owner = "bao-2" if fault == "owner-changing" and sample > 1 else "bao-1"
            owned = host == owner
            if fault in {"zero", "near-match"}:
                owned = False
            if fault == "duplicate" and target:
                owned = True
            addresses = ["192.0.2.200"] if owned else []
            # A textual prefix match must not count as ownership.
            addresses += ["192.0.2.2000", "192.0.2.20"]
            interfaces = [{
                "ifname": "eth1" if fault == "wrong-interface" else "eth0",
                "addr_info": [{"local": address} for address in addresses],
            }]
            if fault == "duplicate-interface" and owned:
                interfaces.append({"ifname": "eth1", "addr_info": [{"local": "192.0.2.200"}]})
            if fault == "zero":
                interfaces[0]["addr_info"] = []
            stdout = json.dumps(interfaces)
            if target and fault == "address-malformed":
                stdout = "not json"
        elif kind == "getent":
            assert argv == ["getent", "ahostsv4", "bao.example.invalid"], argv
            addresses = variables.get("vip_test_dns", ["192.0.2.200"])
            stdout = "\n".join(f"{address} {mode} bao.example.invalid"
                               for address in addresses for mode in ("STREAM", "DGRAM", "RAW"))
            if fault == "dns-error":
                result.update(rc=2, failed=True, msg="offline DNS error")
        elif kind == "curl":
            if "--output" in argv:
                stdout = "503" if fault == "haproxy-error" else "200"
            else:
                path = "forced" if "--resolve" in argv else "dns"
                body = {"initialized": True, "sealed": False, "standby": False,
                        "cluster_id": "test-cluster"}
                status, address = "200", "192.0.2.200"
                if target and path == variables.get("vip_test_path", "dns"):
                    body.update(variables.get("vip_test_body", {}))
                    status = variables.get("vip_test_http", status)
                    address = variables.get("vip_test_remote_ip", address)
                    if fault == "curl-error":
                        result.update(rc=60, failed=True, msg="offline TLS certificate error")
                stdout = json.dumps(body)
                if target and fault == "body-malformed" and path == "dns":
                    stdout = "not json"
                stdout += f"\n{status} {address}"
        else:
            raise AssertionError(f"Unexpected command: {argv}")
        result.update(stdout=stdout, stdout_lines=stdout.splitlines())
        return result
