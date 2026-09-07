"""Offline action boundaries; never call a host service manager or network."""

import json
from pathlib import Path
from typing import Any

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        variables = task_vars or {}
        host = variables["inventory_hostname"]
        action = self._task.action.rsplit(".", 1)[-1]
        result: dict[str, Any] = {"changed": False}
        phase = "preflight"
        if action == "setup":
            return result
        if action == "service_facts":
            result["ansible_facts"] = {"services": {
                "haproxy.service": {
                    "state": variables.get("test_haproxy_state", "running"),
                    "status": variables.get("test_haproxy_status", "enabled"),
                },
                "keepalived.service": {
                    "state": variables.get("test_keepalived_state", "stopped"),
                    "status": variables.get("test_keepalived_status", "disabled"),
                },
            }}
            if variables.get("test_service_drift") and variables["test_preflight_count"] > 1:
                result["ansible_facts"]["services"]["haproxy.service"]["state"] = "stopped"
            return result
        if action == "systemd_service":
            assert self._task.args["name"] == "keepalived.service"
            phase = "start" if self._task.args["state"] == "started" else "rollback"
            assert self._task.args["enabled"] == (phase == "start")
        elif action == "activation_probe":
            phase = "qualification"
        elif action == "election_pause":
            assert set(self._task.args) == {"seconds"}
            assert int(self._task.args["seconds"]) >= 9
            phase = "election"
        else:
            raise AssertionError(f"Unexpected mock action: {action}")
        root = Path(variables["openbao_test_root"])
        with (root / f"{host}.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"phase": phase, "host": host}) + "\n")
        # Atomic append records the cross-host activation barrier in a shared log.
        with (root / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"phase": phase, "host": host}) + "\n")
        for kind in ("failure", "unreachable"):
            targets = variables.get(f"test_{phase}_{kind}", [])
            if host in targets:
                result["failed" if kind == "failure" else "unreachable"] = True
                result["msg"] = f"Mocked {phase} {kind} on {host}"
        return result
