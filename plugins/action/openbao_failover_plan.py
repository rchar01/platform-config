"""Controller-only failover review binding; caller owns exact manual approval."""
from __future__ import annotations

from pathlib import Path
import sys

from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils import platform_openbao_failover_plan as plans
except ImportError:
    module_utils_path = str(Path(__file__).parents[1] / "module_utils")
    if module_utils_path not in sys.path:
        sys.path.insert(0, module_utils_path)
    import platform_openbao_failover_plan as plans


class ActionModule(ActionBase):
    TRANSFERS_FILES = False
    _VALID_ARGS = frozenset({"action", "mode", "path", "plan", "owner", "evidence"})

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        result["_ansible_no_log"] = True
        variables, args = task_vars or {}, self._task.args
        try:
            if self._task.check_mode:
                raise plans.PlanError("Use read-only plan mode, not Ansible check mode")
            action, mode = args.get("action"), args.get("mode")
            if action not in {"prepare", "verify"}:
                raise plans.PlanError("Unsupported failover plan action")
            sources = variables.get("ansible_inventory_sources", [])
            if len(sources) != 1:
                raise plans.PlanError("Failover requires one tracked inventory source")
            hosts = sorted(variables.get("groups", {}).get("openbao", []))
            current = plans.context(Path(__file__).parents[2] / "ansible.cfg", sources[0],
                                    variables.get("platform_environment"), mode)
            if action == "prepare":
                plan = plans.prepare(mode, args.get("path", ""), hosts, current,
                                     args.get("owner"), args.get("evidence"), args.get("plan"))
            else:
                if args.get("path"):
                    raise plans.PlanError("Verify takes the already prepared plan")
                plan = plans.validate(args.get("plan"), mode, hosts, current,
                                      args.get("owner"), args.get("evidence"))
            route = "recover" if mode == "recover" else "test"
            result.update(changed=False, plan=plan, owner=plan["owner"], nonce=plan["nonce"],
                          approval=f"{route}-openbao-haproxy-failover|{plan['owner']}|"
                                   f"{','.join(hosts)}|{plan['digest']}")
        except plans.PlanError as exc:
            result.update(failed=True, msg=str(exc))
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            result.update(failed=True, msg=f"Invalid or unreadable failover plan ({type(exc).__name__})")
        return result
