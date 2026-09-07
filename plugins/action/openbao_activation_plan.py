from __future__ import annotations

from pathlib import Path
import sys

from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils import platform_openbao_activation_plan as plans
except ImportError:  # Standalone action plugins do not package local module_utils.
    module_utils_path = str(Path(__file__).parents[1] / "module_utils")
    if module_utils_path not in sys.path:
        sys.path.insert(0, module_utils_path)
    import platform_openbao_activation_plan as plans


class ActionModule(ActionBase):
    TRANSFERS_FILES = False
    _VALID_ARGS = frozenset({"action", "operation", "mode", "path", "evidence", "plan"})

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        task_vars = task_vars or {}
        args = self._task.args
        try:
            if self._task.check_mode:
                raise plans.PlanError("Use read-only plan mode, not Ansible check mode")
            action = args.get("action")
            operation, mode = args.get("operation"), args.get("mode", "interactive")
            if action not in {"prepare", "verify"} or mode not in {"plan", "interactive", "ci"}:
                raise plans.PlanError("Unsupported activation plan action or mode")
            sources = task_vars.get("ansible_inventory_sources", [])
            if len(sources) != 1:
                raise plans.PlanError("Activation requires one tracked inventory source")
            hosts = sorted(task_vars.get("groups", {}).get("openbao", []))
            current = plans.context(
                Path(__file__).parents[2] / "ansible.cfg", sources[0],
                task_vars.get("platform_environment", "dev"), operation, mode,
            )
            if action == "prepare":
                plan = plans.prepare(operation, mode, args.get("path", ""), hosts, current, args.get("evidence"))
            else:
                plan = plans.validate(args.get("plan"), operation, hosts, current, args.get("evidence"))
            result.update(changed=False, plan=plan,
                          approval=f"activate-openbao-{operation}|{','.join(hosts)}|{plan['digest']}")
        except plans.PlanError as exc:
            result.update(failed=True, msg=str(exc))
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            result.update(failed=True, msg=f"Invalid or unreadable activation plan ({type(exc).__name__})")
        return result
