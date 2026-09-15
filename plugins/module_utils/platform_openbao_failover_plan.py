"""Controller contract for one approved HAProxy-owner fault and later restoration.

Authorization (TTY exact approval or native protected manual job) and live proof
belong to the fixed playbook. Recovery takes the plan from inspected target
records, never a newly generated plan. Only recovery may ignore TTL/pipeline.
"""
from __future__ import annotations

import os
import re
import time
import uuid

try:
    from ansible.module_utils import platform_openbao_activation_plan as base
except ImportError:
    import platform_openbao_activation_plan as base

PlanError = base.PlanError
canonical = base.canonical
digest = base.digest
read_plan = base.read_plan
write_plan = base.write_plan
TTL = base.TTL
MAX_BYTES = base.MAX_BYTES
OPERATION = "haproxy-failover"
KEYS = base.KEYS | {"owner", "service", "nonce"}
CONTEXT_KEYS = {"config_sha", "private_sha", "inventory", "environment", "lane",
                "project", "pipeline", "image", "plan_job"}


class PlanRejection(PlanError):
    """A public reason code, separate from protected plan details."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _match(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def validate_context(value):
    if (not isinstance(value, dict) or set(value) != CONTEXT_KEYS
            or not all(_match(r"[0-9a-f]{40}", value[k]) for k in ("config_sha", "private_sha"))
            or not _match(r"[A-Za-z0-9_.-]{1,64}", value["environment"])
            or not isinstance(value["inventory"], str) or not value["inventory"]
            or value["inventory"].startswith("/") or ".." in value["inventory"].split("/")):
        raise PlanError("Invalid failover source/environment identity")
    if value["lane"] == "operator":
        if any(value[k] != "" for k in ("project", "pipeline", "image", "plan_job")):
            raise PlanError("Operator plan contains CI identity")
    elif value["lane"] == "gitlab":
        if (not all(_match(r"[1-9][0-9]*", value[k]) for k in ("project", "pipeline"))
                or not _match(r"[^\s]+@sha256:[0-9a-f]{64}", value["image"])
                or not _match(r"[A-Za-z0-9_.-]+-haproxy-failover-plan", value["plan_job"])
                or len(value["plan_job"]) > 128):
            raise PlanError("Invalid failover GitLab identity")
    else:
        raise PlanError("Unknown failover lane")


def context(config_file, inventory, environment, mode, env=None):
    if mode not in {"plan", "test", "recover"}:
        raise PlanError("Unsupported failover mode")
    env = dict(os.environ if env is None else env)
    # Reuse clean-source and protected-lane checks, translating only fixed job
    # suffixes to the existing activation primitive's vocabulary.
    if "CI" in env:
        suffix = f"-{OPERATION}-{mode}"
        name = env.get("CI_JOB_NAME", "")
        # Manual test jobs also restore retained transactions on replay/partial
        # claim cleanup. This is one-way: recover jobs cannot authorize a fault.
        if mode == "recover" and name.endswith(f"-{OPERATION}-test"):
            suffix = f"-{OPERATION}-test"
        if not name.endswith(suffix) or len(name) <= len(suffix):
            raise PlanError("Expected fixed failover plan/test/recover job")
        env["CI_JOB_NAME"] = name[:-len(suffix)] + f"-{OPERATION}-" + (
            "plan" if mode == "plan" else "activate")
    result = base.context(config_file, inventory, environment, OPERATION,
                          "plan" if mode == "plan" else ("ci" if "CI" in env else "interactive"), env)
    validate_context(result)
    return result


def validate_shape(plan):
    if (not isinstance(plan, dict) or set(plan) != KEYS
            or type(plan["schema"]) is not int or plan["schema"] != 1
            or plan["operation"] != OPERATION or plan["service"] != "haproxy.service"
            or not all(_match(r"[0-9a-f]{32}", plan[k]) for k in ("plan_id", "nonce"))
            or type(plan["created"]) is not int or type(plan["expires"]) is not int
            or plan["created"] < 0 or plan["expires"] - plan["created"] != TTL):
        raise PlanError("Invalid failover plan schema")
    hosts = plan["hosts"]
    if (not isinstance(hosts, list) or len(hosts) != 3
            or not all(_match(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}", h) for h in hosts)
            or len(set(hosts)) != 3 or hosts != sorted(hosts) or plan["owner"] not in hosts
            or not isinstance(plan["evidence"], dict) or not plan["evidence"]):
        raise PlanError("Failover requires exactly three sorted hosts, owner and baseline evidence")
    validate_context(plan["context"])
    if len(canonical(plan)) > MAX_BYTES or plan["digest"] != digest(plan):
        raise PlanError("Invalid failover plan size or digest")
    return plan


def validate(plan, mode, hosts, current_context, owner=None, evidence=None, now=None):
    validate_shape(plan)
    validate_context(current_context)
    if mode not in {"test", "recover"}:
        raise PlanError("Verification requires test or recover mode")
    now = int(time.time()) if now is None else now
    original, current = dict(plan["context"]), dict(current_context)
    if mode == "recover":
        # Same lane/project/environment/image/revisions/job family; later pipeline
        # is permitted exclusively for restore. Baseline VIP ownership may differ.
        original.pop("pipeline")
        current.pop("pipeline")
    else:
        if not plan["created"] <= now < plan["expires"]:
            code = "PLAN_EXPIRED" if now >= plan["expires"] else "PLAN_NOT_YET_VALID"
            raise PlanRejection(code, "Failover plan expired or future-dated")
        if canonical(owner) != canonical(plan["owner"]):
            raise PlanRejection("VIP_OWNER_CHANGED", "Failover plan exact owner changed")
        if canonical(evidence) != canonical(plan["evidence"]):
            raise PlanRejection("BASELINE_CHANGED", "Failover plan exact baseline changed")
    if canonical(hosts) != canonical(plan["hosts"]) or canonical(current) != canonical(original):
        raise PlanRejection("SOURCE_OR_CI_IDENTITY_CHANGED",
                            "Failover hosts, source, environment or lane identity changed")
    return plan


def prepare(mode, path, hosts, current_context, owner=None, evidence=None, plan=None, now=None):
    now = int(time.time()) if now is None else now
    if mode == "recover":
        if path or plan is None:
            raise PlanError("Recovery requires a retained target plan, not an artifact path")
        return validate(plan, mode, hosts, current_context, now=now)
    if mode == "test":
        if not path or plan is not None:
            raise PlanError("Fresh fault requires the reviewed plan file")
        return validate(read_plan(path), mode, hosts, current_context, owner, evidence, now)
    if mode != "plan" or not path or plan is not None:
        raise PlanError("Plan generation requires an exclusive output path")
    plan = {"schema": 1, "operation": OPERATION, "plan_id": uuid.uuid4().hex,
            "nonce": uuid.uuid4().hex, "created": now, "expires": now + TTL,
            "hosts": hosts, "context": current_context, "owner": owner,
            "service": "haproxy.service", "evidence": evidence}
    plan["digest"] = digest(plan)
    validate_shape(plan)
    write_plan(path, plan)
    return plan
