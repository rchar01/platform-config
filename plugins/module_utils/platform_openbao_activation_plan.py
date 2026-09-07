"""Bounded, source-bound review plans; authorization remains with the caller."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import time
import uuid
from pathlib import Path

MAX_BYTES = 256 * 1024
TTL = 1800
KEYS = {"schema", "operation", "plan_id", "created", "expires", "hosts", "context", "evidence", "digest"}


class PlanError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(plan):
    return hashlib.sha256(canonical({key: value for key, value in plan.items() if key != "digest"})).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise PlanError("Plan contains duplicate JSON keys")
        result[key] = value
    return result


def read_plan(path):
    if not os.path.isabs(path):
        raise PlanError("Plan path must be absolute")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > MAX_BYTES):
            raise PlanError("Plan must be a bounded, owner-private regular file")
        data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise PlanError("Plan exceeds size limit")
    return json.loads(data, object_pairs_hook=_pairs)


def write_plan(path, plan):
    destination = Path(path)
    if not destination.is_absolute() or destination.parent.resolve() != destination.parent:
        raise PlanError("Plan output requires an absolute, non-symlink parent")
    info = destination.parent.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise PlanError("Plan output parent must already exist with mode 0700")
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    inside_git = subprocess.run(
        ["git", "-C", str(destination.parent), "rev-parse", "--git-dir"], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False,
    )
    if inside_git.returncode != 128:
        raise PlanError("Operator plans must stay outside every Git repository")
    data = canonical(plan) + b"\n"
    if len(data) > MAX_BYTES:
        raise PlanError("Plan exceeds size limit")
    # Exclusive publication never replaces a reviewed plan. Partial writes fail validation.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def source_identity(path):
    path = Path(path).absolute()
    if path.resolve() != path or not path.is_file():
        raise PlanError("Source must be a regular file without symlink components")
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")

    def git(*args):
        try:
            return subprocess.check_output(
                ["git", "-C", str(path.parent), *args], env=env, stderr=subprocess.DEVNULL, timeout=10,
            ).decode().strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise PlanError("Unable to establish committed activation source identity") from exc

    root = Path(git("rev-parse", "--show-toplevel"))
    relative = path.relative_to(root).as_posix()
    git("ls-files", "--error-unmatch", "--", str(path))
    if git("status", "--porcelain", "--untracked-files=normal"):
        raise PlanError("Activation requires clean committed configuration and inventory checkouts")
    sha = git("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise PlanError("Source revision is not an immutable Git commit")
    return sha, relative


def context(config_file, inventory, environment, operation, mode, env=None):
    env = os.environ if env is None else env
    config_sha, _ = source_identity(config_file)
    private_sha, inventory_name = source_identity(inventory)
    result = {"config_sha": config_sha, "private_sha": private_sha, "inventory": inventory_name,
              "environment": environment, "lane": "operator", "project": "", "pipeline": "",
              "image": "", "plan_job": ""}
    if not isinstance(environment, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", environment):
        raise PlanError("Activation environment must be explicit and safe")
    if "CI" not in env:
        if mode == "ci":
            raise PlanError("CI activation requires a matching protected manual GitLab job")
        return result
    if (env.get("CI") != "true" or mode not in {"plan", "ci"}
            or env.get("CI_PIPELINE_SOURCE") != "web" or env.get("CI_COMMIT_REF_PROTECTED") != "true"
            or not env.get("CI_DEFAULT_BRANCH") or env.get("CI_COMMIT_BRANCH") != env["CI_DEFAULT_BRANCH"]
            or env.get("CI_COMMIT_SHA") != private_sha):
        raise PlanError("Activation requires the protected default-branch web pipeline and exact private revision")
    suffix = f"-{operation}-{'plan' if mode == 'plan' else 'activate'}"
    name = env.get("CI_JOB_NAME", "")
    if (not name.endswith(suffix) or len(name) <= len(suffix)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
            or not re.fullmatch(r"[1-9][0-9]*", env.get("CI_PROJECT_ID", ""))
            or not re.fullmatch(r"[1-9][0-9]*", env.get("CI_PIPELINE_ID", ""))
            or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", env.get("CI_JOB_IMAGE", ""))
            or (mode == "ci" and env.get("CI_JOB_MANUAL") != "true")):
        raise PlanError("Activation requires fixed matching plan/manual job identities and a pinned image")
    result.update(lane="gitlab", project=env["CI_PROJECT_ID"], pipeline=env["CI_PIPELINE_ID"],
                  image=env["CI_JOB_IMAGE"], plan_job=name if mode == "plan" else name[:-9] + "-plan")
    return result


def validate(plan, operation, hosts, current_context, evidence, now=None):
    now = int(time.time()) if now is None else now
    if not isinstance(plan, dict) or set(plan) != KEYS or type(plan["schema"]) is not int or plan["schema"] != 1:
        raise PlanError("Unsupported activation plan schema")
    if (plan["operation"] != operation or not isinstance(plan["plan_id"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", plan["plan_id"])
            or type(plan["created"]) is not int or type(plan["expires"]) is not int
            or plan["expires"] - plan["created"] != TTL or not plan["created"] <= now < plan["expires"]):
        raise PlanError("Activation plan is expired, future-dated, or for a different operation")
    if (not isinstance(plan["digest"], str) or plan["digest"] != digest(plan)
            or canonical(plan["hosts"]) != canonical(hosts)
            or canonical(plan["context"]) != canonical(current_context)
            or canonical(plan["evidence"]) != canonical(evidence)):
        raise PlanError("Activation plan digest, source, lane, hosts, or live evidence changed; create a new plan")
    return plan


def prepare(operation, mode, path, hosts, current_context, evidence, now=None):
    now = int(time.time()) if now is None else now
    if operation not in {"haproxy", "keepalived"} or mode not in {"plan", "interactive", "ci"}:
        raise PlanError("Unsupported activation operation or mode")
    if (not isinstance(hosts, list) or len(hosts) != 3 or len(set(hosts)) != 3
            or hosts != sorted(hosts) or not isinstance(evidence, dict) or not evidence):
        raise PlanError("Activation requires evidence for exactly three sorted hosts")
    if mode == "ci" and not path:
        raise PlanError("CI activation requires the matching plan artifact")
    if mode != "plan" and path:
        return validate(read_plan(path), operation, hosts, current_context, evidence, now)
    plan = {"schema": 1, "operation": operation, "plan_id": uuid.uuid4().hex, "created": now,
            "expires": now + TTL, "hosts": hosts, "context": current_context, "evidence": evidence}
    plan["digest"] = digest(plan)
    if mode == "plan":
        if not path:
            raise PlanError("Plan generation requires an explicit output path")
        write_plan(path, plan)
    return plan
