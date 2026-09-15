from __future__ import annotations

import ipaddress
import json
import math
import os
import stat
from typing import Any

from ansible.plugins.callback import CallbackBase


DOCUMENTATION = r"""
name: platform_config_operation_summary
type: aggregate
short_description: Record sanitized fixed-operation events
version_added: "1.0.0"
requirements:
  - Enabled only by scripts/platform-config-operation
"""

COUNTERS = ("ok", "changed", "failures", "unreachable", "skipped", "rescued", "ignored")
FAILOVER_RESULTS = {
    "failover_test_result": {"passed", "failed", "not_run"},
    "recovery_result": {"passed", "failed", "not_required"},
    "final_smoke_result": {"passed", "failed", "not_run"},
}
FAILOVER_TIMES = {"failover_elapsed_seconds", "transaction_elapsed_seconds"}


def _safe_text(value: object, maximum: int) -> str | None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        return None
    if not value.isascii() or any(not 32 <= ord(character) <= 126 for character in value):
        return None
    return value


def _safe_host(value: object) -> str | None:
    host = _safe_text(value, 255)
    if host is None:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


def _append_record(path: str, record: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise OSError("summary path is not a regular file")
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o600:
            raise OSError("summary path has unsafe ownership or mode")
        payload = json.dumps(record, ensure_ascii=True, separators=(",", ":"))
        remaining = memoryview(payload.encode("ascii") + b"\n")
        while remaining:
            remaining = remaining[os.write(descriptor, remaining) :]
    finally:
        os.close(descriptor)


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "platform_config_operation_summary"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self) -> None:
        super().__init__()
        self._write_failed = False

    def _context(self) -> tuple[str, str] | None:
        path = os.environ.get("PLATFORM_CONFIG_OPERATION_SUMMARY_PATH", "")
        phase = _safe_text(
            os.environ.get("PLATFORM_CONFIG_OPERATION_PHASE", ""), 64
        )
        if not path or phase is None:
            return None
        return path, phase

    def _write_error(self) -> None:
        context = self._context()
        if context is None:
            return
        path, phase = context
        try:
            _append_record(path, {"schema": 1, "kind": "error", "phase": phase})
        except OSError:
            self._write_failed = True

    def _write_task(self, result: Any, outcome: str) -> None:
        context = self._context()
        if context is None:
            return
        path, phase = context
        host = _safe_host(result._host.get_name())
        task = _safe_text(result._task.get_name(), 255)
        if host is None or task is None:
            self._write_error()
            return
        try:
            _append_record(
                path,
                {
                    "schema": 1,
                    "kind": "task",
                    "phase": phase,
                    "host": host,
                    "outcome": outcome,
                    "task": task,
                },
            )
        except OSError:
            self._write_failed = True

    def v2_runner_on_ok(self, result: Any) -> None:
        context = self._context()
        if (context is not None and context[1] in {"failover-plan", "failover-test", "failover-recover"}
                and result._task.action in {"debug", "ansible.builtin.debug"}
                and result._task.get_name() == "Publish sanitized failover phase results on every selected host"):
            self._write_failover(result, context)
        if result._result.get("changed", False) is True:
            self._write_task(result, "changed")

    def _write_failover(self, result: Any, context: tuple[str, str]) -> None:
        path, phase = context
        host = _safe_host(result._host.get_name())
        values = result._result.get("msg")
        if (host is None or not isinstance(values, dict)
                or set(values) != FAILOVER_RESULTS.keys() | FAILOVER_TIMES
                or any(not isinstance(values[key], str) or values[key] not in allowed
                       for key, allowed in FAILOVER_RESULTS.items())):
            self._write_error()
            return
        for key in FAILOVER_TIMES:
            value = values[key]
            if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 86400):
                self._write_error()
                return
        try:
            _append_record(path, {"schema": 1, "kind": "failover", "phase": phase, "host": host, **values})
        except OSError:
            self._write_failed = True

    def v2_runner_on_failed(self, result: Any, ignore_errors: bool = False) -> None:
        if not ignore_errors:
            self._write_task(result, "failed")

    def v2_runner_on_unreachable(self, result: Any) -> None:
        self._write_task(result, "unreachable")

    def v2_playbook_on_stats(self, stats: Any) -> None:
        context = self._context()
        if context is None:
            return
        path, phase = context
        if self._write_failed:
            try:
                _append_record(
                    path, {"schema": 1, "kind": "error", "phase": phase}
                )
            except OSError:
                pass
            return
        try:
            for host in sorted(stats.processed):
                safe_host = _safe_host(host)
                summary = stats.summarize(host)
                if safe_host is None or any(
                    not isinstance(summary.get(counter, 0), int)
                    or isinstance(summary.get(counter, 0), bool)
                    or summary.get(counter, 0) < 0
                    for counter in COUNTERS
                ):
                    _append_record(
                        path,
                        {"schema": 1, "kind": "error", "phase": phase},
                    )
                    return
                _append_record(
                    path,
                    {
                        "schema": 1,
                        "kind": "recap",
                        "phase": phase,
                        "host": safe_host,
                        "counters": {
                            counter: summary.get(counter, 0) for counter in COUNTERS
                        },
                    },
                )
        except OSError:
            self._write_failed = True
