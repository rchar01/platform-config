"""Record executed task outcomes, excluding skipped host operations."""

import json
import os

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "alloy_tls_evidence"
    CALLBACK_NEEDS_ENABLED = True

    def _record(self, result, status):
        value = result._result
        # Only aggregate runner callbacks write events. Keep every failed loop
        # item, including errors, so one bad item cannot hide behind another's
        # expected assertion failure.
        failed_assertions = []
        if status == "failed":
            failed_assertions = (
                [item for item in value["results"]
                 if "failed" in item and item["failed"] is not False]
                if "results" in value else [value]
            )
        event = {
            "host": result._host.get_name(),
            "action": result._task.action,
            "name": result._task.get_name(),
            "status": status,
            "changed": value.get("changed", False),
            # Scalar assertion callback results may omit the failed key; the
            # runner callback itself supplies the authoritative failure status.
            "failed": value.get("failed", status == "failed"),
            "errors": {key: value[key] for key in ("exception", "error") if key in value},
            "failed_assertions": failed_assertions,
        }
        with open(os.environ["ALLOY_TLS_TEST_EVIDENCE"], "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, default=str) + "\n")

    def v2_runner_on_ok(self, result):
        self._record(result, "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record(result, "failed")

    def v2_runner_on_unreachable(self, result):
        self._record(result, "unreachable")
