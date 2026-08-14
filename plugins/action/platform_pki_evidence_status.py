"""Authenticate one canonical controller evidence publication without mutation."""

from __future__ import annotations

import os
import time

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils.platform_pki_exchange import (
        EVIDENCE_NAMES,
        ExchangeError,
        PinnedDirectory,
        PinnedTree,
        REQUEST_PUBLICATION_NAMES,
        RESPONSE_NAMES,
        TRUST_NAMES,
        require_digest,
        require_principal,
        require_request_id,
        require_service,
        validate_evidence_snapshot,
    )
except ImportError:  # Direct pytest imports do not use Ansible's plugin loader.
    from plugins.module_utils.platform_pki_exchange import (
        EVIDENCE_NAMES,
        ExchangeError,
        PinnedDirectory,
        PinnedTree,
        REQUEST_PUBLICATION_NAMES,
        RESPONSE_NAMES,
        TRUST_NAMES,
        require_digest,
        require_principal,
        require_request_id,
        require_service,
        validate_evidence_snapshot,
    )


ACTION_ARGUMENTS = frozenset(
    (
        "exchange_root",
        "service",
        "target",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
    )
)


class ActionModule(ActionBase):
    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        del tmp
        task_vars = task_vars or {}
        result = super().run(tmp=None, task_vars=task_vars)
        args = self._task.args
        if set(args) != ACTION_ARGUMENTS:
            raise AnsibleActionFail(
                "evidence status action requires its exact structured argument set"
            )

        parent = request = response = trust = evidence = None
        try:
            request_id = require_request_id(args["request_id"])
            service = require_service(args["service"])
            require_principal(args["target"], "target")
            artifact_sha = require_digest(args["artifact_sha256"], "artifact_sha256")
            deployment_sha = require_digest(
                args["deployment_sha256"], "deployment_sha256"
            )
            if not isinstance(args["exchange_root"], str):
                raise ExchangeError("exchange_root must be an absolute canonical path")
            parent = PinnedDirectory.open(
                os.path.join(args["exchange_root"], service, request_id),
                "exchange request parent",
            )
            request = PinnedTree.open(
                os.path.join(parent.path, "request"),
                REQUEST_PUBLICATION_NAMES,
                "controller request publication",
            )
            response = PinnedTree.open(
                os.path.join(parent.path, "response"),
                RESPONSE_NAMES,
                "controller response publication",
            )
            trust = PinnedTree.open(
                os.path.join(parent.path, "trust"),
                TRUST_NAMES,
                "controller frozen trust",
            )
            evidence = PinnedTree.open(
                os.path.join(parent.path, "evidence", deployment_sha),
                EVIDENCE_NAMES,
                "controller evidence publication",
            )
            metadata = validate_evidence_snapshot(
                evidence,
                request,
                response,
                trust,
                args,
                now=int(time.time()),
                require_current=False,
            )
            evidence.recheck()
            request.recheck()
            response.recheck()
            trust.recheck()
            parent.recheck()
            result.update(
                changed=False,
                status="verified",
                service=service,
                target=args["target"],
                request_id=request_id,
                artifact_sha256=artifact_sha,
                deployment_sha256=deployment_sha,
                action=metadata["action"],
                result=metadata["result"],
            )
            return result
        except ExchangeError as error:
            raise AnsibleActionFail(str(error)) from None
        except OSError:
            raise AnsibleActionFail(
                "controller evidence publication is absent or unsafe"
            ) from None
        finally:
            for tree in (evidence, trust, response, request, parent):
                if tree is not None:
                    tree.close()
