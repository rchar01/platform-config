"""Authenticate and publish one direct five-file host-local evidence package."""

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
        prepare_evidence_parent,
        publish_exact_tree,
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
        prepare_evidence_parent,
        publish_exact_tree,
        require_digest,
        require_principal,
        require_request_id,
        require_service,
        validate_evidence_snapshot,
    )


ACTION_ARGUMENTS = frozenset(
    (
        "evidence_dir",
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
        result = super().run(tmp=None, task_vars=task_vars or {})
        args = self._task.args
        if set(args) != ACTION_ARGUMENTS:
            raise AnsibleActionFail(
                "direct evidence intake requires its exact structured argument set"
            )
        if self._task.check_mode:
            raise AnsibleActionFail("direct evidence intake is unavailable in check mode")

        parent = request = response = trust = source = evidence_parent = None
        try:
            service = require_service(args["service"])
            require_principal(args["target"], "target")
            request_id = require_request_id(args["request_id"])
            require_digest(args["artifact_sha256"], "artifact_sha256")
            deployment = require_digest(
                args["deployment_sha256"], "deployment_sha256"
            )
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
            source = PinnedTree.open(
                args["evidence_dir"], EVIDENCE_NAMES, "direct evidence intake"
            )
            metadata = validate_evidence_snapshot(
                source, request, response, trust, args, now=int(time.time())
            )
            evidence_parent = prepare_evidence_parent(parent)

            def recheck() -> None:
                source.recheck()
                request.recheck()
                response.recheck()
                trust.recheck()

            changed = publish_exact_tree(
                evidence_parent, deployment, source.data, pre_publish=recheck
            )
            recheck()
            result.update(
                changed=changed,
                status="collected" if changed else "existing",
                request_id=request_id,
                evidence_dir=os.path.join(evidence_parent.path, deployment),
                **metadata,
            )
            return result
        except ExchangeError as error:
            raise AnsibleActionFail(str(error)) from None
        except OSError:
            raise AnsibleActionFail(
                "direct evidence intake filesystem operation failed"
            ) from None
        finally:
            for tree in (
                evidence_parent,
                source,
                trust,
                response,
                request,
                parent,
            ):
                if tree is not None:
                    tree.close()
