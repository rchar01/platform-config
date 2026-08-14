"""Validate and snapshot one exact certificate-only PKI response."""

from __future__ import annotations

import os
import time

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils.platform_pki_exchange import (
        ExchangeError,
        PinnedDirectory,
        PinnedTree,
        REQUEST_PUBLICATION_NAMES,
        RESPONSE_NAMES,
        pin_trust,
        publish_exact_tree,
        require_digest,
        require_principal,
        require_request_id,
        require_service,
        validate_response_snapshot,
    )
except ImportError:  # Direct pytest imports do not use Ansible's plugin loader.
    from plugins.module_utils.platform_pki_exchange import (
        ExchangeError,
        PinnedDirectory,
        PinnedTree,
        REQUEST_PUBLICATION_NAMES,
        RESPONSE_NAMES,
        pin_trust,
        publish_exact_tree,
        require_digest,
        require_principal,
        require_request_id,
        require_service,
        validate_response_snapshot,
    )


ACTION_ARGUMENTS = frozenset(
    (
        "response_dir",
        "exchange_root",
        "service",
        "target",
        "request_id",
        "inventory_sha256",
        "expected_artifact_sha256",
        "response_principal",
        "trust_paths",
        "trust_sha256",
        "common_name",
        "dns_sans",
        "ip_sans",
        "minimum_remaining_lifetime_seconds",
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
            raise AnsibleActionFail("response intake action requires its exact structured argument set")
        if self._task.check_mode:
            raise AnsibleActionFail("response intake is unavailable in check mode")

        source = None
        request = None
        trust = {}
        parent = None
        try:
            request_id = require_request_id(args["request_id"])
            service = require_service(args["service"])
            require_principal(args["target"], "target")
            require_principal(args["response_principal"], "response_principal")
            for name in (
                "inventory_sha256",
                "expected_artifact_sha256",
            ):
                require_digest(args[name], name)
            if not isinstance(args["exchange_root"], str):
                raise ExchangeError("exchange_root must be an absolute canonical path")

            trust = pin_trust(args["trust_paths"], args["trust_sha256"])
            source = PinnedTree.open(
                args["response_dir"], RESPONSE_NAMES, "certificate response source"
            )
            parent = PinnedDirectory.open(
                os.path.join(
                    args["exchange_root"], service, request_id
                ),
                "exchange request parent",
            )
            request = PinnedTree.open(
                os.path.join(parent.path, "request"),
                REQUEST_PUBLICATION_NAMES,
                "controller request publication",
            )
            try:
                source_inside_exchange = (
                    os.path.commonpath((os.fspath(args["exchange_root"]), source.directory.path))
                    == os.fspath(args["exchange_root"])
                )
                exchange_inside_source = (
                    os.path.commonpath((source.directory.path, os.fspath(args["exchange_root"])))
                    == source.directory.path
                )
            except ValueError:
                raise ExchangeError("cannot compare response source and exchange paths") from None
            if source_inside_exchange or exchange_inside_source:
                raise ExchangeError("response source and exchange workspace must not overlap")

            metadata = validate_response_snapshot(
                source, request, args, trust, now=int(time.time())
            )

            def recheck() -> None:
                source.recheck()
                request.recheck()
                for trust_source in trust.values():
                    trust_source.recheck()

            changed = publish_exact_tree(
                parent, "response", source.data, pre_publish=recheck
            )
            source.recheck()
            request.recheck()
            for trust_source in trust.values():
                trust_source.recheck()
            result.update(
                changed=changed,
                status="received" if changed else "existing",
                request_id=request_id,
                response_dir=os.path.join(parent.path, "response"),
                **metadata,
            )
            return result
        except ExchangeError as error:
            raise AnsibleActionFail(str(error)) from None
        except OSError:
            raise AnsibleActionFail("response intake filesystem operation failed") from None
        finally:
            if request is not None:
                request.close()
            if parent is not None:
                parent.close()
            if source is not None:
                source.close()
            for trust_source in trust.values():
                trust_source.close()
