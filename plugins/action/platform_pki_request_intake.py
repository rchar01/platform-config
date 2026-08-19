"""Authenticate and publish one direct three-file host-local PKI request."""

from __future__ import annotations

import os
import time

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils.platform_pki_exchange import (
        ExchangeError,
        PinnedTree,
        REQUEST_PUBLICATION_NAMES,
        REQUEST_REMOTE_NAMES,
        TRUST_NAMES,
        collection_receipt,
        pin_trust,
        prepare_request_parent,
        publish_exact_tree,
        require_digest,
        require_principal,
        require_request_id,
        require_service,
        validate_collection_receipt,
        validate_request_payload,
    )
except ImportError:  # Direct pytest imports do not use Ansible's plugin loader.
    from plugins.module_utils.platform_pki_exchange import (
        ExchangeError,
        PinnedTree,
        REQUEST_PUBLICATION_NAMES,
        REQUEST_REMOTE_NAMES,
        TRUST_NAMES,
        collection_receipt,
        pin_trust,
        prepare_request_parent,
        publish_exact_tree,
        require_digest,
        require_principal,
        require_request_id,
        require_service,
        validate_collection_receipt,
        validate_request_payload,
    )


ACTION_ARGUMENTS = frozenset(
    (
        "request_dir",
        "exchange_root",
        "service",
        "target",
        "transport_host_key_sha256",
        "inventory_sha256",
        "profile",
        "requester_principal",
        "response_principal",
        "common_name",
        "dns_sans",
        "ip_sans",
        "trust_paths",
        "trust_sha256",
        "expected_request_sha256",
        "expected_csr_sha256",
        "expected_csr_spki_sha256",
        "request_id",
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
                "direct request intake requires its exact structured argument set"
            )
        if self._task.check_mode:
            raise AnsibleActionFail("direct request intake is unavailable in check mode")

        source = existing = parent = None
        trust = {}
        try:
            request_id = require_request_id(args["request_id"])
            service = require_service(args["service"])
            require_principal(args["target"], "target")
            require_principal(args["requester_principal"], "requester_principal")
            require_principal(args["response_principal"], "response_principal")
            for name in (
                "transport_host_key_sha256",
                "inventory_sha256",
                "expected_request_sha256",
                "expected_csr_sha256",
                "expected_csr_spki_sha256",
            ):
                require_digest(args[name], name)
            bindings = {**args, "transport": "ssh"}
            source = PinnedTree.open(
                args["request_dir"], REQUEST_REMOTE_NAMES, "direct request intake"
            )
            trust = pin_trust(args["trust_paths"], args["trust_sha256"])
            now = int(time.time())
            request = validate_request_payload(
                source.data, bindings, trust, source.files["request.sig"], now=now
            )
            parent = prepare_request_parent(args["exchange_root"], service, request_id)

            def recheck() -> None:
                source.recheck()
                for item in trust.values():
                    item.recheck()

            trust_changed = publish_exact_tree(
                parent,
                "trust",
                {name: trust[name].data for name in TRUST_NAMES},
                pre_publish=recheck,
            )
            destination = os.path.join(parent.path, "request")
            if os.path.lexists(destination):
                existing = PinnedTree.open(
                    destination, REQUEST_PUBLICATION_NAMES, "published direct request"
                )
                public = {name: existing.data[name] for name in REQUEST_REMOTE_NAMES}
                if public != source.data:
                    raise ExchangeError(
                        "published request conflicts with direct request intake"
                    )
                validate_collection_receipt(
                    existing.data["collection-receipt"],
                    public,
                    bindings,
                    trust,
                    request,
                    now=now,
                )
                request_changed = False
            else:
                publication = {
                    **source.data,
                    "collection-receipt": collection_receipt(
                        source.data, bindings, trust, now
                    ),
                }
                request_changed = publish_exact_tree(
                    parent, "request", publication, pre_publish=recheck
                )
            recheck()
            changed = trust_changed or request_changed
            result.update(
                changed=changed,
                status="collected" if changed else "existing",
                request_id=request_id,
                request_dir=destination,
                trust_dir=os.path.join(parent.path, "trust"),
                request_sha256=args["expected_request_sha256"],
                csr_sha256=args["expected_csr_sha256"],
                csr_spki_sha256=args["expected_csr_spki_sha256"],
                transport="ssh",
                transport_host_key_sha256=args["transport_host_key_sha256"],
            )
            return result
        except ExchangeError as error:
            raise AnsibleActionFail(str(error)) from None
        except OSError:
            raise AnsibleActionFail(
                "direct request intake filesystem operation failed"
            ) from None
        finally:
            if existing is not None:
                existing.close()
            if parent is not None:
                parent.close()
            for item in trust.values():
                item.close()
            if source is not None:
                source.close()
