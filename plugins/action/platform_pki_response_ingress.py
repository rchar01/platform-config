"""Transfer one pinned certificate-only response into target hidden ingress."""

from __future__ import annotations

import os
import posixpath
import re

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils.platform_pki_exchange import (
        ExchangeError,
        PinnedTree,
        RESPONSE_NAMES,
        require_digest,
        require_request_id,
        require_service,
        sha256,
    )
except ImportError:  # Direct pytest imports do not use Ansible's plugin loader.
    from plugins.module_utils.platform_pki_exchange import (
        ExchangeError,
        PinnedTree,
        RESPONSE_NAMES,
        require_digest,
        require_request_id,
        require_service,
        sha256,
    )


ACTION_ARGUMENTS = frozenset(
    (
        "exchange_root",
        "service",
        "request_id",
        "ingress_root",
        "artifact_sha256",
    )
)
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9_@%+=:,.-]+\Z", re.ASCII)


def response_source_path(exchange_root: object, service: str, request_id: str) -> str:
    if not isinstance(exchange_root, str):
        raise ExchangeError("exchange_root must be an absolute canonical path")
    return os.path.join(exchange_root, service, request_id, "response")


def validate_ingress_root(value: object, request_id: str) -> str:
    expected_suffix = f"/tls-versions/.ingress-{request_id}"
    if (
        not isinstance(value, str)
        or not posixpath.isabs(value)
        or value == "/"
        or posixpath.normpath(value) != value
        or not value.endswith(expected_suffix)
        or any(_PATH_COMPONENT.fullmatch(part) is None for part in value.split("/")[1:])
    ):
        raise ExchangeError(
            "ingress_root must be the canonical request-specific tls-versions ingress path"
        )
    return value


class ActionModule(ActionBase):
    TRANSFERS_FILES = True

    def run(self, tmp=None, task_vars=None):
        del tmp
        task_vars = task_vars or {}
        result = super().run(tmp=None, task_vars=task_vars)
        args = self._task.args
        if set(args) != ACTION_ARGUMENTS:
            raise AnsibleActionFail(
                "response ingress action requires its exact structured argument set"
            )
        if self._task.check_mode:
            raise AnsibleActionFail("response ingress transfer is unavailable in check mode")

        source = None
        remote_tmp = None
        try:
            request_id = require_request_id(args["request_id"])
            service = require_service(args["service"])
            ingress_root = validate_ingress_root(args["ingress_root"], request_id)
            artifact_sha = require_digest(
                args["artifact_sha256"], "artifact_sha256"
            )

            source_path = response_source_path(
                args["exchange_root"], service, request_id
            )
            source = PinnedTree.open(
                source_path, RESPONSE_NAMES, "controller response publication"
            )
            digests = {
                name: sha256(source.files[name].data) for name in RESPONSE_NAMES
            }
            if digests["artifact"] != artifact_sha:
                raise ExchangeError(
                    "controller response artifact differs from the reviewed digest"
                )
            source.recheck()

            remote_tmp = self._make_tmp_path()
            changed = False
            for name in RESPONSE_NAMES:
                source.recheck()
                source.files[name].recheck()
                remote_source = self._connection._shell.join_path(
                    remote_tmp, f".platform-pki-response-{name}"
                )
                self._transfer_data(remote_source, source.files[name].data)
                source.files[name].recheck()
                source.recheck()
                module_result = self._execute_module(
                    module_name="ansible.legacy.copy",
                    module_args={
                        "src": remote_source,
                        "dest": posixpath.join(ingress_root, name),
                        "remote_src": True,
                        "owner": "root",
                        "group": "root",
                        "mode": "0600",
                        "force": True,
                        "follow": False,
                    },
                    task_vars=task_vars,
                )
                if module_result.get("failed"):
                    raise AnsibleActionFail(
                        f"target response ingress copy failed: {name}"
                    )
                changed = changed or bool(module_result.get("changed"))
                source.files[name].recheck()
                source.recheck()
            source.recheck()
            result.update(
                changed=changed,
                status="transferred",
                request_id=request_id,
                ingress_root=ingress_root,
                artifact_sha256=artifact_sha,
                sha256=digests,
            )
            return result
        except ExchangeError as error:
            raise AnsibleActionFail(str(error)) from None
        except OSError:
            raise AnsibleActionFail(
                "response ingress filesystem operation failed"
            ) from None
        finally:
            if remote_tmp is not None:
                self._remove_tmp_path(remote_tmp)
            if source is not None:
                source.close()
