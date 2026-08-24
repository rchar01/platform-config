"""Transfer reviewed trust bytes from pinned controller descriptors."""

from __future__ import annotations

import os
import sys

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils.platform_pki_secure_source import (
        PinnedSource,
        REPOSITORY_ROOT,
        pin_controller_source,
    )
except ImportError:  # Standalone action plugins do not package local module_utils.
    module_utils_path = os.path.realpath(
        os.path.join(os.path.dirname(__file__), "..", "module_utils")
    )
    if module_utils_path not in sys.path:
        sys.path.insert(0, module_utils_path)
    from platform_pki_secure_source import (
        PinnedSource,
        REPOSITORY_ROOT,
        pin_controller_source,
    )


TRUST_NAMES = (
    "approvers.allowed_signers",
    "policy",
    "requesters.allowed_signers",
    "responses.allowed_signers",
)
MAX_TRUST_SIZE = 65536


def pin_source(path: str, expected_digest: str) -> PinnedSource:
    """Retain the trust action's public test seam over shared pinning."""

    return pin_controller_source(
        path,
        expected_digest,
        maximum=MAX_TRUST_SIZE,
        label="reviewed trust source",
    )


class ActionModule(ActionBase):
    TRANSFERS_FILES = True

    def run(self, tmp=None, task_vars=None):
        del tmp
        task_vars = task_vars or {}
        result = super().run(tmp=None, task_vars=task_vars)
        sources = self._task.args.get("sources")
        digests = self._task.args.get("sha256")
        ingress_root = self._task.args.get("ingress_root")
        if set(self._task.args) != {"sources", "sha256", "ingress_root"}:
            raise AnsibleActionFail("trust ingress action accepts only fixed source, digest, and ingress mappings")
        if not isinstance(sources, dict) or set(sources) != set(TRUST_NAMES):
            raise AnsibleActionFail("trust ingress action requires the exact four-key source mapping")
        if not isinstance(digests, dict) or set(digests) != set(TRUST_NAMES):
            raise AnsibleActionFail("trust ingress action requires the exact four-key digest mapping")
        if not isinstance(ingress_root, str) or not ingress_root.startswith("/") or os.path.normpath(ingress_root) != ingress_root:
            raise AnsibleActionFail("trust ingress destination must be an absolute canonical path")
        if self._task.check_mode:
            raise AnsibleActionFail("trust ingress transfer is unavailable in check mode")

        pinned: dict[str, PinnedSource] = {}
        remote_tmp = None
        try:
            for name in TRUST_NAMES:
                digest = digests[name]
                if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                    raise AnsibleActionFail(f"trust ingress digest is not canonical SHA-256: {name}")
                if not isinstance(sources[name], str) or not os.path.isabs(sources[name]):
                    raise AnsibleActionFail(f"reviewed trust source is not an absolute path string: {name}")
                if os.path.basename(sources[name]) != name:
                    raise AnsibleActionFail(f"reviewed trust source basename does not match mapping key: {name}")
                pinned[name] = pin_source(sources[name], digest)
            if len({source.path for source in pinned.values()}) != len(TRUST_NAMES):
                raise AnsibleActionFail("reviewed trust source paths must be distinct")
            for source in pinned.values():
                source.recheck()

            remote_tmp = self._make_tmp_path()
            changed = False
            for name in TRUST_NAMES:
                source = pinned[name]
                source.recheck()
                remote_source = self._connection._shell.join_path(remote_tmp, f".trust-{name}")
                self._transfer_data(remote_source, source.data)
                module_result = self._execute_module(
                    module_name="ansible.legacy.copy",
                    module_args={
                        "src": remote_source,
                        "dest": os.path.join(ingress_root, name),
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
                    return module_result
                changed = changed or bool(module_result.get("changed"))
                source.recheck()
            for source in pinned.values():
                source.recheck()
            result.update(changed=changed, status="transferred")
            return result
        finally:
            try:
                if remote_tmp is not None:
                    self._remove_tmp_path(remote_tmp)
            finally:
                for source in pinned.values():
                    source.close()
