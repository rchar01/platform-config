"""Install a reviewed platform-pki client from a pinned controller descriptor."""

from __future__ import annotations

import os
import sys

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils.platform_pki_secure_source import (
        PinnedSource,
        pin_controller_source,
    )
except ImportError:  # Standalone action plugins do not package local module_utils.
    module_utils_path = os.path.realpath(
        os.path.join(os.path.dirname(__file__), "..", "module_utils")
    )
    if module_utils_path not in sys.path:
        sys.path.insert(0, module_utils_path)
    from platform_pki_secure_source import PinnedSource, pin_controller_source


MAX_TRANSPORT_CLIENT_SIZE = 8 * 1024 * 1024


def pin_source(path: str, expected_digest: str) -> PinnedSource:
    """Retain a focused test seam over shared descriptor pinning."""

    return pin_controller_source(
        path,
        expected_digest,
        maximum=MAX_TRANSPORT_CLIENT_SIZE,
        label="reviewed platform-pki transport client",
    )


class ActionModule(ActionBase):
    TRANSFERS_FILES = True

    def run(self, tmp=None, task_vars=None):
        del tmp
        task_vars = task_vars or {}
        result = super().run(tmp=None, task_vars=task_vars)
        if set(self._task.args) != {"source", "sha256", "dest"}:
            raise AnsibleActionFail(
                "transport client action accepts only source, digest, and destination"
            )
        source = self._task.args["source"]
        digest = self._task.args["sha256"]
        destination = self._task.args["dest"]
        if (
            not isinstance(destination, str)
            or not os.path.isabs(destination)
            or destination == "/"
            or os.path.normpath(destination) != destination
        ):
            raise AnsibleActionFail(
                "transport client destination must be an absolute canonical path"
            )
        if self._task.check_mode:
            raise AnsibleActionFail(
                "transport client installation is unavailable in check mode"
            )

        pinned = pin_source(source, digest)
        remote_tmp = None
        try:
            pinned.recheck()
            remote_tmp = self._make_tmp_path()
            remote_source = self._connection._shell.join_path(
                remote_tmp, ".platform-pki"
            )
            self._transfer_data(remote_source, pinned.data)
            pinned.recheck()
            module_result = self._execute_module(
                module_name="ansible.legacy.copy",
                module_args={
                    "src": remote_source,
                    "dest": destination,
                    "remote_src": True,
                    "owner": "root",
                    "group": "root",
                    "mode": "0755",
                    "force": True,
                    "follow": False,
                },
                task_vars=task_vars,
            )
            pinned.recheck()
            if module_result.get("failed"):
                return module_result
            result.update(
                changed=bool(module_result.get("changed")), status="installed"
            )
            return result
        finally:
            try:
                if remote_tmp is not None:
                    self._remove_tmp_path(remote_tmp)
            finally:
                pinned.close()
