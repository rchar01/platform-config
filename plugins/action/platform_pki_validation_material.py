"""Deploy one descriptor-pinned reviewed validation material file."""

from __future__ import annotations

import os
import posixpath
import re
import sys
from typing import TypedDict

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils.platform_pki_exchange import (
        ExchangeError,
        require_digest,
        require_principal,
        require_service,
        require_validation_endpoint,
        validate_reviewed_ca_bundle,
        validate_validation_boundary,
    )
    from ansible.module_utils.platform_pki_secure_source import (
        SourcePinError,
        pin_controller_source,
    )
except ImportError:  # Standalone action plugins do not package local module_utils.
    module_utils_path = os.path.realpath(
        os.path.join(os.path.dirname(__file__), "..", "module_utils")
    )
    if module_utils_path not in sys.path:
        sys.path.insert(0, module_utils_path)
    from platform_pki_exchange import (
        ExchangeError,
        require_digest,
        require_principal,
        require_service,
        require_validation_endpoint,
        validate_reviewed_ca_bundle,
        validate_validation_boundary,
    )
    from platform_pki_secure_source import (
        SourcePinError,
        pin_controller_source,
    )


ACTION_ARGUMENTS = frozenset(
    (
        "material",
        "source",
        "destination",
        "sha256",
        "mode",
        "service",
        "target",
        "remote_validator",
        "endpoint",
    )
)
MATERIALS = {
    "reviewed-ca": 131072,
    "validation-boundary": 16384,
}
MOVING_PATH_COMPONENTS = frozenset(("latest", "current"))
PATH_COMPONENT = re.compile(r"[A-Za-z0-9_@%+=:,.-]+\Z", re.ASCII)
DESTINATION_FIELDS = (
    "exists",
    "isreg",
    "islnk",
    "uid",
    "gid",
    "nlink",
    "mode",
    "checksum",
    "dev",
    "inode",
    "size",
    "mtime",
    "ctime",
)
DIRECTORY_FIELDS = (
    "exists",
    "isdir",
    "islnk",
    "uid",
    "gid",
    "mode",
    "nlink",
    "dev",
    "inode",
)


class ValidationMaterialBindings(TypedDict):
    material: str
    source: str
    destination: str
    sha256: str
    mode: str
    service: str
    target: str
    remote_validator: str
    endpoint: str
    maximum: int


def validate_arguments(args: object) -> ValidationMaterialBindings:
    if not isinstance(args, dict) or set(args) != ACTION_ARGUMENTS:
        raise ExchangeError(
            "validation material action requires its exact structured argument set"
        )
    material = args["material"]
    if not isinstance(material, str) or material not in MATERIALS:
        raise ExchangeError("validation material kind is not allowlisted")
    service = require_service(args["service"])
    target = require_principal(args["target"], "target")
    runner = require_principal(args["remote_validator"], "remote_validator")
    if runner == target:
        raise ExchangeError("validation material requires a distinct remote validator")
    endpoint = require_validation_endpoint(args["endpoint"])
    digest = require_digest(args["sha256"], "validation material sha256")
    destination = args["destination"]
    if (
        not isinstance(destination, str)
        or not posixpath.isabs(destination)
        or destination == "/"
        or posixpath.normpath(destination) != destination
        or any(
            component in MOVING_PATH_COMPONENTS
            or PATH_COMPONENT.fullmatch(component) is None
            for component in destination.split("/")[1:]
        )
    ):
        raise ExchangeError(
            "validation material destination must be absolute, canonical, and immutable"
        )
    source = args["source"]
    if not isinstance(source, str) or source == destination:
        raise ExchangeError("validation material source and destination must be separate")
    mode = args["mode"]
    if material == "reviewed-ca":
        if mode not in {"0600", "0644"}:
            raise ExchangeError("reviewed CA destination mode must be 0600 or 0644")
    elif mode != "0600":
        raise ExchangeError("validation boundary destination mode must be 0600")
    return {
        "material": material,
        "source": source,
        "destination": destination,
        "sha256": digest,
        "mode": mode,
        "service": service,
        "target": target,
        "remote_validator": runner,
        "endpoint": endpoint,
        "maximum": MATERIALS[material],
    }


def destination_snapshot(stat_result: object, destination: str) -> dict[str, object]:
    if not isinstance(stat_result, dict) or stat_result.get("failed"):
        raise AnsibleActionFail(
            f"validation material destination inspection failed: {destination}"
        )
    metadata = stat_result.get("stat")
    if not isinstance(metadata, dict) or "exists" not in metadata:
        raise AnsibleActionFail(
            f"validation material destination inspection was incomplete: {destination}"
        )
    snapshot: dict[str, object] = {
        field: metadata.get(field) for field in DESTINATION_FIELDS
    }
    snapshot["exists"] = bool(metadata["exists"])
    if snapshot["exists"] and (
        metadata.get("isreg") is not True
        or metadata.get("islnk") is True
        or metadata.get("uid") != 0
        or metadata.get("gid") != 0
        or metadata.get("nlink") != 1
    ):
        raise AnsibleActionFail(
            f"validation material destination metadata is unsafe: {destination}"
        )
    return snapshot


def directory_snapshot(stat_result: object, directory: str) -> dict[str, object]:
    if not isinstance(stat_result, dict) or stat_result.get("failed"):
        raise AnsibleActionFail(
            f"validation material directory inspection failed: {directory}"
        )
    metadata = stat_result.get("stat")
    if not isinstance(metadata, dict) or "exists" not in metadata:
        raise AnsibleActionFail(
            f"validation material directory inspection was incomplete: {directory}"
        )
    snapshot: dict[str, object] = {
        field: metadata.get(field) for field in DIRECTORY_FIELDS
    }
    snapshot["exists"] = bool(metadata["exists"])
    if snapshot["exists"] and (
        metadata.get("isdir") is not True
        or metadata.get("islnk") is True
        or metadata.get("uid") != 0
        or metadata.get("gid") != 0
        or metadata.get("mode") != "0700"
    ):
        raise AnsibleActionFail(
            f"validation material directory metadata is unsafe: {directory}"
        )
    return snapshot


class ActionModule(ActionBase):
    TRANSFERS_FILES = True

    def _inspect_destination(
        self, destination: str, task_vars: dict[str, object]
    ) -> dict[str, object]:
        return destination_snapshot(
            self._execute_module(
                module_name="ansible.legacy.stat",
                module_args={
                    "path": destination,
                    "follow": False,
                    "get_checksum": True,
                    "checksum_algorithm": "sha256",
                },
                task_vars=task_vars,
            ),
            destination,
        )

    def _inspect_directory(
        self, directory: str, task_vars: dict[str, object]
    ) -> dict[str, object]:
        return directory_snapshot(
            self._execute_module(
                module_name="ansible.legacy.stat",
                module_args={"path": directory, "follow": False},
                task_vars=task_vars,
            ),
            directory,
        )

    def run(self, tmp=None, task_vars=None):
        del tmp
        task_vars = task_vars or {}
        result = super().run(tmp=None, task_vars=task_vars)
        source = None
        remote_tmp = None
        try:
            bindings = validate_arguments(self._task.args)
            source = pin_controller_source(
                bindings["source"],
                bindings["sha256"],
                maximum=bindings["maximum"],
                label=f"reviewed {bindings['material']} source",
            )
            if bindings["material"] == "reviewed-ca":
                validate_reviewed_ca_bundle(source.data)
            else:
                validate_validation_boundary(
                    source.data,
                    service=bindings["service"],
                    target=bindings["target"],
                    remote_validator=bindings["remote_validator"],
                    endpoint=bindings["endpoint"],
                )
            source.recheck()
            destination_parent = posixpath.dirname(bindings["destination"])
            parent_before = self._inspect_directory(destination_parent, task_vars)
            before = self._inspect_destination(
                bindings["destination"], task_vars
            )
            exact = (
                before["exists"]
                and before["mode"] == bindings["mode"]
                and before["checksum"] == bindings["sha256"]
            )
            if self._task.check_mode:
                source.recheck()
                result.update(
                    changed=not exact,
                    status="existing" if exact else "would-deploy",
                    material=bindings["material"],
                    destination=bindings["destination"],
                    sha256=bindings["sha256"],
                )
                return result
            if not parent_before["exists"]:
                raise AnsibleActionFail(
                    "validation material destination directory is absent"
                )
            if exact:
                source.recheck()
                result.update(
                    changed=False,
                    status="existing",
                    material=bindings["material"],
                    destination=bindings["destination"],
                    sha256=bindings["sha256"],
                )
                return result

            remote_tmp = self._make_tmp_path()
            remote_source = self._connection._shell.join_path(
                remote_tmp, ".platform-pki-validation-material"
            )
            source.recheck()
            self._transfer_data(remote_source, source.data)
            source.recheck()
            if self._inspect_directory(destination_parent, task_vars) != parent_before:
                raise AnsibleActionFail(
                    "validation material destination directory changed during transfer"
                )
            if self._inspect_destination(bindings["destination"], task_vars) != before:
                raise AnsibleActionFail(
                    "validation material destination changed during transfer"
                )
            copy_result = self._execute_module(
                module_name="ansible.legacy.copy",
                module_args={
                    "src": remote_source,
                    "dest": bindings["destination"],
                    "remote_src": True,
                    "owner": "root",
                    "group": "root",
                    "mode": bindings["mode"],
                    "force": True,
                    "follow": False,
                },
                task_vars=task_vars,
            )
            if copy_result.get("failed"):
                raise AnsibleActionFail("validation material destination copy failed")
            source.recheck()
            if self._inspect_directory(destination_parent, task_vars) != parent_before:
                raise AnsibleActionFail(
                    "validation material destination directory changed during transfer"
                )
            final = self._inspect_destination(bindings["destination"], task_vars)
            if (
                not final["exists"]
                or final["mode"] != bindings["mode"]
                or final["checksum"] != bindings["sha256"]
            ):
                raise AnsibleActionFail(
                    "validation material destination failed final validation"
                )
            result.update(
                changed=True,
                status="deployed",
                material=bindings["material"],
                destination=bindings["destination"],
                sha256=bindings["sha256"],
            )
            return result
        except (ExchangeError, SourcePinError) as error:
            raise AnsibleActionFail(str(error)) from None
        except OSError:
            raise AnsibleActionFail(
                "validation material filesystem operation failed"
            ) from None
        finally:
            if remote_tmp is not None:
                self._remove_tmp_path(remote_tmp)
            if source is not None:
                source.close()
