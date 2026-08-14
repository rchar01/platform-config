"""Collect and publish one authenticated host-local deployment evidence attempt."""

from __future__ import annotations

import json
import os
import posixpath
import re
import secrets
import stat
import time

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils.platform_pki_exchange import (
        EVIDENCE_NAMES,
        ExchangeError,
        MAX_SIZES,
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
        sha256,
        validate_evidence_snapshot,
    )
except ImportError:  # Direct pytest imports do not use Ansible's plugin loader.
    from plugins.module_utils.platform_pki_exchange import (
        EVIDENCE_NAMES,
        ExchangeError,
        MAX_SIZES,
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
        sha256,
        validate_evidence_snapshot,
    )


ACTION_ARGUMENTS = frozenset(
    (
        "lifecycle_helper_path",
        "state_root",
        "pending_root",
        "versions_root",
        "trust_id",
        "exchange_root",
        "service",
        "target",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
    )
)
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9_@%+=:,.-]+\Z", re.ASCII)
_TRUST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
_FILE_METADATA_KEYS = {
    name: f"{name.replace('-', '_').replace('.', '_')}_sha256"
    for name in EVIDENCE_NAMES
}
_HELPER_METADATA = frozenset(
    {
        "status",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
        "action",
        "result",
        *_FILE_METADATA_KEYS.values(),
    }
)


def _canonical_remote_path(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not posixpath.isabs(value)
        or value == "/"
        or posixpath.normpath(value) != value
        or any(_PATH_COMPONENT.fullmatch(part) is None for part in value.split("/")[1:])
    ):
        raise ExchangeError(f"{label} must be an absolute canonical non-root path")
    return value


def _remote_path(output_dir: str, name: str) -> str:
    if name not in EVIDENCE_NAMES:
        raise AnsibleActionFail("evidence collection remote basename is not allowlisted")
    return posixpath.join(output_dir, name)


def _private_access(metadata: dict[str, object], *, directory: bool) -> bool:
    return (
        metadata.get("rusr") is True
        and metadata.get("wusr") is True
        and metadata.get("xusr") is directory
        and metadata.get("rgrp") is False
        and metadata.get("wgrp") is False
        and metadata.get("xgrp") is False
        and metadata.get("roth") is False
        and metadata.get("woth") is False
        and metadata.get("xoth") is False
    )


def _directory_snapshot(metadata: dict[str, object]) -> tuple[int, tuple[object, ...]]:
    owner = metadata.get("uid")
    if (
        metadata.get("exists") is not True
        or metadata.get("isdir") is not True
        or metadata.get("islnk") is True
        or not isinstance(owner, int)
        or isinstance(owner, bool)
        or owner < 0
        or metadata.get("mode") != "0700"
        or not _private_access(metadata, directory=True)
    ):
        raise AnsibleActionFail("action-owned remote evidence directory metadata is unsafe")
    return owner, tuple(metadata.get(key) for key in ("dev", "inode", "uid", "gid", "mode"))


def _file_snapshot(
    metadata: dict[str, object], name: str, owner_uid: int
) -> tuple[object, ...]:
    size = metadata.get("size")
    if (
        metadata.get("exists") is not True
        or metadata.get("isreg") is not True
        or metadata.get("islnk") is True
        or metadata.get("uid") != owner_uid
        or metadata.get("mode") != "0600"
        or metadata.get("nlink") != 1
        or not isinstance(size, int)
        or size <= 0
        or size > MAX_SIZES[name]
        or not isinstance(metadata.get("checksum"), str)
        or not _private_access(metadata, directory=False)
    ):
        raise AnsibleActionFail(f"remote evidence file metadata is unsafe: {name}")
    keys = ("dev", "inode", "uid", "gid", "mode", "nlink", "size", "mtime", "ctime", "checksum")
    return tuple(metadata.get(key) for key in keys)


class ActionModule(ActionBase):
    TRANSFERS_FILES = True

    def _stat(
        self, path: str, task_vars: dict[str, object], *, checksum: bool
    ) -> dict[str, object]:
        result = self._execute_module(
            module_name="ansible.legacy.stat",
            module_args={
                "path": path,
                "follow": False,
                "get_checksum": checksum,
                "checksum_algorithm": "sha256",
                "get_attributes": False,
                "get_mime": False,
            },
            task_vars=task_vars,
        )
        if result.get("failed") or not isinstance(result.get("stat"), dict):
            raise AnsibleActionFail("cannot inspect action-owned remote evidence path")
        return result["stat"]

    def _prepare(
        self,
        args: dict[str, object],
        task_vars: dict[str, object],
        output_dir: str,
        owner_uid: int,
        expected_status: str,
        expected: dict[str, str] | None = None,
    ) -> dict[str, str]:
        argv = [
            args["lifecycle_helper_path"],
            "evidence-collection-prepare",
            "--state-root",
            args["state_root"],
            "--pending-root",
            args["pending_root"],
            "--versions-root",
            args["versions_root"],
            "--service",
            args["service"],
            "--target",
            args["target"],
            "--trust-id",
            args["trust_id"],
            "--request-id",
            args["request_id"],
            "--artifact-sha256",
            args["artifact_sha256"],
            "--deployment-sha256",
            args["deployment_sha256"],
            "--output-dir",
            output_dir,
            "--output-owner-uid",
            str(owner_uid),
        ]
        result = self._execute_module(
            module_name="ansible.legacy.command",
            module_args={"argv": argv},
            task_vars=task_vars,
        )
        if result.get("failed") or result.get("rc") != 0:
            raise AnsibleActionFail("lifecycle helper evidence collection failed")
        stdout = result.get("stdout")
        if not isinstance(stdout, str) or not stdout or "\r" in stdout or "\x00" in stdout:
            raise AnsibleActionFail("lifecycle helper returned invalid evidence metadata")
        encoded = stdout[:-1] if stdout.endswith("\n") else stdout
        if "\n" in encoded or not encoded:
            raise AnsibleActionFail("lifecycle helper returned invalid evidence metadata")
        try:
            metadata = json.loads(encoded)
        except (TypeError, ValueError):
            raise AnsibleActionFail("lifecycle helper returned invalid evidence metadata") from None
        if (
            not isinstance(metadata, dict)
            or set(metadata) != _HELPER_METADATA
            or any(not isinstance(value, str) for value in metadata.values())
            or json.dumps(metadata, sort_keys=True, separators=(",", ":")) != encoded
            or result.get("stderr") not in {None, ""}
        ):
            raise AnsibleActionFail("lifecycle helper returned invalid evidence metadata")
        if (
            metadata["status"] != expected_status
            or metadata["request_id"] != args["request_id"]
            or metadata["artifact_sha256"] != args["artifact_sha256"]
            or metadata["deployment_sha256"] != args["deployment_sha256"]
            or (metadata["action"], metadata["result"])
            not in {
                ("finalize", "activated"),
                ("abandon", "not-activated"),
                ("abandon", "rolled-back"),
            }
        ):
            raise AnsibleActionFail("lifecycle helper evidence metadata differs from coordinates")
        for key in _FILE_METADATA_KEYS.values():
            require_digest(metadata[key], f"lifecycle helper evidence digest {key}")
        if expected is not None and any(
            metadata[key] != expected[key] for key in _HELPER_METADATA.difference(("status",))
        ):
            raise AnsibleActionFail("lifecycle helper evidence metadata changed after fetch")
        return metadata

    def run(self, tmp=None, task_vars=None):
        del tmp
        task_vars = task_vars or {}
        result = super().run(tmp=None, task_vars=task_vars)
        args = self._task.args
        if set(args) != ACTION_ARGUMENTS:
            raise AnsibleActionFail("evidence collection action requires its exact structured argument set")
        if self._task.check_mode:
            raise AnsibleActionFail("evidence collection is unavailable in check mode")

        parent = request_tree = response_tree = trust_tree = fetched = evidence_parent = None
        remote_tmp = remote_tmp_root = fetch_stage = None
        try:
            request_id = require_request_id(args["request_id"])
            service = require_service(args["service"])
            require_principal(args["target"], "target")
            require_digest(args["artifact_sha256"], "artifact_sha256")
            require_digest(args["deployment_sha256"], "deployment_sha256")
            helper = _canonical_remote_path(
                args["lifecycle_helper_path"], "lifecycle_helper_path"
            )
            if posixpath.basename(helper) != "platform-pki-host-local-lifecycle":
                raise ExchangeError("lifecycle_helper_path has an unexpected basename")
            for name in ("state_root", "pending_root", "versions_root"):
                _canonical_remote_path(args[name], name)
            if not isinstance(args["trust_id"], str) or _TRUST_ID.fullmatch(args["trust_id"]) is None:
                raise ExchangeError("trust_id is not canonical")
            if not isinstance(args["exchange_root"], str):
                raise ExchangeError("exchange_root must be an absolute canonical path")

            parent = PinnedDirectory.open(
                os.path.join(args["exchange_root"], service, request_id),
                "exchange request parent",
            )
            request_tree = PinnedTree.open(
                os.path.join(parent.path, "request"),
                REQUEST_PUBLICATION_NAMES,
                "controller request publication",
            )
            response_tree = PinnedTree.open(
                os.path.join(parent.path, "response"),
                RESPONSE_NAMES,
                "controller response publication",
            )
            trust_tree = PinnedTree.open(
                os.path.join(parent.path, "trust"),
                TRUST_NAMES,
                "controller frozen trust",
            )

            remote_tmp_root = _canonical_remote_path(
                self._make_tmp_path().rstrip("/"),
                "action-owned remote temporary directory",
            )
            remote_tmp = _canonical_remote_path(
                posixpath.join(remote_tmp_root, "public-evidence"),
                "action-owned remote evidence directory",
            )
            create_directory = self._execute_module(
                module_name="ansible.legacy.file",
                module_args={"path": remote_tmp, "state": "directory", "mode": "0700"},
                task_vars=task_vars,
            )
            if create_directory.get("failed"):
                raise AnsibleActionFail("cannot create action-owned remote evidence directory")
            owner_uid, directory_identity = _directory_snapshot(
                self._stat(remote_tmp, task_vars, checksum=False)
            )
            first = self._prepare(args, task_vars, remote_tmp, owner_uid, "collected")
            owner_after, directory_after = _directory_snapshot(
                self._stat(remote_tmp, task_vars, checksum=False)
            )
            if owner_after != owner_uid or directory_after != directory_identity:
                raise ExchangeError("action-owned remote evidence directory changed")
            remote_files: dict[str, tuple[object, ...]] = {}
            for name in EVIDENCE_NAMES:
                snapshot = _file_snapshot(
                    self._stat(_remote_path(remote_tmp, name), task_vars, checksum=True),
                    name,
                    owner_uid,
                )
                if snapshot[-1] != first[_FILE_METADATA_KEYS[name]]:
                    raise ExchangeError(f"remote evidence checksum differs from helper metadata: {name}")
                remote_files[name] = snapshot

            fetch_stage = f".platform-pki-evidence.{secrets.token_hex(16)}"
            os.mkdir(fetch_stage, 0o700, dir_fd=parent.fileno())
            fetch_path = os.path.join(parent.path, fetch_stage)
            old_umask = os.umask(0o077)
            try:
                for name in EVIDENCE_NAMES:
                    self._connection.fetch_file(
                        _remote_path(remote_tmp, name), os.path.join(fetch_path, name)
                    )
                    descriptor = os.open(
                        os.path.join(fetch_path, name),
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    )
                    try:
                        metadata = os.fstat(descriptor)
                        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1:
                            raise ExchangeError(f"fetched evidence file metadata is unsafe: {name}")
                        os.fchmod(descriptor, 0o600)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    if _file_snapshot(
                        self._stat(_remote_path(remote_tmp, name), task_vars, checksum=True),
                        name,
                        owner_uid,
                    ) != remote_files[name]:
                        raise ExchangeError(f"remote evidence changed during fetch: {name}")
            finally:
                os.umask(old_umask)

            fetched = PinnedTree.open(fetch_path, EVIDENCE_NAMES, "collected evidence stage")
            second = self._prepare(
                args, task_vars, remote_tmp, owner_uid, "existing", first
            )
            if any(second[key] != first[key] for key in _HELPER_METADATA.difference(("status",))):
                raise ExchangeError("lifecycle helper evidence metadata changed after fetch")
            final_owner, final_directory = _directory_snapshot(
                self._stat(remote_tmp, task_vars, checksum=False)
            )
            if final_owner != owner_uid or final_directory != directory_identity:
                raise ExchangeError(
                    "action-owned remote evidence directory changed after fetch"
                )
            for name in EVIDENCE_NAMES:
                if sha256(fetched.files[name].data) != first[_FILE_METADATA_KEYS[name]]:
                    raise ExchangeError(f"fetched evidence checksum mismatch: {name}")
                if _file_snapshot(
                    self._stat(_remote_path(remote_tmp, name), task_vars, checksum=True),
                    name,
                    owner_uid,
                ) != remote_files[name]:
                    raise ExchangeError(f"remote evidence changed after helper revalidation: {name}")

            metadata = validate_evidence_snapshot(
                fetched,
                request_tree,
                response_tree,
                trust_tree,
                args,
                now=int(time.time()),
            )
            evidence_parent = prepare_evidence_parent(parent)

            def recheck() -> None:
                fetched.recheck()
                request_tree.recheck()
                response_tree.recheck()
                trust_tree.recheck()
                for name in EVIDENCE_NAMES:
                    if _file_snapshot(
                        self._stat(_remote_path(remote_tmp, name), task_vars, checksum=True),
                        name,
                        owner_uid,
                    ) != remote_files[name]:
                        raise ExchangeError(f"remote evidence changed at publication: {name}")
                current_owner, current_directory = _directory_snapshot(
                    self._stat(remote_tmp, task_vars, checksum=False)
                )
                if (
                    current_owner != owner_uid
                    or current_directory != directory_identity
                ):
                    raise ExchangeError(
                        "action-owned remote evidence directory changed at publication"
                    )

            changed = publish_exact_tree(
                evidence_parent,
                args["deployment_sha256"],
                fetched.data,
                pre_publish=recheck,
            )
            result.update(
                changed=changed,
                status="collected" if changed else "existing",
                request_id=request_id,
                evidence_dir=os.path.join(
                    evidence_parent.path, args["deployment_sha256"]
                ),
                **metadata,
            )
            return result
        except ExchangeError as error:
            raise AnsibleActionFail(str(error)) from None
        except OSError:
            raise AnsibleActionFail("evidence collection filesystem operation failed") from None
        finally:
            if remote_tmp_root is not None:
                self._remove_tmp_path(remote_tmp_root)
            if fetched is not None:
                fetched.close()
            if fetch_stage is not None and parent is not None:
                try:
                    stage_fd = os.open(
                        fetch_stage,
                        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=parent.fileno(),
                    )
                    try:
                        for name in EVIDENCE_NAMES:
                            try:
                                os.unlink(name, dir_fd=stage_fd)
                            except FileNotFoundError:
                                pass
                    finally:
                        os.close(stage_fd)
                    os.rmdir(fetch_stage, dir_fd=parent.fileno())
                    os.fsync(parent.fileno())
                except OSError:
                    pass
            for tree in (evidence_parent, trust_tree, response_tree, request_tree, parent):
                if tree is not None:
                    tree.close()
