"""Collect only the three public host-local PKI request files."""

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
        ExchangeError,
        MAX_SIZES,
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
        sha256,
        validate_collection_receipt,
        validate_request_payload,
    )
except ImportError:  # Direct pytest imports do not use Ansible's plugin loader.
    from plugins.module_utils.platform_pki_exchange import (
        ExchangeError,
        MAX_SIZES,
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
        sha256,
        validate_collection_receipt,
        validate_request_payload,
    )


ACTION_ARGUMENTS = frozenset(
    (
        "lifecycle_helper_path",
        "state_root",
        "pending_root",
        "versions_root",
        "trust_id",
        "request_id",
        "exchange_root",
        "service",
        "target",
        "transport",
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
    )
)


_TRUST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9_@%+=:,.-]+\Z", re.ASCII)
_HELPER_METADATA = frozenset(
    (
        "status",
        "request_id",
        "request_sha256",
        "csr_sha256",
        "request_signature_sha256",
    )
)
_SAFE_HELPER_ERROR = re.compile(r"[A-Za-z0-9 .,:;()_-]{1,400}\Z", re.ASCII)


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
    if name not in REQUEST_REMOTE_NAMES:
        raise AnsibleActionFail("request collection remote basename is not allowlisted")
    return posixpath.join(output_dir, name)


def _access_is_private(stat_result: dict[str, object], *, directory: bool) -> bool:
    return (
        stat_result.get("rusr") is True
        and stat_result.get("wusr") is True
        and stat_result.get("xusr") is directory
        and stat_result.get("rgrp") is False
        and stat_result.get("wgrp") is False
        and stat_result.get("xgrp") is False
        and stat_result.get("roth") is False
        and stat_result.get("woth") is False
        and stat_result.get("xoth") is False
    )


def _directory_snapshot(stat_result: dict[str, object]) -> tuple[int, tuple[object, ...]]:
    owner_uid = stat_result.get("uid")
    if (
        stat_result.get("exists") is not True
        or stat_result.get("isdir") is not True
        or stat_result.get("islnk") is True
        or not isinstance(owner_uid, int)
        or isinstance(owner_uid, bool)
        or owner_uid < 0
        or stat_result.get("mode") != "0700"
        or not _access_is_private(stat_result, directory=True)
    ):
        raise AnsibleActionFail("action-owned remote collection directory metadata is unsafe")
    keys = ("dev", "inode", "uid", "gid", "mode")
    return owner_uid, tuple(stat_result.get(key) for key in keys)


def _file_snapshot(
    stat_result: dict[str, object], name: str, owner_uid: int
) -> tuple[object, ...]:
    size = stat_result.get("size")
    if (
        stat_result.get("exists") is not True
        or stat_result.get("isreg") is not True
        or stat_result.get("islnk") is True
        or stat_result.get("uid") != owner_uid
        or stat_result.get("mode") != "0600"
        or stat_result.get("nlink") != 1
        or not isinstance(size, int)
        or size <= 0
        or size > MAX_SIZES[name]
        or not isinstance(stat_result.get("checksum"), str)
        or not _access_is_private(stat_result, directory=False)
    ):
        raise AnsibleActionFail(f"remote public collection file metadata is unsafe: {name}")
    keys = ("dev", "inode", "uid", "gid", "mode", "nlink", "size", "mtime", "ctime", "checksum")
    return tuple(stat_result.get(key) for key in keys)


def _helper_failure_message(command: dict[str, object]) -> str:
    message = command.get("stderr")
    if isinstance(message, str):
        message = message.removeprefix("platform-pki-host-local-lifecycle: ")
        if _SAFE_HELPER_ERROR.fullmatch(message) is not None:
            return f"lifecycle helper request collection failed: {message}"
    return "lifecycle helper request collection failed"


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
            raise AnsibleActionFail("cannot inspect action-owned remote collection path")
        return result["stat"]

    def _collection_prepare(
        self,
        args: dict[str, object],
        task_vars: dict[str, object],
        output_dir: str,
        owner_uid: int,
        expected_status: str,
        expected_signature_sha256: str | None = None,
    ) -> dict[str, str]:
        argv = [
            args["lifecycle_helper_path"],
            "collection-prepare",
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
            "--output-dir",
            output_dir,
            "--output-owner-uid",
            str(owner_uid),
        ]
        command = self._execute_module(
            module_name="ansible.legacy.command",
            module_args={"argv": argv},
            task_vars=task_vars,
        )
        if command.get("failed") or command.get("rc") != 0:
            raise AnsibleActionFail(_helper_failure_message(command))
        stdout = command.get("stdout")
        if not isinstance(stdout, str) or not stdout or "\r" in stdout or "\x00" in stdout:
            raise AnsibleActionFail("lifecycle helper returned invalid collection metadata")
        encoded = stdout[:-1] if stdout.endswith("\n") else stdout
        if "\n" in encoded or not encoded:
            raise AnsibleActionFail("lifecycle helper returned invalid collection metadata")
        try:
            metadata = json.loads(encoded)
        except (TypeError, ValueError):
            raise AnsibleActionFail("lifecycle helper returned invalid collection metadata") from None
        if (
            not isinstance(metadata, dict)
            or set(metadata) != _HELPER_METADATA
            or any(not isinstance(value, str) for value in metadata.values())
            or json.dumps(metadata, sort_keys=True, separators=(",", ":")) != encoded
            or command.get("stderr") not in {None, ""}
        ):
            raise AnsibleActionFail("lifecycle helper returned invalid collection metadata")
        if (
            metadata["status"] != expected_status
            or metadata["request_id"] != args["request_id"]
            or metadata["request_sha256"] != args["expected_request_sha256"]
            or metadata["csr_sha256"] != args["expected_csr_sha256"]
        ):
            raise AnsibleActionFail("lifecycle helper collection metadata does not match expected request")
        require_digest(
            metadata["request_signature_sha256"],
            "lifecycle helper request signature digest",
        )
        if (
            expected_signature_sha256 is not None
            and metadata["request_signature_sha256"] != expected_signature_sha256
        ):
            raise AnsibleActionFail("lifecycle helper collection metadata changed after fetch")
        return metadata

    def run(self, tmp=None, task_vars=None):
        del tmp
        task_vars = task_vars or {}
        result = super().run(tmp=None, task_vars=task_vars)
        args = self._task.args
        if set(args) != ACTION_ARGUMENTS:
            raise AnsibleActionFail("request collection action requires its exact structured argument set")
        if self._task.check_mode:
            raise AnsibleActionFail("request collection is unavailable in check mode")

        parent = None
        fetched = None
        trust = {}
        fetch_stage = None
        remote_tmp = None
        remote_tmp_root = None
        try:
            request_id = require_request_id(args["request_id"])
            service = require_service(args["service"])
            target = require_principal(args["target"], "target")
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
            if args["transport"] not in {"ssh", "sftp"}:
                raise ExchangeError("transport must be exactly ssh or sftp")
            helper_path = _canonical_remote_path(
                args["lifecycle_helper_path"], "lifecycle_helper_path"
            )
            if posixpath.basename(helper_path) != "platform-pki-host-local-lifecycle":
                raise ExchangeError("lifecycle_helper_path has an unexpected basename")
            for name in ("state_root", "pending_root", "versions_root"):
                _canonical_remote_path(args[name], name)
            if not isinstance(args["trust_id"], str) or _TRUST_ID.fullmatch(args["trust_id"]) is None:
                raise ExchangeError("trust_id is not canonical")

            trust = pin_trust(args["trust_paths"], args["trust_sha256"])
            if set(trust) != set(TRUST_NAMES):
                raise ExchangeError("frozen trust set is incomplete")
            parent = prepare_request_parent(args["exchange_root"], service, request_id)

            remote_tmp_root = _canonical_remote_path(
                self._make_tmp_path().rstrip("/"),
                "action-owned remote temporary directory",
            )
            remote_tmp = _canonical_remote_path(
                posixpath.join(remote_tmp_root, "public-request"),
                "action-owned remote collection directory",
            )
            create_directory = self._execute_module(
                module_name="ansible.legacy.file",
                module_args={"path": remote_tmp, "state": "directory", "mode": "0700"},
                task_vars=task_vars,
            )
            if create_directory.get("failed"):
                raise AnsibleActionFail("cannot create action-owned remote collection directory")
            owner_uid, remote_directory = _directory_snapshot(
                self._stat(remote_tmp, task_vars, checksum=False)
            )
            first_helper = self._collection_prepare(
                args, task_vars, remote_tmp, owner_uid, "collected"
            )
            owner_after, directory_after = _directory_snapshot(
                self._stat(remote_tmp, task_vars, checksum=False)
            )
            if owner_after != owner_uid or directory_after != remote_directory:
                raise ExchangeError("action-owned remote collection directory changed")

            remote_before: dict[str, tuple[object, ...]] = {}
            expected = {
                "tls.csr": args["expected_csr_sha256"],
                "request": args["expected_request_sha256"],
                "request.sig": first_helper["request_signature_sha256"],
            }
            for name in REQUEST_REMOTE_NAMES:
                path = _remote_path(remote_tmp, name)
                snapshot = _file_snapshot(
                    self._stat(path, task_vars, checksum=True), name, owner_uid
                )
                if snapshot[-1] != expected[name]:
                    raise ExchangeError(f"remote {name} checksum differs from the exact expected pin")
                remote_before[name] = snapshot

            fetch_stage = f".platform-pki-collection.{secrets.token_hex(16)}"
            os.mkdir(fetch_stage, 0o700, dir_fd=parent.fileno())
            fetch_path = os.path.join(parent.path, fetch_stage)
            old_umask = os.umask(0o077)
            try:
                for name in REQUEST_REMOTE_NAMES:
                    local_path = os.path.join(fetch_path, name)
                    self._connection.fetch_file(_remote_path(remote_tmp, name), local_path)
                    descriptor = os.open(
                        local_path,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    )
                    try:
                        metadata = os.fstat(descriptor)
                        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1:
                            raise ExchangeError(f"fetched public request file metadata is unsafe: {name}")
                        os.fchmod(descriptor, 0o600)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    after = _file_snapshot(
                        self._stat(
                            _remote_path(remote_tmp, name), task_vars, checksum=True
                        ),
                        name,
                        owner_uid,
                    )
                    if after != remote_before[name]:
                        raise ExchangeError(f"remote public request file changed during collection: {name}")
            finally:
                os.umask(old_umask)

            fetched = PinnedTree.open(fetch_path, REQUEST_REMOTE_NAMES, "collected request stage")
            second_helper = self._collection_prepare(
                args,
                task_vars,
                remote_tmp,
                owner_uid,
                "existing",
                first_helper["request_signature_sha256"],
            )
            if any(
                second_helper[name] != first_helper[name]
                for name in _HELPER_METADATA.difference(("status",))
            ):
                raise ExchangeError("lifecycle helper collection metadata changed after fetch")
            owner_final, directory_final = _directory_snapshot(
                self._stat(remote_tmp, task_vars, checksum=False)
            )
            if owner_final != owner_uid or directory_final != remote_directory:
                raise ExchangeError("action-owned remote collection directory changed after fetch")
            for name in REQUEST_REMOTE_NAMES:
                if sha256(fetched.data[name]) != remote_before[name][-1]:
                    raise ExchangeError(f"fetched public request checksum mismatch: {name}")
                if (
                    _file_snapshot(
                        self._stat(
                            _remote_path(remote_tmp, name), task_vars, checksum=True
                        ),
                        name,
                        owner_uid,
                    )
                    != remote_before[name]
                ):
                    raise ExchangeError(f"remote public request file changed after helper revalidation: {name}")
            now = int(time.time())
            request = validate_request_payload(
                fetched.data, args, trust, fetched.files["request.sig"], now=now
            )

            trust_publication = {
                name: trust[name].data for name in TRUST_NAMES
            }
            for source in trust.values():
                source.recheck()

            def recheck_trust() -> None:
                for source in trust.values():
                    source.recheck()

            trust_changed = publish_exact_tree(
                parent,
                "trust",
                trust_publication,
                pre_publish=recheck_trust,
            )
            for source in trust.values():
                source.recheck()

            destination = os.path.join(parent.path, "request")
            if os.path.lexists(destination):
                existing = PinnedTree.open(destination, REQUEST_PUBLICATION_NAMES, "published request")
                try:
                    if any(existing.data[name] != fetched.data[name] for name in REQUEST_REMOTE_NAMES):
                        raise ExchangeError("published request conflicts with collected public bytes")
                    existing_request = validate_request_payload(
                        {name: existing.data[name] for name in REQUEST_REMOTE_NAMES},
                        args,
                        trust,
                        existing.files["request.sig"],
                        now=now,
                    )
                    validate_collection_receipt(
                        existing.data["collection-receipt"],
                        {name: existing.data[name] for name in REQUEST_REMOTE_NAMES},
                        args,
                        trust,
                        existing_request,
                        now=now,
                    )
                finally:
                    existing.close()
                request_changed = False
            else:
                publication = fetched.data
                publication["collection-receipt"] = collection_receipt(
                    publication, args, trust, now
                )

                def recheck() -> None:
                    fetched.recheck()
                    for source in trust.values():
                        source.recheck()
                    for name, snapshot in remote_before.items():
                        if (
                            _file_snapshot(
                                self._stat(
                                    _remote_path(remote_tmp, name),
                                    task_vars,
                                    checksum=True,
                                ),
                                name,
                                owner_uid,
                            )
                            != snapshot
                        ):
                            raise ExchangeError(f"remote public request file changed at publication: {name}")
                    final_owner, final_directory = _directory_snapshot(
                        self._stat(remote_tmp, task_vars, checksum=False)
                    )
                    if final_owner != owner_uid or final_directory != remote_directory:
                        raise ExchangeError("action-owned remote collection directory changed at publication")

                request_changed = publish_exact_tree(
                    parent, "request", publication, pre_publish=recheck
                )

            for source in trust.values():
                source.recheck()
            changed = trust_changed or request_changed
            status = "collected" if changed else "existing"

            result.update(
                changed=changed,
                status=status,
                request_id=request_id,
                request_dir=destination,
                trust_dir=os.path.join(parent.path, "trust"),
                request_sha256=args["expected_request_sha256"],
                csr_sha256=args["expected_csr_sha256"],
                csr_spki_sha256=args["expected_csr_spki_sha256"],
            )
            return result
        except ExchangeError as error:
            raise AnsibleActionFail(str(error)) from None
        except OSError:
            raise AnsibleActionFail("request collection filesystem operation failed") from None
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
                        for name in REQUEST_REMOTE_NAMES:
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
            if parent is not None:
                parent.close()
            for source in trust.values():
                source.close()
