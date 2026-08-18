"""Authenticate and import one exact host-local signer-outcome package."""

from __future__ import annotations

import json
import os
import posixpath
import re
import secrets
import shlex
import stat
import time

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

try:
    from ansible.module_utils.platform_pki_exchange import (
        EVIDENCE_NAMES,
        DescriptorCleanupError,
        DECISION_FIELDS,
        ExchangeError,
        MAX_SIZES,
        OUTCOME_NAMES,
        OUTCOME_FIELDS,
        PinnedDirectory,
        PinnedTree,
        REQUEST_PUBLICATION_NAMES,
        RESPONSE_NAMES,
        TRUST_NAMES,
        require_digest,
        require_principal,
        require_request_id,
        require_service,
        parse_record,
        sha256,
        validate_outcome_snapshot,
    )
except ImportError:  # Direct pytest imports do not use Ansible's plugin loader.
    from plugins.module_utils.platform_pki_exchange import (
        EVIDENCE_NAMES,
        DescriptorCleanupError,
        DECISION_FIELDS,
        ExchangeError,
        MAX_SIZES,
        OUTCOME_NAMES,
        OUTCOME_FIELDS,
        PinnedDirectory,
        PinnedTree,
        REQUEST_PUBLICATION_NAMES,
        RESPONSE_NAMES,
        TRUST_NAMES,
        require_digest,
        require_principal,
        require_request_id,
        require_service,
        parse_record,
        sha256,
        validate_outcome_snapshot,
    )


ACTION_ARGUMENTS = frozenset(
    (
        "lifecycle_helper_path",
        "state_root",
        "pending_root",
        "versions_root",
        "zot_config_path",
        "trust_id",
        "exchange_root",
        "outcome_dir",
        "service",
        "target",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
        "outcome_sha256",
        "response_principal",
    )
)
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9_@%+=:,.-]+\Z", re.ASCII)
_TRUST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
_SSH_CONNECTION_CLOSED = re.compile(
    r"Shared connection to [A-Za-z0-9.:%_-]+ closed\.\Z", re.ASCII
)
_REMOTE_STAGE_ROOT = "/var/tmp"
_RESULT_FIELDS = frozenset(
    (
        "status",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
        "outcome_sha256",
        "action",
        "result",
        "state",
        "resulting_active_request_id",
        "history_path",
    )
)


def _remote_path(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not posixpath.isabs(value)
        or value == "/"
        or posixpath.normpath(value) != value
        or any(_PATH_COMPONENT.fullmatch(part) is None for part in value.split("/")[1:])
    ):
        raise ExchangeError(f"{label} must be an absolute canonical non-root path")
    return value


def _safe_low_level_stderr(value: object) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    return not stripped or _SSH_CONNECTION_CLOSED.fullmatch(stripped) is not None


def _private(metadata: dict[str, object], *, directory: bool) -> bool:
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


def _shell_command(argv: list[str]) -> str:
    if not argv or any(not isinstance(value, str) or not value for value in argv):
        raise ExchangeError("target preflight command contains an invalid argument")
    return " ".join(shlex.quote(value) for value in argv)


def _directory_identity(metadata: dict[str, object]) -> tuple[object, ...]:
    identity = _cleanup_directory_identity(metadata)
    if (
        metadata.get("mode") != "0700"
        or not _private(metadata, directory=True)
    ):
        raise ExchangeError("remote signer-outcome stage has unsafe metadata")
    return identity


def _cleanup_directory_identity(metadata: dict[str, object]) -> tuple[object, ...]:
    dev = metadata.get("dev")
    inode = metadata.get("inode")
    if (
        metadata.get("exists") is not True
        or metadata.get("isdir") is not True
        or metadata.get("islnk") is True
        or metadata.get("uid") != 0
        or metadata.get("gid") != 0
        or not isinstance(dev, int)
        or isinstance(dev, bool)
        or not isinstance(inode, int)
        or isinstance(inode, bool)
    ):
        raise ExchangeError("remote signer-outcome stage identity is unsafe")
    return tuple(metadata.get(name) for name in ("dev", "inode", "uid", "gid", "mode"))


def _file_identity(
    metadata: dict[str, object], name: str, expected_sha256: str
) -> tuple[object, ...]:
    identity = _cleanup_file_identity(metadata, name)
    size = metadata.get("size")
    if (
        metadata.get("mode") != "0600"
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > MAX_SIZES[name]
        or metadata.get("checksum") != expected_sha256
        or not _private(metadata, directory=False)
    ):
        raise ExchangeError(f"remote signer-outcome stage file is unsafe: {name}")
    return identity


def _cleanup_file_identity(
    metadata: dict[str, object], name: str
) -> tuple[object, ...]:
    dev = metadata.get("dev")
    inode = metadata.get("inode")
    size = metadata.get("size")
    checksum = metadata.get("checksum")
    if (
        metadata.get("exists") is not True
        or metadata.get("isreg") is not True
        or metadata.get("islnk") is True
        or metadata.get("uid") != 0
        or metadata.get("gid") != 0
        or metadata.get("nlink") != 1
        or not isinstance(dev, int)
        or isinstance(dev, bool)
        or not isinstance(inode, int)
        or isinstance(inode, bool)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or not isinstance(checksum, str)
        or re.fullmatch(r"[0-9a-f]{64}", checksum, re.ASCII) is None
    ):
        raise ExchangeError(
            f"remote signer-outcome stage file identity is unsafe: {name}"
        )
    return tuple(
        metadata.get(field)
        for field in (
            "dev",
            "inode",
            "uid",
            "gid",
            "mode",
            "nlink",
            "size",
            "mtime",
            "ctime",
            "checksum",
        )
    )


class ActionModule(ActionBase):
    # Normal mode allocates its transfer workspace explicitly after check-mode
    # preflight has branched away from all remote staging.
    TRANSFERS_FILES = False

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
            raise AnsibleActionFail("cannot inspect remote signer-outcome stage")
        return result["stat"]

    def _remove_stage(
        self,
        stage: str,
        directory_identity: tuple[object, ...],
        files: dict[str, tuple[object, ...]],
        task_vars: dict[str, object],
    ) -> None:
        failures: list[str] = []
        try:
            current_directory = _cleanup_directory_identity(
                self._stat(stage, task_vars, checksum=False)
            )
        except Exception:
            raise AnsibleActionFail(
                "protected remote stage retained because its identity is unsafe"
            ) from None
        if current_directory != directory_identity:
            raise AnsibleActionFail(
                "protected remote stage retained because its identity changed"
            )
        for name in OUTCOME_NAMES:
            try:
                metadata = self._stat(
                    posixpath.join(stage, name), task_vars, checksum=True
                )
            except Exception:
                failures.append(f"cannot inspect allowlisted file {name}")
                continue
            path = posixpath.join(stage, name)
            if metadata.get("exists") is False:
                continue
            try:
                identity = _cleanup_file_identity(metadata, name)
            except ExchangeError:
                failures.append(f"unsafe allowlisted file {name}")
                continue
            if name in files and identity != files[name]:
                failures.append(f"changed allowlisted file {name}")
                continue
            try:
                removed = self._execute_module(
                    module_name="ansible.legacy.file",
                    module_args={"path": path, "state": "absent"},
                    task_vars=task_vars,
                )
                absent = self._stat(path, task_vars, checksum=False).get("exists") is False
            except Exception:
                failures.append(f"cannot verify removal of allowlisted file {name}")
                continue
            if removed.get("failed") or not absent:
                failures.append(f"cannot remove allowlisted file {name}")
        try:
            current_directory = _cleanup_directory_identity(
                self._stat(stage, task_vars, checksum=False)
            )
        except Exception:
            failures.append("cannot reinspect protected directory")
            current_directory = None
        if current_directory is not None and current_directory != directory_identity:
            failures.append("protected directory identity changed")
            current_directory = None
        if current_directory is not None:
            try:
                removed = self._execute_module(
                    module_name="ansible.legacy.command",
                    module_args={"argv": ["rmdir", "--", stage]},
                    task_vars=task_vars,
                )
                absent = self._stat(stage, task_vars, checksum=False).get("exists") is False
            except Exception:
                failures.append("cannot verify protected directory removal")
            else:
                if removed.get("failed") or not absent:
                    failures.append("cannot remove protected directory")
        if failures:
            raise AnsibleActionFail(
                "protected remote stage retained or incompletely cleaned: "
                + "; ".join(dict.fromkeys(failures))
            )

    def run(self, tmp=None, task_vars=None):
        del tmp
        task_vars = task_vars or {}
        result = super().run(tmp=None, task_vars=task_vars)
        args = self._task.args
        check_mode = self._task.check_mode
        if set(args) != ACTION_ARGUMENTS:
            raise AnsibleActionFail(
                "signer-outcome import action requires its exact structured argument set"
            )

        parent = request = response = trust = evidence = package = None
        remote_tmp = stage = None
        stage_identity: tuple[object, ...] | None = None
        stage_cleanup_required = False
        remote_files: dict[str, tuple[object, ...]] = {}
        digests: dict[str, str] = {}
        action_result: dict[str, object] | None = None
        primary_failure: Exception | None = None
        constructor_cleanups: list[tuple[str, DescriptorCleanupError]] = []
        opening_label = "package"
        try:
            service = require_service(args["service"])
            target = require_principal(args["target"], "target")
            request_id = require_request_id(args["request_id"])
            artifact_sha = require_digest(args["artifact_sha256"], "artifact_sha256")
            deployment_sha = require_digest(
                args["deployment_sha256"], "deployment_sha256"
            )
            outcome_sha = require_digest(args["outcome_sha256"], "outcome_sha256")
            require_principal(args["response_principal"], "response_principal")
            helper = _remote_path(args["lifecycle_helper_path"], "lifecycle_helper_path")
            if posixpath.basename(helper) != "platform-pki-host-local-lifecycle":
                raise ExchangeError("lifecycle_helper_path has an unexpected basename")
            for name in (
                "state_root", "pending_root", "versions_root", "zot_config_path"
            ):
                _remote_path(args[name], name)
            if not isinstance(args["trust_id"], str) or _TRUST_ID.fullmatch(args["trust_id"]) is None:
                raise ExchangeError("trust_id is not canonical")

            package = PinnedTree.open(
                args["outcome_dir"], OUTCOME_NAMES, "reviewed signer-outcome package"
            )
            opening_label = "request parent"
            parent = PinnedDirectory.open(
                os.path.join(args["exchange_root"], service, request_id),
                "exchange request parent",
            )
            opening_label = "request"
            request = PinnedTree.open(
                os.path.join(parent.path, "request"),
                REQUEST_PUBLICATION_NAMES,
                "controller request publication",
            )
            opening_label = "response"
            response = PinnedTree.open(
                os.path.join(parent.path, "response"),
                RESPONSE_NAMES,
                "controller response publication",
            )
            opening_label = "trust"
            trust = PinnedTree.open(
                os.path.join(parent.path, "trust"),
                TRUST_NAMES,
                "controller frozen trust",
            )
            opening_label = "evidence"
            evidence = PinnedTree.open(
                os.path.join(parent.path, "evidence", deployment_sha),
                EVIDENCE_NAMES,
                "controller evidence publication",
            )
            metadata = validate_outcome_snapshot(
                package,
                evidence,
                request,
                response,
                trust,
                args,
                now=int(time.time()),
            )
            reviewed_decision = parse_record(
                package.files["decision"].data,
                DECISION_FIELDS,
                "reviewed signer decision",
            )
            reviewed_outcome = parse_record(
                package.files["outcome"].data,
                OUTCOME_FIELDS,
                "reviewed signer outcome",
            )
            for tree in (package, parent, request, response, trust, evidence):
                tree.recheck()
            common_argv = [
                "--state-root", args["state_root"],
                "--pending-root", args["pending_root"],
                "--versions-root", args["versions_root"],
                "--zot-config", args["zot_config_path"],
                "--service", service,
                "--target", target,
                "--trust-id", args["trust_id"],
                "--request-id", request_id,
                "--artifact-sha256", artifact_sha,
                "--deployment-sha256", deployment_sha,
                "--outcome-sha256", outcome_sha,
            ]
            if check_mode:
                argv = [
                    helper, "outcome-preflight", *common_argv,
                    "--decision-sha256", sha256(package.files["decision"].data),
                    "--outcome-principal", reviewed_outcome["outcome_principal"],
                ]
                for field in DECISION_FIELDS:
                    if field != "schema":
                        argv.extend((
                            f"--decision-{field.replace('_', '-')}",
                            reviewed_decision[field],
                        ))
            else:
                digests = {
                    name: sha256(package.files[name].data) for name in OUTCOME_NAMES
                }
                stage = posixpath.join(
                    _REMOTE_STAGE_ROOT,
                    f".platform-pki-outcome-{secrets.token_hex(16)}",
                )
                if self._stat(stage, task_vars, checksum=False).get("exists") is not False:
                    raise AnsibleActionFail("remote signer-outcome stage name collided")
                stage_cleanup_required = True
                created = self._execute_module(
                    module_name="ansible.legacy.file",
                    module_args={
                        "path": stage, "state": "directory", "owner": "root",
                        "group": "root", "mode": "0700",
                    },
                    task_vars=task_vars,
                )
                stage_metadata = self._stat(stage, task_vars, checksum=False)
                if stage_metadata.get("exists") is False:
                    stage_cleanup_required = False
                else:
                    stage_identity = _cleanup_directory_identity(stage_metadata)
                if created.get("failed"):
                    raise AnsibleActionFail("cannot create remote signer-outcome stage")
                if created.get("changed") is not True:
                    raise AnsibleActionFail(
                        "remote signer-outcome stage was not newly created"
                    )
                _directory_identity(stage_metadata)
                remote_tmp = self._make_tmp_path()
                for name in OUTCOME_NAMES:
                    package.recheck()
                    package.files[name].recheck()
                    transfer = self._connection._shell.join_path(
                        remote_tmp, f".platform-pki-outcome-{name}"
                    )
                    self._transfer_data(transfer, package.files[name].data)
                    package.files[name].recheck()
                    package.recheck()
                    copied = self._execute_module(
                        module_name="ansible.legacy.copy",
                        module_args={
                            "src": transfer, "dest": posixpath.join(stage, name),
                            "remote_src": True, "owner": "root", "group": "root",
                            "mode": "0600", "force": False, "follow": False,
                        },
                        task_vars=task_vars,
                    )
                    if copied.get("failed"):
                        raise AnsibleActionFail(
                            f"cannot stage signer-outcome package file: {name}"
                        )
                    remote_files[name] = _file_identity(
                        self._stat(
                            posixpath.join(stage, name), task_vars, checksum=True
                        ),
                        name,
                        digests[name],
                    )
                package.recheck()
                if (
                    _directory_identity(
                        self._stat(stage, task_vars, checksum=False)
                    ) != stage_identity
                ):
                    raise ExchangeError(
                        "remote signer-outcome stage changed before import"
                    )
                argv = [
                    helper, "outcome-import", *common_argv,
                    "--outcome-dir", stage,
                ]
            if check_mode:
                imported = self._low_level_execute_command(
                    _shell_command(argv),
                    sudoable=True,
                )
                if (
                    set(imported)
                    != {"rc", "stdout", "stdout_lines", "stderr", "stderr_lines"}
                    or not isinstance(imported["rc"], int)
                    or isinstance(imported["rc"], bool)
                    or not isinstance(imported["stdout"], str)
                    or not isinstance(imported["stderr"], str)
                    or imported["stdout_lines"] != imported["stdout"].splitlines()
                    or imported["stderr_lines"] != imported["stderr"].splitlines()
                ):
                    raise AnsibleActionFail(
                        "target signer-outcome preflight returned an invalid execution result"
                    )
            else:
                imported = self._execute_module(
                    module_name="ansible.legacy.command",
                    module_args={"argv": argv},
                    task_vars=task_vars,
                )
            if imported.get("failed") or imported.get("rc") != 0:
                raise AnsibleActionFail("target signer-outcome import failed")
            stdout = imported.get("stdout")
            if isinstance(stdout, str) and stdout.endswith("\r\n"):
                encoded = stdout[:-2]
            elif isinstance(stdout, str) and stdout.endswith("\n"):
                encoded = stdout[:-1]
            else:
                encoded = stdout
            try:
                target_metadata = json.loads(encoded)
            except (TypeError, ValueError):
                raise AnsibleActionFail(
                    "target signer-outcome import returned invalid metadata"
                ) from None
            expected_metadata = {
                "request_id": request_id,
                "artifact_sha256": artifact_sha,
                "deployment_sha256": deployment_sha,
                "outcome_sha256": outcome_sha,
                "action": metadata["action"],
                "result": metadata["result"],
                "state": metadata["state"],
                "resulting_active_request_id": metadata[
                    "resulting_active_request_id"
                ],
            }
            mismatch_fields = sorted(
                name
                for name, expected in expected_metadata.items()
                if not isinstance(target_metadata, dict)
                or target_metadata.get(name) != expected
            )
            if (
                isinstance(target_metadata, dict)
                and target_metadata.get("status")
                not in (
                    {"would-import", "existing"}
                    if check_mode
                    else {"imported", "existing"}
                )
            ):
                mismatch_fields.append("status")
            structural_mismatches = []
            if not isinstance(encoded, str):
                structural_mismatches.append("stdout-type")
            if not isinstance(target_metadata, dict):
                structural_mismatches.append("metadata-type")
            else:
                actual_fields = set(target_metadata)
                if actual_fields != _RESULT_FIELDS:
                    structural_mismatches.extend(
                        f"missing-{name}"
                        for name in sorted(_RESULT_FIELDS - actual_fields)
                    )
                    structural_mismatches.extend(
                        f"extra-{name}"
                        for name in sorted(actual_fields - _RESULT_FIELDS)
                    )
                if any(
                    not isinstance(value, str)
                    for value in target_metadata.values()
                ):
                    structural_mismatches.append("value-type")
                if (
                    isinstance(encoded, str)
                    and json.dumps(
                        target_metadata, sort_keys=True, separators=(",", ":")
                    ) != encoded
                ):
                    structural_mismatches.append("canonical-encoding")
            stderr = imported.get("stderr")
            if stderr is not None and not _safe_low_level_stderr(stderr):
                structural_mismatches.append("stderr")
            if (
                not isinstance(encoded, str)
                or not isinstance(target_metadata, dict)
                or set(target_metadata) != _RESULT_FIELDS
                or any(not isinstance(value, str) for value in target_metadata.values())
                or json.dumps(target_metadata, sort_keys=True, separators=(",", ":")) != encoded
                or (stderr is not None and not _safe_low_level_stderr(stderr))
                or target_metadata["request_id"] != request_id
                or target_metadata["artifact_sha256"] != artifact_sha
                or target_metadata["deployment_sha256"] != deployment_sha
                or target_metadata["outcome_sha256"] != outcome_sha
                or target_metadata["action"] != metadata["action"]
                or target_metadata["result"] != metadata["result"]
                or target_metadata["state"] != metadata["state"]
                or target_metadata["resulting_active_request_id"]
                != metadata["resulting_active_request_id"]
                or target_metadata["status"]
                not in ({"would-import", "existing"} if check_mode else {"imported", "existing"})
            ):
                raise AnsibleActionFail(
                    "target signer-outcome import metadata differs from reviewed package"
                    + (
                        f" in fields: {','.join(mismatch_fields)}"
                        if mismatch_fields
                        else " structurally: "
                        + ",".join(structural_mismatches)
                    )
                )
            result.update(
                changed=target_metadata["status"] in {"would-import", "imported"},
                **target_metadata,
            )
            action_result = result
        except DescriptorCleanupError as error:
            constructor_cleanups.append((opening_label, error))
            cause = error.__cause__
            primary_failure = AnsibleActionFail(
                str(cause)
                if isinstance(cause, ExchangeError)
                else "controller protected source construction failed"
            )
        except ExchangeError as error:
            primary_failure = AnsibleActionFail(str(error))
        except AnsibleActionFail as error:
            primary_failure = error
        except OSError:
            primary_failure = AnsibleActionFail(
                "signer-outcome import filesystem operation failed"
            )
        except Exception:  # Cleanup must also run for unexpected plugin failures.
            primary_failure = AnsibleActionFail(
                "unexpected signer-outcome import failure"
            )

        cleanup_failures: list[str] = []
        if remote_tmp is not None:
            try:
                self._remove_tmp_path(remote_tmp)
            except Exception:
                cleanup_failures.append("temporary Ansible workspace cleanup failed")
        if stage is not None and stage_cleanup_required:
            if stage_identity is None:
                cleanup_failures.append(
                    f"protected remote stage retained at {stage}: safe identity unavailable"
                )
            else:
                try:
                    self._remove_stage(
                        stage, stage_identity, remote_files, task_vars
                    )
                except Exception as error:
                    detail = (
                        str(error)
                        if isinstance(error, (AnsibleActionFail, ExchangeError))
                        else "protected cleanup operation failed"
                    )
                    cleanup_failures.append(
                        f"protected remote stage cleanup failed at {stage}: {detail}"
                    )
        descriptor_retries: list[tuple[str, PinnedDirectory | PinnedTree]] = []
        for label, tree in (
            ("evidence", evidence),
            ("trust", trust),
            ("response", response),
            ("request", request),
            ("request parent", parent),
            ("package", package),
        ):
            if tree is None:
                continue
            try:
                tree.close()
            except Exception:
                cleanup_failures.append(f"controller {label} descriptor closure failed")
                descriptor_retries.append((label, tree))
        for label, tree in descriptor_retries:
            try:
                tree.close()
            except Exception:
                cleanup_failures.append(
                    f"controller {label} descriptor closure retry failed"
                )
        for label, cleanup_error in constructor_cleanups:
            try:
                cleanup_error.retry_close()
            except Exception:
                cleanup_failures.append(
                    f"controller {label} construction descriptor closure retry failed"
                )
            cleanup_failures.append(
                f"controller {label} construction descriptor closure failed"
            )

        if cleanup_failures:
            cleanup_message = "; ".join(cleanup_failures)
            if primary_failure is not None:
                raise AnsibleActionFail(
                    f"{primary_failure}; cleanup failures: {cleanup_message}"
                ) from None
            raise AnsibleActionFail(f"signer-outcome import cleanup failed: {cleanup_message}")
        if primary_failure is not None:
            raise primary_failure
        if action_result is None:
            raise AnsibleActionFail("signer-outcome import produced no result")
        return action_result
