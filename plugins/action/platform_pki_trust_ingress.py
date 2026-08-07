"""Transfer reviewed trust bytes from pinned controller descriptors."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase


TRUST_NAMES = (
    "approvers.allowed_signers",
    "deployers.allowed_signers",
    "policy",
    "requesters.allowed_signers",
    "responses.allowed_signers",
)
MAX_TRUST_SIZE = 65536
REPOSITORY_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))


def trusted_ancestor_owners() -> set[int]:
    owners = {0, os.geteuid()}
    try:
        with open("/proc/self/uid_map", encoding="ascii") as stream:
            uid_map = [line.split() for line in stream if line.strip()]
        if uid_map != [["0", "0", "4294967295"]]:
            with open("/proc/sys/kernel/overflowuid", encoding="ascii") as stream:
                owners.add(int(stream.read().strip()))
    except (OSError, ValueError):
        pass
    return owners


def require_safe_ancestor(metadata: os.stat_result, path: str, owners: set[int]) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid not in owners:
        raise AnsibleActionFail(f"reviewed trust source ancestor has an unsafe owner: {path}")
    if mode & 0o022 and not mode & stat.S_ISVTX:
        raise AnsibleActionFail(f"reviewed trust source ancestor is unsafely writable: {path}")


def identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@dataclass
class PinnedSource:
    path: str
    descriptors: list[int]
    components: list[str]
    file_descriptor: int
    file_identity: tuple[int, ...]
    data: bytes

    def recheck(self) -> None:
        for index, component in enumerate(self.components[:-1]):
            actual = os.stat(component, dir_fd=self.descriptors[index], follow_symlinks=False)
            if not stat.S_ISDIR(actual.st_mode) or identity(actual) != identity(os.fstat(self.descriptors[index + 1])):
                raise AnsibleActionFail(f"reviewed trust source ancestor changed during transfer: {self.path}")
        actual = os.stat(self.components[-1], dir_fd=self.descriptors[-1], follow_symlinks=False)
        if identity(actual) != self.file_identity or identity(os.fstat(self.file_descriptor)) != self.file_identity:
            raise AnsibleActionFail(f"reviewed trust source changed during transfer: {self.path}")

    def close(self) -> None:
        os.close(self.file_descriptor)
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)


def pin_source(path: str, expected_digest: str) -> PinnedSource:
    if not isinstance(path, str) or not os.path.isabs(path) or path == "/" or os.path.normpath(path) != path:
        raise AnsibleActionFail("reviewed trust source paths must be absolute and canonical")
    try:
        if os.path.commonpath((REPOSITORY_ROOT, path)) == REPOSITORY_ROOT:
            raise AnsibleActionFail(f"reviewed trust source must be outside the public repository: {path}")
    except ValueError as exc:
        raise AnsibleActionFail(f"cannot compare reviewed trust source path: {path}") from exc

    components = path.split("/")[1:]
    descriptors = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))]
    safe_ancestor_owners = trusted_ancestor_owners()
    file_descriptor = -1
    try:
        require_safe_ancestor(os.fstat(descriptors[0]), path, safe_ancestor_owners)
        for component in components[:-1]:
            parent = descriptors[-1]
            descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent,
            )
            metadata = os.fstat(descriptor)
            require_safe_ancestor(metadata, path, safe_ancestor_owners)
            descriptors.append(descriptor)
        file_descriptor = os.open(
            components[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NOATIME", 0),
            dir_fd=descriptors[-1],
        )
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > MAX_TRUST_SIZE
        ):
            raise AnsibleActionFail(f"reviewed trust source metadata is unsafe: {path}")
        data = b""
        while len(data) <= MAX_TRUST_SIZE:
            chunk = os.read(file_descriptor, min(65536, MAX_TRUST_SIZE + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        after = os.fstat(file_descriptor)
        snapshot = identity(before)
        if identity(after) != snapshot or len(data) != before.st_size:
            raise AnsibleActionFail(f"reviewed trust source changed while being read: {path}")
        if hashlib.sha256(data).hexdigest() != expected_digest:
            raise AnsibleActionFail(f"reviewed trust source digest mismatch: {path}")
        pinned = PinnedSource(path, descriptors, components, file_descriptor, snapshot, data)
        pinned.recheck()
        return pinned
    except Exception:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


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
            raise AnsibleActionFail("trust ingress action requires the exact five-key source mapping")
        if not isinstance(digests, dict) or set(digests) != set(TRUST_NAMES):
            raise AnsibleActionFail("trust ingress action requires the exact five-key digest mapping")
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
            if remote_tmp is not None:
                self._remove_tmp_path(remote_tmp)
            for source in pinned.values():
                source.close()
