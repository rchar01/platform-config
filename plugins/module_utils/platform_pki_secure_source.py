"""Descriptor-pinned controller sources for public security inputs."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass

from ansible.errors import AnsibleActionFail


REPOSITORY_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))


class SourcePinError(AnsibleActionFail):
    """A controller source failed its fixed descriptor-pinning contract."""


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


def require_safe_ancestor(
    metadata: os.stat_result, path: str, owners: set[int], label: str
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in owners:
        raise SourcePinError(f"{label} ancestor has an unsafe owner: {path}")
    if mode & 0o022 and not mode & stat.S_ISVTX:
        raise SourcePinError(f"{label} ancestor is unsafely writable: {path}")


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
    label: str

    def recheck(self) -> None:
        for index, component in enumerate(self.components[:-1]):
            actual = os.stat(
                component, dir_fd=self.descriptors[index], follow_symlinks=False
            )
            if not stat.S_ISDIR(actual.st_mode) or identity(actual) != identity(
                os.fstat(self.descriptors[index + 1])
            ):
                raise SourcePinError(
                    f"{self.label} ancestor changed during transfer: {self.path}"
                )
        actual = os.stat(
            self.components[-1],
            dir_fd=self.descriptors[-1],
            follow_symlinks=False,
        )
        if identity(actual) != self.file_identity or identity(
            os.fstat(self.file_descriptor)
        ) != self.file_identity:
            raise SourcePinError(f"{self.label} changed during transfer: {self.path}")

    def close(self) -> None:
        os.close(self.file_descriptor)
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)
        self.descriptors.clear()


def pin_controller_source(
    path: object,
    expected_digest: str,
    *,
    maximum: int = 65536,
    label: str = "reviewed trust source",
) -> PinnedSource:
    if (
        not isinstance(expected_digest, str)
        or len(expected_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_digest)
    ):
        raise SourcePinError(f"{label} digest is not canonical SHA-256")
    if (
        not isinstance(path, str)
        or not os.path.isabs(path)
        or path == "/"
        or os.path.normpath(path) != path
    ):
        raise SourcePinError(f"{label} paths must be absolute and canonical")
    try:
        if os.path.commonpath((REPOSITORY_ROOT, path)) == REPOSITORY_ROOT:
            raise SourcePinError(f"{label} must be outside the public repository: {path}")
    except ValueError as exc:
        raise SourcePinError(f"cannot compare {label} path: {path}") from exc

    components = path.split("/")[1:]
    descriptors = [
        os.open(
            "/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
        )
    ]
    safe_ancestor_owners = trusted_ancestor_owners()
    file_descriptor = -1
    try:
        require_safe_ancestor(
            os.fstat(descriptors[0]), path, safe_ancestor_owners, label
        )
        for component in components[:-1]:
            parent = descriptors[-1]
            descriptor = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent,
            )
            metadata = os.fstat(descriptor)
            require_safe_ancestor(metadata, path, safe_ancestor_owners, label)
            descriptors.append(descriptor)
        file_descriptor = os.open(
            components[-1],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NOATIME", 0),
            dir_fd=descriptors[-1],
        )
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise SourcePinError(f"{label} metadata is unsafe: {path}")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(
                file_descriptor, min(65536, maximum + 1 - len(data))
            )
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(file_descriptor)
        snapshot = identity(before)
        if identity(after) != snapshot or len(data) != before.st_size:
            raise SourcePinError(f"{label} changed while being read: {path}")
        pinned_data = bytes(data)
        if hashlib.sha256(pinned_data).hexdigest() != expected_digest:
            raise SourcePinError(f"{label} digest mismatch: {path}")
        pinned = PinnedSource(
            path,
            descriptors,
            components,
            file_descriptor,
            snapshot,
            pinned_data,
            label,
        )
        pinned.recheck()
        return pinned
    except Exception:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise
