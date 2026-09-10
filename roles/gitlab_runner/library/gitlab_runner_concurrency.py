#!/usr/bin/python
"""Change only the canonical root concurrent integer in a Runner-owned TOML file."""

import os
import re
import stat
import tempfile
import time
import tomllib

from ansible.module_utils.basic import AnsibleModule


def candidate_config(content, desired):
    original = tomllib.loads(content.decode("utf-8"))
    current = original.get("concurrent")
    if type(current) is not int or current <= 0:
        raise ValueError("Invalid root concurrency")
    # Runner writes global values before tables. Reject ambiguous/unsupported
    # spellings rather than attempting a general TOML source transformation.
    header = re.search(rb"(?m)^[ \t]*\[", content)
    root = content[:header.start()] if header else content
    matches = list(re.finditer(
        rb"(?m)^[ \t]*concurrent[ \t]*=[ \t]*([1-9][0-9]*)[ \t]*(?:#[^\r\n]*)?\r?$",
        root,
    ))
    if len(matches) != 1:
        raise ValueError("Expected one canonical root assignment")
    start, end = matches[0].span(1)
    # A line inside a multiline string is not a root assignment, even if its
    # integer happens to equal the real (possibly quoted-key) root value.
    if tomllib.loads(content[:end].decode("utf-8")).get("concurrent") != current:
        raise ValueError("Not a root assignment")
    candidate = content[:start] + str(desired).encode("ascii") + content[end:]
    if tomllib.loads(candidate.decode("utf-8")) != dict(original, concurrent=desired):
        raise ValueError("Candidate changes other TOML values")
    return current, candidate


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def main():
    module = AnsibleModule(
        argument_spec={"path": {"type": "path", "required": True},
                       "concurrent": {"type": "raw", "required": True}},
        supports_check_mode=True,
    )
    desired = module.params["concurrent"]
    if type(desired) is not int or desired <= 0:
        module.fail_json(msg="concurrent must be a positive integer, not a boolean or string")
    path = module.params["path"]
    temporary = None
    try:
        # Root-only Linux read without following a symlink or changing atime,
        # including in check mode. NONBLOCK avoids hanging on an invalid FIFO.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1):
                raise ValueError("Unsafe configuration file")
            content = source.read()
            current, candidate = candidate_config(content, desired)
            if identity(os.fstat(source.fileno())) != identity(before):
                raise ValueError("Configuration changed during read")
        changed = current != desired
        if changed and not module.check_mode:
            fd, temporary = tempfile.mkstemp(prefix=".config.toml.concurrent-", dir=os.path.dirname(path))
            with os.fdopen(fd, "wb") as target:
                target.write(candidate)
                target.flush()
                os.fsync(target.fileno())
            # Runner's native reload is mtime-based. Never preserve the old mtime,
            # including when it is ahead of the target's current clock.
            stamp = max(time.time_ns(), before.st_mtime_ns + 1)
            os.utime(temporary, ns=(stamp, stamp))
        # Detect token rotation/replacement since the read; this is not a lock
        # against concurrent lifecycle operations, which must remain serialized.
        if identity(os.lstat(path)) != identity(before):
            raise ValueError("Configuration changed before publication")
        if temporary is not None:
            module.atomic_move(temporary, path)
    except (OSError, ValueError, UnicodeError):
        # TOML parser errors can contain token-bearing source lines.
        module.fail_json(msg="Runner concurrency requires an unchanged root-owned 0600 single-link regular file "
                             "with valid TOML and one canonical positive decimal root concurrent assignment")
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
    module.exit_json(changed=changed, needs_change=changed, current_concurrent=current)


if __name__ == "__main__":
    main()
