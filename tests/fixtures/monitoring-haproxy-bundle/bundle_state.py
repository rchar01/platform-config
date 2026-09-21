"""Local-only tamper setup and evidence; never implements the production validator."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path


def snapshot(root: Path) -> dict:
    """Use lstat and never follow a substituted bundle/member symlink."""
    result = {}

    def visit(path: Path) -> None:
        metadata = path.lstat()
        entry: dict[str, int | str] = {
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "type": stat.S_IFMT(metadata.st_mode),
            "inode": metadata.st_ino,
            "nlink": metadata.st_nlink,
            "mtime_ns": metadata.st_mtime_ns,
        }
        if stat.S_ISLNK(metadata.st_mode):
            entry["link"] = os.readlink(path)
        elif stat.S_ISREG(metadata.st_mode):
            entry["bytes"] = path.read_bytes().hex()
        result[str(path.relative_to(root))] = entry
        if stat.S_ISDIR(metadata.st_mode):
            for child in sorted(path.iterdir()):
                visit(child)

    visit(root)
    return result


def prepare(root: Path, case: dict) -> None:
    target = root / "target"
    shutil.rmtree(target)
    shutil.copytree(root / "pristine", target, symlinks=True)
    bundle = (target / "current").resolve(strict=True)
    # Keep a distinct previous generation selected: accepting corruption would
    # now switch the pointer rather than merely leave an already-current link.
    previous = target / "bundles" / ("0" * 64)
    assert previous != bundle
    shutil.copytree(bundle, previous)
    (target / "current").unlink()
    (target / "current").symlink_to(previous)
    (target / "current.next").symlink_to(previous)
    external = root / "external"
    if external.is_symlink() or external.is_file():
        external.unlink()
    elif external.exists():
        shutil.rmtree(external)
    kind = case["kind"]
    path = bundle / case.get("file", "")
    if kind == "content":
        content = path.read_bytes()
        assert content
        # Same length, same permissions: a size/mode-only check is insufficient.
        if path.name == "haproxy.cfg":
            # A valid HAProxy setting change must not pass as the reviewed bundle.
            changed = content.replace(b"maxconn 4096", b"maxconn 4097", 1)
            assert changed != content
        else:
            changed = bytes([content[0] ^ 1]) + content[1:]
        path.write_bytes(changed)
    elif kind == "mode":
        path.chmod(int(case["mode"], 8))
    elif kind == "missing":
        path.unlink()
    elif kind == "symlink":
        path.rename(external)
        path.symlink_to(external)
    elif kind == "directory":
        path.unlink()
        path.mkdir(mode=0o640)
    elif kind == "hardlink":
        os.link(path, external)
    elif kind == "extra":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"unreviewed extra\n")
    elif kind == "bundle-mode":
        bundle.chmod(0o770)
    elif kind == "bundle-symlink":
        bundle.rename(external)
        bundle.symlink_to(external, target_is_directory=True)
    elif kind == "bundle-file":
        shutil.rmtree(bundle)
        bundle.write_bytes(b"not a directory\n")
    else:
        raise AssertionError(f"unknown test case: {case}")
    evidence = {"target": snapshot(target), "calls": (root / "native-calls.jsonl").read_text()}
    if external.exists():
        evidence["external"] = snapshot(external)
    (root / "before.json").write_text(json.dumps(evidence))


def record(root: Path, case: dict, failure: str) -> None:
    before = json.loads((root / "before.json").read_text())
    after = snapshot(root / "target")
    changed_paths = sorted(
        path for path in before["target"].keys() | after.keys()
        if before["target"].get(path) != after.get(path)
    )
    if "external" in before:
        if snapshot(root / "external") != before["external"]:
            changed_paths.append("external symlink/hardlink destination")
    calls = (root / "native-calls.jsonl").read_text()
    assert calls.startswith(before["calls"]), "native call evidence was truncated"
    row = {
        "case": case,
        "failure": failure,
        "unchanged": not changed_paths,
        "changed_paths": changed_paths,
        "native_calls": calls[len(before["calls"]):].splitlines(),
    }
    with (root / "results.jsonl").open("a") as output:
        output.write(json.dumps(row) + "\n")


def main() -> None:
    assert (os.geteuid(), os.getegid()) == (0, 0), "fixture requires namespace root"
    action, raw_root, *arguments = sys.argv[1:]
    root = Path(raw_root)
    if action == "snapshot":
        print(json.dumps(snapshot(root)))
    elif action == "save":
        shutil.copytree(root / "target", root / "pristine", symlinks=True)
    elif action == "prepare":
        prepare(root, json.loads(arguments[0]))
    elif action == "record":
        record(root, json.loads(arguments[0]), arguments[1])
    else:
        raise AssertionError(f"unknown fixture action: {action}")


if __name__ == "__main__":
    main()
