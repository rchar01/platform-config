from __future__ import annotations

import os
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path

import pytest

from conftest import CommandResult, CommandRunner


pytestmark = pytest.mark.pki

FUNCTION_START = "```bash\nmaterialize_exact_tree() {\n"
FUNCTION_END = "\n```\n\nAn exact retry reports"


@pytest.fixture(scope="session")
def materialize_script(repo_root: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    workflow = (
        repo_root / "docs/registry-host-local-pki-workflow.md"
    ).read_text(encoding="utf-8")
    assert workflow.count(FUNCTION_START) == 1
    assert workflow.count(FUNCTION_END) == 1

    start = workflow.index(FUNCTION_START) + len("```bash\n")
    end = workflow.index(FUNCTION_END, start)
    function = workflow[start:end]
    assert function.startswith("materialize_exact_tree() {\n")
    assert function.endswith("\n}")

    root = tmp_path_factory.mktemp("registry-pki-materialization")
    root.chmod(0o700)
    script = root / "materialize-exact-tree.bash"
    script.write_text(
        f'{function}\n\numask "$1"\nshift\nmaterialize_exact_tree "$@"\n',
        encoding="utf-8",
    )
    script.chmod(0o700)
    return script


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _exact_file(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def _source_tree(root: Path) -> tuple[Path, dict[str, bytes]]:
    source = _private_directory(root / "source")
    contents = {
        "alpha": b"synthetic alpha payload\n",
        "beta": b"synthetic beta payload\x00\n",
    }
    for name, content in contents.items():
        _exact_file(source / name, content)
    return source, contents


def _arguments(destination: Path | str, source: Path) -> tuple[str, ...]:
    return (
        os.fspath(destination),
        "alpha",
        os.fspath(source / "alpha"),
        "beta",
        os.fspath(source / "beta"),
    )


def _command(
    script: Path, umask: str, destination: Path | str, source: Path
) -> tuple[str, ...]:
    return ("bash", "--noprofile", "--norc", os.fspath(script), umask, *_arguments(destination, source))


def _run(
    command_runner: CommandRunner,
    script: Path,
    destination: Path | str,
    source: Path,
    *,
    umask: str = "0022",
) -> CommandResult:
    return command_runner.run(
        _command(script, umask, destination, source),
        timeout=15,
    )


def _tree_snapshot(root: Path) -> tuple[object, ...]:
    root_metadata = root.lstat()
    entries: list[object] = []
    for path in sorted(root.iterdir(), key=lambda value: value.name):
        metadata = path.lstat()
        content: bytes | str | None
        if stat.S_ISREG(metadata.st_mode):
            content = path.read_bytes()
        elif stat.S_ISLNK(metadata.st_mode):
            content = os.readlink(path)
        else:
            content = None
        entries.append(
            (
                path.name,
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_size,
                content,
            )
        )
    return (
        root_metadata.st_dev,
        root_metadata.st_ino,
        root_metadata.st_mode,
        root_metadata.st_nlink,
        root_metadata.st_uid,
        root_metadata.st_gid,
        tuple(entries),
    )


def _assert_exact_tree(destination: Path, contents: dict[str, bytes]) -> None:
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert set(path.name for path in destination.iterdir()) == set(contents)
    for name, content in contents.items():
        path = destination / name
        metadata = path.stat()
        assert path.read_bytes() == content
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_nlink == 1


@pytest.mark.parametrize("umask", ["0022", "0077"])
def test_creates_multiple_exact_files_with_fixed_modes(
    tmp_path: Path,
    command_runner: CommandRunner,
    materialize_script: Path,
    umask: str,
) -> None:
    root = _private_directory(tmp_path / "owner-only")
    source, contents = _source_tree(root)
    parent = _private_directory(root / "published")
    destination = parent / "attempt"

    result = _run(
        command_runner, materialize_script, destination, source, umask=umask
    ).assert_success()

    assert result.stdout == f"status=created destination={destination}\n"
    _assert_exact_tree(destination, contents)


def test_exact_retry_preserves_tree_identities_and_bytes(
    tmp_path: Path,
    command_runner: CommandRunner,
    materialize_script: Path,
) -> None:
    root = _private_directory(tmp_path / "owner-only")
    source, contents = _source_tree(root)
    parent = _private_directory(root / "published")
    destination = parent / "attempt"
    _run(command_runner, materialize_script, destination, source).assert_success()
    before = _tree_snapshot(destination)

    result = _run(
        command_runner, materialize_script, destination, source
    ).assert_success()

    assert result.stdout == f"status=existing destination={destination}\n"
    assert _tree_snapshot(destination) == before
    _assert_exact_tree(destination, contents)


def _existing_destination(
    parent: Path, contents: dict[str, bytes], variant: str
) -> Path:
    destination = _private_directory(parent / "attempt")
    for name, content in contents.items():
        _exact_file(destination / name, content)

    if variant == "differing-bytes":
        _exact_file(destination / "alpha", b"different synthetic payload\n")
    elif variant == "extra-file":
        _exact_file(destination / "unexpected", b"synthetic extra\n")
    elif variant == "missing-file":
        (destination / "beta").unlink()
    elif variant == "unsafe-directory-mode":
        destination.chmod(0o750)
    elif variant == "unsafe-file-mode":
        (destination / "alpha").chmod(0o640)
    elif variant == "hard-link":
        external = _exact_file(parent / "hard-link-source", contents["alpha"])
        (destination / "alpha").unlink()
        os.link(external, destination / "alpha")
    elif variant == "symlink":
        external = _exact_file(parent / "symlink-target", contents["alpha"])
        (destination / "alpha").unlink()
        (destination / "alpha").symlink_to(external)
    else:
        raise AssertionError(f"unknown destination variant: {variant}")
    return destination


@pytest.mark.parametrize(
    "variant",
    [
        "differing-bytes",
        "extra-file",
        "missing-file",
        "unsafe-directory-mode",
        "unsafe-file-mode",
        "hard-link",
        "symlink",
    ],
)
def test_conflicting_existing_tree_fails_without_replacement(
    tmp_path: Path,
    command_runner: CommandRunner,
    materialize_script: Path,
    variant: str,
) -> None:
    root = _private_directory(tmp_path / "owner-only")
    source, contents = _source_tree(root)
    parent = _private_directory(root / "published")
    destination = _existing_destination(parent, contents, variant)
    before = _tree_snapshot(destination)

    result = _run(
        command_runner, materialize_script, destination, source
    ).assert_failure()

    assert "materialization failed:" in result.stderr
    assert _tree_snapshot(destination) == before


@pytest.mark.parametrize("noncanonical", ["destination", "source"])
def test_noncanonical_paths_fail_without_replacing_destination(
    tmp_path: Path,
    command_runner: CommandRunner,
    materialize_script: Path,
    noncanonical: str,
) -> None:
    root = _private_directory(tmp_path / "owner-only")
    source, contents = _source_tree(root)
    parent = _private_directory(root / "published")
    destination = _existing_destination(parent, contents, "differing-bytes")
    before = _tree_snapshot(destination)
    arguments = list(_arguments(destination, source))
    if noncanonical == "destination":
        arguments[0] = f"{parent}/unused/../attempt"
    else:
        arguments[2] = f"{source}/./alpha"

    result = command_runner.run(
        (
            "bash",
            "--noprofile",
            "--norc",
            os.fspath(materialize_script),
            "0022",
            *arguments,
        ),
        timeout=15,
    ).assert_failure()

    assert "is not an absolute canonical path" in result.stderr
    assert _tree_snapshot(destination) == before


@pytest.mark.parametrize("variant", ["unsafe-mode", "hard-link", "symlink"])
def test_unsafe_sources_fail_without_creating_destination(
    tmp_path: Path,
    command_runner: CommandRunner,
    materialize_script: Path,
    variant: str,
) -> None:
    root = _private_directory(tmp_path / "owner-only")
    source, _ = _source_tree(root)
    parent = _private_directory(root / "published")
    destination = parent / "attempt"
    if variant == "unsafe-mode":
        (source / "alpha").chmod(0o640)
    elif variant == "hard-link":
        os.link(source / "alpha", root / "second-alpha-link")
    else:
        (source / "alpha").unlink()
        (source / "alpha").symlink_to(source / "beta")

    result = _run(
        command_runner, materialize_script, destination, source
    ).assert_failure()

    assert "materialization failed:" in result.stderr
    assert not destination.exists()


@pytest.mark.serial
def test_race_created_destination_is_not_clobbered_and_stage_is_preserved(
    tmp_path: Path,
    command_runner: CommandRunner,
    materialize_script: Path,
) -> None:
    root = _private_directory(tmp_path / "owner-only")
    source = _private_directory(root / "source")
    _exact_file(source / "alpha", b"a" * (32 * 1024 * 1024))
    _exact_file(source / "beta", b"synthetic beta\n")
    parent = _private_directory(root / "published")
    destination = parent / "attempt"
    sentinel = b"race publisher evidence\n"
    published = threading.Event()
    stop = threading.Event()
    watcher_error: list[BaseException] = []

    def publish_on_stage() -> None:
        try:
            deadline = time.monotonic() + 10
            while not stop.is_set() and time.monotonic() < deadline:
                if any(
                    path.name.startswith(".pki-materialize.")
                    for path in parent.iterdir()
                ):
                    destination.mkdir(mode=0o700)
                    destination.chmod(0o700)
                    _exact_file(destination / "race-evidence", sentinel)
                    published.set()
                    return
        except BaseException as error:
            watcher_error.append(error)

    watcher = threading.Thread(target=publish_on_stage, daemon=True)
    watcher.start()
    process = subprocess.Popen(
        _command(materialize_script, "0077", destination, source),
        env=command_runner.environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=2)
        pytest.fail(f"materialization race timed out\nstdout:\n{stdout}\nstderr:\n{stderr}")
    finally:
        stop.set()
        watcher.join(timeout=2)

    assert not watcher_error
    assert published.is_set()
    assert process.returncode != 0
    assert stdout == ""
    assert "materialization failed:" in stderr
    assert "preserved_stage=" in stderr
    assert (destination / "race-evidence").read_bytes() == sentinel
    assert set(path.name for path in destination.iterdir()) == {"race-evidence"}
    assert any(path.name.startswith(".pki-materialize.") for path in parent.iterdir())


def test_unsupported_renameat2_is_documented_and_has_no_fallback(
    repo_root: Path,
) -> None:
    workflow = (
        repo_root / "docs/registry-host-local-pki-workflow.md"
    ).read_text(encoding="utf-8")
    start = workflow.index(FUNCTION_START) + len("```bash\n")
    end = workflow.index(FUNCTION_END, start)
    function = workflow[start:end]
    section = workflow[
        workflow.index("## Canonical No-Clobber Materialization") : workflow.index(
            "## Argument Provenance"
        )
    ]

    assert "If `renameat2` is unavailable or" in section
    assert "unsupported by libc" in section
    assert "fails closed" in section
    assert "preserves the reported stage" in section
    assert "renameat2(parent_fd" in function
    assert "os.rename(" not in function
    assert "os.replace(" not in function
