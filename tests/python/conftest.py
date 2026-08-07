from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest


def _redact(value: str, redactions: Sequence[str]) -> str:
    for redaction in sorted(set(redactions), key=len, reverse=True):
        if redaction:
            value = value.replace(redaction, "<redacted>")
    return value


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    redactions: tuple[str, ...] = ()

    def diagnostics(self) -> str:
        redacted_argv = tuple(_redact(argument, self.redactions) for argument in self.argv)
        command = shlex.join(redacted_argv)
        stdout = _redact(self.stdout, self.redactions)
        stderr = _redact(self.stderr, self.redactions)
        return (
            f"command: {command}\n"
            f"return code: {self.returncode}\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )

    def assert_success(self) -> CommandResult:
        if self.returncode != 0:
            raise AssertionError(f"command failed\n{self.diagnostics()}")
        return self

    def assert_failure(self) -> CommandResult:
        if self.returncode == 0:
            raise AssertionError(
                f"command unexpectedly succeeded\n{self.diagnostics()}"
            )
        return self


class CommandTimeout(AssertionError):
    def __init__(self, timeout_seconds: float, result: CommandResult) -> None:
        self.timeout_seconds = timeout_seconds
        self.result = result
        super().__init__(
            f"command timed out after {timeout_seconds:.3f}s\n"
            f"{result.diagnostics()}"
        )


class CommandRunner:
    def __init__(self, cwd: Path, environment: Mapping[str, str]) -> None:
        self.cwd = cwd
        self.environment = dict(environment)

    def run(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
        timeout: float = 30.0,
        redactions: Sequence[str] = (),
    ) -> CommandResult:
        command = tuple(os.fspath(argument) for argument in argv)
        if not command:
            raise ValueError("command argv must not be empty")

        command_environment = self.environment.copy()
        if environment:
            command_environment.update(environment)

        started = time.monotonic()
        process = subprocess.Popen(
            command,
            cwd=cwd or self.cwd,
            env=command_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            stdout, stderr = self._terminate_group(process)
            result = CommandResult(
                argv=command,
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=time.monotonic() - started,
                redactions=tuple(redactions),
            )
            raise CommandTimeout(timeout, result) from None

        return CommandResult(
            argv=command,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            redactions=tuple(redactions),
        )

    @staticmethod
    def _terminate_group(process: subprocess.Popen[str]) -> tuple[str, str]:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

        try:
            return process.communicate(timeout=0.5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                return process.communicate(timeout=0.5)
            except subprocess.TimeoutExpired as error:
                stdout = CommandRunner._timeout_output(error.stdout)
                stderr = CommandRunner._timeout_output(error.stderr)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
                process.wait(timeout=0.5)
                return stdout, stderr

    @staticmethod
    def _timeout_output(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode(errors="replace")
        return value


@pytest.fixture(scope="session")
def repo_root() -> Path:
    root = Path(__file__).resolve().parents[2]
    if not (root / "Makefile").is_file():
        raise RuntimeError(f"repository root is invalid: {root}")
    return root


@pytest.fixture(scope="session")
def worker_name(request: pytest.FixtureRequest) -> str:
    worker_input = getattr(request.config, "workerinput", None)
    if worker_input is None:
        return "master"
    return str(worker_input["workerid"])


@pytest.fixture
def isolated_test_dir(tmp_path: Path, worker_name: str) -> Path:
    path = tmp_path / worker_name
    path.mkdir()
    return path


@pytest.fixture
def test_environment(
    isolated_test_dir: Path,
    repo_root: Path,
    worker_name: str,
) -> dict[str, str]:
    temporary = isolated_test_dir / "tmp"
    ansible_local = isolated_test_dir / "ansible-local"
    ansible_remote = isolated_test_dir / "ansible-remote"
    home = isolated_test_dir / "home"
    cache = isolated_test_dir / "cache"
    config = isolated_test_dir / "config"
    for path in (temporary, ansible_local, ansible_remote, home, cache, config):
        path.mkdir()

    inherited_names = (
        "ANSIBLE_COLLECTIONS_PATH",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
    )
    environment = {
        name: os.environ[name] for name in inherited_names if name in os.environ
    }
    environment.update(
        {
            "ANSIBLE_CONFIG": str(repo_root / "ansible.cfg"),
            "ANSIBLE_LOCAL_TEMP": str(ansible_local),
            "ANSIBLE_REMOTE_TEMP": str(ansible_remote),
            "HOME": str(home),
            "LC_ALL": "C.UTF-8",
            "PLATFORM_CONFIG_TEST_WORKER": worker_name,
            "PYTHONDONTWRITEBYTECODE": "1",
            "TEMP": str(temporary),
            "TMP": str(temporary),
            "TMPDIR": str(temporary),
            "XDG_CACHE_HOME": str(cache),
            "XDG_CONFIG_HOME": str(config),
        }
    )
    return environment


@pytest.fixture
def command_runner(repo_root: Path, test_environment: Mapping[str, str]) -> CommandRunner:
    return CommandRunner(repo_root, test_environment)
