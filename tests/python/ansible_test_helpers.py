from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from conftest import CommandResult, CommandRunner


def run_playbook(
    command_runner: CommandRunner,
    playbook: Path,
    *,
    inventory: Path | None = None,
    extra_vars: Sequence[Mapping[str, Any] | str] = (),
    limit: str | None = None,
    environment: Mapping[str, str] | None = None,
    syntax_check: bool = False,
    timeout: float = 120,
) -> CommandResult:
    argv: list[str | os.PathLike[str]] = ["ansible-playbook"]
    if inventory is not None:
        argv.extend(["-i", inventory])
    argv.append(playbook)
    for value in extra_vars:
        encoded = (
            json.dumps(value, separators=(",", ":"), sort_keys=True)
            if isinstance(value, Mapping)
            else value
        )
        argv.extend(["--extra-vars", encoded])
    if limit is not None:
        argv.extend(["--limit", limit])
    if syntax_check:
        argv.append("--syntax-check")
    return command_runner.run(argv, environment=environment, timeout=timeout)


def assert_failed_with(result: CommandResult, expected: str) -> None:
    result.assert_failure()
    output = result.stdout + result.stderr
    assert expected in output, (
        f"expected failure message not found: {expected!r}\n{result.diagnostics()}"
    )
