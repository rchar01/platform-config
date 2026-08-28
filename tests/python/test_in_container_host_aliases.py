from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def _run_wrapper(
    repo_root: Path,
    tmp_path: Path,
    aliases: str,
    *,
    profile: str = "development",
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    podman_log = tmp_path / "podman.log"
    fake_podman = fake_bin / "podman"
    fake_podman.write_text(
        "#!/bin/sh\n"
        "if [ \"$1 $2\" = \"image exists\" ]; then exit 0; fi\n"
        "printf '%s\\n' \"$@\" > \"$PODMAN_LOG\"\n",
        encoding="utf-8",
    )
    fake_podman.chmod(0o755)

    aliases_file = tmp_path / "container.hostaliases"
    aliases_file.write_text(aliases, encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "PATH": f"{fake_bin}:{env['PATH']}",
            "PODMAN_LOG": str(podman_log),
            "PLATFORM_CONFIG_CONTAINER_HOST_ALIASES_FILE": str(aliases_file),
            "PLATFORM_CONFIG_CONTAINER_PROFILE": profile,
            "PLATFORM_CONFIG_PRIVATE_ROOT": str(tmp_path / "private"),
            "PLATFORM_CONFIG_SECRET_ROOT": str(tmp_path / "secrets"),
            "PLATFORM_CONFIG_TEST_SCRATCH_ROOT": str(tmp_path / "scratch"),
        }
    )
    result = subprocess.run(
        [str(repo_root / "scripts/in-container"), "true"],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    arguments = (
        podman_log.read_text(encoding="utf-8").splitlines()
        if podman_log.exists()
        else []
    )
    return result, arguments


def test_development_profile_adds_private_host_aliases(
    repo_root: Path, tmp_path: Path
) -> None:
    result, arguments = _run_wrapper(
        repo_root,
        tmp_path,
        "# controller-only aliases\nbao-1.test:192.0.2.10\nbao-2.test:198.51.100.20\n",
    )

    assert result.returncode == 0, result.stderr
    assert arguments.count("--add-host") == 2
    assert "bao-1.test:192.0.2.10" in arguments
    assert "bao-2.test:198.51.100.20" in arguments


@pytest.mark.parametrize(
    "alias",
    (
        "missing-address",
        "bad_name:192.0.2.10",
        "-bad.test:192.0.2.10",
        "bao.test:192.0.2.256",
        "bao.test:192.0.2.10:extra",
    ),
)
def test_development_profile_rejects_invalid_host_aliases(
    repo_root: Path, tmp_path: Path, alias: str
) -> None:
    result, arguments = _run_wrapper(repo_root, tmp_path, f"{alias}\n")

    assert result.returncode == 2
    assert f"Invalid container host alias: {alias}" in result.stderr
    assert not arguments


def test_test_profile_ignores_private_host_aliases(
    repo_root: Path, tmp_path: Path
) -> None:
    result, arguments = _run_wrapper(
        repo_root,
        tmp_path,
        "bao.test:192.0.2.10\n",
        profile="test",
    )

    assert result.returncode == 0, result.stderr
    assert "--add-host" not in arguments
