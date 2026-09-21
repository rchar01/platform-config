"""The opt-in runner may clean up only a container created by this invocation."""

import json
import os
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("created", [False, True])
def test_failed_interop_startup_cleanup_is_bound_to_created_id(
    repo_root: Path, tmp_path: Path, command_runner, created: bool,
) -> None:
    tools = tmp_path / "tools"
    tests = tools / "tests/pki"
    tests.mkdir(parents=True)
    (tests / "test_client_target_interop.py").write_text("# test-only placeholder\n")
    executables = tmp_path / "bin"
    executables.mkdir()
    log = tmp_path / "podman.jsonl"
    podman = executables / "podman"
    podman.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\nfrom pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "with open(os.environ['PODMAN_LOG'], 'a') as log: log.write(json.dumps(args) + '\\n')\n"
        "if args[0] == 'run':\n"
        "    if os.environ['CREATED'] == '1':\n"
        "        Path(args[args.index('--cidfile') + 1]).write_text('a' * 64 + '\\n')\n"
        "    sys.exit(23)\n"
    )
    podman.chmod(0o755)
    result = command_runner.run([
        "bash", str(repo_root / "tests/integration/test-pki-client-staging-interop.sh"),
    ], environment={
        "PATH": str(executables) + os.pathsep + os.environ["PATH"],
        "TMPDIR": str(tmp_path), "PODMAN_LOG": str(log), "CREATED": str(int(created)),
        "PLATFORM_TOOLS_TEST_SOURCE": str(tools),
        "PLATFORM_PKI_INTEROP_TEST_IMAGE": "sha256:" + "b" * 64,
    })
    assert result.returncode == 23, result.diagnostics()
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert calls[0][0] == "run"
    assert calls[1:] == ([["rm", "-f", "a" * 64]] if created else [])
    assert not list(tmp_path.glob("platform-pki-client-interop.*"))
