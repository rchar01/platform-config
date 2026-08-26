from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import pwd
import re
import shutil
import stat
import tarfile
from types import SimpleNamespace
from pathlib import Path

import pytest

from conftest import CommandRunner


SCRIPT = "scripts/gitlab-runner-self-bootstrap-preflight"
EXPORT_SCRIPT = "scripts/gitlab-runner-self-bootstrap-export"
MANIFEST_SCRIPT = "scripts/gitlab-runner-self-bootstrap-manifest"
CONTROLLER_CHECK = "scripts/gitlab-runner-self-bootstrap-controller-check"
MANIFEST_NAME = ".platform-runner-self-bootstrap-export.json"
DEFAULT_OPTIONS = {
    "--env": "test",
    "--limit": "gitlab-runner-01",
    "--min-controller-free-gib": "1",
    "--min-root-free-gib": "1",
    "--connect-timeout": "10",
    "--connect-retries": "6",
}


def _arguments(**overrides: str) -> list[str]:
    options = DEFAULT_OPTIONS | overrides
    arguments = ["inspect"]
    for name, value in options.items():
        arguments.extend((name, value))
    return arguments


def _git(
    command_runner: CommandRunner, repository: Path, *arguments: str
) -> str:
    return command_runner.run(["git", "-C", repository, *arguments]).assert_success().stdout.strip()


def _commit_fixture(command_runner: CommandRunner, repository: Path) -> None:
    _git(command_runner, repository, "init", "--quiet")
    _git(command_runner, repository, "add", ".")
    command_runner.run(
        [
            "git",
            "-C",
            repository,
            "-c",
            "user.name=Self Bootstrap Test",
            "-c",
            "user.email=self-bootstrap@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "test fixture",
        ]
    ).assert_success()


def _export_fixture_sources(
    tmp_path: Path, repo_root: Path, command_runner: CommandRunner
) -> tuple[Path, Path, Path]:
    public = tmp_path / "platform-config"
    private = tmp_path / "platform-private"
    secret = tmp_path / "platform-secrets"
    (public / "scripts").mkdir(parents=True)
    for relative in (SCRIPT, EXPORT_SCRIPT, MANIFEST_SCRIPT, CONTROLLER_CHECK):
        shutil.copy2(repo_root / relative, public / relative)
    for relative in (
        "Containerfile.dev",
        "Makefile",
        "ansible.cfg",
        "requirements-dev.txt",
        "requirements-test.txt",
        "requirements.yml",
    ):
        (public / relative).write_text(f"fixture for {relative}\n", encoding="utf-8")
    (public / "scripts/in-container").write_text(
        "#!/usr/bin/env sh\nexit 1\n", encoding="utf-8"
    )
    (public / "scripts/in-container").chmod(0o755)
    (public / "playbooks").mkdir()
    for playbook in (
        "bootstrap.yml",
        "base-os.yml",
        "storage-volumes.yml",
        "container-runtime.yml",
        "gitlab-runners.yml",
    ):
        (public / "playbooks" / playbook).write_text("---\n", encoding="utf-8")
    (public / ".gitignore").write_text("ignored-public\n", encoding="utf-8")
    (public / "ignored-public").write_text("not exported\n", encoding="utf-8")

    (private / "config/inventories/test").mkdir(parents=True)
    (private / ".gitignore").write_text("ignored-private\n", encoding="utf-8")
    (private / "ignored-private").write_text("not exported\n", encoding="utf-8")
    (private / "config/test.ansible.env").write_text(
        "export ANSIBLE_HOST_KEY_CHECKING=True\n", encoding="utf-8"
    )
    (private / "config/inventories/test/hosts.yml").write_text(
        "---\nall:\n  hosts: {}\n", encoding="utf-8"
    )

    secret.mkdir(mode=0o700)
    (secret / "runner.token").write_text("outside-git-secret\n", encoding="utf-8")
    _commit_fixture(command_runner, public)
    _commit_fixture(command_runner, private)
    return public, private, secret


def _create_export(
    tmp_path: Path, repo_root: Path, command_runner: CommandRunner, name: str = "bootstrap.tgz"
) -> tuple[Path, Path, Path, Path]:
    public, private, secret = _export_fixture_sources(
        tmp_path, repo_root, command_runner
    )
    output = tmp_path / "output"
    output.mkdir()
    archive = output / name
    command_runner.run(
        [public / EXPORT_SCRIPT, "--env", "test", "--output", archive],
        environment={
            "PLATFORM_CONFIG_PRIVATE_ROOT": str(private),
            "PLATFORM_CONFIG_SECRET_ROOT": str(secret),
        },
    ).assert_success()
    return public, private, secret, archive


def _extract_export(
    command_runner: CommandRunner, archive: Path, destination: Path
) -> tuple[Path, Path]:
    destination.mkdir(mode=0o700)
    command_runner.run(
        ["tar", "-C", destination, "-xzf", archive]
    ).assert_success()
    return destination / "platform-config", destination / "platform-private"


@pytest.fixture(scope="module")
def preflight_source(repo_root: Path) -> str:
    return (repo_root / SCRIPT).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def controller_check_module(repo_root: Path) -> object:
    path = repo_root / CONTROLLER_CHECK
    loader = importlib.machinery.SourceFileLoader("self_bootstrap_controller_check", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_preflight_is_executable_and_has_valid_bash_syntax(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    script = repo_root / SCRIPT

    assert script.is_file()
    assert script.stat().st_mode & 0o111
    assert script.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n")
    command_runner.run(["bash", "-n", script]).assert_success()


def test_preflight_requires_pinned_images_and_partial_chain_ca(
    preflight_source: str,
) -> None:
    assert (
        "manager, Docker fallback, and helper images must be digest-pinned"
        in preflight_source
    )
    assert '"ca_sha256": ca_sha256' in preflight_source
    assert "sha256sum \"$resolved\"" in preflight_source
    assert "ssl.VERIFY_X509_PARTIAL_CHAIN" in preflight_source


def test_export_helpers_are_executable_and_have_valid_help(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    export = repo_root / EXPORT_SCRIPT
    manifest = repo_root / MANIFEST_SCRIPT

    for script in (export, manifest):
        assert script.is_file()
        assert script.stat().st_mode & 0o111
    command_runner.run(["bash", "-n", export]).assert_success()
    export_help = command_runner.run([export, "--help"]).assert_success()
    manifest_help = command_runner.run([manifest, "--help"]).assert_success()
    assert "Operator-attended use only" in export_help.stderr
    assert "--env ENV --output ARCHIVE.tgz" in export_help.stderr
    assert "{create,verify}" in manifest_help.stdout


def test_controller_check_is_executable_and_has_valid_help(
    tmp_path: Path, repo_root: Path, command_runner: CommandRunner
) -> None:
    controller_check = repo_root / CONTROLLER_CHECK

    assert controller_check.is_file()
    assert controller_check.stat().st_mode & 0o111
    command_runner.run(
        ["python3", "-m", "py_compile", controller_check],
        environment={"PYTHONPYCACHEPREFIX": str(tmp_path / "pycache")},
    ).assert_success()
    help_result = command_runner.run([controller_check, "--help"]).assert_success()
    assert "--controller-root" in help_result.stdout
    assert "--private-root" in help_result.stdout
    assert "--subuid-file" not in help_result.stdout
    assert "--subgid-file" not in help_result.stdout


def _controller_check_fixture(
    tmp_path: Path, repo_root: Path
) -> tuple[list[Path | str], dict[str, str], dict[str, Path]]:
    controller_root = tmp_path / "controller"
    public_root = controller_root / "source/platform-config"
    private_root = controller_root / "source/platform-private"
    graphroot = controller_root / "containers/storage"
    runtime_root = tmp_path / "runtime"
    runroot = runtime_root / "containers"
    home = tmp_path / "home"
    config_root = home / ".config"
    storage_config = config_root / "containers/storage.conf"
    for directory in (
        public_root / "scripts",
        private_root,
        graphroot,
        runroot,
        storage_config.parent,
        home,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    in_container = public_root / "scripts/in-container"
    in_container.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
    in_container.chmod(0o755)
    storage_config.write_text(
        "[storage]\n"
        'driver = "overlay"\n'
        f'graphroot = "{graphroot}"\n'
        "\n[storage.options.overlay]\n"
        'mountopt = "nodev"\n',
        encoding="utf-8",
    )
    storage_config.chmod(0o600)

    podman_info = tmp_path / "podman.json"
    podman_info.write_text(
        json.dumps(
            {
                "host": {
                    "security": {"rootless": True, "selinuxEnabled": True},
                    "idMappings": {
                        "uidmap": [
                            {"container_id": 0, "host_id": os.getuid(), "size": 1},
                            {"container_id": 1, "host_id": 100000, "size": 65536},
                        ],
                        "gidmap": [
                            {"container_id": 0, "host_id": os.getgid(), "size": 1},
                            {"container_id": 1, "host_id": 100000, "size": 65536},
                        ],
                    },
                },
                "store": {
                    "configFile": str(storage_config),
                    "graphDriverName": "overlay",
                    "graphOptions": {"overlay.mountopt": "nodev"},
                    "graphRoot": str(graphroot),
                    "runRoot": str(runroot),
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    mount_info = tmp_path / "mount.json"
    mount_info.write_text(
        json.dumps(
            {
                "filesystems": [
                    {
                        "target": str(controller_root),
                        "source": "/dev/mapper/example-bootstrap",
                        "fstype": "xfs",
                        "options": "rw,relatime,seclabel",
                        "fsroot": "/",
                        "maj:min": "254:42",
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    equivalences = tmp_path / "selinux-equivalences.txt"
    equivalences.write_text(
        f"{graphroot} = /var/lib/containers/storage\n", encoding="utf-8"
    )
    username = pwd.getpwuid(os.getuid()).pw_name
    subuid = tmp_path / "subuid"
    subgid = tmp_path / "subgid"
    for path in (subuid, subgid):
        path.write_text(f"{username}:100000:65536\n", encoding="utf-8")
    arguments: list[Path | str] = [
        repo_root / CONTROLLER_CHECK,
        "--controller-root",
        controller_root,
        "--repository-root",
        public_root,
        "--private-root",
        private_root,
        "--podman-info",
        podman_info,
        "--mount-info",
        mount_info,
        "--selinux-equivalences",
        equivalences,
    ]
    environment = {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(config_root),
        "XDG_RUNTIME_DIR": str(runtime_root),
    }
    paths = {
        "controller_root": controller_root,
        "equivalences": equivalences,
        "graphroot": graphroot,
        "home": home,
        "mount_info": mount_info,
        "podman_info": podman_info,
        "runtime_root": runtime_root,
        "storage_config": storage_config,
        "subgid": subgid,
        "subuid": subuid,
    }
    return arguments, environment, paths


def _validate_controller_check_fixture(
    controller_check_module: object,
    arguments: list[Path | str],
    environment: dict[str, str],
    paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, str]:
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR"):
        if name in environment:
            monkeypatch.setenv(name, environment[name])
        else:
            monkeypatch.delenv(name, raising=False)
    user = pwd.getpwuid(os.getuid())
    account = SimpleNamespace(
        pw_dir=str(paths["home"]), pw_name=user.pw_name, pw_uid=user.pw_uid
    )
    parsed = controller_check_module.parse_arguments(
        [os.fspath(argument) for argument in arguments[1:]]
    )
    return controller_check_module.validate(
        parsed,
        account=account,
        expected_runtime_root=paths["runtime_root"],
        subuid_file=paths["subuid"],
        subgid_file=paths["subgid"],
    )


def test_controller_check_accepts_the_complete_dedicated_storage_contract(
    tmp_path: Path,
    repo_root: Path,
    controller_check_module: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, environment, paths = _controller_check_fixture(tmp_path, repo_root)

    result = _validate_controller_check_fixture(
        controller_check_module, arguments, environment, paths, monkeypatch
    )

    assert result == {
        "driver": "overlay",
        "graphroot": str(paths["graphroot"]),
        "runroot": f"{environment['XDG_RUNTIME_DIR']}/containers",
    }


@pytest.mark.parametrize(
    ("tamper", "message"),
    (
        ("wrong-graphroot", "effective Podman graphroot does not match"),
        ("noexec", "read-write and exec-capable"),
        ("small-subuid", "subordinate-ID range"),
        ("small-effective-map", "effective Podman UID mapping does not match"),
        ("stale-effective-map", "effective Podman UID mapping does not match"),
        ("configured-runroot", "must not override runroot"),
        ("wrong-driver", "configured storage driver does not match"),
        ("effective-vfs", "must use the overlay storage driver"),
        ("nested-mount", "must not contain nested mounts"),
        ("bind-mount", "block-backed filesystem"),
        ("unsafe-source-mode", "repository source path must not be"),
        ("transient-home", "HOME must match"),
        ("transient-runtime", "XDG_RUNTIME_DIR must match"),
        ("transient-config", "XDG_CONFIG_HOME must match"),
        ("legacy-rootless-equivalence", "missing SELinux fcontext equivalence"),
        ("missing-equivalence", "missing SELinux fcontext equivalence"),
    ),
)
def test_controller_check_rejects_incomplete_or_mismatched_storage_state(
    tamper: str,
    message: str,
    tmp_path: Path,
    repo_root: Path,
    controller_check_module: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments, environment, paths = _controller_check_fixture(tmp_path, repo_root)
    podman = json.loads(paths["podman_info"].read_text(encoding="utf-8"))
    mount = json.loads(paths["mount_info"].read_text(encoding="utf-8"))
    config = paths["storage_config"].read_text(encoding="utf-8")
    if tamper == "wrong-graphroot":
        podman["store"]["graphRoot"] = str(tmp_path / "wrong")
    elif tamper == "noexec":
        mount["filesystems"][0]["options"] += ",noexec"
    elif tamper == "small-subuid":
        username = pwd.getpwuid(os.getuid()).pw_name
        paths["subuid"].write_text(f"{username}:100000:65535\n", encoding="utf-8")
    elif tamper == "small-effective-map":
        podman["host"]["idMappings"]["uidmap"][1]["size"] = 65535
    elif tamper == "stale-effective-map":
        podman["host"]["idMappings"]["uidmap"][1]["host_id"] = 200000
    elif tamper == "configured-runroot":
        config = config.replace(
            '[storage]\n', f'[storage]\nrunroot = "{environment["XDG_RUNTIME_DIR"]}"\n'
        )
    elif tamper == "wrong-driver":
        config = config.replace('driver = "overlay"', 'driver = "vfs"')
    elif tamper == "effective-vfs":
        podman["store"]["graphDriverName"] = "vfs"
        config = config.replace('driver = "overlay"', 'driver = "vfs"')
    elif tamper == "nested-mount":
        nested = mount["filesystems"][0].copy()
        nested["target"] = str(paths["graphroot"] / "nested")
        mount["filesystems"][0]["children"] = [nested]
    elif tamper == "bind-mount":
        mount["filesystems"][0]["fsroot"] = "/bootstrap"
    elif tamper == "unsafe-source-mode":
        (paths["controller_root"] / "source").chmod(0o777)
    elif tamper == "transient-home":
        environment["HOME"] = str(tmp_path / "alternate-home")
    elif tamper == "transient-runtime":
        environment["XDG_RUNTIME_DIR"] = str(tmp_path / "alternate-runtime")
    elif tamper == "transient-config":
        environment["XDG_CONFIG_HOME"] = str(tmp_path / "alternate-config")
    elif tamper == "legacy-rootless-equivalence":
        paths["equivalences"].write_text(
            f"{paths['graphroot']} = {paths['home']}/.local/share/containers\n",
            encoding="utf-8",
        )
    else:
        paths["equivalences"].write_text("", encoding="utf-8")
    paths["podman_info"].write_text(json.dumps(podman) + "\n", encoding="utf-8")
    paths["mount_info"].write_text(json.dumps(mount) + "\n", encoding="utf-8")
    paths["storage_config"].write_text(config, encoding="utf-8")
    paths["storage_config"].chmod(0o600)

    with pytest.raises(controller_check_module.ValidationError) as error:
        _validate_controller_check_fixture(
            controller_check_module, arguments, environment, paths, monkeypatch
        )

    assert message in str(error.value)


def test_preflight_help_is_available_without_an_operation(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = command_runner.run([repo_root / SCRIPT, "--help"]).assert_success()

    assert result.stdout == ""
    assert "{inspect|build|connect|all}" in result.stderr
    for option in DEFAULT_OPTIONS:
        assert option in result.stderr
    assert "--allow-dirty" in result.stderr
    assert "--controller-root" in result.stderr
    assert "Operator-attended use only" in result.stderr


def test_preflight_requires_an_operation(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = command_runner.run([repo_root / SCRIPT]).assert_failure()

    assert result.returncode == 2
    assert result.stderr.startswith("Usage: gitlab-runner-self-bootstrap-preflight")


def test_preflight_rejects_an_unsupported_operation(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = command_runner.run([repo_root / SCRIPT, "apply"]).assert_failure()

    assert result.returncode == 2
    assert "unsupported operation: apply" in result.stderr


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        ({"--env": "../test"}, "--env must be a literal environment name"),
        ({"--limit": "gitlab-runner-*"}, "--limit must be one literal inventory hostname"),
        ({"--min-controller-free-gib": "0"}, "--min-controller-free-gib must be a positive integer"),
        ({"--min-root-free-gib": "0"}, "--min-root-free-gib must be a positive integer"),
        ({"--min-controller-free-gib": "1000001"}, "--min-controller-free-gib is unreasonably large"),
        ({"--min-root-free-gib": "1000001"}, "--min-root-free-gib is unreasonably large"),
        ({"--connect-timeout": "0"}, "--connect-timeout must be a positive integer"),
        ({"--connect-timeout": "3601"}, "--connect-timeout must not exceed 3600 seconds"),
        ({"--connect-retries": "0"}, "--connect-retries must be a positive integer"),
        ({"--connect-retries": "101"}, "--connect-retries must not exceed 100"),
        ({"--controller-root": "relative"}, "--controller-root must be a safe absolute path"),
        ({"--controller-root": "/"}, "--controller-root must be a safe absolute path"),
        ({"--controller-root": "/srv/example/../bootstrap"}, "--controller-root must be canonical"),
    ),
)
def test_preflight_rejects_unsafe_cli_values_before_inspection(
    overrides: dict[str, str],
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    result = command_runner.run(
        [repo_root / SCRIPT, *_arguments(**overrides)]
    ).assert_failure()

    assert result.returncode == 2
    assert message in result.stderr
    assert "== Inspect" not in result.stdout


def test_preflight_operations_and_worktree_policy_are_explicit(
    preflight_source: str,
) -> None:
    operation_case = re.search(
        r'case "\$operation" in\s+([^\n)]+)\) ;;', preflight_source
    )

    assert operation_case is not None
    assert operation_case.group(1).split("|") == ["inspect", "build", "connect", "all"]
    assert 'inspect_phase\nif [[ -n $controller_root && $operation != inspect' in preflight_source
    for dispatch in (
        "inspect) ;;",
        "build) build_phase ;;",
        "connect) connect_phase ;;",
    ):
        assert dispatch in preflight_source
    assert re.search(r"\n +all\)\s+build_phase\s+connect_phase\s+;;", preflight_source)

    assert "allow_dirty=false" in preflight_source
    assert "--allow-dirty)\n      allow_dirty=true" in preflight_source
    assert 'worktree_status=$(git -C "$path" status --porcelain=v1 --untracked-files=normal' in preflight_source
    assert 'fail "repository.$label.clean" "could not inspect worktree status"' in preflight_source
    assert 'elif [[ -z $worktree_status ]]; then' in preflight_source
    assert "elif [[ $allow_dirty == true ]]; then" in preflight_source
    assert 'fail "repository.$label.clean" "worktree is dirty; review it or use --allow-dirty"' in preflight_source
    assert "check_worktree public \"$repo_root\"" in preflight_source
    assert "check_worktree private \"$private_root\"" in preflight_source
    assert 'git_root=$(git -C "$path" rev-parse --show-toplevel' in preflight_source
    assert 'if [[ -n $path_root && $git_root == "$path_root" ]]; then' in preflight_source
    assert (
        'python3 "$repo_root/scripts/gitlab-runner-self-bootstrap-manifest" verify'
        in preflight_source
    )
    assert 'pass "repository.$label.clean" "history-free export manifest is valid"' in preflight_source


def test_history_free_export_is_deterministic_and_manifest_validated(
    tmp_path: Path, repo_root: Path, command_runner: CommandRunner
) -> None:
    public, private, _, archive = _create_export(
        tmp_path, repo_root, command_runner
    )
    sidecar = archive.with_name(f"{archive.name}.sha256")

    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
    command_runner.run(
        ["sha256sum", "-c", sidecar.name], cwd=archive.parent
    ).assert_success()

    with tarfile.open(archive, "r:gz") as stream:
        names = {member.name.rstrip("/") for member in stream.getmembers()}
    assert not any(".git" in Path(name).parts for name in names)
    assert "platform-config/ignored-public" not in names
    assert "platform-private/ignored-private" not in names
    assert not any("runner.token" in name for name in names)
    assert f"platform-config/{MANIFEST_NAME}" in names
    assert f"platform-private/{MANIFEST_NAME}" in names

    extracted_public, extracted_private = _extract_export(
        command_runner, archive, tmp_path / "extracted"
    )
    public_result = command_runner.run(
        [
            repo_root / MANIFEST_SCRIPT,
            "verify",
            "--repository",
            "public",
            "--tree",
            extracted_public,
        ]
    ).assert_success()
    private_result = command_runner.run(
        [
            repo_root / MANIFEST_SCRIPT,
            "verify",
            "--repository",
            "private",
            "--tree",
            extracted_private,
        ]
    ).assert_success()
    assert public_result.stdout.strip() == _git(
        command_runner, public, "rev-parse", "HEAD"
    )
    assert private_result.stdout.strip() == _git(
        command_runner, private, "rev-parse", "HEAD"
    )

    second_output = tmp_path / "second-output"
    second_output.mkdir()
    second_archive = second_output / "second.tar.gz"
    command_runner.run(
        [public / EXPORT_SCRIPT, "--env", "test", "--output", second_archive],
        environment={"PLATFORM_CONFIG_PRIVATE_ROOT": str(private)},
    ).assert_success()
    assert archive.read_bytes() == second_archive.read_bytes()

    with archive.open("ab") as stream:
        stream.write(b"tampered")
    command_runner.run(
        ["sha256sum", "-c", sidecar.name], cwd=archive.parent
    ).assert_failure()


def test_preflight_recognizes_extracted_manifest_backed_sources(
    tmp_path: Path, repo_root: Path, command_runner: CommandRunner
) -> None:
    _, _, secret, archive = _create_export(tmp_path, repo_root, command_runner)
    public, private = _extract_export(command_runner, archive, tmp_path / "extracted")
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for command in ("dnf", "podman", "rpm", "sudo", "systemctl"):
        stub = stubs / command
        stub.write_text("#!/usr/bin/env sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)

    result = command_runner.run(
        [
            public / SCRIPT,
            "inspect",
            "--env",
            "test",
            "--limit",
            "gitlab-runner-01",
            "--min-controller-free-gib",
            "1",
            "--min-root-free-gib",
            "1",
        ],
        environment={
            "PATH": f"{stubs}:{os.environ['PATH']}",
            "PLATFORM_CONFIG_PRIVATE_ROOT": str(private),
            "PLATFORM_CONFIG_SECRET_ROOT": str(secret),
        },
    ).assert_failure()

    assert re.search(r"\[PASS\] repository\.public\s+export commit [0-9a-f]{12}", result.stdout)
    assert re.search(r"\[PASS\] repository\.private\s+export commit [0-9a-f]{12}", result.stdout)
    assert result.stdout.count("history-free export manifest is valid") == 2
    assert "controller.command." not in result.stdout
    assert "controller.storage.contract" not in result.stderr


def test_selected_controller_failure_blocks_build_and_target_contact(
    tmp_path: Path, repo_root: Path, command_runner: CommandRunner
) -> None:
    public, private, secret = _export_fixture_sources(
        tmp_path, repo_root, command_runner
    )
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for command in ("dnf", "rpm", "sudo", "systemctl"):
        stub = stubs / command
        stub.write_text("#!/usr/bin/env sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
    podman = stubs / "podman"
    podman.write_text(
        "#!/usr/bin/env sh\n"
        'if [ "${1:-}" = build ]; then : >"$BUILD_MARKER"; fi\n'
        "exit 1\n",
        encoding="utf-8",
    )
    podman.chmod(0o755)
    marker = tmp_path / "build-called"

    result = command_runner.run(
        [
            public / SCRIPT,
            "all",
            "--env",
            "test",
            "--limit",
            "gitlab-runner-01",
            "--min-controller-free-gib",
            "1",
            "--min-root-free-gib",
            "1",
            "--controller-root",
            tmp_path,
        ],
        environment={
            "BUILD_MARKER": str(marker),
            "PATH": f"{stubs}:{os.environ['PATH']}",
            "PLATFORM_CONFIG_PRIVATE_ROOT": str(private),
            "PLATFORM_CONFIG_SECRET_ROOT": str(secret),
        },
    ).assert_failure()

    assert "inspection failed; build and target contact are blocked" in result.stdout
    assert "== Build and validate controller image ==" not in result.stdout
    assert "== Validate inventory and self-connection ==" not in result.stdout
    assert not marker.exists()


@pytest.mark.parametrize("dirty_repository", ("public", "private"))
def test_export_rejects_dirty_sources(
    dirty_repository: str,
    tmp_path: Path,
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    public, private, secret = _export_fixture_sources(
        tmp_path, repo_root, command_runner
    )
    selected = public if dirty_repository == "public" else private
    (selected / ".gitignore").write_text("changed\n", encoding="utf-8")
    archive = tmp_path / "dirty.tgz"

    result = command_runner.run(
        [public / EXPORT_SCRIPT, "--env", "test", "--output", archive],
        environment={
            "PLATFORM_CONFIG_PRIVATE_ROOT": str(private),
            "PLATFORM_CONFIG_SECRET_ROOT": str(secret),
        },
    ).assert_failure()

    assert f"{dirty_repository} source is dirty" in result.stderr
    assert not archive.exists()
    assert not archive.with_name(f"{archive.name}.sha256").exists()


def test_export_requires_selected_private_files_at_head(
    tmp_path: Path, repo_root: Path, command_runner: CommandRunner
) -> None:
    public, private, _ = _export_fixture_sources(tmp_path, repo_root, command_runner)
    inventory = "config/inventories/test/hosts.yml"
    with (private / ".gitignore").open("a", encoding="utf-8") as stream:
        stream.write(f"/{inventory}\n")
    _git(command_runner, private, "rm", "--cached", inventory)
    _git(command_runner, private, "add", ".gitignore")
    command_runner.run(
        [
            "git",
            "-C",
            private,
            "-c",
            "user.name=Self Bootstrap Test",
            "-c",
            "user.email=self-bootstrap@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "untrack inventory",
        ]
    ).assert_success()

    result = command_runner.run(
        [public / EXPORT_SCRIPT, "--env", "test", "--output", tmp_path / "untracked.tgz"],
        environment={"PLATFORM_CONFIG_PRIVATE_ROOT": str(private)},
    ).assert_failure()

    assert "private source file is not tracked as a regular file" in result.stderr


def test_export_refuses_an_existing_or_symlinked_output(
    tmp_path: Path, repo_root: Path, command_runner: CommandRunner
) -> None:
    public, private, _ = _export_fixture_sources(tmp_path, repo_root, command_runner)
    target = tmp_path / "target"
    target.write_text("keep\n", encoding="utf-8")
    archive = tmp_path / "existing.tgz"
    archive.symlink_to(target)

    result = command_runner.run(
        [public / EXPORT_SCRIPT, "--env", "test", "--output", archive],
        environment={"PLATFORM_CONFIG_PRIVATE_ROOT": str(private)},
    ).assert_failure()

    assert "output already exists" in result.stderr
    assert target.read_text(encoding="utf-8") == "keep\n"


def test_export_does_not_replace_an_output_created_during_publication(
    tmp_path: Path, repo_root: Path, command_runner: CommandRunner
) -> None:
    public, private, _ = _export_fixture_sources(tmp_path, repo_root, command_runner)
    output = tmp_path / "output"
    output.mkdir()
    archive = output / "raced.tgz"
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    gzip = stubs / "gzip"
    gzip.write_text(
        "#!/usr/bin/env sh\n"
        "printf 'raced\\n' >\"$RACE_OUTPUT\"\n"
        "exec \"$REAL_GZIP\" \"$@\"\n",
        encoding="utf-8",
    )
    gzip.chmod(0o755)
    real_gzip = shutil.which("gzip")
    assert real_gzip is not None

    result = command_runner.run(
        [public / EXPORT_SCRIPT, "--env", "test", "--output", archive],
        environment={
            "PATH": f"{stubs}:{os.environ['PATH']}",
            "PLATFORM_CONFIG_PRIVATE_ROOT": str(private),
            "RACE_OUTPUT": str(archive),
            "REAL_GZIP": real_gzip,
        },
    ).assert_failure()

    assert "could not publish without replacing an existing path" in result.stderr
    assert archive.read_text(encoding="utf-8") == "raced\n"
    assert not archive.with_name(f"{archive.name}.sha256").exists()


@pytest.mark.parametrize(
    ("tamper", "repository", "message"),
    (
        ("modified", "public", "file digest does not match"),
        ("missing", "private", "export tree mismatch"),
        ("extra", "private", "export tree mismatch"),
        ("symlink", "private", "exported file type does not match"),
        ("schema", "public", "unsupported schema"),
        ("manifest-missing", "public", "export manifest is missing"),
        ("manifest-malformed", "public", "not valid UTF-8 JSON"),
        ("manifest-duplicate-top", "public", "duplicate JSON object key"),
        ("manifest-duplicate-entry", "public", "duplicate JSON object key"),
    ),
)
def test_manifest_rejects_tampered_export_trees(
    tamper: str,
    repository: str,
    message: str,
    tmp_path: Path,
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    _, _, _, archive = _create_export(tmp_path, repo_root, command_runner)
    public, private = _extract_export(command_runner, archive, tmp_path / "extracted")
    tree = public if repository == "public" else private

    if tamper == "modified":
        with (public / EXPORT_SCRIPT).open("a", encoding="utf-8") as stream:
            stream.write("# changed\n")
    elif tamper == "missing":
        (private / "config/inventories/test/hosts.yml").unlink()
    elif tamper == "extra":
        (private / "extra").write_text("unexpected\n", encoding="utf-8")
    elif tamper == "symlink":
        inventory = private / "config/inventories/test/hosts.yml"
        inventory.unlink()
        inventory.symlink_to("/dev/null")
    elif tamper == "schema":
        manifest_path = public / MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["schema"] = "unknown"
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)
    elif tamper == "manifest-missing":
        (public / MANIFEST_NAME).unlink()
    elif tamper == "manifest-malformed":
        manifest_path = public / MANIFEST_NAME
        manifest_path.write_text("{\n", encoding="utf-8")
        manifest_path.chmod(0o600)
    elif tamper == "manifest-duplicate-top":
        manifest_path = public / MANIFEST_NAME
        content = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text(
            content[:-2] + ',"schema":"duplicate"}\n', encoding="utf-8"
        )
    else:
        manifest_path = public / MANIFEST_NAME
        content = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text(
            content.replace(
                '"mode":"100644"',
                '"mode":"100644","mode":"100644"',
                1,
            ),
            encoding="utf-8",
        )

    result = command_runner.run(
        [
            repo_root / MANIFEST_SCRIPT,
            "verify",
            "--repository",
            repository,
            "--tree",
            tree,
        ]
    ).assert_failure()

    assert message in result.stderr


def test_preflight_only_syntax_checks_the_required_playbooks(
    preflight_source: str,
) -> None:
    expected = [
        "bootstrap.yml",
        "base-os.yml",
        "storage-volumes.yml",
        "container-runtime.yml",
        "gitlab-runners.yml",
    ]
    playbook_loop = re.search(r"for playbook in ([^;\n]+); do", preflight_source)
    ansible_playbook_lines = [
        line.strip()
        for line in preflight_source.splitlines()
        if "run_in_environment ansible-playbook" in line
    ]

    assert playbook_loop is not None
    assert playbook_loop.group(1).split() == expected
    assert preflight_source.count("ansible-playbook") == 1
    assert len(ansible_playbook_lines) == 1
    syntax_command = ansible_playbook_lines[0]
    assert '"/workspace/playbooks/$playbook"' in syntax_command
    assert "--syntax-check" in syntax_command
    assert '--limit "$limit"' in syntax_command
    assert "--check" not in syntax_command.split()
    assert "--diff" not in syntax_command.split()


def test_preflight_rejects_unsafe_host_keys_and_requires_a_literal_limit(
    preflight_source: str,
) -> None:
    for variable in (
        "ansible_ssh_args",
        "ansible_ssh_common_args",
        "ansible_ssh_extra_args",
    ):
        assert variable in preflight_source
    assert "no|false|off|0|accept-new" in preflight_source
    assert "/dev/null|none" in preflight_source
    assert 'item.get("name") == "HOST_KEY_CHECKING"' in preflight_source
    assert 'matches[0].get("value") is True' in preflight_source
    assert 'if strict not in {"yes", "true", "ask"}:' in preflight_source
    assert 'normalized_value != "/tmp/platform-home/.ssh/known_hosts"' in preflight_source
    assert 'value != "/tmp/platform-home/.ssh/known_hosts"' in preflight_source

    assert '[[ $limit =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]' in preflight_source
    assert "if target not in hostvars:" in preflight_source
    assert 'ansible -i "$container_inventory" all --list-hosts --limit "$limit"' in preflight_source
    assert '${#listed_hosts[@]} -eq 1 && ${listed_hosts[0]} == "$limit"' in preflight_source
    assert preflight_source.count('--limit "$3"') == 3


def test_preflight_canonicalizes_secret_paths_before_use(
    preflight_source: str,
) -> None:
    secret_root = "/tmp/platform-home/.config/platform-infrastructure"

    assert preflight_source.count(f"root=$(realpath -e {secret_root})") == 2
    assert preflight_source.count('resolved=$(realpath -e "$path")') == 2
    assert preflight_source.count('case "$resolved" in "$root"/*) ;; *) exit 1 ;; esac') == 2
    assert preflight_source.count('test -f "$resolved" && test ! -L "$path"') == 2


def test_preflight_disk_signature_probes_are_privileged_and_read_only(
    preflight_source: str,
) -> None:
    wipefs = 'sudo wipefs --no-act --noheadings --output TYPE,UUID,LABEL "$device"'
    blkid = 'sudo blkid "$device"'

    assert preflight_source.count(wipefs) == 1
    assert preflight_source.count(blkid) == 1
    assert preflight_source.index(wipefs) < preflight_source.index(blkid)
    assert "wipefs --all" not in preflight_source
    assert "wipefs -a" not in preflight_source
    assert "blkid_status == 2" in preflight_source


def test_preflight_storage_checks_fail_closed(preflight_source: str) -> None:
    assert "type(capacity) is not int" in preflight_source
    assert "type(size) is not int" in preflight_source
    assert "type(required_free) is not int" in preflight_source
    assert "type(partition) is not int" in preflight_source
    assert 'pv_parent_real == "$device_real"' in preflight_source
    assert 'pv_partition == "$partition"' in preflight_source
    assert '[[ ! -e $mountpoint && ! -L $mountpoint ]]' in preflight_source
    assert '[[ -L $mountpoint || ! -d $mountpoint ]]' in preflight_source
    assert "grow_from_size_gib" in preflight_source
    assert '"initialize" not in layout' in preflight_source
    assert 'or "lv_size" in volume' in preflight_source
    assert 'or fstype != "xfs"' in preflight_source
    assert 'or state != "mounted"' in preflight_source
    assert "size_bytes == source_rounded_bytes || size_bytes == rounded_bytes" in preflight_source
    assert 'mount_active=true' in preflight_source
    assert '[[ $mount_active == true ]]' in preflight_source
    assert 'record.get("fsroot") != "/"' in preflight_source
    assert 'record.get("maj:min") != identity' in preflight_source
    assert 'must already exist for reviewed growth' in preflight_source
    assert "vg_missing_bytes[$vg]" in preflight_source
    assert "vg_growth_bytes[$vg]" in preflight_source
    assert "${vg_growth_bytes[$vg]:-0}" in preflight_source
    assert "vg_headroom_bytes[$vg]=${vg_headroom_bytes[$vg]:-0}" in preflight_source


def test_preflight_storage_parser_emits_unambiguous_growth_row(
    tmp_path: Path,
    preflight_source: str,
    command_runner: CommandRunner,
) -> None:
    parser_match = re.search(
        r"if ! storage_rows=\$\(python3 - \"\$selected_file\" <<'PY'\n(.*?)\nPY",
        preflight_source,
        re.DOTALL,
    )
    assert parser_match is not None
    selected = tmp_path / "selected.json"
    selected.write_text(
        json.dumps(
            {
                "storage_layouts": [
                    {
                        "capacity_gib": 79,
                        "device": "/dev/disk/by-path/test-disk",
                        "initialize": False,
                        "name": "data",
                        "pv_device": "/dev/disk/by-path/test-disk-part1",
                        "required_free_gib": 19,
                        "reuse_existing_vg": True,
                        "vg_name": "data",
                    }
                ],
                "storage_volumes": [
                    {
                        "grow_from_size_gib": 1,
                        "layout": "data",
                        "lv_name": "var",
                        "mountpoint": "/var",
                        "name": "var",
                        "size_gib": 8,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = command_runner.run(
        ["python3", "-c", parser_match.group(1), selected]
    ).assert_success()

    fields = result.stdout.strip().split("\t")
    assert len(fields) == 13
    assert fields[-2:] == ["1", "1"]


@pytest.mark.parametrize(
    "invalid_update",
    (
        {"grow_from_size_gib": True},
        {"grow_from_size_gib": 8},
        {"lv_size": "9g"},
        {"fstype": "ext4"},
        {"state": "present"},
    ),
)
def test_preflight_storage_parser_rejects_invalid_growth_contract(
    invalid_update: dict[str, object],
    tmp_path: Path,
    preflight_source: str,
    command_runner: CommandRunner,
) -> None:
    parser_match = re.search(
        r"if ! storage_rows=\$\(python3 - \"\$selected_file\" <<'PY'\n(.*?)\nPY",
        preflight_source,
        re.DOTALL,
    )
    assert parser_match is not None
    volume = {
        "grow_from_size_gib": 1,
        "layout": "data",
        "lv_name": "var",
        "mountpoint": "/var",
        "name": "var",
        "size_gib": 8,
    }
    volume.update(invalid_update)
    selected = tmp_path / "selected.json"
    selected.write_text(
        json.dumps(
            {
                "storage_layouts": [
                    {
                        "capacity_gib": 79,
                        "device": "/dev/disk/by-path/test-disk",
                        "initialize": False,
                        "name": "data",
                        "pv_device": "/dev/disk/by-path/test-disk-part1",
                        "required_free_gib": 19,
                        "reuse_existing_vg": True,
                        "vg_name": "data",
                    }
                ],
                "storage_volumes": [volume],
            }
        ),
        encoding="utf-8",
    )

    command_runner.run(
        ["python3", "-c", parser_match.group(1), selected]
    ).assert_failure()


def test_preflight_make_targets_forward_the_development_image(repo_root: Path) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")

    for operation in ("inspect", "build", "connect", "all"):
        target = f"runner-self-bootstrap-{operation}:"
        assert target in makefile
    assert makefile.count('PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" ./scripts/gitlab-runner-self-bootstrap-preflight') == 4
    assert "runner-self-bootstrap-export:" in makefile
    assert './scripts/gitlab-runner-self-bootstrap-export --env "$(ENV)" --output "$(EXPORT_ARCHIVE)"' in makefile
    assert makefile.count("operator-attended only") == 4


def test_dedicated_controller_validation_is_opt_in_and_read_only(
    preflight_source: str, repo_root: Path
) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")

    assert 'controller_root=""' in preflight_source
    assert '--controller-root "$controller_root"' in preflight_source
    assert "findmnt --evaluate --json --submounts" in preflight_source
    assert "TARGET,SOURCE,FSTYPE,OPTIONS,FSROOT,MAJ:MIN" in preflight_source
    assert "stat.S_ISBLK(metadata.st_mode)" in preflight_source
    assert 'sudo -n semanage fcontext -l -n -C' in preflight_source
    assert 'sudo -n restorecon -R -x -n -v "$graph_root"' in preflight_source
    assert "semanage fcontext -a" not in preflight_source
    assert "restorecon -R -v" not in preflight_source
    assert "CONTROLLER_ROOT ?=" in makefile
    assert makefile.count("$(CONTROLLER_ROOT_ARG)") == 4
