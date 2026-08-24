from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml


HELPER = Path(
    "roles/rocky_repository_policy/files/platform-rocky-repository-policy"
)
PACKAGE_MODULES = tuple(
    "ansible.builtin." + name for name in ("package", "dnf", "dnf5", "yum")
)


@pytest.fixture(scope="module")
def helper(repo_root: Path) -> ModuleType:
    path = repo_root / HELPER
    loader = importlib.machinery.SourceFileLoader(
        "platform_rocky_repository_policy", str(path)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def policy() -> dict[str, dict[str, object]]:
    return {
        "baseos": {
            "baseurl": ["https://repo.example.test/rocky/10/BaseOS/x86_64/os/"],
            "gpgcheck": True,
            "gpgkey": ["file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10"],
            "metalink": None,
            "mirrorlist": None,
            "repo_gpgcheck": False,
        }
    }


def repository(repository_id: str = "baseos") -> SimpleNamespace:
    values = policy()["baseos"]
    return SimpleNamespace(id=repository_id, enabled=True, **values)


class FakeSubstitutions:
    def __init__(self) -> None:
        self.arguments: tuple[str, tuple[str, ...]] | None = None

    def update_from_etc(
        self, installroot: str, varsdir: tuple[str, ...]
    ) -> None:
        self.arguments = (installroot, varsdir)


class FakeBase:
    def __init__(self, repositories: list[SimpleNamespace]) -> None:
        self.conf = SimpleNamespace(
            read=lambda: None,
            installroot="/",
            releasever="10",
            substitutions=FakeSubstitutions(),
            varsdir=("/etc/yum/vars", "/etc/dnf/vars"),
        )
        self.repos = SimpleNamespace(values=lambda: repositories)
        self.read_all_repos_called = False
        self.closed = False

    def read_all_repos(self) -> None:
        self.read_all_repos_called = True

    def close(self) -> None:
        self.closed = True


def install_fake_dnf(
    monkeypatch: pytest.MonkeyPatch,
    repositories: list[SimpleNamespace],
) -> FakeBase:
    base = FakeBase(repositories)
    monkeypatch.setitem(sys.modules, "dnf", SimpleNamespace(Base=lambda: base))
    return base


def test_helper_is_executable_and_does_not_load_metadata(
    repo_root: Path, helper: ModuleType
) -> None:
    path = repo_root / HELPER
    source = path.read_text(encoding="utf-8")

    assert path.stat().st_mode & 0o111
    assert "fill_sack" not in source
    assert ".enable()" not in source
    assert ".disable()" not in source
    assert "read_all_repos" in source


def test_collects_only_effective_enabled_repositories(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    disabled = repository("extras")
    disabled.enabled = False
    base = install_fake_dnf(monkeypatch, [disabled, repository()])

    releasever, repositories = helper.collect_repositories()

    assert releasever == "10"
    assert repositories == policy()
    assert base.read_all_repos_called
    assert base.closed
    assert base.conf.substitutions.arguments == (
        "/",
        ("/etc/yum/vars", "/etc/dnf/vars"),
    )


def test_exact_policy_passes_with_list_order_normalized(helper: ModuleType) -> None:
    expected = policy()
    expected["baseos"]["gpgkey"] = [
        "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-TEST",
        "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10",
    ]
    actual = json.loads(json.dumps(expected))
    actual["baseos"]["gpgkey"].reverse()

    decoded = helper.decode_policy(json.dumps(expected))
    helper.validate_repositories(decoded, actual)


def test_requires_exact_releasever(helper: ModuleType) -> None:
    helper.validate_releasever("10", "10")

    with pytest.raises(helper.PolicyError, match="releasever differs"):
        helper.validate_releasever("10.2", "10")
    with pytest.raises(helper.PolicyError, match="releasever is invalid"):
        helper.validate_releasever("10\n2", "10.2")


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update({"Extras": value["baseos"]}),
        lambda value: value["baseos"].update({"gpgcheck": False}),
        lambda value: value["baseos"].update({"baseurl": ["http://repo.test/"]}),
        lambda value: value["baseos"].update(
            {"gpgkey": ["https://repo.test/key"]}
        ),
        lambda value: value["baseos"].update({"unknown": None}),
    ],
)
def test_rejects_malformed_or_unsafe_policy(
    helper: ModuleType, mutator
) -> None:
    value = policy()
    mutator(value)

    with pytest.raises(helper.PolicyError):
        helper.decode_policy(json.dumps(value))


@pytest.mark.parametrize(
    ("field", "value", "secret"),
    [
        (
            "baseurl",
            "https://operator:password@repo.example.test/rocky/10/",
            "password",
        ),
        (
            "mirrorlist",
            "https://repo.example.test/mirrorlist?token=private-value",
            "private-value",
        ),
    ],
)
def test_rejects_credentials_without_echoing_values(
    helper: ModuleType, field: str, value: str, secret: str
) -> None:
    candidate = policy()
    candidate["baseos"]["baseurl"] = []
    candidate["baseos"][field] = value

    with pytest.raises(helper.PolicyError) as error:
        helper.decode_policy(json.dumps(candidate))

    assert secret not in str(error.value)


def test_rejects_missing_unexpected_and_changed_repositories(
    helper: ModuleType,
) -> None:
    expected = policy()

    with pytest.raises(helper.PolicyError, match="missing IDs: baseos"):
        helper.validate_repositories(expected, {})
    with pytest.raises(helper.PolicyError, match="unexpected IDs: extras"):
        helper.validate_repositories(
            expected, {**expected, "extras": expected["baseos"]}
        )
    changed = json.loads(json.dumps(expected))
    changed["baseos"]["repo_gpgcheck"] = True
    with pytest.raises(helper.PolicyError, match="baseos.repo_gpgcheck"):
        helper.validate_repositories(expected, changed)


def test_role_runs_read_only_validation_in_check_mode(repo_root: Path) -> None:
    defaults = yaml.safe_load(
        (repo_root / "roles/rocky_repository_policy/defaults/main.yml").read_text(
            encoding="utf-8"
        )
    )
    tasks = yaml.safe_load(
        (repo_root / "roles/rocky_repository_policy/tasks/main.yml").read_text(
            encoding="utf-8"
        )
    )

    assert defaults == {
        "rocky_repository_policy_enabled": False,
        "rocky_repository_policy_releasever": None,
        "rocky_repository_policy": {},
    }
    validation_block = tasks[1]["block"][1]["block"]
    command_task = validation_block[2]
    command = command_task["ansible.builtin.command"]
    assert command["argv"][-3:] == [
        "validate",
        "--releasever",
        "{{ rocky_repository_policy_releasever }}",
    ]
    assert command["stdin"] == "{{ rocky_repository_policy | to_json }}"
    assert command_task["changed_when"] is False
    assert command_task["check_mode"] is False
    assert command_task["no_log"] is True
    assert "policy-b64" not in (
        repo_root / "roles/rocky_repository_policy/tasks/main.yml"
    ).read_text(encoding="utf-8")

    cleanup_task = tasks[1]["block"][1]["always"][0]
    assert cleanup_task["ansible.builtin.file"]["state"] == "absent"
    assert cleanup_task["when"] == (
        "rocky_repository_policy_tempdir.path is defined"
    )
    assert cleanup_task["changed_when"] is False
    assert cleanup_task["check_mode"] is False

    playbook = yaml.safe_load(
        (
            repo_root
            / "playbooks/maintenance/rocky-repository-policy.yml"
        ).read_text(encoding="utf-8")
    )
    assert playbook[0]["gather_facts"] is False
    assert playbook[0]["roles"] == ["rocky_repository_policy"]


def test_every_package_consuming_role_depends_on_policy(repo_root: Path) -> None:
    role_root = repo_root / "roles"
    consumers = set()
    for task_file in role_root.glob("*/tasks/**/*.yml"):
        source = task_file.read_text(encoding="utf-8")
        if any(module in source for module in PACKAGE_MODULES):
            consumers.add(task_file.relative_to(role_root).parts[0])

    for role_name in sorted(consumers):
        metadata_path = role_root / role_name / "meta/main.yml"
        assert metadata_path.is_file(), role_name
        metadata = yaml.safe_load(metadata_path.read_text(encoding="utf-8"))
        dependencies = [
            item if isinstance(item, str) else item.get("role")
            for item in metadata.get("dependencies", [])
        ]
        assert "rocky_repository_policy" in dependencies, role_name
