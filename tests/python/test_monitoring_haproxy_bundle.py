"""Exercise the real bundle entry point, with only native HAProxy validation stubbed."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from ansible_test_helpers import assert_failed_with
from conftest import CommandResult, NamespaceRootRunner


FILES = {
    "frontend.pem": 0o640,
    "client-ca.crt": 0o644,
    "client-ca.crl": 0o644,
    "backend-ca.crt": 0o644,
    "backend-client.pem": 0o640,
    "roles.map": 0o640,
    "haproxy.cfg": 0o640,
}
REJECTED = "Monitoring HAProxy rejected the published immutable bundle"
UNSAFE_DIRECTORY = "content-addressed monitoring HAProxy bundle path is unsafe"


@dataclass
class BundleHarness:
    runner: NamespaceRootRunner
    fixtures: Path
    root: Path
    variables: dict

    @property
    def target(self) -> Path:
        return self.root / "target"

    @property
    def current(self) -> Path:
        return self.target / "current"

    def calls(self) -> list[list[str]]:
        path = self.root / "native-calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def snapshot(self) -> dict:
        result = self.runner.run([
            sys.executable, self.fixtures / "bundle_state.py", "snapshot", self.target,
        ]).assert_success()
        return json.loads(result.stdout)

    def run(self, *, check: bool = False, cases: list[dict] | None = None) -> CommandResult:
        variables = self.variables | {"bundle_test_cases": cases or []}
        return self.runner.run([
            "ansible-playbook", "-i", "localhost,", "-c", "local",
            self.fixtures / ("matrix.yml" if cases else "bundle.yml"),
            "-e", json.dumps(variables),
            *(["--check"] if check else []),
        ], timeout=360 if cases else 90)

    def assert_rejections(self, cases: list[dict], *, check: bool = False) -> None:
        if check:
            # Seed the bundle in apply mode, then test real CLI --check semantics.
            self.run().assert_success()
        result = self.run(check=check, cases=cases).assert_success()
        rows = [json.loads(line) for line in (self.root / "results.jsonl").read_text().splitlines()]
        assert [row["case"] for row in rows] == cases, result.diagnostics()
        problems = []
        for row in rows:
            expected = UNSAFE_DIRECTORY if row["case"]["kind"].startswith("bundle-") else REJECTED
            if expected not in row["failure"]:
                problems.append(f"{row['case']}: expected rejection {expected!r}, got {row['failure']!r}")
            if not row["unchanged"]:
                problems.append(f"{row['case']}: changed paths: {row['changed_paths']}")
            if row["native_calls"]:
                problems.append(f"{row['case']}: native validation ran before integrity rejection")
        assert not problems, "\n".join(problems)


@pytest.fixture
def bundle(
    repo_root: Path, isolated_test_dir: Path, namespace_root_runner: NamespaceRootRunner,
) -> BundleHarness:
    root = isolated_test_dir / "bundle-test"
    root.mkdir()
    (root / "target").mkdir()
    sources = root / "sources"
    sources.mkdir()
    variables = {
        "ansible_python_interpreter": sys.executable,
        "bundle_test_root": str(root),
        "monitoring_haproxy_bundle_root": str(root / "target/bundles"),
        "monitoring_haproxy_current_link": str(root / "target/current"),
        "monitoring_haproxy_config_path": str(root / "target/haproxy.cfg"),
        "monitoring_haproxy_group": "root",
        "monitoring_haproxy_selinux_manage": False,
        "rocky_repository_policy_enabled": False,
    }
    for variable, name in (
        ("frontend_pem", "frontend.pem"),
        ("client_ca", "client-ca.crt"),
        ("client_crl", "client-ca.crl"),
        ("backend_ca", "backend-ca.crt"),
        ("backend_client_pem", "backend-client.pem"),
    ):
        path = sources / name
        # Deliberately synthetic bytes: this suite tests bundle integrity, not PKI.
        path.write_text(f"synthetic offline {name}\n", encoding="utf-8")
        path.chmod(0o600)
        variables[f"monitoring_haproxy_{variable}_src"] = str(path)
    native = root / "native-validator"
    native.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "assert (os.geteuid(), os.getegid()) == (0, 0)\n"
        f"with open({str(root / 'native-calls.jsonl')!r}, 'a') as calls:\n"
        "    calls.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        f"marker = Path({str(root / 'native-fault')!r})\n"
        "fault = marker.read_text() if marker.exists() else ''\n"
        "config = Path(sys.argv[-1])\n"
        "candidate = config.parent.name.endswith('.candidate')\n"
        "if fault == 'candidate-integrity' and candidate:\n"
        "    config.with_name('roles.map').write_text('unreviewed map drift\\n')\n"
        "if fault == 'final-native' and not candidate:\n"
        "    sys.exit('fixture rejected published configuration')\n",
        encoding="utf-8",
    )
    native.chmod(0o700)
    variables["monitoring_haproxy_binary_path"] = str(native)
    return BundleHarness(
        namespace_root_runner, repo_root / "tests/fixtures/monitoring-haproxy-bundle", root, variables,
    )


def test_first_publish_is_root_owned_and_second_apply_is_unchanged(bundle: BundleHarness) -> None:
    first = bundle.run().assert_success()
    assert re.search(r"changed=[1-9][0-9]*", first.stdout), first.diagnostics()
    published = bundle.current.resolve(strict=True)
    assert re.fullmatch(r"[0-9a-f]{64}", published.name)
    assert published.parent == bundle.target / "bundles"
    assert {path.name for path in published.iterdir()} == FILES.keys()
    assert list(published.parent.iterdir()) == [published]
    assert (bundle.target / "haproxy.cfg").readlink() == bundle.current / "haproxy.cfg"
    assert not (bundle.target / "current.next").is_symlink()
    before = bundle.snapshot()
    for name, mode in FILES.items():
        entry = before[f"bundles/{published.name}/{name}"]
        assert (entry["uid"], entry["gid"], entry["mode"], entry["nlink"]) == (0, 0, mode, 1)
        if (bundle.root / "sources" / name).exists():
            assert (published / name).read_bytes() == (bundle.root / "sources" / name).read_bytes()
    for directory in ("bundles", f"bundles/{published.name}"):
        entry = before[directory]
        assert (entry["uid"], entry["gid"], entry["mode"]) == (0, 0, 0o750)
    config = (published / "haproxy.cfg").read_text()
    for name in FILES.keys() - {"haproxy.cfg"}:
        assert str(published / name) in config
    assert ".candidate/" not in config
    assert "CN=operator,OU=operators,O=platform-test,C=XX operator" in (published / "roles.map").read_text()
    assert bundle.calls() == [
        ["-c", "-f", str(published.parent / f".{published.name}.candidate/haproxy.cfg")],
        ["-c", "-f", str(published / "haproxy.cfg")],
    ]
    second = bundle.run().assert_success()
    assert "changed=0" in second.stdout, second.diagnostics()
    assert bundle.snapshot() == before
    assert bundle.calls()[2:] == [["-c", "-f", str(published / "haproxy.cfg")]]


def test_healthy_published_bundle_check_is_read_only(bundle: BundleHarness) -> None:
    bundle.run().assert_success()
    before, calls = bundle.snapshot(), bundle.calls()
    result = bundle.run(check=True).assert_success()
    assert "changed=0" in result.stdout, result.diagnostics()
    assert bundle.snapshot() == before
    assert bundle.calls() == calls + [["-c", "-f", str(bundle.current.resolve() / "haproxy.cfg")]]


def test_first_check_does_not_materialize_bundle_or_pointers(bundle: BundleHarness) -> None:
    before = bundle.snapshot()
    result = bundle.run(check=True).assert_success()
    assert bundle.snapshot() == before
    assert list(bundle.target.iterdir()) == []
    assert bundle.calls() == []
    assert re.search(r"changed=[1-9][0-9]*", result.stdout), result.diagnostics()


@pytest.mark.parametrize("fault", ["final-native", "candidate-integrity"])
def test_newly_published_failure_removes_only_new_generation(bundle: BundleHarness, fault: str) -> None:
    bundle.run().assert_success()
    previous = bundle.current.resolve(strict=True)
    (bundle.target / "current.next").symlink_to(previous)
    before, calls_before = bundle.snapshot(), bundle.calls()
    (bundle.root / "native-fault").write_text(fault)
    bundle.variables["monitoring_haproxy_tenant"] = "rejected-new-tenant"

    result = bundle.run()
    assert_failed_with(result, REJECTED)
    calls = bundle.calls()[len(calls_before):]
    assert calls, result.diagnostics()
    candidate = Path(calls[0][-1]).parent
    assert re.fullmatch(r"\.[0-9a-f]{64}\.candidate", candidate.name)
    published = previous.parent / candidate.name[1:-len(".candidate")]
    assert published != previous
    expected_calls = [["-c", "-f", str(candidate / "haproxy.cfg")]]
    if fault == "final-native":
        expected_calls.append(["-c", "-f", str(published / "haproxy.cfg")])
        assert "fixture rejected published configuration" in result.stdout
    assert calls == expected_calls, result.diagnostics()
    assert not candidate.exists() and not candidate.is_symlink()
    assert not published.exists() and not published.is_symlink()
    after = bundle.snapshot()
    assert after.keys() == before.keys()
    for path, entry in before.items():
        # Creating and removing the failed generation changes its parent's mtime.
        if path != "bundles":
            assert after[path] == entry, path


@pytest.mark.parametrize("check", [False, True], ids=["apply", "check"])
def test_published_content_drift_rejected(bundle: BundleHarness, check: bool) -> None:
    """Small full-entry regression for the pre-fix baseline, in both execution modes."""
    bundle.assert_rejections([{"kind": "content", "file": "haproxy.cfg"}], check=check)


def test_published_bundle_tamper_matrix(bundle: BundleHarness) -> None:
    """One publication and one Ansible process for all integrity failures."""
    cases = [{"kind": "content", "file": name} for name in FILES]
    cases += [
        {"kind": "bundle-mode"},
        {"kind": "mode", "file": "frontend.pem", "mode": "0644"},
        {"kind": "mode", "file": "roles.map", "mode": "0644"},
        {"kind": "mode", "file": "haproxy.cfg", "mode": "0644"},
        {"kind": "mode", "file": "client-ca.crt", "mode": "0664"},
        {"kind": "missing", "file": "client-ca.crl"},
        {"kind": "symlink", "file": "backend-ca.crt"},
        {"kind": "directory", "file": "backend-client.pem"},
        {"kind": "hardlink", "file": "frontend.pem"},
        {"kind": "extra", "file": "unexpected.txt"},
        {"kind": "extra", "file": ".hidden"},
        {"kind": "extra", "file": "nested/.hidden"},
        {"kind": "bundle-symlink"},
        {"kind": "bundle-file"},
    ]
    bundle.assert_rejections(cases)
