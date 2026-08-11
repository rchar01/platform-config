from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import date, datetime
from pathlib import Path
from typing import Any


EXPECTED_VERSIONS = {
    "alloy": "1.18.1",
    "garage": "2.3.0",
    "grafana": "13.1.3",
    "loki": "3.7.6",
    "mimir": "3.1.4",
}
EXPECTED_SELECTIONS = {
    "alloy": "focused_candidate",
    "garage": "stabilized_candidate",
    "grafana": "focused_candidate",
    "loki": "focused_candidate",
    "mimir": "stabilized_candidate",
}
EXPECTED_STABILIZATION_WINDOWS = {
    "garage": 30,
    "mimir": 14,
}
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def load_candidates(repo_root: Path) -> dict[str, Any]:
    path = repo_root / "tests/fixtures/monitoring-artifacts/candidates.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_monitoring_candidate_set_and_policy(repo_root: Path) -> None:
    lock = load_candidates(repo_root)
    assert lock["schema_version"] == 1
    assert lock["observed_at"] == "2026-08-10"
    assert lock["stabilization_policy"] == {
        "patch_days": 14,
        "minor_or_branch_days": 30,
        "security_fixes": "focused_qualification",
    }
    assert {name: value["version"] for name, value in lock["components"].items()} == (
        EXPECTED_VERSIONS
    )
    assert {
        name: value["selection_status"]
        for name, value in lock["components"].items()
    } == EXPECTED_SELECTIONS


def test_monitoring_candidate_policy_evidence(repo_root: Path) -> None:
    lock = load_candidates(repo_root)
    observed_at = date.fromisoformat(lock["observed_at"])
    for name, candidate in lock["components"].items():
        assert re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            candidate["release_published_at"],
        )
        published_at = datetime.fromisoformat(
            candidate["release_published_at"].replace("Z", "+00:00")
        )
        assert published_at.tzinfo is not None
        assert REVISION_PATTERN.fullmatch(candidate["source_revision"])
        if candidate["selection_status"] == "stabilized_candidate":
            window = candidate["stabilization_window_days"]
            assert window == EXPECTED_STABILIZATION_WINDOWS[name]
            assert (observed_at - published_at.date()).days >= window
            assert "policy_basis" not in candidate
            assert "policy_evidence_url" not in candidate
        else:
            assert candidate["selection_status"] == "focused_candidate"
            assert candidate["policy_basis"]
            assert candidate["policy_evidence_url"].startswith("https://")
            assert "stabilization_window_days" not in candidate


def test_identity_target_rejects_eroded_oci_candidate_set(
    repo_root: Path, tmp_path: Path
) -> None:
    script = repo_root / "tests/integration/test-monitoring-artifact-identities.sh"
    mutations = {
        "empty": lambda components: components.clear(),
        "missing": lambda components: components.pop("garage"),
        "wrong-kind": lambda components: components["garage"].update({"kind": "rpm"}),
    }

    for name, mutate in mutations.items():
        lock = load_candidates(repo_root)
        mutate(lock["components"])
        malformed_lock = tmp_path / f"{name}.json"
        malformed_lock.write_text(json.dumps(lock), encoding="utf-8")
        result = subprocess.run(
            ["bash", str(script)],
            check=False,
            capture_output=True,
            env={
                **os.environ,
                "MONITORING_ARTIFACT_LOCK": str(malformed_lock),
                "PYTHONOPTIMIZE": "1",
            },
            text=True,
        )
        assert result.returncode != 0
        assert "Monitoring candidate lock failed identity preflight" in result.stderr


def test_monitoring_oci_candidate_contracts(repo_root: Path) -> None:
    components = load_candidates(repo_root)["components"]
    images = [value for value in components.values() if value["kind"] == "oci_image"]
    assert len(images) == 4
    assert len({value["repository"] for value in images}) == len(images)
    assert len({value["index_digest"] for value in images}) == len(images)

    for candidate in images:
        assert candidate["repository"].startswith("docker.io/")
        assert candidate["qualification_tag"] != "latest"
        assert candidate["version"] in candidate["qualification_tag"]
        assert DIGEST_PATTERN.fullmatch(candidate["index_digest"])
        assert DIGEST_PATTERN.fullmatch(candidate["linux_amd64_digest"])
        assert candidate["index_digest"] != candidate["linux_amd64_digest"]
        assert candidate["os"] == "linux"
        assert candidate["architecture"] == "amd64"
        assert isinstance(candidate["configured_user"], str)
        for field in ("entrypoint", "command", "version_command"):
            assert isinstance(candidate[field], list)
            assert all(isinstance(value, str) for value in candidate[field])
        assert len(candidate["version_command"]) > 0
        assert candidate["version_command"][0].startswith("/")


def test_alloy_candidate_matches_role_and_integration(repo_root: Path) -> None:
    alloy = load_candidates(repo_root)["components"]["alloy"]
    assert alloy["kind"] == "rpm"
    assert re.fullmatch(r"[0-9a-f]{64}", alloy["rpm_sha256"])
    assert alloy["rpm_name"] == f"alloy-{alloy['version']}-1.amd64.rpm"
    assert alloy["package_nevra"] == f"alloy-0:{alloy['version']}-1.x86_64"
    assert alloy["download_url"].endswith(f"/{alloy['rpm_name']}")
    assert alloy["attestation_url"].endswith(alloy["rpm_sha256"])
    assert alloy["package_signature"] == "not_present_in_github_release_asset"

    defaults = (repo_root / "roles/grafana_alloy/defaults/main.yml").read_text(
        encoding="utf-8"
    )
    tasks = (repo_root / "roles/grafana_alloy/tasks/main.yml").read_text(
        encoding="utf-8"
    )
    integration = (
        repo_root / "tests/integration/test-platform-external-probe-alloy.sh"
    ).read_text(encoding="utf-8")
    for value in (alloy["version"], alloy["rpm_sha256"], alloy["package_nevra"]):
        assert value in defaults
        assert value in tasks
        assert value in integration
    assert alloy["rpm_name"] in tasks
    assert alloy["rpm_name"] in integration
    assert "1[.]18[.]0" not in integration
