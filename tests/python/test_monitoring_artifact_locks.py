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
POSTGRES_PATRONI_DIGEST = (
    "sha256:d8146b724297381532a7f0b6dcaefd114de4350785e4ac493237ab3202c061d8"
)
POSTGRES_PATRONI_REFERENCE = (
    "codeberg.org/rch/postgres-patroni@" + POSTGRES_PATRONI_DIGEST
)
POSTGRES_PATRONI_REVISION = "923c59323cceb620ad6cc7dfa1c2e57718d1c0ce"
SUPERSEDED_POSTGRES_PATRONI_DIGEST = (
    "sha256:aa1fa024dd06337ae70ad55775ed07f8e472f630f903125b975fb26b8b63f52b"
)


def load_candidates(repo_root: Path) -> dict[str, Any]:
    path = repo_root / "tests/fixtures/monitoring-artifacts/candidates.json"
    return json.loads(path.read_text(encoding="utf-8"))


def load_postgres_patroni_release(repo_root: Path) -> dict[str, Any]:
    path = repo_root / "tests/fixtures/monitoring-artifacts/postgres-patroni.json"
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


def test_postgres_patroni_release_identity(repo_root: Path) -> None:
    lock = load_postgres_patroni_release(repo_root)
    release = lock["release"]
    image = lock["image"]

    assert lock["schema_version"] == 1
    assert lock["component"] == "postgres-patroni"
    assert release == {
        "version": "0.2.1",
        "tag": "v0.2.1",
        "tag_object": "90967a28589dfa492d988cfbfa97afbe41e5dbea",
        "published_at": "2026-08-17T14:50:25Z",
        "source_repository": "https://codeberg.org/rch/postgres-patroni",
        "source_revision": POSTGRES_PATRONI_REVISION,
    }
    assert image["repository"] == "codeberg.org/rch/postgres-patroni"
    assert image["mutable_tag"] == "0.2.1"
    assert image["mutable_tag_authoritative"] is False
    assert image["digest"] == POSTGRES_PATRONI_DIGEST
    assert image["immutable_reference"] == POSTGRES_PATRONI_REFERENCE
    assert image["platform"] == "linux/amd64"
    assert image["configured_user"] == "26:26"
    assert image["entrypoint"] == ["/opt/patroni/bin/patroni"]
    assert image["command"] == ["/etc/patroni/patroni.yml"]
    assert image["created"] == "2026-08-17T16:25:04+02:00"
    assert image["root_layout"] == "curated-debian-files-v1"
    assert (
        image["components_digest"]
        == "sha256:dfc30ab14bf6280ca37a6542f6539f0178f18c36a41d823442b0a36436df3fd3"
    )
    assert image["immutable_reference"].count("@sha256:") == 1
    assert f":{image['mutable_tag']}" not in image["immutable_reference"]
    assert lock["components"] == {
        "postgresql": "18.6",
        "patroni": "4.1.4",
        "pgbackrest": "2.59.0",
    }


def test_postgres_patroni_release_qualification_and_trust(repo_root: Path) -> None:
    lock = load_postgres_patroni_release(repo_root)
    qualification = lock["qualification"]
    trust = lock["trust"]

    assert qualification == {
        "platform": "linux/amd64",
        "allowed_high_critical_findings": 0,
        "direct_high_critical_findings": 0,
        "augmented_high_critical_findings": 0,
        "trivy_version": "0.72.0",
    }
    assert trust["publication_completed"] is True
    assert trust["destination_verified"] is True
    assert trust["destination_signing_verified"] is True
    assert trust["signer_mode"] == "managed-key"
    assert (
        trust["public_key_spki_sha256"]
        == "883296cca60499fca9ab67d6e17e4746f2a38759de491c2d88440ad7ec36245c"
    )
    assert (
        trust["trusted_root_sha256"]
        == "844a1c6de3986c9f02070266b25e0d1a2fa99ceccc89f6b9ad90aae47b62a16e"
    )
    assert trust["transparency_log_required"] is True
    assert trust["bundle_required"] is True
    assert trust["independent_builder_provenance"] is False
    assert trust["provenance_mode"] == "release-authority"
    assert trust["verified_at"] == "2026-08-17T14:50:46Z"

    assert lock["evidence"] == {
        "release_publication_verification_sha256": (
            "9df3a350536db91a30f23f182f75d4c2642e498466cb6e386739a743627f2c06"
        ),
        "publication_handoff_sha256": (
            "2c46f5704c52db0232aee0f5d56279ef77a21f2f7a8dbc7ba766372df7326753"
        ),
        "release_manifest_sha256": (
            "dc0a2c058a58e0096ed0045d34b2158932f86c6b009d2339275f7c61444cbb03"
        ),
        "release_authority_build_sha256": (
            "6c276f9e1da54ff7300a8243927487e0755c5d38ebc533b84a9582c28dff3b85"
        ),
        "release_qualification_sha256": (
            "a87c59164ae73d3032b338180937c41a4cbe7d15ba3c292310b9ddc19d62d67d"
        ),
        "evidence_manifest_sha256": (
            "5db7cf5db4a3966acd668ab7fbb928867395d797211a202e0aca0a860a8238d7"
        ),
        "sbom_spdx_sha256": (
            "c92d30e6b36a3c21e33dabbf65dad8c5ea0694b1cb3d6706f748dc999b6901b6"
        ),
        "sbom_cyclonedx_sha256": (
            "c8adc2b1d2d6327715305acc3f1596083b4e652bde2898f620751b1d5967c5eb"
        ),
        "vulnerabilities_sha256": (
            "e3c8f08af386bba0633531187d36544c12ddc75fa3c0d4a779e868c9865760a2"
        ),
        "destination_image_bundle_sha256": (
            "41433f9f23edd6cf00727bd1fab2edb5013402ffc99e9016be948d4605c56196"
        ),
        "destination_build_attestation_bundle_sha256": (
            "27fed53bd18aa8738b251734f39774ce257af21a1c765a6371a6b90ab8381c28"
        ),
    }
    assert lock["retention"] == {
        "codeberg_release_assets_required": False,
        "codeberg_release_assets_published": False,
        "protected_archive_required": False,
        "protected_archive_confirmed": False,
    }


def test_grafana_postgresql_lane_uses_published_patroni_digest(
    repo_root: Path,
) -> None:
    integration = (
        repo_root / "tests/integration/test-monitoring-grafana-postgresql.sh"
    ).read_text(encoding="utf-8")
    development = (repo_root / "docs/development.md").read_text(encoding="utf-8")

    assert "postgres-patroni.json" in integration
    assert "POSTGRES_EXPECTED_DIGEST" in integration
    assert "POSTGRES_EXPECTED_REVISION" in integration
    assert "POSTGRES_EXPECTED_VERSION" in integration
    assert "--pull never" in integration
    assert "--authfile" in integration
    assert (
        '"${POSTGRES_EXPECTED_REPOSITORY}@${POSTGRES_EXPECTED_DIGEST}"'
        in integration
    )
    assert ".Config.Entrypoint'" in integration
    assert ".Config.Entrypoint[0]" not in integration
    assert ".Config.Cmd'" in integration
    assert ".Config.Cmd[0]" not in integration
    assert ".image.mutable_tag_authoritative == false" in integration
    for content in (integration, development):
        assert SUPERSEDED_POSTGRES_PATRONI_DIGEST not in content
        assert "localhost/postgres-patroni:dev" not in content


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
    preflight = (repo_root / "roles/grafana_alloy/tasks/preflight.yml").read_text(
        encoding="utf-8"
    )
    integration = (
        repo_root / "tests/integration/test-platform-external-probe-alloy.sh"
    ).read_text(encoding="utf-8")
    for value in (alloy["version"], alloy["rpm_sha256"], alloy["package_nevra"]):
        assert value in defaults
        assert value in preflight
        assert value in integration
    assert alloy["rpm_name"] in preflight
    assert alloy["rpm_name"] in integration
    assert "1[.]18[.]0" not in integration
