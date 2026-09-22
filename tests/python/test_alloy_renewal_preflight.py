"""Read-only first-predecessor observations using real signed client stages."""

import fcntl
import json
import time

import pytest

from test_alloy_initial_activation import (
    ca_remaining_secs, initial_case, pki_zipapp, ready_server, signed_hold,
)
from test_pki_host_local_lifecycle_helper import REQUEST_ID, digest, result_json, tree_snapshot


pytestmark = pytest.mark.pki


def preflight(case, writer, *, future=None):
    if future is None:
        return case.namespace_root_runner.run(
            [case.helper, "renewal-preflight", "--config", case.context_path, "--writer", writer],
            environment=case.environment, timeout=50,
        )
    return case.namespace_root_runner.run(
        ["python3", "-I", "-c",
         "import runpy,sys,json,time; time.time=lambda: int(sys.argv[4]); "
         "api=runpy.run_path(sys.argv[1]); "
         "print(json.dumps(api['Initial'](sys.argv[2]).execute('renewal-preflight', writer=sys.argv[3])))",
         case.helper, case.context_path, writer, str(future)],
        environment=case.environment, timeout=50,
    )


@pytest.mark.parametrize("writer", ["loki", "mimir"])
def test_completed_predecessor_binds_both_writers_without_writes(initial_case, ready_server, writer):
    c = initial_case
    assert result_json(c.run("activate"))["status"] == "complete"
    before = tree_snapshot(c.root)
    receipt = json.loads((c.state / "complete.json").read_bytes())
    started = int(time.time())
    result = result_json(preflight(c, writer))
    assert set(result) == {"schema", "kind", "status", "changed", "target", "writer",
                           "initial_receipt_sha256", "inventory_sha256", "observed_at_epoch", "writers"}
    assert result["schema"] == 1 and result["kind"] == "alloy-initial-renewal-preflight"
    assert result["status"] == "predecessor-verified" and result["changed"] is False
    assert result["target"] == c.context["target"] and result["writer"] == writer
    assert result["initial_receipt_sha256"] == digest(c.state / "complete.json")
    assert result["inventory_sha256"] == digest(c.snapshot)
    assert started <= result["observed_at_epoch"] <= int(time.time())
    assert set(result["writers"]) == set(c.writers)
    for name, entry in result["writers"].items():
        prior = receipt["evidence"]["writers"][name]
        assert set(entry) == {"service", "profile", "subject_dn", "request_id", "request_sha256",
                              "certificate_sha256", "certificate_spki_sha256", "version_path",
                              "validation_boundary_sha256", "rollback_hold_seconds", "leaf_not_after_epoch",
                              "client_chain_not_after_epoch", "remaining_lifetime_seconds"}
        for field in ("service", "subject_dn", "request_id", "request_sha256", "certificate_sha256",
                      "certificate_spki_sha256", "version_path", "validation_boundary_sha256"):
            assert entry[field] == prior[field]
        assert entry["profile"] == "client-p384-sha384-v1"
        assert entry["rollback_hold_seconds"] == int(prior["rollback_hold_seconds"])
        case = c.cases[name]
        version = case.versions_root / REQUEST_ID
        leaf, = case.module.pem_certificates((version / "tls.crt").read_bytes(), 1, "leaf")
        chain = case.module.pem_certificates((version / "ca-chain.crt").read_bytes(), 2, "chain")
        assert entry["leaf_not_after_epoch"] == int(leaf.not_valid_after_utc.timestamp())
        assert entry["client_chain_not_after_epoch"] == min(int(cert.not_valid_after_utc.timestamp()) for cert in chain)
        assert entry["remaining_lifetime_seconds"] == min(entry["leaf_not_after_epoch"], entry["client_chain_not_after_epoch"]) - result["observed_at_epoch"]
    assert tree_snapshot(c.root) == before
    assert c.log.read_text().splitlines() == ["enable --now alloy.service"]
    assert "PRIVATE KEY" not in json.dumps(result)
    assert result_json(c.run("status"))["status"] == "complete"


@pytest.mark.parametrize("state", ["prepared", "failed", "after-journal", "after-start"])
def test_incomplete_receipts_cannot_report_predecessor(initial_case, state):
    c = initial_case
    if state == "failed":
        c.run("activate", ALLOY_TEST_START_FAIL="1").assert_failure()
    elif state != "prepared":
        c.run("activate", PLATFORM_ALLOY_INITIAL_CRASH_AT=state).assert_failure()
    before = tree_snapshot(c.root)
    result = preflight(c, "loki").assert_failure()
    assert result.stdout == ""
    assert tree_snapshot(c.root) == before


@pytest.mark.parametrize("fault", ["receipt", "receipt-link", "receipt-hardlink", "same-config-new-inode",
                                   "counterpart-signature", "counterpart-key-mode", "unknown-version", "rpm-unit"])
def test_drift_or_unknown_state_is_retained_without_service_action(initial_case, ready_server, fault):
    c = initial_case
    result_json(c.run("activate"))
    complete = c.state / "complete.json"
    counterpart = c.cases["mimir"].versions_root / REQUEST_ID
    if fault == "receipt":
        data = json.loads(complete.read_bytes())
        data["evidence"]["writers"]["loki"]["request_id"] = "f" * 32
        complete.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
    elif fault == "receipt-link":
        saved = c.state / "saved"
        complete.rename(saved)
        complete.symlink_to(saved)
    elif fault == "receipt-hardlink":
        (c.root / "receipt-hardlink").hardlink_to(complete)
    elif fault == "same-config-new-inode":
        copy = c.config.with_name("candidate")
        copy.write_bytes(c.config.read_bytes())
        copy.chmod(0o640)
        copy.replace(c.config)
    elif fault == "counterpart-signature":
        (counterpart / "response.sig").write_bytes(b"invalid\n")
    elif fault == "counterpart-key-mode":
        (counterpart / "tls.key").chmod(0o644)
    elif fault == "unknown-version":
        (c.cases["loki"].versions_root / ("f" * 32)).mkdir(mode=0o700)
    else:
        c.unit.write_bytes(c.unit.read_bytes() + b"# drift\n")
    before = tree_snapshot(c.root)
    assert preflight(c, "loki").assert_failure().stdout == ""
    assert tree_snapshot(c.root) == before
    assert c.log.read_text().splitlines() == ["enable --now alloy.service"]


def test_preflight_retains_locks_and_rejects_contention(initial_case, ready_server):
    c = initial_case
    result_json(c.run("activate"))
    before = tree_snapshot(c.root)
    paths = [c.state / "lock", *(case.state / "lock" for case in c.cases.values())]
    for path in paths:
        with path.open() as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            preflight(c, "loki").assert_failure()
        assert tree_snapshot(c.root) == before
    observations = []
    def probe():
        for path in paths:
            with path.open() as lock:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            observations.append(str(path))
    ready_server.callbacks.append(probe)
    assert result_json(preflight(c, "mimir"))["status"] == "predecessor-verified"
    assert observations == [str(path) for path in paths]
    for path in paths:
        with path.open() as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert tree_snapshot(c.root) == before


@pytest.mark.parametrize("fault", ["inactive", "disabled", "native", "unready", "receipt-during-ready"])
def test_late_preflight_failure_never_stops_or_repairs(initial_case, ready_server, fault):
    c = initial_case
    result_json(c.run("activate"))
    if fault == "inactive":
        c.service_state.write_text("inactive enabled")
    elif fault == "disabled":
        c.service_state.write_text("active disabled")
    elif fault == "native":
        c.environment["ALLOY_TEST_VALIDATE_FAIL"] = "1"
    elif fault == "unready":
        ready_server.response_status = 503
    before = tree_snapshot(c.root)
    expected = [before]
    if fault == "receipt-during-ready":
        def remove_receipt():
            (c.state / "complete.json").unlink()
            expected[0] = tree_snapshot(c.root)
        ready_server.callbacks.append(remove_receipt)
    assert preflight(c, "loki").assert_failure().stdout == ""
    assert tree_snapshot(c.root) == expected[0]
    assert c.log.read_text().splitlines() == ["enable --now alloy.service"]


@pytest.mark.parametrize("ca_remaining_secs", [2 * 86400], indirect=True)
def test_preflight_reports_chain_limit_without_applying_start_margin(initial_case, ready_server):
    c = initial_case
    result_json(c.run("activate"))
    result = result_json(preflight(c, "loki"))
    expiry = min(entry["client_chain_not_after_epoch"] for entry in result["writers"].values())
    before = tree_snapshot(c.root)
    result = result_json(preflight(c, "mimir", future=expiry - 1))
    assert min(entry["remaining_lifetime_seconds"] for entry in result["writers"].values()) == 1
    assert all(entry["leaf_not_after_epoch"] > entry["client_chain_not_after_epoch"] for entry in result["writers"].values())
    preflight(c, "loki", future=expiry).assert_failure()
    assert tree_snapshot(c.root) == before


@pytest.mark.parametrize("initial_case", [("loki",), ("mimir",)], indirect=True, ids=["loki", "mimir"])
def test_preflight_one_writer_and_cli_selection_guards(initial_case, ready_server):
    c = initial_case
    result_json(c.run("activate"))
    writer, = c.writers
    before = tree_snapshot(c.root)
    assert set(result_json(preflight(c, writer))["writers"]) == {writer}
    for invalid in ("", "unknown", "loki,mimir", "mimir" if writer == "loki" else "loki"):
        preflight(c, invalid).assert_failure()
    for argv in (["renewal-preflight"], ["activate", "--writer", writer], ["status", "--writer", writer]):
        c.namespace_root_runner.run([c.helper, *argv, "--config", c.context_path], environment=c.environment).assert_failure()
    assert tree_snapshot(c.root) == before
