"""Real client-stage crypto + real generated zipapp; synthetic fixed host I/O.

Mount the generated public artifact and set PLATFORM_ALLOY_TEST_PKI_ZIPAPP.
No inventory parser is copied into this repository. No live CA/host is contacted.
"""

from __future__ import annotations

import fcntl
import http.server
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import stat
import sys
import threading
import time
import zipfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from jinja2 import Environment, StrictUndefined
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from test_pki_host_local_client_staging import issue_response, replace_request, signed
from test_pki_host_local_lifecycle_helper import (
    REQUEST_ID, TARGET, digest, lifecycle_case, private_dir, private_file, record,
    result_json, tree_snapshot,
)


pytestmark = pytest.mark.pki
NEVRA = "alloy-0:1.18.1-1.x86_64"


@pytest.fixture(scope="session")
def pki_zipapp():
    if os.environ.get("PLATFORM_ALLOY_TEST_PKI_ZIPAPP"):
        data = Path(os.environ["PLATFORM_ALLOY_TEST_PKI_ZIPAPP"]).read_bytes()
    else:
        pytest.skip("requires the generated platform-tools platform-pki zipapp")
    assert data.startswith(b"#!") and b"PK\x03\x04" in data
    return data


@pytest.fixture
def activation_api(repo_root):
    source = repo_root / "roles/grafana_alloy/files/platform-alloy-initial-activate"
    loader = importlib.machinery.SourceFileLoader("alloy_activation_api_test", str(source))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_verified_inventory_parser_preserves_flat_scalar_tokens(activation_api, pki_zipapp, monkeypatch):
    api = activation_api
    def forbidden(*_args, **_kwargs):
        raise AssertionError("must load only the supplied artifact bytes")
    monkeypatch.setattr(api, "Initial", forbidden)
    monkeypatch.setattr(api, "bootstrap_read", forbidden)
    monkeypatch.setitem(sys.modules, "platform_pki.inventory", SimpleNamespace(parse_inventory=forbidden))
    name = "_platform_alloy_inventory_" + digest(pki_zipapp)
    monkeypatch.setitem(sys.modules, name, SimpleNamespace(parse_inventory=forbidden))
    paths = list(sys.path)
    parser = api.load_inventory_parser(pki_zipapp)
    assert sys.path == paths
    assert sys.modules[name] is parser
    raw = inventory({"loki": {"service": "loki-writer"}}, {"loki": "0" * 64})
    raw = (raw.replace(b"subject_cn: loki.sender.test", b"subject_cn: 17")
           .replace(b"subject_ou: Telemetry", b"subject_ou: true")
           .replace(b"subject_o: Example", b"subject_o: 0017")
           .replace(b"subject_c: US", b"subject_c: NO"))
    parsed = parser.parse_inventory(raw)
    service, = parsed.services
    assert service.subject_cn == "17" and service.subject_c == "NO"
    assert service.subject_ou == "true" and service.subject_o == "0017"
    assert service.subject_dn == "CN=17,OU=true,O=0017,C=NO"
    assert service.days == "397" and service.rollback_hold_seconds == "1"
    assert type(parsed).__module__ == name  # Real tools dataclass registration.


def test_inventory_loader_rejects_bad_entries_before_read_or_exec(activation_api, monkeypatch):
    api = activation_api
    entry = "platform_pki/inventory.py"
    def archive_bytes(entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, source in entries:
                archive.writestr(name, source)
        return buffer.getvalue()
    link = zipfile.ZipInfo(entry)
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    bad_archives = [b"not a ZIP archive", b"x" * (api.MAXIMUM + 1), bytearray(b"mutable"),
                    archive_bytes([(entry, b"")]), archive_bytes([(link, b"some-other-file")])]
    for wrong_path in ("../" + entry, "/" + entry, "platform_pki/../" + entry,
                       "platform_pki\\inventory.py", entry + ".pyc"):
        bad_archives.append(archive_bytes([(wrong_path, b"raise AssertionError('must not execute')")]))
    with pytest.warns(UserWarning, match="Duplicate name"):
        bad_archives.append(archive_bytes([(entry, b"first"), (entry, b"second")]))
    oversized = archive_bytes([(entry, b"#" * (api.MAXIMUM + 1))])
    assert len(oversized) < api.MAXIMUM  # Compressed bomb rejected by declared size.
    bad_archives.append(oversized)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("invalid entry must be rejected before reading or executing its contents")
    monkeypatch.setattr(api.zipfile.ZipFile, "open", forbidden)
    monkeypatch.setattr(api, "compile", forbidden, raising=False)
    monkeypatch.setattr(api, "exec", forbidden, raising=False)
    modules = {name for name in sys.modules if name.startswith("_platform_alloy_inventory_")}
    for artifact in bad_archives:
        with pytest.raises(api.Rejected):
            api.load_inventory_parser(artifact)
    assert {name for name in sys.modules if name.startswith("_platform_alloy_inventory_")} == modules


def test_inventory_loader_rejects_corrupt_module_before_exec(activation_api, monkeypatch):
    api = activation_api
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("platform_pki/inventory.py", b"def parse_inventory(data): return data\n")
    corrupt = buffer.getvalue().replace(b"def parse_inventory", b"dez parse_inventory", 1)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("corrupt source must not compile or execute")
    monkeypatch.setattr(api, "compile", forbidden, raising=False)
    monkeypatch.setattr(api, "exec", forbidden, raising=False)
    with pytest.raises(api.Rejected, match="invalid platform-pki inventory archive"):
        api.load_inventory_parser(corrupt)


def inventory(writers, boundaries, hold=1):
    rows = ["services:"]
    for name, writer in writers.items():
        rows.extend([
            f"  {writer['service']}:", "    profile: client-p384-sha384-v1",
            f"    subject_cn: {name}.sender.test", "    subject_ou: Telemetry",
            "    subject_o: Example", "    subject_c: US", "    days: 397",
            "    key_custody: host-local", f"    target: {TARGET}",
            f"    validation_boundary_sha256: {boundaries[name]}",
            f"    rollback_hold_seconds: {hold}",
        ])
    return ("\n".join(rows) + "\n").encode("ascii")


@pytest.fixture
def signed_hold(request):
    return getattr(request, "param", 1)


@pytest.fixture
def ca_remaining_secs(request):
    return getattr(request, "param", None)


@pytest.fixture
def initial_case(repo_root, isolated_test_dir, namespace_root_runner, pki_zipapp, signed_hold, ca_remaining_secs, request):
    root = private_dir(isolated_test_dir / "host")
    def fixed(value):
        return root / value.lstrip("/")
    def put(value, data, mode=0o600):
        destination = fixed(value)
        destination.parent.mkdir(parents=True, exist_ok=True)
        return private_file(destination, data, mode)
    lc_source = repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle"
    helper = put("/usr/local/libexec/platform-alloy-initial-activate",
                 (repo_root / "roles/grafana_alloy/files/platform-alloy-initial-activate").read_bytes().replace(
                     b"#!/usr/bin/python3 -I\n", b"#!/usr/bin/env -S python3 -I\n", 1), 0o755)
    lifecycle = put("/usr/local/libexec/platform-pki-host-local-lifecycle", lc_source.read_bytes(), 0o755)
    artifact = put("/usr/local/bin/platform-pki", pki_zipapp, 0o755)
    state = private_dir(fixed("/var/lib/platform-config/pki/alloy/process-owner"))
    private_file(state / "lock", b"")
    cases = {}
    writers = {}
    for name in getattr(request, "param", ("loki", "mimir")):
        base = getattr(lifecycle_case, "__wrapped__")(repo_root, private_dir(isolated_test_dir / name), namespace_root_runner)
        writer = {
            "service": name + "-writer", "trust_id": "reviewed-v1",
            "state_root": str(fixed(f"/var/lib/platform-config/pki/alloy/{name}")),
            "pending_root": str(fixed(f"/etc/alloy/pki/{name}/tls-pending")),
            "versions_root": str(fixed(f"/etc/alloy/pki/{name}/tls-versions")),
            "ca_file": str(put(f"/etc/alloy/pki/{name}-server-ca.crt", base.reviewed_ca.read_bytes(), 0o644)),
            "ca_sha256": digest(base.reviewed_ca),
        }
        shutil.copytree(base.state, writer["state_root"])
        shutil.copytree(base.pending_root, writer["pending_root"])
        private_dir(Path(writer["versions_root"]))
        cases[name] = replace(base, state=Path(writer["state_root"]), pending_root=Path(writer["pending_root"]),
                              pending=Path(writer["pending_root"]) / REQUEST_ID, versions_root=Path(writer["versions_root"]))
        writers[name] = writer
    defaults = yaml.safe_load((repo_root / "roles/grafana_alloy/defaults/main.yml").read_text())
    values = {**defaults, "grafana_alloy_config_path": "/etc/alloy/config.alloy",
              "grafana_alloy_environment": "test", "grafana_alloy_vm_name": TARGET,
              "grafana_alloy_ip": "192.0.2.1", "grafana_alloy_platform_role": "vm"}
    for name, writer in writers.items():
        prefix = "grafana_alloy_loki_" if name == "loki" else "grafana_alloy_prometheus_remote_write_"
        for key, value in {"url": f"https://{name}.test/api/push", "ca_file": writer["ca_file"],
                           "server_name": name + ".test",
                           "client_cert_file": writer["versions_root"] + "/" + REQUEST_ID + "/fullchain.crt",
                           "client_key_file": writer["versions_root"] + "/" + REQUEST_ID + "/tls.key"}.items():
            values[prefix + key] = value
    templates = Environment(undefined=StrictUndefined, trim_blocks=True, keep_trailing_newline=True)
    templates.filters["to_json"] = json.dumps
    def render(name):
        return templates.from_string((repo_root / "roles/grafana_alloy/templates" / name).read_text()).render(values)
    config = put("/etc/alloy/config.alloy", render("config.alloy.j2"), 0o640)
    dropin = put("/etc/systemd/system/alloy.service.d/platform.conf", render("alloy.service.override.conf.j2"), 0o644)
    snapshot = put("/etc/alloy/pki/inventory.yml", inventory(writers, dict.fromkeys(writers, "0" * 64), signed_hold))
    context = {
        "schema": 1, "target": TARGET, "inventory_path": str(snapshot), "inventory_sha256": digest(snapshot),
        "platform_pki_path": str(artifact), "platform_pki_sha256": digest(artifact),
        "lifecycle_helper_path": str(lifecycle), "lifecycle_helper_sha256": digest(lifecycle),
        "config_path": str(config), "dropin_path": str(dropin), "state_root": str(state),
        "package_nevra": NEVRA, "writers": writers,
    }
    context_path = put("/etc/alloy/pki/initial-activation.json", json.dumps(context))
    environment = {"PLATFORM_ALLOY_INITIAL_TESTING": "1", "PLATFORM_ALLOY_INITIAL_TEST_ROOT": str(root)}
    def run(action, **extra):
        # Execute the same entry class with tracebacks for actionable test
        # failures. A separate test covers the actual CLI's redacted errors.
        future = extra.pop("future", None)
        clock = "" if future is None else f"import time; time.time=lambda: {future}; "
        return namespace_root_runner.run([
            "python3", "-I", "-c",
            clock + "import runpy,sys,json; m=runpy.run_path(sys.argv[1]); "
            "print(json.dumps(m['Initial'](sys.argv[2]).execute(sys.argv[3])))",
            helper, context_path, action,
        ], environment={**environment, **extra}, timeout=50)
    boundaries = result_json(run("boundary"))
    private_file(snapshot, inventory(writers, boundaries, signed_hold))
    context["inventory_sha256"] = digest(snapshot)
    private_file(context_path, json.dumps(context))
    for name, case in cases.items():
        writer = writers[name]
        replace_request(case, service=writer["service"], inventory_sha256=digest(snapshot))
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Telemetry"),
            x509.NameAttribute(NameOID.COMMON_NAME, name + ".sender.test"),
        ])
        key = serialization.load_pem_private_key((case.pending / "tls.key").read_bytes(), None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA384())
        issue_response(case, subject=subject, csr=csr, ca_remaining_secs=ca_remaining_secs)
        source = case.root / "response-source"
        response = case.module.parse_record((source / "response").read_bytes(), case.module.RESPONSE_V2_FIELDS, "fixture")
        response.update(service=writer["service"], inventory_sha256=digest(snapshot))
        private_file(source / "response", record(case.module.RESPONSE_V2_FIELDS, response))
        signed(case, source / "response", case.module.RESPONSE_NAMESPACE_V2)
        exported = case.module.parse_record((source / "artifact").read_bytes(), case.module.ARTIFACT_FIELDS, "fixture")
        exported.update(service=writer["service"], source_response_sha256=digest(source / "response"),
                        source_response_signature_sha256=digest(source / "response.sig"))
        private_file(source / "artifact", record(case.module.ARTIFACT_FIELDS, exported))
        common = ["--service", writer["service"], "--service-adapter", "client-stage-v1", "--trust-id", "reviewed-v1"]
        ingress = Path(result_json(case.run([*case.common("target-response-prepare"), *common]))["ingress_dir"])
        for filename in case.module.RESPONSE_NAMES:
            private_file(ingress / filename, (source / filename).read_bytes())
        result_json(case.run([*case.common("target-response-install"), *common,
                              "--subject-cn", name + ".sender.test", "--subject-ou", "Telemetry",
                              "--subject-o", "Example", "--subject-c", "US", "--validity-days", "397",
                              "--minimum-remaining-lifetime-seconds", "1"]))
    unit = put("/usr/lib/systemd/system/alloy.service", "[Service]\nExecStart=/usr/bin/alloy\n", 0o644)
    alloy = put("/usr/bin/alloy", "#!/bin/sh\n[ \"$1\" = validate ] && [ \"${ALLOY_TEST_VALIDATE_FAIL:-0}\" = 0 ]\n", 0o755)
    # RPM directory entries have empty digests, including possibly the last row.
    manifest = f"8\n{unit}\t{digest(unit)}\n{alloy}\t{digest(alloy)}\n{fixed('/var/lib/alloy')}\t\n"
    put("/usr/bin/rpm", "#!/usr/bin/env python3\nimport sys\n"
        f"print({(NEVRA + chr(10) + NEVRA)!r} if sys.argv[1] == '-qf' else {manifest!r}, end='\\n')\n", 0o755)
    service_state = put("/service-state", "inactive disabled")
    log = fixed("/actions")
    put("/usr/bin/systemctl", "#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\n"
        f"state=Path({str(service_state)!r}); log=Path({str(log)!r})\n"
        "if sys.argv[1] == 'show':\n"
        " active,enabled=state.read_text().split()\n"
        f" print('LoadState=loaded\\nFragmentPath={unit}\\nSourcePath=\\nDropInPaths={dropin}\\nNeedDaemonReload=no')\n"
        " print('ActiveState='+active+'\\nUnitFileState='+enabled)\n"
        "else:\n"
        " with log.open('a') as stream: stream.write(' '.join(sys.argv[1:])+'\\n')\n"
        " if sys.argv[1:] == ['enable','--now','alloy.service']:\n"
        "  state.write_text('active enabled')\n"
        "  if os.environ.get('ALLOY_TEST_START_FAIL') == '1': sys.exit(1)\n"
        " elif sys.argv[1:] == ['disable','--now','alloy.service']:\n"
        "  if os.environ.get('ALLOY_TEST_STOP_FAIL') == '1': sys.exit(1)\n"
        "  state.write_text('inactive disabled')\n"
        " else: sys.exit(1)\n", 0o755)
    return SimpleNamespace(**locals())


@pytest.fixture
def ready_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        response_status = 200
        payload = b"ready\n"
        requests = []
        callbacks: list[Callable[[], None]] = []
        def do_GET(self):
            self.requests.append(self.path)
            for callback in self.callbacks:
                callback()
            self.send_response(self.response_status)
            self.send_header("Content-Length", str(len(self.payload)))
            self.send_header("Location", "http://127.0.0.1:9/forbidden")
            self.end_headers()
            self.wfile.write(self.payload)
        def log_message(self, format, *args):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 12345), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_boundary_without_stages_and_normalized_ids(initial_case):
    c = initial_case
    original = result_json(c.run("boundary"))
    before = tree_snapshot(c.root)
    assert result_json(c.run("boundary")) == original
    assert tree_snapshot(c.root) == before
    config = c.config.read_bytes()
    private_file(c.config, config.replace(REQUEST_ID.encode(), b"0" * 32), 0o640)
    for writer in c.writers.values():
        shutil.rmtree(writer["versions_root"])
        shutil.rmtree(writer["pending_root"])
    assert result_json(c.run("boundary")) == original
    assert not c.log.exists()


def test_pure_boundary_matches_pre_csr_template_without_initial(initial_case, monkeypatch):
    c = initial_case
    expected = result_json(c.run("boundary"))
    loader = importlib.machinery.SourceFileLoader("alloy_boundary", str(c.helper))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("pure boundary must not construct Initial or read artifacts")
    monkeypatch.setattr(module, "Initial", forbidden)
    monkeypatch.setattr(module, "bootstrap_read", forbidden)
    for name in c.writers:
        prefix = "grafana_alloy_loki_" if name == "loki" else "grafana_alloy_prometheus_remote_write_"
        for field in ("client_cert_file", "client_key_file"):
            c.values[prefix + field] = c.values[prefix + field].replace(REQUEST_ID, "@VERSION@")
    subjects = {name: f"CN={name}.sender.test,OU=Telemetry,O=Example,C=US" for name in c.writers}
    writer_bytes = json.dumps(c.writers)
    before = tree_snapshot(c.root)
    assert module.boundary_digests(
        TARGET, subjects, c.writers, c.render("config.alloy.j2").encode("ascii"), c.dropin.read_bytes(),
    ) == expected
    assert json.dumps(c.writers) == writer_bytes
    assert tree_snapshot(c.root) == before


def test_check_start_receipts_replay_and_stages_unchanged(initial_case, ready_server):
    c = initial_case
    stages = {name: (tree_snapshot(case.state), tree_snapshot(case.pending_root), tree_snapshot(case.versions_root))
              for name, case in c.cases.items()}
    before = tree_snapshot(c.root)
    assert result_json(c.run("check"))["status"] == "prepared"
    assert tree_snapshot(c.root) == before
    assert result_json(c.run("activate")) == {"schema": 1, "status": "complete", "changed": True}
    completed = tree_snapshot(c.state)
    for action in ("activate", "check", "status", "recover"):
        assert result_json(c.run(action)) == {"schema": 1, "status": "complete", "changed": False}
    assert tree_snapshot(c.state) == completed
    assert c.log.read_text().splitlines() == ["enable --now alloy.service"]
    assert set(ready_server.requests) == {"/-/ready"}
    receipt = json.loads((c.state / "complete.json").read_bytes())["evidence"]
    assert set(receipt["writers"]) == {"loki", "mimir"}
    for name, case in c.cases.items():
        assert receipt["writers"][name]["rollback_hold_seconds"] == "1"
        assert receipt["writers"][name]["validity_days"] == 397
        assert stages[name] == (tree_snapshot(case.state), tree_snapshot(case.pending_root), tree_snapshot(case.versions_root))
    assert "PRIVATE KEY" not in (c.state / "complete.json").read_text()
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in c.state.iterdir())


@pytest.mark.parametrize("response,payload", [(503, b"no"), (302, b"redirect"), (200, b"x" * 4097)],
                         ids=["unready", "redirect", "oversized"])
def test_failed_readiness_rolls_back_and_never_retries(initial_case, ready_server, response, payload):
    c = initial_case
    ready_server.response_status, ready_server.payload = response, payload
    c.run("activate").assert_failure()
    assert c.log.read_text().splitlines() == ["enable --now alloy.service", "disable --now alloy.service"]
    assert c.service_state.read_text() == "inactive disabled"
    assert (c.state / "failed.json").exists() and not (c.state / "complete.json").exists()
    before = tree_snapshot(c.root)
    c.run("activate").assert_failure()
    assert result_json(c.run("recover"))["status"] == "failed"
    assert tree_snapshot(c.root) == before
    assert len(ready_server.requests) == 10


@pytest.mark.parametrize("point", ["after-journal", "after-start"])
def test_interrupted_journal_stop_only_recovery(initial_case, point):
    c = initial_case
    c.run("activate", PLATFORM_ALLOY_INITIAL_CRASH_AT=point).assert_failure()
    assert result_json(c.run("status"))["status"] == "recovery-required"
    c.run("activate").assert_failure()
    assert result_json(c.run("recover")) == {"schema": 1, "status": "failed", "changed": True}
    expected = ([] if point == "after-journal" else ["enable --now alloy.service"]) + ["disable --now alloy.service"]
    assert c.log.read_text().splitlines() == expected


def test_unknown_stop_retains_intent_then_authenticated_recovery(initial_case, ready_server):
    c = initial_case
    ready_server.response_status = 503
    c.run("activate", ALLOY_TEST_STOP_FAIL="1").assert_failure()
    assert {p.name for p in c.state.iterdir()} == {"lock", "journal.json"}
    assert c.service_state.read_text() == "active enabled"
    assert result_json(c.run("recover"))["status"] == "failed"
    assert c.service_state.read_text() == "inactive disabled"


def test_drift_and_unknown_records_preserved_without_stop(initial_case):
    c = initial_case
    c.run("activate", PLATFORM_ALLOY_INITIAL_CRASH_AT="after-start").assert_failure()
    private_file(c.config, c.config.read_bytes() + b"\n", 0o640)
    before = tree_snapshot(c.root)
    for action in ("activate", "recover", "status", "check"):
        c.run(action).assert_failure()
    assert tree_snapshot(c.root) == before
    assert c.log.read_text().splitlines() == ["enable --now alloy.service"]


def test_input_matrix_rejects_before_service_action(initial_case):
    c = initial_case
    targets = [
        (c.context_path, b'{"schema":true}', 0o600),
        (c.context_path, json.dumps({**c.context, "inventory_sha256": "f" * 64}).encode(), 0o600),
        (c.context_path, json.dumps({**c.context, "platform_pki_sha256": "f" * 64}).encode(), 0o600),
        (c.context_path, json.dumps({**c.context, "lifecycle_helper_sha256": "f" * 64}).encode(), 0o600),
        (c.context_path, json.dumps({**c.context, "package_nevra": "alloy-0:1.18.0-1.x86_64"}).encode(), 0o600),
        (c.snapshot, c.snapshot.read_bytes(), 0o644),
        (c.snapshot, c.snapshot.read_bytes() + b"# changed bytes\n", 0o600),
        (c.config, c.config.read_bytes().replace(b"insecure_skip_verify = false", b"insecure_skip_verify = true"), 0o640),
        (c.config, c.config.read_bytes().replace(b"follow_redirects = false", b"follow_redirects = true"), 0o640),
        (c.config, c.config.read_bytes().replace(b'    follow_redirects = false', b'    bearer_token_file = "/token"\n    follow_redirects = false'), 0o640),
        (c.config, c.config.read_bytes().replace(b"/tls-versions/" + REQUEST_ID.encode(), b"/tls-versions/current"), 0o640),
        (c.dropin, c.dropin.read_bytes().replace(b"User=root", b"User=alloy"), 0o644),
        (c.lifecycle, c.lifecycle.read_bytes(), 0o777),
        (c.artifact, c.artifact.read_bytes(), 0o644),
        (c.service_state, b"active enabled", 0o600),
        (c.service_state, b"inactive masked", 0o600),
        (c.service_state, b"inactive enabled", 0o600),
        (c.unit, b"[Service]\nExecStart=/wrong\n", 0o644),
    ]
    for name, case in c.cases.items():
        targets.extend([
            (case.pending / "request.sig", b"invalid\n", 0o600),
            (case.versions_root / REQUEST_ID / "response.sig", b"invalid\n", 0o600),
            (case.versions_root / REQUEST_ID / "tls.key", b"invalid\n", 0o600),
            (case.versions_root / REQUEST_ID / "tls.crt", b"invalid\n", 0o600),
            (case.versions_root / REQUEST_ID / "fullchain.crt", (case.versions_root / REQUEST_ID / "fullchain.crt").read_bytes(), 0o644),
            (case.state / "trust/reviewed-v1/policy", b"invalid\n", 0o600),
            (Path(c.writers[name]["ca_file"]), b"wrong CA\n", 0o644),
        ])
    for target, data, mode in targets:
        original, original_mode = target.read_bytes(), target.stat().st_mode & 0o777
        try:
            private_file(target, data, mode)
            before = tree_snapshot(c.root)
            c.run("activate").assert_failure()
            assert tree_snapshot(c.root) == before
            assert not c.log.exists()
        finally:
            private_file(target, original, original_mode)


def test_signed_inventory_policy_and_unknown_stage_matrix(initial_case):
    c = initial_case
    original = c.snapshot.read_bytes()
    for old, new in [(b"days: 397", b"days: 396"), (b"rollback_hold_seconds: 1", b"rollback_hold_seconds: 0"),
                     (b"subject_ou: Telemetry", b"subject_ou: Other"), (b"target: test-target", b"target: other"),
                     (b"profile: client-p384-sha384-v1", b"profile: server-p384-sha384-v1")]:
        private_file(c.snapshot, original.replace(old, new))
        private_file(c.context_path, json.dumps({**c.context, "inventory_sha256": digest(c.snapshot)}))
        c.run("activate").assert_failure()
        assert not c.log.exists()
    private_file(c.snapshot, original)
    private_file(c.context_path, json.dumps(c.context))
    for directory, name in [(c.state, "unknown"), (c.state, "complete.json"),
                            (c.cases["loki"].state, "active"), (c.cases["mimir"].state, "target-terminal"),
                            (c.cases["loki"].versions_root, ".stage-unknown"),
                            (c.cases["mimir"].versions_root, ".ingress-" + REQUEST_ID)]:
        retained = private_file(directory / name, b"retained\n")
        before = tree_snapshot(c.root)
        c.run("activate").assert_failure()
        assert tree_snapshot(c.root) == before
        retained.unlink()


def test_protected_links_and_concurrent_lock(initial_case):
    c = initial_case
    original = c.snapshot.read_bytes()
    c.snapshot.unlink()
    c.snapshot.symlink_to(c.config)
    c.run("activate").assert_failure()
    c.snapshot.unlink()
    private_file(c.snapshot, original)
    link = c.root / "inventory-hardlink"
    link.hardlink_to(c.snapshot)
    c.run("activate").assert_failure()
    link.unlink()
    with (c.state / "lock").open() as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for action in ("check", "activate", "recover", "status"):
            c.run(action).assert_failure()
    assert not c.log.exists()
    assert result_json(c.run("check"))["status"] == "prepared"


def test_writer_lock_contention_rejects_all_transactions_before_service_action(initial_case):
    c = initial_case
    before = tree_snapshot(c.root)
    for case in c.cases.values():
        with (case.state / "lock").open() as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for action in ("activate", "check", "status", "recover"):
                failure = c.run(action).assert_failure()
                assert "another lifecycle operation holds the state lock" in failure.stderr
                assert not c.log.exists()
                assert tree_snapshot(c.root) == before
        # Also proves partial acquisition released the other writer/process lock.
        assert result_json(c.run("check"))["status"] == "prepared"


def test_writer_locks_remain_shared_through_readiness_and_release_afterward(initial_case, ready_server):
    c = initial_case
    observed = []
    def probe():
        for name, case in c.cases.items():
            with (case.state / "lock").open() as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    exclusive_blocked = True
                else:
                    exclusive_blocked = False
                    fcntl.flock(lock, fcntl.LOCK_UN)
                try:
                    fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError:
                    shared_allowed = False
                else:
                    shared_allowed = True
                observed.append((name, exclusive_blocked, shared_allowed))
    ready_server.callbacks.append(probe)
    assert result_json(c.run("activate"))["status"] == "complete"
    assert observed == [(name, True, True) for name in c.cases]
    for case in c.cases.values():
        with (case.state / "lock").open() as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert c.log.read_text().splitlines() == ["enable --now alloy.service"]


def test_cli_has_only_fixed_actions_and_redacts_failure(initial_case):
    c = initial_case
    private_file(c.snapshot, b"PRIVATE-POLICY-DIAGNOSTIC\n")
    result = c.namespace_root_runner.run([c.helper, "activate", "--config", c.context_path], environment=c.environment)
    result.assert_failure()
    assert result.stdout == ""
    assert result.stderr == "Alloy initial activation rejected: inventory digest mismatch\n"
    assert not c.log.exists()


def test_expired_leaf_or_chain_cannot_start_or_authorize_recovery(initial_case):
    c = initial_case
    before = tree_snapshot(c.root)
    for days in (398, 1001):
        c.run("activate", future=int(time.time()) + days * 86400).assert_failure()
    assert tree_snapshot(c.root) == before
    assert not c.log.exists()
    c.run("activate", PLATFORM_ALLOY_INITIAL_CRASH_AT="after-start").assert_failure()
    retained = tree_snapshot(c.root)
    c.run("recover", future=int(time.time()) + 398 * 86400).assert_failure()
    assert tree_snapshot(c.root) == retained
    assert c.log.read_text().splitlines() == ["enable --now alloy.service"]
    assert c.service_state.read_text() == "active enabled"


def clock_with_remaining(case, remaining):
    return min(int(x509.load_pem_x509_certificate(
        (writer.versions_root / REQUEST_ID / "tls.crt").read_bytes(),
    ).not_valid_after_utc.timestamp()) for writer in case.cases.values()) - remaining


def test_currently_valid_near_expiry_rejected_before_initial_intent(initial_case):
    c = initial_case
    # Two seconds passes ordinary staged crypto but cannot cover even readiness.
    clock = clock_with_remaining(c, 2)
    before = tree_snapshot(c.root)
    for action in ("check", "activate"):
        failure = c.run(action, future=clock).assert_failure()
        assert "initial hold plus one-day buffer" in failure.stderr
        assert tree_snapshot(c.root) == before
        assert not c.log.exists()
        assert {entry.name for entry in c.state.iterdir()} == {"lock"}


@pytest.mark.parametrize("ca_remaining_secs", [3600], indirect=True)
def test_authenticated_short_client_chain_rejected_before_initial_intent(initial_case):
    c = initial_case
    before = tree_snapshot(c.root)
    for name, case in c.cases.items():
        staged = result_json(case.run([
            *case.common("target-stage-status"), "--service", c.writers[name]["service"],
            "--service-adapter", "client-stage-v1", "--trust-id", "reviewed-v1",
            "--subject-cn", name + ".sender.test", "--subject-ou", "Telemetry",
            "--subject-o", "Example", "--subject-c", "US", "--validity-days", "397",
            "--minimum-remaining-lifetime-seconds", "1",
        ]))
        assert staged["status"] == "staged"
        chain = case.module.pem_certificates(
            (case.versions_root / REQUEST_ID / "ca-chain.crt").read_bytes(), 2, "test client chain",
        )
        assert all(0 < certificate.not_valid_after_utc.timestamp() - time.time() < 86401 for certificate in chain)
    assert clock_with_remaining(c, 86401) > time.time()  # Leaf margin alone passes.
    for action in ("check", "activate"):
        failure = c.run(action).assert_failure()
        assert "initial hold plus one-day buffer" in failure.stderr
        assert tree_snapshot(c.root) == before and not c.log.exists()
        assert {entry.name for entry in c.state.iterdir()} == {"lock"}


@pytest.mark.parametrize("ca_remaining_secs", [2 * 86400], indirect=True)
def test_completed_receipt_allows_current_client_chain_below_start_margin(initial_case, ready_server):
    c = initial_case
    assert result_json(c.run("activate"))["status"] == "complete"
    clock = min(int(certificate.not_valid_after_utc.timestamp()) for case in c.cases.values()
                for certificate in case.module.pem_certificates(
                    (case.versions_root / REQUEST_ID / "ca-chain.crt").read_bytes(), 2, "test client chain",
                )) - 3600
    before = tree_snapshot(c.root)
    for action in ("check", "status", "activate", "recover"):
        assert result_json(c.run(action, future=clock)) == {"schema": 1, "status": "complete", "changed": False}
    assert tree_snapshot(c.root) == before
    assert c.log.read_text().splitlines() == ["enable --now alloy.service"]


@pytest.mark.parametrize("signed_hold", [398 * 86400], indirect=True)
def test_signed_hold_exceeding_certificate_remainder_rejects_initial_start(initial_case):
    c = initial_case
    before = tree_snapshot(c.root)
    for action in ("check", "activate"):
        failure = c.run(action).assert_failure()
        assert "initial hold plus one-day buffer" in failure.stderr
        assert tree_snapshot(c.root) == before and not c.log.exists()


@pytest.mark.parametrize("outcome", ["complete", "failed", "interrupted"])
def test_existing_receipts_and_recovery_allow_aging_below_initial_margin(initial_case, ready_server, outcome):
    c = initial_case
    if outcome == "complete":
        assert result_json(c.run("activate"))["status"] == "complete"
    elif outcome == "failed":
        c.run("activate", ALLOY_TEST_START_FAIL="1").assert_failure()
    else:
        c.run("activate", PLATFORM_ALLOY_INITIAL_CRASH_AT="after-start").assert_failure()
    # Only the clock changes: authenticated certs, source metadata and receipts
    # stay byte-for-byte intact, and the leaves are still currently valid.
    clock = clock_with_remaining(c, 3600)
    before = tree_snapshot(c.root)
    if outcome == "interrupted":
        assert result_json(c.run("status", future=clock))["status"] == "recovery-required"
        assert tree_snapshot(c.root) == before
        assert result_json(c.run("recover", future=clock)) == {"schema": 1, "status": "failed", "changed": True}
        assert c.log.read_text().splitlines() == ["enable --now alloy.service", "disable --now alloy.service"]
    else:
        for action in ("check", "status", "recover"):
            assert result_json(c.run(action, future=clock)) == {"schema": 1, "status": outcome, "changed": False}
        if outcome == "complete":
            assert result_json(c.run("activate", future=clock))["changed"] is False
        else:
            c.run("activate", future=clock).assert_failure()
        assert tree_snapshot(c.root) == before


def test_start_margin_rechecked_after_intent_before_enable(initial_case):
    c = initial_case
    after_intent = clock_with_remaining(c, 86400)
    # With signed hold=1 the initial threshold is 86401, not a generic 30 days.
    script = f"""
import runpy, sys, time
module = runpy.run_path(sys.argv[1])
original = module['Initial'].write_record
time.time = lambda: {after_intent - 60}
def publish(self, state, status, evidence):
    original(self, state, status, evidence)
    if status == 'intent':
        time.time = lambda: {after_intent}
module['Initial'].write_record = publish
module['Initial'](sys.argv[2]).execute('activate')
"""
    c.namespace_root_runner.run(
        ["python3", "-I", "-c", script, c.helper, c.context_path], environment=c.environment,
    ).assert_failure()
    assert c.log.read_text().splitlines() == ["disable --now alloy.service"]
    assert (c.state / "failed.json").exists() and not (c.state / "complete.json").exists()
    assert c.service_state.read_text() == "inactive disabled"


@pytest.mark.parametrize("initial_case", [("loki",), ("mimir",)], indirect=True, ids=["loki", "mimir"])
def test_one_writer_subset(initial_case, ready_server):
    c = initial_case
    assert result_json(c.run("activate"))["status"] == "complete"
    receipt = json.loads((c.state / "complete.json").read_bytes())
    assert set(receipt["evidence"]["writers"]) == set(c.writers)


def test_native_validation_and_partial_enable_failure(initial_case):
    c = initial_case
    before = tree_snapshot(c.root)
    c.run("activate", ALLOY_TEST_VALIDATE_FAIL="1").assert_failure()
    assert tree_snapshot(c.root) == before and not c.log.exists()
    c.run("activate", ALLOY_TEST_START_FAIL="1").assert_failure()
    assert c.log.read_text().splitlines() == ["enable --now alloy.service", "disable --now alloy.service"]
    assert (c.state / "failed.json").exists()


def test_boundary_binds_counterpart_ca_and_all_writers(initial_case):
    c = initial_case
    original = result_json(c.run("boundary"))
    ca = Path(c.writers["mimir"]["ca_file"])
    private_file(ca, c.cases["mimir"].reviewed_ca.read_bytes() + b"\n", 0o644)
    c.context["writers"]["mimir"]["ca_sha256"] = digest(ca)
    private_file(c.context_path, json.dumps(c.context))
    changed = result_json(c.run("boundary"))
    assert all(original[name] != changed[name] for name in original)
    c.run("activate").assert_failure()
    del c.context["writers"]["mimir"]
    private_file(c.context_path, json.dumps(c.context))
    c.run("boundary").assert_failure()
    assert not c.log.exists()


def test_real_signed_distinct_subjects_cannot_share_spki(initial_case):
    c = initial_case
    case = c.cases["mimir"]
    key_bytes = (c.cases["loki"].pending / "tls.key").read_bytes()
    private_file(case.pending / "tls.key", key_bytes)
    key = serialization.load_pem_private_key(key_bytes, None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    spki = case.module.spki_digest(key.public_key())
    replace_request(case, csr_spki_sha256=spki)
    old_csr = x509.load_pem_x509_csr((case.pending / "tls.csr").read_bytes())
    csr = x509.CertificateSigningRequestBuilder().subject_name(old_csr.subject).sign(key, hashes.SHA384())
    issue_response(case, subject=old_csr.subject, csr=csr)
    source = case.root / "response-source"
    response = case.module.parse_record((source / "response").read_bytes(), case.module.RESPONSE_V2_FIELDS, "fixture")
    response.update(csr_spki_sha256=spki, certificate_spki_sha256=spki)
    private_file(source / "response", record(case.module.RESPONSE_V2_FIELDS, response))
    signed(case, source / "response", case.module.RESPONSE_NAMESPACE_V2)
    artifact = case.module.parse_record((source / "artifact").read_bytes(), case.module.ARTIFACT_FIELDS, "fixture")
    artifact.update(certificate_spki_sha256=spki, source_response_sha256=digest(source / "response"),
                    source_response_signature_sha256=digest(source / "response.sig"))
    private_file(source / "artifact", record(case.module.ARTIFACT_FIELDS, artifact))
    for name in case.module.VERSION_NAMES:
        origin = case.pending if name in ("tls.key", "tls.csr") else source
        private_file(case.versions_root / REQUEST_ID / name, (origin / name).read_bytes())
    before = tree_snapshot(c.root)
    failure = c.run("activate").assert_failure()
    assert "writer keys collide" in failure.stderr
    assert tree_snapshot(c.root) == before and not c.log.exists()
