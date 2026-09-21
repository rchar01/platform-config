from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from ansible_test_helpers import run_playbook
from conftest import CommandRunner


ROLE = "roles/grafana_alloy"
FIXTURE = "tests/fixtures/grafana-alloy-tls"
LOKI = "grafana_alloy_loki_"
MIMIR = "grafana_alloy_prometheus_remote_write_"
TLS_FIELDS = ("ca_file", "server_name", "client_cert_file", "client_key_file")
LOKI_URL = "https://logs.example.invalid:8443/custom/push"
LOKI_TLS = {
    LOKI + "ca_file": "/etc/alloy/pki/loki/ca.crt",
    LOKI + "server_name": "logs.example.invalid",
    LOKI + "client_cert_file": "/etc/alloy/pki/loki/writer.crt",
    LOKI + "client_key_file": "/etc/alloy/pki/loki/writer.key",
}
MIMIR_TLS = {
    MIMIR + "url": "https://metrics.example.invalid/api/v1/push",
    MIMIR + "ca_file": "/etc/alloy/pki/mimir/ca.crt",
    MIMIR + "server_name": "metrics.example.invalid",
    MIMIR + "client_cert_file": "/etc/alloy/pki/mimir/writer.crt",
    MIMIR + "client_key_file": "/etc/alloy/pki/mimir/writer.key",
}


def _inputs(**overrides: Any) -> dict[str, Any]:
    return {
        "grafana_alloy_enabled": True,
        **{prefix + field: "" for prefix in (LOKI, MIMIR) for field in TLS_FIELDS},
        LOKI + "url": LOKI_URL,
        MIMIR + "url": "",
        **overrides,
    }


def _playbook(
    directory: Path, tasks: list[dict[str, Any]], **play_options: Any
) -> Path:
    path = directory / "playbook.yml"
    path.write_text(
        yaml.safe_dump(
            [{
                "name": "Exercise the real Grafana Alloy TLS contract",
                "hosts": "localhost",
                "connection": "local",
                "gather_facts": False,
                **play_options,
                "tasks": tasks,
            }],
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def _component(config: str, declaration: str) -> str:
    # Alloy's top-level closing brace is unindented; nested TLS blocks are not.
    match = re.search(rf"^{re.escape(declaration)} \{{\n.*?^\}}$", config, re.M | re.S)
    assert match is not None, declaration
    return match.group()


def _assignment(component: str, name: str, value: Any) -> None:
    assert re.search(
        rf"^\s*{re.escape(name)}\s*=\s*{re.escape(json.dumps(value))}\s*$",
        component,
        re.M,
    ), (name, value, component)


def test_loki_tls_defaults_are_empty_strings(repo_root: Path) -> None:
    defaults = yaml.safe_load((repo_root / ROLE / "defaults/main.yml").read_text())
    for field in TLS_FIELDS:
        assert defaults[LOKI + field] == ""


def test_render_loki_tls_and_independent_mimir_credentials(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    cases = {
        "mtls": _inputs(**LOKI_TLS, **MIMIR_TLS),
        "ca-only": _inputs(**{
            LOKI + "ca_file": LOKI_TLS[LOKI + "ca_file"],
            LOKI + "server_name": LOKI_TLS[LOKI + "server_name"],
        }),
        "system-trust": _inputs(),
        "empty": _inputs(**{LOKI + "url": ""}),
    }
    playbook = _playbook(isolated_test_dir, [
        {
            "name": "Render file references without opening credential files",
            "ansible.builtin.template": {
                "src": str(repo_root / ROLE / "templates/config.alloy.j2"),
                "dest": str(isolated_test_dir / "{{ item.name }}.alloy"),
                "mode": "0600",
            },
            "vars": {name: "{{ item.variables." + name + " }}" for name in _inputs()},
            "loop": [{"name": name, "variables": values} for name, values in cases.items()],
            "loop_control": {"label": "{{ item.name }}"},
        },
    ], vars_files=[str(repo_root / ROLE / "defaults/main.yml")])
    run_playbook(command_runner, playbook, extra_vars=({
        "grafana_alloy_environment": "tls-test",
        "grafana_alloy_vm_name": "collector-example",
        "grafana_alloy_ip": "192.0.2.10",
        "grafana_alloy_platform_role": "vm",
        "grafana_alloy_feature_config": '// synthetic feature remains composed\n',
    },)).assert_success()
    rendered = {
        name: (isolated_test_dir / f"{name}.alloy").read_text() for name in cases
    }
    loki = _component(rendered["mtls"], 'loki.write "default"')
    mimir = _component(rendered["mtls"], 'prometheus.remote_write "platform_metrics"')
    for component, prefix, values in ((loki, LOKI, LOKI_TLS), (mimir, MIMIR, MIMIR_TLS)):
        for setting, field in (
            ("ca_file", "ca_file"), ("server_name", "server_name"),
            ("cert_file", "client_cert_file"), ("key_file", "client_key_file"),
        ):
            _assignment(component, setting, values[prefix + field])
        _assignment(component, "min_version", "TLS12")
        _assignment(component, "insecure_skip_verify", False)
        _assignment(component, "follow_redirects", False)
    _assignment(loki, "url", LOKI_URL)
    _assignment(mimir, "url", MIMIR_TLS[MIMIR + "url"])
    assert "/mimir/" not in loki
    assert "/loki/" not in mimir

    ca_only = _component(rendered["ca-only"], 'loki.write "default"')
    _assignment(ca_only, "ca_file", LOKI_TLS[LOKI + "ca_file"])
    _assignment(ca_only, "server_name", LOKI_TLS[LOKI + "server_name"])
    _assignment(ca_only, "min_version", "TLS12")
    _assignment(ca_only, "insecure_skip_verify", False)
    assert not re.search(r"\b(?:cert_file|key_file)\s*=", ca_only)
    system_trust = _component(rendered["system-trust"], 'loki.write "default"')
    assert not re.search(r"\b(?:ca_file|server_name|cert_file|key_file)\s*=", system_trust)
    for name in ("mtls", "ca-only", "system-trust"):
        config = rendered[name]
        _assignment(_component(config, 'loki.write "default"'), "follow_redirects", False)
        relabel = _component(config, 'loki.relabel "journal"')
        assert "forward_to = [loki.write.default.receiver]" in relabel
        for source, target in (
            ("__journal__systemd_unit", "unit"),
            ("__journal_container_name", "container"),
            ("__journal_priority_keyword", "level"),
        ):
            assert re.search(
                rf'\brule\s*\{{\s*source_labels\s*=\s*\["{source}"\]'
                rf'\s*target_label\s*=\s*"{target}"\s*\}}', relabel,
            )
        journal = _component(config, 'loki.source.journal "system"')
        assert "forward_to = [loki.relabel.journal.receiver]" in journal
        for key, value in (
            ("path", "/var/log/journal"), ("max_age", "12h"),
        ):
            _assignment(journal, key, value)
        for key, value in (
            ("job", "systemd-journal"), ("environment", "tls-test"),
            ("vm_name", "collector-example"), ("ip", "192.0.2.10"),
            ("platform_role", "vm"),
        ):
            assert re.search(rf'\b{key}\s*=\s*"{re.escape(value)}",', journal)
        assert "// synthetic feature remains composed" in config
    assert "loki." not in rendered["empty"]
    assert "tls_config" not in rendered["empty"]
    assert "// synthetic feature remains composed" in rendered["empty"]


def _rejection_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    def add(name: str, overrides: dict[str, Any], *, mtls: bool = True) -> None:
        cases.append({
            "name": name,
            "variables": _inputs(**{**(LOKI_TLS if mtls else {}), **overrides}),
        })

    for field in TLS_FIELDS:
        for label, value in (
            ("null", None), ("bool", False), ("number", 42),
            ("list", []), ("mapping", {}),
        ):
            add(f"{field}-{label}", {LOKI + field: value})
    for field in ("ca_file", "client_cert_file", "client_key_file"):
        for label, value in (
            ("relative", "etc/alloy/tls.pem"),
            ("root", "/"),
            ("trailing-slash", "/etc/alloy/tls.pem/"),
            ("empty-segment", "/etc//alloy/tls.pem"),
            ("double-leading-slash", "//etc/alloy/tls.pem"),
            ("dot", "/etc/./alloy/tls.pem"),
            ("dotdot", "/etc/alloy/../tls.pem"),
            ("space", "/etc/alloy/tls file.pem"),
            ("quote", '/etc/alloy/tls".pem'),
            ("backslash", "/etc/alloy/tls\\file.pem"),
            ("newline", "/etc/alloy/tls.pem\n"),
            ("control", "/etc/alloy/tls\x01.pem"),
            ("tab", "/etc/alloy/tls\t.pem"),
            ("delete", "/etc/alloy/tls\x7f.pem"),
        ):
            add(f"{field}-{label}", {LOKI + field: value})
    for label, value in (
        ("space", "logs example.invalid"),
        ("path", "logs.example.invalid/push"),
        ("url", "https://logs.example.invalid"),
        ("port", "logs.example.invalid:443"),
        ("empty-label", "logs..example.invalid"),
        ("leading-hyphen", "-logs.example.invalid"),
        ("trailing-hyphen", "logs-.example.invalid"),
        ("underscore", "logs_example.invalid"),
        ("wildcard", "*.example.invalid"),
        ("long-label", "a" * 64 + ".example.invalid"),
        ("long-name", ".".join(["a" * 63] * 4)),
        ("newline", "logs.example.invalid\n"),
        ("control", "logs\x01.example.invalid"),
    ):
        add(f"server-name-{label}", {LOKI + "server_name": value})
    for label, value in (
        ("http", "http://logs.example.invalid/push"),
        ("userinfo", "https://user:synthetic@logs.example.invalid/push"),
        ("username", "https://user@logs.example.invalid/push"),
        ("missing-host", "https:///push"),
        ("empty-authority", "https://"),
        ("colon-only", "https://:"),
        ("nonnumeric-port", "https://logs.example.invalid:invalid/push"),
        ("empty-port", "https://logs.example.invalid:/push"),
        ("port-zero", "https://logs.example.invalid:0/push"),
        ("port-too-large", "https://logs.example.invalid:65536/push"),
        ("port-negative", "https://logs.example.invalid:-1/push"),
        ("ipv6-bad-address", "https://[2001:::1]/push"),
        ("ipv6-no-closing-bracket", "https://[::1/push"),
        ("ipv6-suffix", "https://[::1]bad/push"),
        ("ipv6-unbracketed", "https://2001:db8::1/push"),
        ("ipv6-zone", "https://[fe80::1%25eth0]/push"),
        ("bad-ipv4", "https://999.1.1.1/push"),
        ("bad-dns", "https://logs..example.invalid/push"),
        ("long-host", "https://" + "a" * 64 + ".invalid/push"),
        ("whitespace", "https://logs.example.invalid/p ush"),
        ("fragment", "https://logs.example.invalid/push#fragment"),
        ("newline", "https://logs.example.invalid/push\n"),
        ("null", None), ("number", 42), ("list", []), ("mapping", {}),
    ):
        add(f"url-{label}", {LOKI + "url": value}, mtls=False)
    for field in TLS_FIELDS:
        add(f"unpaired-{field}", {LOKI + field: LOKI_TLS[LOKI + field]}, mtls=False)
        # Keep a valid Mimir output so an orphan cannot fail the at-least-one-output guard.
        add(f"orphan-{field}", {
            LOKI + "url": "",
            LOKI + field: LOKI_TLS[LOKI + field],
            MIMIR + "url": MIMIR_TLS[MIMIR + "url"],
        }, mtls=False)
    for field in ("client_cert_file", "client_key_file"):
        add(f"missing-{field}-with-ca", {LOKI + field: ""})
    add("orphan-ca-pair", {
        LOKI + "url": "",
        LOKI + "ca_file": LOKI_TLS[LOKI + "ca_file"],
        LOKI + "server_name": LOKI_TLS[LOKI + "server_name"],
        MIMIR + "url": MIMIR_TLS[MIMIR + "url"],
    }, mtls=False)
    add("orphan-complete-tls", {
        LOKI + "url": "", MIMIR + "url": MIMIR_TLS[MIMIR + "url"],
    })
    add("client-pair-without-ca", {
        LOKI + "ca_file": "", LOKI + "server_name": "",
    })
    add("same-client-cert-and-key", {
        LOKI + "client_key_file": LOKI_TLS[LOKI + "client_cert_file"],
    })
    for field in ("client_cert_file", "client_key_file"):
        add(f"shared-mimir-{field}", {
            **MIMIR_TLS, MIMIR + field: LOKI_TLS[LOKI + field],
        })
    add("shared-mimir-client-pair", {
        **MIMIR_TLS,
        **{MIMIR + field: LOKI_TLS[LOKI + field]
           for field in ("client_cert_file", "client_key_file")},
    })
    return cases


def _evidence_environment(repo_root: Path, directory: Path) -> dict[str, str]:
    # Add narrowly scoped task-argument evidence to the existing callback in
    # test scratch. Keep its failed-loop and error reporting intact.
    callbacks = directory / "callback_plugins"
    callbacks.mkdir(exist_ok=True)
    source = (repo_root / FIXTURE / "callback_plugins/alloy_tls_evidence.py").read_text()
    anchor = '"action": result._task.action,'
    assert source.count(anchor) == 1
    source = source.replace(anchor, anchor + '''
            "args": value.get("invocation", {}).get("module_args", result._task.args)
                if result._task.action == "ansible.builtin.stat" else {},
            "check_mode": result._task.check_mode,''')
    (callbacks / "alloy_tls_evidence.py").write_text(source)
    return {
        "ANSIBLE_CALLBACK_PLUGINS": str(callbacks),
        "ANSIBLE_CALLBACKS_ENABLED": "alloy_tls_evidence",
        "ALLOY_TLS_TEST_EVIDENCE": str(directory / "events.jsonl"),
    }


def _events(directory: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()]


def _assert_guard_stat(event: dict[str, Any], *, path: str = "/var/lib/platform-config/pki/alloy/process-owner") -> None:
    assert event["action"] == "ansible.builtin.stat", event
    assert event["name"].endswith("Inspect Grafana Alloy initial process-owner root without following links"), event
    assert event["status"] == "ok" and event["changed"] is False, event
    assert event["check_mode"] is False, event
    assert event["args"]["path"] == path, event
    for field in ("follow", "get_checksum", "get_mime", "get_attributes"):
        assert event["args"][field] is False, event


def _assert_input_only(events: list[dict[str, Any]]) -> None:
    assert events, "The real preflight must produce callback evidence"
    # Only the fixed metadata-only takeover guard may inspect the target before
    # input rejection. No other stat, helper, package or mutation is allowed.
    # Skipped tasks are not execution evidence.
    allowed = {"assert", "set_fact", "include_role", "include_tasks"}
    for event in events:
        if event["action"] == "ansible.builtin.stat":
            _assert_guard_stat(event)
        else:
            assert event["action"].removeprefix("ansible.builtin.") in allowed, event
    assert not any(event["changed"] or event["status"] == "unreachable" for event in events), events


def _assert_loki_rejection(event: dict[str, Any]) -> None:
    assert event["status"] == "failed", event
    assert event["action"] == "ansible.builtin.assert", event
    assert event["failed"] is True, json.dumps(event)
    assert "error" not in event["errors"], event
    assert event["errors"].get("exception", "(traceback unavailable)") == "(traceback unavailable)", event
    assert event["failed_assertions"], event
    for failure in event["failed_assertions"]:
        assert failure.get("failed", True) is True, failure
        assert failure.get("evaluated_to") is False, failure
        assert isinstance(failure.get("assertion"), str), failure
        assert "grafana_alloy_loki_" in failure["assertion"], failure
        assert not {"error", "results"}.intersection(failure), failure
        assert failure.get("exception", "(traceback unavailable)") == "(traceback unavailable)", failure
        assert not failure.get("changed", False), failure


def test_preflight_batches_invalid_loki_inputs_before_file_inspection(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    cases = _rejection_cases()
    playbook = _playbook(isolated_test_dir, [{
        "name": "Batch invalid inputs through the real preflight",
        "ansible.builtin.include_tasks": str(repo_root / FIXTURE / "reject-case.yml"),
        "vars": {name: "{{ tls_case.variables." + name + " }}" for name in _inputs()},
        "loop": cases,
        "loop_control": {"loop_var": "tls_case", "label": "{{ tls_case.name }}"},
    }])
    run_playbook(
        command_runner, playbook,
        environment=_evidence_environment(repo_root, isolated_test_dir), timeout=180,
    ).assert_success()
    events = _events(isolated_test_dir)
    _assert_input_only(events)
    rejected = [event for event in events if event["status"] == "failed"]
    assert len(rejected) == len(cases)
    for event in rejected:
        _assert_loki_rejection(event)


def test_preflight_accepts_generic_loki_url_with_system_trust(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    playbook = _playbook(isolated_test_dir, [{
        "name": "Validate a generic HTTPS push URL without private TLS files",
        "ansible.builtin.include_role": {"name": "grafana_alloy", "tasks_from": "preflight.yml"},
        "vars": _inputs(**{LOKI + "url": "{{ tls_url }}"}),
        "loop": [
            LOKI_URL,
            "https://127.0.0.1:443/loki/api/v1/push",
            "https://[::1]:8443/loki/api/v1/push",
            "https://[2001:db8::1]/loki/api/v1/push",
            "https://logs.example.invalid.:65535/custom/push?tenant=test",
        ],
        "loop_control": {"loop_var": "tls_url"},
    }])
    run_playbook(
        command_runner, playbook,
        environment=_evidence_environment(repo_root, isolated_test_dir),
    ).assert_success()
    events = _events(isolated_test_dir)
    _assert_input_only(events)
    assert any(event["action"] == "ansible.builtin.assert" for event in events)


def test_normal_role_rejects_loki_input_before_host_inspection_or_mutation(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    sentinel = isolated_test_dir / "mutation-sentinel"
    impossible_root = "/proc/grafana-alloy-tls-tests-must-not-exist"
    playbook = _playbook(isolated_test_dir, [
        {
            "name": "Exercise the normal role entry point with invalid Loki TLS",
            "ansible.builtin.include_role": {"name": "grafana_alloy"},
            "vars": _inputs(**{
                LOKI + "ca_file": impossible_root + "/ca.crt",
                "grafana_alloy_config_dir": impossible_root,
                "grafana_alloy_config_path": impossible_root + "/config.alloy",
                "grafana_alloy_cache_dir": impossible_root + "/cache",
                "grafana_alloy_storage_dir": impossible_root + "/data",
            }),
        },
        {
            "name": "Mutation sentinel after normal role",
            "ansible.builtin.copy": {"dest": str(sentinel), "content": "reached", "mode": "0600"},
        },
    ], vars={
        "rocky_repository_policy_enabled": True,
        "rocky_repository_policy_releasever": "10",
        "rocky_repository_policy": {"fixture": {"enabled": True}},
    })
    result = run_playbook(
        command_runner, playbook,
        environment=_evidence_environment(repo_root, isolated_test_dir),
    )
    result.assert_failure()
    assert not sentinel.exists(), result.diagnostics()
    events = _events(isolated_test_dir)
    _assert_input_only(events)
    failed = [event for event in events if event["status"] == "failed"]
    assert len(failed) == 1, events
    _assert_loki_rejection(failed[0])


def test_all_host_preflight_blocks_mutation_when_second_host_has_invalid_tls(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    inventory = isolated_test_dir / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {"hosts": {
        "collector-first": {"ansible_host": "localhost", **_inputs()},
        "collector-second": {"ansible_host": "localhost", **_inputs(**{
            LOKI + "ca_file": "/etc/alloy/pki/loki/ca.crt",
        })},
    }}}), encoding="utf-8")
    playbook = _playbook(isolated_test_dir, [
        {
            "name": "Run real preflight on every selected host before convergence",
            "ansible.builtin.include_role": {"name": "grafana_alloy", "tasks_from": "preflight.yml"},
        },
        {
            "name": "Mutation sentinel after the all-host barrier",
            "ansible.builtin.copy": {
                "dest": str(isolated_test_dir / "sentinel-{{ inventory_hostname }}"),
                "content": "reached", "mode": "0600",
            },
        },
    ], hosts="all", strategy="linear", any_errors_fatal=True, vars={
        "rocky_repository_policy_enabled": True,
        "rocky_repository_policy_releasever": "10",
        "rocky_repository_policy": {"fixture": {"enabled": True}},
    })
    result = run_playbook(
        command_runner, playbook, inventory=inventory,
        environment=_evidence_environment(repo_root, isolated_test_dir),
    )
    result.assert_failure()
    assert not list(isolated_test_dir.glob("sentinel-*")), result.diagnostics()
    events = _events(isolated_test_dir)
    _assert_input_only(events)
    failed = [event for event in events if event["status"] == "failed"]
    assert len(failed) == 1, events
    assert failed[0]["host"] == "collector-second"
    _assert_loki_rejection(failed[0])
    assert any(
        event["host"] == "collector-first" and event["name"] == failed[0]["name"]
        and event["status"] == "ok" for event in events
    ), events
