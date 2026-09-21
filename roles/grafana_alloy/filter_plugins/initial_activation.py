"""Controller bridge to the shipped initial-only helper, never its target runtime."""

import base64
import functools
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

from ansible.errors import AnsibleFilterError


ROLE = Path(__file__).resolve().parents[1]
PREFIXES = {"loki": "grafana_alloy_loki_", "mimir": "grafana_alloy_prometheus_remote_write_"}


@functools.lru_cache(maxsize=1)
def helper():
    # The source path is repository-owned, never an inventory argument. Importing
    # this file executes stdlib definitions only, not Initial or the tools parser.
    loader = importlib.machinery.SourceFileLoader(
        "platform_alloy_initial_boundary", str(ROLE / "files/platform-alloy-initial-activate")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def sanitized(function):
    @functools.wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            raise AnsibleFilterError("Alloy initial inputs rejected: " + function.__name__) from None
    return call


def require(condition):
    if not condition:
        raise ValueError("invalid initial input")


def text(value, pattern):
    require(isinstance(value, str) and re.fullmatch(pattern, value) is not None)
    return value


def safe_path(value):
    text(value, r"/[A-Za-z0-9_./-]+")
    require(value != "/" and os.path.normpath(value) == value and "//" not in value)
    return value


def sha(value):
    return text(value, r"[0-9a-f]{64}")


def dns(value):
    text(value, r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
    require(len(value) <= 253)


@sanitized
def validate(values, boundary=False):
    h = helper()
    require(type(boundary) is bool)
    for key in ("enabled", "service_enabled"):
        require(type(values["grafana_alloy_" + key]) is bool)
    require(values["grafana_alloy_service_state"] in ("started", "stopped"))
    require(values["grafana_alloy_service_enabled"] == (values["grafana_alloy_service_state"] == "started"))
    fixed = {"service_name": "alloy.service", "config_dir": "/etc/alloy", "config_path": h.CONFIG,
             "storage_dir": "/var/lib/alloy/data", "http_listen_address": "127.0.0.1",
             "http_listen_port": 12345, "package_nevra": h.NEVRA, "version": "1.18.1",
             "arch": "amd64", "config_validate_command": "/usr/bin/alloy validate %s"}
    for key, expected in fixed.items():
        value = values["grafana_alloy_" + key]
        require(type(value) is not bool and value == expected)
    for key in ("environment", "vm_name", "ip", "platform_role", "feature_config", "journal_max_age"):
        require(isinstance(values["grafana_alloy_" + key], str))
    labels = values["grafana_alloy_external_labels"]
    require(isinstance(labels, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items()))
    text(values["grafana_alloy_prometheus_wal_max_keepalive_time"], r"[1-9][0-9]*[hms]")
    require(values["grafana_alloy_prometheus_remote_write_bearer_token_file"] == "")
    target = text(values["inventory_hostname"], r"[a-z0-9][a-z0-9.-]*")
    declared = values["grafana_alloy_initial_writers"]
    require(isinstance(declared, dict) and declared and set(declared) <= set(PREFIXES))
    writers, template_vars = {}, {}
    for name, prefix in PREFIXES.items():
        fields = {key: values[prefix + key] for key in
                  ("url", "ca_file", "server_name", "client_cert_file", "client_key_file")}
        require(all(isinstance(value, str) for value in fields.values()))
        if name not in declared:
            require(all(value == "" for value in fields.values()))
            continue
        w = declared[name]
        require(isinstance(w, dict) and set(w) == {"service", "trust_id", "ca_file", "ca_sha256"})
        for key in ("service", "trust_id"):
            text(w[key], r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
        safe_path(w["ca_file"])
        require(w["ca_file"].startswith("/etc/alloy/pki/") and w["ca_file"] == fields["ca_file"])
        sha(w["ca_sha256"])
        url = fields["url"]
        text(url, r"https://[^\s\x00-\x20\x7f-\uffff]+")
        parsed = urlsplit(url)
        require(parsed.hostname and parsed.username is None and parsed.password is None
                and not parsed.query and not parsed.fragment and not parsed.netloc.endswith(":"))
        require(parsed.port is None or 1 <= parsed.port <= 65535)
        dns(parsed.hostname)
        dns(fields["server_name"])
        writers[name] = {**w, "state_root": str(Path(h.STATE).parent / name),
                         "pending_root": f"/etc/alloy/pki/{name}/tls-pending",
                         "versions_root": f"/etc/alloy/pki/{name}/tls-versions"}
        version_root = writers[name]["versions_root"]
        if not boundary:
            match = re.fullmatch(re.escape(version_root) + r"/([0-9a-f]{32})/fullchain\.crt", fields["client_cert_file"])
            require(match is not None)
            require(fields["client_key_file"] == version_root + "/" + match[1] + "/tls.key")
        for field, basename in (("client_cert_file", "fullchain.crt"), ("client_key_file", "tls.key")):
            template_vars[prefix + field] = version_root + "/@VERSION@/" + basename
    require(len({w["service"] for w in writers.values()}) == len(writers))
    # CA references cannot alias control inputs or any writer lifecycle tree.
    reserved = [h.CONTEXT, "/etc/alloy/pki/inventory.yml"]
    reserved += [f"/etc/alloy/pki/{name}/{tree}" for name in PREFIXES for tree in ("tls-pending", "tls-versions")]
    for w in writers.values():
        require(all(w["ca_file"] != p and not w["ca_file"].startswith(p + "/")
                    and not p.startswith(w["ca_file"] + "/") for p in reserved))
    return {"target": target, "writers": writers, "template_vars": template_vars}


def source_identity(metadata):
    # A normal O_RDONLY read may advance atime under relatime. It must not
    # change any identity, ownership, permission or content-change evidence.
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
        metadata.st_mode, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def source_bytes(filename):
    """Bounded direct-file read, including every ancestor and a stable fd snapshot."""
    safe_path(filename)
    descriptors = [os.open("/", os.O_RDONLY | os.O_DIRECTORY)]
    try:
        for part in filename.split("/")[1:-1]:
            descriptors.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                       dir_fd=descriptors[-1]))
        fd = os.open(os.path.basename(filename), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=descriptors[-1])
        descriptors.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= helper().MAXIMUM)
        chunks, remaining = [], helper().MAXIMUM + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        require(len(data) == before.st_size and source_identity(os.fstat(fd)) == source_identity(before)
                and source_identity(os.stat(os.path.basename(filename), dir_fd=descriptors[-2], follow_symlinks=False))
                == source_identity(before))
        return data
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


@sanitized
def sources(values, boundary=False):
    h = helper()
    inventory = source_bytes(values["grafana_alloy_initial_inventory_src"])
    require(h.digest(inventory) == sha(values["grafana_alloy_initial_inventory_sha256"]))
    result = {"inventory": inventory.decode("utf-8"), "inventory_sha256": h.digest(inventory)}
    artifact = source_bytes(values["grafana_alloy_initial_platform_pki_src"])
    require(h.digest(artifact) == sha(values["grafana_alloy_initial_platform_pki_sha256"]))
    result.update(platform_pki=base64.b64encode(artifact).decode("ascii"), platform_pki_sha256=h.digest(artifact))
    if not boundary:
        for key, filename in (("helper", ROLE / "files/platform-alloy-initial-activate"),
                              ("lifecycle", ROLE.parent / "pki_host_local_certificate/files/platform-pki-host-local-lifecycle")):
            data = source_bytes(str(filename))
            result[key] = data.decode("utf-8")
            result[key + "_sha256"] = h.digest(data)
    return result


@sanitized
def boundary(plan, inputs, config, dropin):
    h = helper()
    inventory = inputs["inventory"].encode("utf-8")
    require(0 < len(inventory) <= h.MAXIMUM and h.digest(inventory) == sha(inputs["inventory_sha256"]))
    require(0 < len(inputs["platform_pki"]) <= 4 * ((h.MAXIMUM + 2) // 3))
    artifact = base64.b64decode(inputs["platform_pki"], validate=True)
    require(h.digest(artifact) == sha(inputs["platform_pki_sha256"]))
    # Reauthenticate the in-memory snapshots before executing the pinned module.
    # Use the same full byte parser and service projection as target Initial.
    parser = h.load_inventory_parser(artifact)
    services = {service.name: service for service in parser.parse_inventory(inventory).services}
    subjects = {}
    for name, writer in plan["writers"].items():
        service = services[writer["service"]]
        require(service.profile == h.PROFILE and service.target == plan["target"]
                and service.key_custody == "host-local" and service.days is not None
                and service.rollback_hold_seconds is not None)
        require(int(service.rollback_hold_seconds) > 0)
        subjects[name] = service.subject_dn
    require(len(set(subjects.values())) == len(subjects))
    return h.boundary_digests(plan["target"], subjects, plan["writers"], config.encode("ascii"), dropin.encode("ascii"))


@sanitized
def build(plan, inputs, config, dropin):
    h = helper()
    context = {"schema": 1, "target": plan["target"], "writers": plan["writers"],
               "inventory_path": "/etc/alloy/pki/inventory.yml", "inventory_sha256": inputs["inventory_sha256"],
               "platform_pki_path": h.PKI, "platform_pki_sha256": inputs["platform_pki_sha256"],
               "lifecycle_helper_path": h.HELPER, "lifecycle_helper_sha256": inputs["lifecycle_sha256"],
               "config_path": h.CONFIG, "dropin_path": h.DROPIN, "state_root": h.STATE, "package_nevra": h.NEVRA}
    context_text = h.canonical(context).decode("ascii")
    files = [
        {"path": h.HELPER, "mode": "0755", "sha256": inputs["lifecycle_sha256"], "required": True},
        # Compare installed bytes with current desired normal renders, never the
        # pre-CSR placeholders. These prerequisites have no publication content.
        {"path": h.CONFIG, "mode": "0640", "sha256": h.digest(config.encode("utf-8")), "required": True},
        {"path": h.DROPIN, "mode": "0644", "sha256": h.digest(dropin.encode("utf-8")), "required": True},
        {"path": "/usr/local/libexec/platform-alloy-initial-activate", "mode": "0755",
         "sha256": inputs["helper_sha256"], "content": inputs["helper"]},
        {"path": h.PKI, "mode": "0755", "sha256": inputs["platform_pki_sha256"],
         "content": inputs["platform_pki"], "base64": True},
        {"path": context["inventory_path"], "mode": "0600", "sha256": inputs["inventory_sha256"], "content": inputs["inventory"]},
        {"path": h.CONTEXT, "mode": "0600", "sha256": h.digest(context_text.encode("ascii")), "content": context_text},
        {"path": h.STATE + "/lock", "mode": "0600", "sha256": h.digest(b""), "content": ""},
    ]
    parents = set()
    for f in files:
        parents.update(str(p) for p in Path(f["path"]).parents)
    return {"files": files, "directories": sorted(parents, key=lambda p: (p.count("/"), p)), "context": context}


@sanitized
def outcome(value, action):
    require(isinstance(value, dict) and set(value) == {"schema", "status", "changed"})
    require(isinstance(value["schema"], int) and not isinstance(value["schema"], bool)
            and value["schema"] == 1 and type(value["changed"]) is bool)
    allowed = {"check": {"prepared", "complete", "failed"}, "status": {"prepared", "complete", "failed", "recovery-required"},
               "activate": {"complete"}, "recover": {"prepared", "complete", "failed"}}
    require(action in allowed and value["status"] in allowed[action])
    require(not value["changed"] or (action == "activate" and value["status"] == "complete")
            or (action == "recover" and value["status"] == "failed"))
    return value


class FilterModule:
    def filters(self):
        return {"grafana_alloy_initial_" + name: function for name, function in
                (("validate", validate), ("sources", sources), ("boundary", boundary),
                 ("build", build), ("outcome", outcome))}
