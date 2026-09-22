# Native Alloy Initial Activation Qualification

Opt-in tests for `roles/grafana_alloy/files/platform-alloy-initial-activate`
against the official SHA-256-pinned Alloy **1.18.1** RPM in a disposable Rocky 10
systemd container. Run from the repository root:

```bash
PLATFORM_TOOLS_TEST_SOURCE=/absolute/path/to/reviewed/public/platform-tools \
PLATFORM_ALLOY_TEST_IMAGE=sha256:<full-reviewed-local-config-dev-image-id> \
  bash tests/integration/test-alloy-initial-activation.sh
```

## Inputs and Isolation

- Select an already-built config development image by full immutable ID or
  digest reference. It must contain the repository's existing Python test
  dependencies, OpenSSL, and `ssh-keygen`. The script uses `--pull=never` for
  this image and does not build images or install Python packages with pip.
- Select exactly one tools input: `PLATFORM_TOOLS_TEST_SOURCE` mounts reviewed
  public source read-only and verifies that `bin/platform-pki` matches its
  deterministic builder; alternatively, `PLATFORM_ALLOY_TEST_PKI_ZIPAPP` mounts
  an explicitly reviewed generated artifact read-only. Artifact-only mode cannot
  verify its source freshness. The selected artifact's digest is printed and
  pinned in the synthetic context.
- `PLATFORM_ALLOY_TEST_ROCKY_IMAGE` defaults to
  `docker.io/rockylinux/rockylinux:10.1`. Rocky installs systemd and existing helper
  prerequisites (`python3-cryptography`, OpenSSL, OpenSSH clients), plus curl/tar.
  The lane copies the cached `.artifacts/alloy-1.18.1-1.amd64.rpm` when present,
  otherwise downloads it inside the target. It checks the fixed SHA-256 before
  installing and checks native NEVRA, version, RPM manifest, and unit ownership.
- The target is rootless Podman's privileged disposable systemd container, using
  private container networking and no published ports, engine socket, private
  inventory, or managed hosts. Only the three kernel mount failures allowlisted
  by the existing Rocky integration pattern may explain degraded systemd.
- Every command deadline runs inside its container. Cleanup uses recorded full
  container IDs, never names, and removes the invocation-local transfer archive.

## Coverage

`build.py` reuses existing test crypto builders in a separate disposable
preparer. It renders both writers from the actual role templates, obtains the
helper's normalized boundaries with a draft full inventory snapshot, verifies
request-ID normalization, then updates the snapshot and re-signs both requests
and responses. Only explicit PKI/config/helper paths cross to Rocky; the existing
fixture's fake systemctl and other unrelated files are excluded.

`native.py` checks the real fixed paths, prepared read-only check, successful
enable/start and HTTP `/-/ready` 200, complete receipt, and unchanged
activate/check/status/recover replays including the same PID and invocation.
Config, certificate, key, trust, inventory, helper, and stage snapshots must remain
unchanged. Tampered config boundary, inventory bytes, and inventory bytes with a
rebound local context digest must reject before enable/start or journal creation.
Read-only `renewal-preflight` rejects prepared state, then authenticates both
writer selections after completion with matching receipt/inventory bindings,
positive validity, unchanged input/record metadata and the same PID/invocation.

`fault.py` traces the unmodified helper at native paths. For readiness failure it
first proves actual Alloy HTTP 200, pauses that process with SIGSTOP, and resumes
it before native rollback. The helper must report verified disabled/inactive
state and retain a failed receipt. For interruption it exits immediately after
the durable journal; recovery must remain stopped and write a failed receipt.
Only the test harness discards verified failed receipts between independent
scenarios in this disposable container. This is not an operational recovery
procedure or authorization to reuse a failed activation.

## Qualification Limits

Synthetic private keys are generated in the preparer and transferred to the
target. This lane makes **no new host-local key-custody proof**; native signing
interoperability is a separate qualification. HTTP 200 proves local readiness,
not ingestion, real Loki/Mimir or HAProxy acceptance. These tests qualify initial
start and read-only first-predecessor observation, not renewal, selectors,
Ansible orchestration, managed-host SELinux, production networking, or complete
monitoring/CI deployment.
