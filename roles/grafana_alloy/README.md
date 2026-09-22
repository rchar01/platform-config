# grafana_alloy

Owns the one host-native Grafana Alloy process used by Linux VM collection and
shared external probe features. The role pins the official Alloy `1.18.1`
`linux/amd64` RPM by SHA-256 and exact installed NEVRA, validates the complete
candidate configuration with that binary before replacement, and is disabled and
stopped by default.

Feature roles do not install, start, reload, or independently configure Alloy.
They contribute validated configuration through `grafana_alloy_feature_config`;
this role remains the sole owner of `/etc/alloy/config.alloy` and
`alloy.service`.

Multi-host orchestration can include `tasks_from: preflight.yml` on every host
before process-owner convergence. The normal role entry point runs the same
non-host-mutating validation before inspecting or changing the service owner.

At least one output is required when the role is enabled. Loki journal forwarding
uses `grafana_alloy_loki_url`. Prometheus features use the stable
`prometheus.remote_write.platform_metrics.receiver` component configured by
`grafana_alloy_prometheus_remote_write_*`. Authentication values are referenced
through restricted outside-Git files and are never rendered inline.

### Loki TLS Inputs

All four settings default to empty strings. Generic HTTPS outputs may use system
trust without client authentication; monitoring HAProxy requires the full mTLS set:

```yaml
grafana_alloy_loki_url: https://logs.example.invalid/loki/api/v1/push
grafana_alloy_loki_ca_file: /etc/alloy/pki/monitoring-server-ca.crt
grafana_alloy_loki_server_name: logs.example.invalid
grafana_alloy_loki_client_cert_file: /etc/alloy/pki/loki/writer-fullchain.crt
grafana_alloy_loki_client_key_file: /etc/alloy/pki/loki/writer.key
```

These are illustrative references to separately provisioned target-local files,
not paths this role creates. CA/server-name and certificate/key must be paired;
client authentication also requires explicit CA/server-name selection. TLS inputs
without a Loki URL are rejected. Loki and Mimir client paths must be separate.
The role renders `insecure_skip_verify = false`, `min_version = "TLS12"`, and
disables redirects on Loki writes, including generic system-trust outputs.

Enabled preflight rejects malformed HTTPS authorities, invalid ports, unsafe
paths, missing/empty files and unsafe metadata before package/config/service work,
including in check mode and the all-host observer preflight. Explicit TLS files
must be root:root single-link regular files; private keys must be `0400` or `0600`.
CA/certificate modes may be `0400`, `0440`, `0444`, `0600`, `0640`, or `0644`.
Ancestors must be root:root directories without group/other write permission.
Neither leaf nor ancestor symlinks are accepted in this initial direct-file slice.
Use a reviewed regular CA bundle, not a symlink to a system trust bundle.

Preflight inspects metadata without reading private-key contents into Ansible
facts. Native Alloy config validation checks file parsing/key pairing; actual
remote certificate/hostname/identity acceptance still requires delivery tests.
These are point-in-time checks, not filesystem locking: exclude concurrent
out-of-band credential/path edits during convergence and operation.

### Certificate Lifecycle And Verification

Ordinary convergence consumes direct credential files. The separate initial-start
entry points below authenticate already-staged versions before starting Alloy;
they do not select a `current` symlink, rotate certificates or create a PKI active
predecessor record. The client staging and initial process receipts are distinct.

The agreed [monitoring PKI direction](../../docs/pki-exchange-setup.md#monitoring-pki-direction)
reuses OpenBao's target-local key generation and offline signed exchange pattern.
`platform-tools` provides the generic `client-p384-sha384-v1` profile through
the same signed exchange: one exchange, two certificate profiles,
service-specific activation. The PKI role's
[issue-only client staging](../pki_host_local_certificate/README.md#initial-client-request-and-staging)
now generates requests and imports immutable versions without selecting them or
touching Alloy. Initial process activation is implemented below; certificate
renewal, rotation and post-completion rollback remain pending.
Host-native collectors will keep separate Loki and Mimir identities
and keys on their consuming hosts; tools inventory/review has no writer field
or Loki/Mimir enum. Monitoring selects 397-day leaves, begins renewal preparation
around 45 days before expiry and requires at least 30 days of valid, trusted,
unrevoked overlap/rollback after rotation. Full enforcement belongs to the pending
rotation adapters; tools require explicit days and a positive inventory-bound
rollback declaration without a generic 30-day minimum. Renewal/overlap handling and
Kubernetes Secret custody remain unimplemented; existing OpenBao certificates or
routes must not be reused for Alloy. Offline request/signing/staging evidence
does not establish live lifecycle or delivery qualification.

### Guarded Initial Start

The fixed initial path starts an **already installed and configured**, inactive,
boot-disabled Alloy `1.18.1`. It never writes Alloy configuration or credential
files during activation. All configured Loki/Mimir outputs must use authenticated
staged client versions at direct immutable paths, with strict mTLS and distinct
writer identities. Mimir bearer-token mode is outside this initial path.

The [fresh-install workflow](../../docs/alloy-initial-install.md) supplies fixed
public playbooks around these `tasks_from` entry points:

| Entry point | Purpose |
| --- | --- |
| `initial_boundary` | Controller-only pre-CSR boundary hashes; no target I/O |
| `initial_stage` | Reuse ordinary convergence only for an absent or inactive/disabled unit and stopped intent |
| `initial_prepare` | Verify stopped/disabled prerequisites and install absent exact control inputs |
| `initial_check` / `initial_status` | Read-only authenticated state observations; inspect the returned status |
| `initial_activate` | One fixed enable/start, readiness proof and durable initial receipt |
| `initial_recover` | Authenticate retained intent and restore disabled/stopped state; never retry activation |

Initial preparation/start/recovery require one literal host limit and apply mode.
Fresh stopped staging also requires that literal limit and supports check mode;
it rejects retained process ownership before ordinary convergence. Preparation
requires `grafana_alloy_enabled: true`, `grafana_alloy_service_enabled: false`,
and `grafana_alloy_service_state: stopped`; activation requires explicit
`true`/`started` service intent. No public Make/CI activation route is added.

Additional private inputs (empty by default):

- `grafana_alloy_initial_inventory_src` and `_inventory_sha256`: exact non-secret
  signer inventory snapshot, including other service definitions if present.
- `grafana_alloy_initial_platform_pki_src` and `_platform_pki_sha256`: reviewed
  generated tools artifact; reuse its inventory parser rather than another parser.
- `grafana_alloy_initial_writers`: nonempty `loki`/`mimir` mapping, each with
  `service`, `trust_id`, `ca_file`, and `ca_sha256`. The CA must match that output's
  ordinary role settings and reside under `/etc/alloy/pki`.

Writer roots are fixed at `/var/lib/platform-config/pki/alloy/<writer>` and
`/etc/alloy/pki/<writer>/{tls-pending,tls-versions}`. The root-only inventory and
context live at `/etc/alloy/pki/{inventory.yml,initial-activation.json}`. All
eight staged version files stay `0600`; Alloy remains root-run in this contract.
The existing lifecycle helper must exactly match the shipped source. Preparation
also verifies the current production-template bytes of the already-installed
config/drop-in and rejects drift without repair. Existing control inputs must
match exactly; preparation cannot overwrite them or clear a retained receipt.

**Order matters:** render `initial_boundary` with draft inventory, the pinned
tools artifact and intended role settings, review/insert its hashes into signer
inventory, then create/sign/
stage the requests against that final inventory digest. Configure stopped Alloy
with the resulting immutable version paths before running `initial_prepare`.
The shared boundary function normalizes only each writer's version directory ID
to `@VERSION@`, so it can be reviewed before the CSR exists. Config/drop-in bytes,
writer/service/DN/target, package identity, CA hashes and fixed path slots remain
bound. Planning and activation both reuse the exact tools parser, including
string-like inventory values such as country `NO`; generic YAML interpretation
is not authority. All configured writers must share the same reviewed inventory
snapshot. Activation checks its exact hash against every signed request.

Initial takeover must exclude ordinary convergence and other lifecycle work
procedurally. Once `/var/lib/platform-config/pki/alloy/process-owner` exists,
ordinary role tasks and handlers fail closed, including check mode. Use the fixed
initial status/check entries instead. This is not a lock around arbitrary Ansible
or root activity: exclude out-of-band config, package, trust and helper edits.
Preparation failures can retain this protection and require reviewed correction;
there is no automatic unlock, migration or reset route.

The helper holds its process lock plus shared writer locks, writes durable intent
before enable/start, verifies RPM-owned binary/unit bytes and native configuration,
then checks bounded loopback `/-/ready`. A new start requires remaining validity
of the leaf and its authenticated client chain covering the signed hold **plus
one day**; this admission margin is not a rotation
or retention implementation. Replay reauthenticates the receipt without restarting.
Failure recovery verifies disabled/inactive state and retains a failed receipt.
Drift, actual expiry or unverified recovery retains intent and returns failure.
Recovery success does not turn the original activation into success or authorize
another attempt. Local readiness does not prove Loki/Mimir ingestion or revocation.

The isolated [native qualification](../../tests/fixtures/alloy-initial-activation/README.md)
uses the actual RPM/systemd and covers startup, no-change replay, readiness failure
and interruption recovery. It does not qualify live GitLab, managed-host SELinux,
networking or 30-day operational rollback. Renewal and PKI-aware day-two convergence
must be implemented before treating this initial-only path as a full lifecycle.

Focused input/render checks:

```bash
PLATFORM_CONFIG_CONTAINER_PROFILE=test ./scripts/in-container python -m pytest -n 0 -x --durations=10 \
  tests/python/test_grafana_alloy_tls.py
```

`make test-platform-external-probe-alloy` qualifies actual Alloy `1.18.1` journal
delivery to a strict synthetic Loki receiver, rejected TLS/identity/key inputs,
redirect suppression and direct-file safety with apply/check non-mutation proof.
It checks the rendered TLS12 setting and native field acceptance, not a handshake
against an obsolete-protocol-only server. Synthetic HTTP 204 acceptance is not
real Loki indexing, HAProxy authorization or full monitoring/CI qualification.

The current systemd override retains root execution for access to the existing
system journal collection contract. Reducing privileges requires separate target
qualification of journal access and all enabled collectors.

### Read-Only Renewal Preflight

Use `tasks_from: renewal_preflight` with one literal host limit and
`grafana_alloy_renewal_writer: loki` or `mimir` (default empty). It requires the
exact installed initial helper/control inputs and a completed initial receipt
with actual active/enabled Alloy. Apply and check mode both run the same read-only
observation; desired service state is not activation authorization for this entry.
It imports only task entries, without role convergence or dependencies.

The helper's fixed `renewal-preflight --config
/etc/alloy/pki/initial-activation.json --writer <loki|mimir>` action retains the
process lock and shared locks for every configured writer. It reauthenticates
signed stages, original config/inventory/file identities, RPM/unit bytes, native
configuration and loopback readiness. Prepared, failed, interrupted, drifted,
expired or unknown state rejects without a service action or state repair.

`grafana_alloy_renewal_result` contains the initial receipt and inventory digests,
selected writer, observation time, and each writer's request/certificate/SPKI,
subject, direct version path, boundary, signed hold, leaf/client-chain expiries
and remaining lifetime. Detailed evidence uses `no_log`; routine reporting exposes
only schema, status, changed, target and writer. The strict result status is
`predecessor-verified`, with `changed: false`.

This is evidence for designing the first renewal handoff, not permission to create
a successor or alter selection. It creates no request, key, selector, active
record, configuration or service change. The signed hold is reported rather than
enforced as a renewal admission margin; a still-valid predecessor may be below
the initial-start margin. It proves neither CRL status nor remote acceptance.
Later mutating operations must reconstruct their evidence under their own locks.

The entry cannot upgrade an older installed helper or overwrite retained control
inputs; exact-source drift fails closed. Do not rerun `initial_prepare` against a
completed initial installation to obtain newer helper bytes. Historical receipt
handoff, reviewed helper upgrades, multiple versions, actual renewal and operational
rollback remain separate work.

Targeted helper tests are in `tests/python/test_alloy_renewal_preflight.py` and
require the reviewed generated tools artifact via `PLATFORM_ALLOY_TEST_PKI_ZIPAPP`.
Selected `test_renewal_*` cases in `tests/python/test_alloy_initial_role.py` cover
the real task chain and strict result schema. The native initial-activation lane
also checks both writer selections with unchanged PID, invocation, inputs and
receipts.
