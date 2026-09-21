# OpenBao CI Initial Deployment

After [host preparation and inactive staging](openbao-preparation.md), seven fixed
CI-only `scripts/platform-config-operation` routes wrap the existing OpenBao PKI
and bootstrap playbooks. They require `CI=true`. Private CI owns protected manual
approval, source/private revision and image bindings, and input provisioning.

## Route And Phase Contract

Every route accepts exactly `--inventory PATH --controller-vars PATH`. The four
PKI routes additionally **require** `--node HOST`, naming one literal canonical
OpenBao host. Bootstrap routes select all three hosts and reject `--node`.
There are no TTL, plan-file, request-ID, response-path, package-coordinate,
adapter, arbitrary-playbook, check-mode or extra-argument flags.

All routes begin with:

```text
inventory → connectivity → openbao-initial-preflight
```

| Route | Remaining phases | Existing playbook |
| --- | --- | --- |
| `openbao-pki-request-plan` | None; read-only readiness only | No action playbook |
| `openbao-pki-request` | `openbao-pki-request` | `playbooks/openbao-pki-request.yml` |
| `openbao-pki-activate-plan` | None; read-only readiness only | No action playbook |
| `openbao-pki-activate` | `openbao-pki-activate` | `playbooks/openbao-pki-activate.yml` |
| `openbao-bootstrap-start` | `openbao-bootstrap-start` | `playbooks/maintenance/openbao-bootstrap-start.yml` |
| `openbao-bootstrap-complete-plan` | `openbao-bootstrap-complete-check` | `playbooks/maintenance/openbao-bootstrap-complete.yml --check --diff` |
| `openbao-bootstrap-complete` | `openbao-bootstrap-complete-check → openbao-bootstrap-complete` | The same completion playbook, first `--check --diff`, then normal execution |

The preflight runs normally but is read-only and must report **zero changes**.
PKI action playbooks reject check mode. Bootstrap start has no nominal check or
plan route: its existing playbook performs pristine preflight, immediate second
preflight, start, and pending-marker publication, retaining its rollback paths.
Completion check performs real pending-state and strict cluster qualification
without persistence and must report **zero changes** before normal completion.

Every command requires complete successful evidence from its predecessor. Each
target phase needs exactly one recap per selected host, a positive successful
task count, and no failed, unreachable, ignored or rescued tasks. Missing,
duplicate or foreign evidence fails even when Ansible exits zero. PKI evidence
covers the selected node; bootstrap evidence covers all three. Failures and
interruptions remain failures, including after restoration.

## Inventory And Controller Inputs

Transport-only controller JSON is validated and copied to an owner-private
snapshot **before inventory execution**. It uses the existing transport schema;
operational intent, TTL, CA/trust pins and token paths cannot be supplied there.
When the per-host SSH key map is present, coverage is required for the selected
PKI host or all three bootstrap hosts.

Inventory resolution checks the entire three-host canonical
`openbao_cluster_members` cohort, including for a one-node PKI operation. All
hosts must be Rocky and disjoint from the same service groups excluded during
preparation, including `openbao_storage`. The reviewed storage-only membership
handoff remains required; `storage_volume_hosts` membership remains allowed.
Canonical mappings must agree on all three hosts. Runtime identity validation
retains the existing OpenBao role contract. Explicit orchestration/enabled
intent and disabled/stopped OpenBao desired state remain required throughout
initial deployment; bootstrap readiness declarations remain inventory-owned.

Let `CONFIG` denote `$PLATFORM_INFRASTRUCTURE_CONFIG_DIR`:

| Routes | Fixed controller files | Inventory binding |
| --- | --- | --- |
| All seven | `CONFIG/openbao/validation-ca.pem` | `openbao_tls_ca_src` and lowercase `openbao_tls_ca_sha256` |
| PKI only | `CONFIG/pki-source/pki/csr-trust/policy`, `requesters.allowed_signers`, `approvers.allowed_signers`, `responses.allowed_signers` | Exact four-key `pki_host_local_certificate_trust_sources` and `pki_host_local_certificate_trust_sha256` maps; each basename is under the same fixed directory |
| Completion only | `CONFIG/openbao/<platform_environment>/status.token` | `openbao_status_token_src`; the existing status role reads the least-privilege token under `no_log` |

PKI also binds `pki_host_local_certificate_reviewed_ca_source` and its SHA-256 to
the same service-validation CA. Public controller sources are regular,
single-link, mode-`0600` files. The CA uses the existing descriptor-pinned source
validator. Trust digests are checked on both controller and target. Source-fetch
Git CA trust remains a separate input. PKI and bootstrap start never read a
status token.

## Initial PKI And Custody

Private PKI inventory must select `transport: filesystem`, `operation: issue`,
and `service_adapter: openbao-pristine-v1` through the existing
`pki_host_local_certificate_*` variables. Preflight reuses target-local input,
trust, filesystem exchange, response and OpenBao custody tasks without role
convergence or dependency execution. It requires the exact installed lifecycle
helper and inactive, masked `openbao.service`. Request planning requires dormant
custody. Activation planning uses authenticated response status so completed
replay and interrupted recovery remain admitted by the existing helper contract.

Preprovision target trust, the signing identity and exchange access separately.
Preflight creates no trust, state, request, key or transport access. Authorized
request/activation actions retain their existing reviewed trust/helper staging
and target-local lifecycle behavior. The filesystem exchange exports only signed
public requests and imports signed public responses through preprovisioned
access. Offline approval, signing and transfer remain a separate handoff; CI
does not carry PKI payloads or leaf/signer private keys. Successful request
publication may report only its authenticated 32-hex request ID.

An optional inventory integer `openbao_pki_request_ttl_seconds` selects request
lifetime from `1` through `604800` seconds. The default stays `3600`; an explicit
`7200` is honored without a CLI or controller-JSON override. Strings and booleans
are rejected. The existing operator Make TTL argument is forwarded as a typed
JSON integer to preserve its interface.

Activation retains temporary unmasking and unconditional independent stop/remask
attempts. Success still requires helper `status=complete`,
`required_action=none`, and an inactive masked unit. Recovery alone is not
activation success. Retained ambiguous state is preserved for reviewed recovery.

## Bootstrap And Ceremony Exclusion

Bootstrap start leaves direct processes running without boot enablement and
publishes the existing pending manual-custody markers. Approved custodians perform
initialization and unseal outside CI and Ansible, retain shares and the initial
root token outside these routes, and establish the least-privilege status
identity. Completion uses the existing pending-marker, CA, audit, health and
stable three-voter checks before persistence and active-marker publication.

Use the existing private CI writer lock and procedurally exclude concurrent
custodian ceremonies, other lifecycle jobs and out-of-band host/trust changes
for the entire operation. These routes add no locks or helper protocol. No route
initializes, unseals, handles root tokens or shares, or edits private desired
state. After completion, make the reviewed active desired-state handoff through
the existing procedure before later operational work.

## Offline Verification

```bash
PLATFORM_CONFIG_CONTAINER_PROFILE=test ./scripts/in-container \
  timeout 360s python -m pytest -n 0 -q -x --durations=10 \
  tests/python/test_openbao_initial_operations.py \
  tests/python/test_openbao_initial_preflight.py \
  tests/python/test_openbao_request_ttl.py \
  tests/python/test_openbao_pki_ci_entry_points.py
```

Tests execute the real preflight/includes with sandboxed target file observations,
synthetic service/helper responses, and native request creation for TTL checks.
Separate existing bootstrap and helper suites cover rollback and lifecycle
semantics. Offline results do not establish live PKI transfer, systemd/Quadlet,
TLS, bootstrap or private CI qualification. HAProxy activation's caller-source
guard and its separate qualification blocker are unchanged.
