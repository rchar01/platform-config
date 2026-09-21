# OpenBao CI Preparation And Inactive Staging

Four fixed `scripts/platform-config-operation` routes prepare an already
provisioned, storage-prepared three-node OpenBao cluster:

| Route | Work |
| --- | --- |
| `openbao-host-plan` | Check bootstrap, base OS, Podman and lifecycle-helper preparation. |
| `openbao-host-apply` | Fresh checks, approved host/runtime/helper applies, zero-change post-checks. |
| `openbao-stage-plan` | Check the existing inactive `playbooks/openbao.yml` staging path. |
| `openbao-stage-apply` | Fresh stage check, inactive stage apply, zero-change stage post-check. |

Continue through the separate [initial PKI and bootstrap routes](openbao-initial-deployment.md)
after preparation and staging succeed.

These routes require `CI=true`. Private CI owns protected manual approval,
source/private revision and image bindings, and job input provisioning. The
environment selector is not an API-proof authorization mechanism. Each route
accepts only `--inventory PATH --controller-vars PATH`; both paths are absolute,
regular, non-symlink files, and controller JSON is current-owner private. There
are no node, limit, runtime-only, arbitrary-playbook or extra-argument selectors.
Use the container tooling described in [Development](development.md).

## Inventory And Storage Prerequisites

Every invocation selects exactly the complete three-host `openbao` group and its
identical canonical `openbao_cluster_members` mapping on all hosts. All members
must be `rocky`, with literal unambiguous inventory names. Membership in
`container_hosts` is not required. The scope must be disjoint from RKE2
cluster/server/agent, registry/client, GitLab/Runner, monitoring-server,
bastion, workload HAProxy/load-balancer groups, and the initial storage-only
`openbao_storage` group.

After completing approved storage preparation, an explicit reviewed private
inventory handoff removes the three hosts from `openbao_storage` and enrolls
them in `rocky` and `openbao` for these preparation routes. Retain their approved
storage layouts, volume declarations and `storage_volume_hosts` membership;
that general storage-management group remains allowed. If layout variables were
attached to `openbao_storage`, preserve their effective values in the new private
host/group scope during the handoff. The routes neither perform this inventory
handoff nor reinitialize storage.

Private inventory must explicitly declare:

```yaml
openbao_orchestration_ready: true
openbao_enabled: true
openbao_service_enabled: false
openbao_service_state: stopped
openbao_haproxy_enabled: true
openbao_haproxy_service_enabled: false
openbao_haproxy_service_state: stopped
keepalived_vip_enabled: true
keepalived_vip_service_enabled: false
keepalived_vip_service_state: stopped

# Required by host preparation before base-os.yml can run:
root_lvm_enabled: false
platform_common_directories: []
```

Bootstrap, audit-migration and edge activation readiness must remain false.
Role defaults are resolved in a separate namespace with explicit inventory
precedence. The existing OpenBao, HAProxy, Keepalived and Podman input validators
remain authoritative for identities, exact package/image pins, service paths,
firewall lifecycle and network configuration. The existing Rocky repository
policy validator also runs before host preparation changes. Missing private
package, network, trust or firewall decisions are errors, not inferred defaults
or permission to choose operational policy.

All four inventory-selected OpenBao service paths must already exist as separate
mounts. Preparation checks them read-only and rejects nonempty Raft data. Host
preparation never invokes `storage_volume`; disabling root LVM and common
directory mutations prevents base OS preparation from changing approved storage.
The Podman role retains its existing optional mounted-storage contract. Service
staging retains the OpenBao role's ownership changes on existing mount roots.

Before host mutation, the target guard rejects active, enabled, failed or
incompletely observed OpenBao/HAProxy/Keepalived services, retained boot
enablement, unsafe paths, leaf material, bootstrap/rolling records and any edge
guard directory. Pending/version trees must be absent or empty. A retained PKI
state root must contain exactly `lock` and `trust`, and replay passes through the
installed helper's existing lifecycle checks. Active/current/terminal and
interrupted records are rejected and preserved. Exclude concurrent out-of-band
service, storage, trust, PKI and configuration changes throughout the operation;
these routes do not acquire a lifecycle lock or repair retained records.

## Runtime And Helper Preparation

Host preparation combines `bootstrap.yml`, `base-os.yml`, and the fixed
`openbao-runtime-prepare.yml`. The last play rechecks the guard and invokes
`podman_host` plus `pki_host_local_certificate`'s
`lifecycle_helper_prepare.yml` entry point. It installs only the cryptography
runtime and shipped lifecycle helper, without PKI requests, transport setup,
credentials or lifecycle records.

Fresh preparation check mode predicts missing helper prerequisites without
creating them. Existing unsafe helper metadata is rejected. The ordinary PKI
`lifecycle_helper.yml` check-mode contract still requires the exact installed
helper; it is not a fresh-install plan. Stage routes always require that exact
helper to be preinstalled, including for pristine hosts. Existing dormant
listener/trust-only state uses the existing lifecycle/custody includes before
staging and is never interpreted as permission for active convergence.

## Public Validation CA Input

Stage jobs provision only the public service-validation CA at:

```text
$PLATFORM_INFRASTRUCTURE_CONFIG_DIR/openbao/validation-ca.pem
```

Private inventory must select exactly that controller path with
`openbao_tls_ca_src` and supply its lowercase SHA-256 in `openbao_tls_ca_sha256`.
The existing descriptor-pinned source validator rejects unsafe, missing,
symlinked, hardlinked, oversized, public-repository-local or digest-mismatched
sources. Preflight validates without installing; the OpenBao role uses the same
digest-bound action for installation when this variable is defined. Existing
non-CI callers that omit the digest retain their original CA copy behavior.
HAProxy retains its separate public CA copy under `/etc/haproxy`.

This CA is separate from source-fetch Git CA trust and from PKI exchange trust.
No status token, leaf key, PKI request, initialization, unseal, edge activation or
active desired-state handoff belongs to these four routes.

## Phase And Evidence Contract

All four routes start with `inventory → connectivity → openbao-preflight`.
Transport-only controller JSON is validated and snapshotted **before inventory
execution**, using the existing transport schema. Operational intent and the CA
digest cannot be supplied through controller JSON.

Host plan continues with:

```text
openbao-bootstrap-check
openbao-base-os-check
openbao-runtime-check
```

Host apply runs `-check → -apply → -post-check` for each of those three step
prefixes, in order. Stage plan runs `openbao-stage-check`; stage apply runs
`openbao-stage-check → openbao-stage-apply → openbao-stage-post-check`. Stage
phases all reuse `playbooks/openbao.yml` with its pristine inactive semantics.
Every check/post-check uses `--check --diff`; plan changes are permitted.

Every command is gated on complete successful preceding evidence. Each target
phase needs exactly one recap for each selected host, with positive successful
task counts and no failed, unreachable, ignored or rescued tasks. Preflight and
all post-check phases require zero changes. Duplicate, foreign or missing host
evidence fails the operation even if Ansible exits zero. Failures stop the next
phase; there is no retry or rollback. Interruption is not successful preparation.

## Offline Verification

```bash
PLATFORM_CONFIG_CONTAINER_PROFILE=test ./scripts/in-container \
  timeout 300s python -m pytest -n 0 -q -x --durations=5 \
  tests/python/test_openbao_preparation_operations.py \
  tests/python/test_openbao_preparation_preflight.py \
  tests/python/test_openbao_helper_prepare.py \
  tests/python/test_openbao_preparation_ca.py
```

Tests exercise the shipped preflight and its real default/validator/lifecycle
includes with sandboxed target I/O, the real target guard, source pinning,
and real helper-file check/apply/idempotence in a user namespace. Systemd/mount
observations and helper authentication responses in orchestration fixtures are
synthetic; the separate host-local OpenBao adapter suite covers helper semantics.
Offline success does not qualify real package sources, image pulls, SELinux,
systemd/Quadlet behavior, TLS acceptance or private CI execution.
