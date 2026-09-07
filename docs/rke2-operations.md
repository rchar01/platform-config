# Fixed RKE2 and OpenBao Operations

`platform-config` provides a fixed launcher for reviewed RKE2 bootstrap and
convergence plus OpenBao status, restart, and convergence jobs. The launcher is
not a generic Ansible wrapper: it accepts one operation, one absolute inventory
path, and one absolute controller-variable file. Its fixed OpenBao edge plan and
activation routes additionally require an absolute `--plan` path.

## Fixed Operations

`scripts/platform-config-operation` exposes only these routes:

| Operation | Commands |
| --- | --- |
| `rke2-bootstrap-plan` | Inventory validation, `ansible.builtin.ping` for `rke2_cluster`, pristine-node preflight, then fixed base RKE2 check mode with diff. |
| `rke2-converge-plan` | Inventory validation, cluster ping, core-health and token-equivalence preflights, then fixed base RKE2, kube-vip, and GitLab Runner check mode with diff. |
| `rke2-bootstrap` | Inventory validation, cluster ping, pristine-node preflight, serial native-RPM installation, kube-vip and GitLab Runner convergence, all three smoke checks, then all three post-smoke checks. |
| `rke2-deploy` | Local inventory resolution for summary initialization, core-health and token-equivalence preflights, serial RKE2 convergence, kube-vip and GitLab Runner convergence, all three smoke checks, then all three post-smoke checks. |
| `openbao-status` | Inventory validation, `ansible.builtin.ping` for `openbao`, then the strict read-only OpenBao status playbook. |
| `openbao-restart-plan` | Inventory validation, exact OpenBao cluster ping, strict status, then the active OpenBao playbook in check mode with diff. Predicted changes fail the plan. |
| `openbao-converge-plan` | Inventory validation, exact OpenBao cluster ping, strict status, then the active OpenBao playbook in check mode with diff. Reviewed same-version configuration changes are valid plan output. |
| `openbao-restart` | The OpenBao preflight, one rolling convergence with fixed restart confirmation and forced restart, strict final status, then an unchanged active check with diff. |
| `openbao-deploy` | The OpenBao preflight, one rolling convergence with fixed restart confirmation and no forced restart, strict final status, then an unchanged active check with diff. |
| `openbao-haproxy-plan` | Exact three-host read-only HAProxy activation preflight, then exclusive publication of a source-bound plan; no target guard acquisition or service mutation. |
| `openbao-haproxy-activate` | Validate the reviewed plan, authorize in its operator or CI lane, acquire all edge guards and consume the plan, repeat final preflight, activate HAProxy, qualify every node-local path, and roll back HAProxy on failure. |
| `openbao-keepalived-plan` | Exact three-host read-only Keepalived activation preflight, then exclusive publication of a source-bound plan; no target guard acquisition or service mutation. |
| `openbao-keepalived-activate` | Validate and authorize the plan, acquire all edge guards and consume the plan, repeat final preflight, start backup-priority members before the preferred member, qualify VIP state, and roll back only Keepalived on failure. |
| `openbao-smoke` | Strict direct-node and all-three-HAProxy smoke for the pre-VIP phase. |
| `openbao-vip-smoke` | The existing smoke plus active desired and actual Keepalived state, repeated exact single-owner VIP checks, strict forced-VIP service-DNS TLS and actual DNS-path checks, and cluster identity agreement. |

The launcher does not accept limits, tags, playbook paths, modules, extra vars,
or arbitrary Ansible arguments. CI generates the controller-variable file for
strict per-host SSH identities and clears password-based SSH and become values
without disabling inventory-authorized passwordless privilege escalation.

Each mutating RKE2 route performs exactly one live base apply and one live apply
for each enabled add-on. After all smoke suites pass, it runs the base, kube-vip,
and GitLab Runner playbooks with `--check --diff`. Every applicable post-check
host must report `changed=0`, `failed=0`, and `unreachable=0`; otherwise the
structured summary and operation fail. This is predictive post-apply
verification, not a second live apply. A disabled GitLab Runner role skips its
management without uninstalling an existing release.

Every fixed launcher operation ends with a deterministic plain-text summary on
both success and failure. It lists only inventory hostnames selected for that
operation, their operation-neutral `server`, `agent`, or `openbao` role,
per-phase `PASS`, `FAIL`, or `N/A` status, recap counts, and the overall result.
An RKE2 host receives role `N/A` only when selected inventory membership cannot
establish exactly one of `server` or `agent`; that unresolved role makes the
summary and otherwise successful operation fail closed.
Ordinary plan and apply phases may report changes. The `rke2-post-check`,
`kube-vip-post-check`, and `rke2-gitlab-runner-post-check` phases fail when they
predict a change. Both add-ons remain server-orchestrated and render `N/A` for
agents.
The `openbao-restart-check` and `openbao-post-check` phases likewise require
`changed=0`; the `openbao-converge-check` phase permits reviewed changes. Every
OpenBao phase applies to exactly three OpenBao hosts, so none renders `N/A`.
Changed, observed-failed, and unreachable task names are grouped with affected
VM names. The GitLab Runner appears only as execution context; delegated
localhost, unrelated inventory groups, and the untargeted bastion are excluded.

An opt-in aggregate callback records only the phase, inventory hostname, safe
task name, outcome category, and recap counters. It never records task results,
arguments, values, diffs, addresses, exceptions, or delegated-host data. Raw
inventory output is reduced to host and role records in an invocation-private
directory and deleted immediately. The callback event file is mode `0600`, the
directory is mode `0700`, no summary artifact or cache is published, and the
launcher removes temporary summary state after success, failure, or a handled
signal. The separate restricted edge plan artifact is not summary scratch and
must remain available for its matching activation job. Matching ASCII start and
end delimiters separate the summary from surrounding CI output. Failure before inventory resolution still prints
`Overall: FAIL` without fabricating a VM row.

By default, the launcher writes that terminal summary to standard output. A
trusted wrapper may instead pre-create a regular file and set the internal
`PLATFORM_CONFIG_OPERATION_SUMMARY_OUTPUT` environment variable to its absolute
path. The file must not be a symlink, and its immediate parent must be a
non-symlink directory with no group or other permissions. The launcher then
writes the same single terminal summary to that file instead of standard output;
this internal handoff is not an operator argument.

For attended qualification before CI adoption, follow the complete manual
fresh-install sequence in the [operator runbook](operator-runbook.md). It uses
the same preflight, base, enabled add-on, and smoke playbooks with explicit
inventory group limits and requires second-apply idempotency.
That attended procedure remains the stronger manual release-qualification path;
fixed GitLab deployments use the non-mutating post-smoke checks described above.

Review the [RKE2 artifact and egress matrix](rke2-egress.md) before installation.
It records the exact qualified package, chart, and release-bundle inputs, where
each fetch originates, and which dynamic upstream services require internal
mirroring for a finite firewall policy.

The bootstrap plan fails before check mode unless every selected node is
pristine. On fresh nodes, check mode validates the RKE2, registry, and Traefik
templates without creating target directories and reports the exact package and
managed configuration scope as changed. Child-file diffs become available after
their parent directories exist; the bootstrap job still requires a reviewed
plan.

RKE2 bootstrap accepts only recreated nodes without existing RKE2 packages,
configuration, state, or binaries. It is a one-time installation path and does
not uninstall or migrate an existing cluster. Recreate a node before retrying a
bootstrap that failed after package installation; the guard intentionally does
not resume a partially installed node. The convergence plan and deployment
require core cluster health without requiring the desired Traefik or kube-vip
state, so those managed resources can be repaired. RKE2 convergence runs servers
before agents with `serial: 1` and `any_errors_fatal: true`, then reconciles
kube-vip and the optional GitLab Runner before verifying all enabled layers.
Each enabled, started node must recover its local service and Kubernetes Node
`Ready` condition before the next serial host can start. Server nodes must also
recover the supervisor port and local API
`/readyz` response. RKE2-specific firewall policy is reconciled before the API
and Node readiness gates. This deployment path is for an existing healthy
cluster; use `rke2-bootstrap` for explicitly recreated clean nodes.
Delegated Kubernetes readiness checks connect to the bootstrap server with that
host's inventory-selected SSH key rather than the current serial node's key.

The convergence preflight reads the controller and installed cluster-token files
under `no_log` and fails before check mode or mutation unless their semantic
values match. The controller token must be a nonempty single line with no CR or
LF. An installed token may have one final LF, which is ignored only for the
comparison; CR and embedded LF remain invalid. Normal convergence never rotates
cluster credentials. The role writes the equivalent target token with exactly
one final LF so repeated convergence does not report byte-level drift.

When both desired registry mappings are empty, the same preflight refuses to
remove registry configuration while `registry.dev/` remains in standard
Kubernetes Pod, ReplicationController, Deployment, ReplicaSet, StatefulSet,
DaemonSet, Job, or CronJob container, init-container, or ephemeral-container
images. It also scans the complete static-manifest tree on every RKE2 server.
Inspection results remain under `no_log`; failures report only a fixed reason,
not workload payloads, image values, manifest paths, or manifest contents.
Custom workload resources are outside this fixed built-in workload query and
require a separately reviewed discovery and access policy before relying on
them during registry retirement.

The launcher translates `HUP`, `INT`, and `TERM` into `TERM` for its active
Ansible child, waits for that child, and returns the conventional launcher
status of 129, 130, or 143. Cancellation stops later fixed commands, but it
cannot roll back changes already completed by Ansible or a managed host.

## OpenBao Edge Lanes

`platform-tools` owns the `platform-openbao-edge` facade. Its `haproxy-plan`,
`haproxy-activate`, `keepalived-plan`, `keepalived-activate`, `smoke`, and
`vip-smoke` subcommands map only to the six corresponding `openbao-*` routes
above. All take `--source`, `--inventory`, and `--controller-vars`; the first
four require `--plan`, which smoke commands reject. The launcher itself runs
from the selected source checkout and does not take `--source`. CI can invoke
it directly without adding the facade to its image. Neither boundary accepts
arbitrary playbooks, limits, approval overrides, or generic command passthrough.

The action plugin and shared module utility own schema `1` plans with a fixed
1800-second TTL. Plans bind clean committed configuration and private inventory
Git identities, inventory path, environment, exact hosts and evidence, and lane.
GitLab plans additionally bind the digest-pinned image, project, pipeline, and
matching plan-job identity. CI requires a protected default-branch web pipeline
and a matching same-pipeline manual activation job; it does not use a TTY or
continue in a terminal. Operator activation requires exact TTY approval of the
displayed host/operation/plan-digest string. Existing Make activation targets
remain direct interactive entry points using an in-memory plan.

Read-only plan mode allows readiness false and is not Ansible check mode.
Activation requires the corresponding private readiness gate to be exactly
boolean true on every host. Review and commit that declaration before planning
an approved activation; changing it after planning invalidates the private SHA.
Retain the pre-activation disabled/stopped desired state for the selected service.
Source, lane, evidence drift, or expiry requires a new plan, not an edited plan.

Operator output must be a new absolute filename outside every Git repository
in an existing current-owner `0700` non-symlink directory. Core publishes it as
`0600` without overwrite. CI uses only the fixed restricted plan artifact from
its matching plan job. Do not publish plan evidence in public logs or reports.
Keep plan review, manual job start, activation, qualification, failure rollback,
and reporting within CI for that lane; there is no terminal completion step.

The target-root guard at `/var/lib/platform-config/openbao-edge-guard` records
`active/owner.json` and permanent `consumed/<plan_id>` entries. It is acquired on
all hosts and consumes the plan before final preflight. It coordinates only
supported HAProxy/Keepalived activation, not root, out-of-band changes, or rolling
operations. Prohibit concurrent other lifecycle operations. Partial acquisition,
interruption, unknown rollback, or unverified release retains affected records
for reviewed recovery; no automatic unlock or consumed-record deletion is
permitted. Success or independently verified per-host rollback releases only
owned active guards. Every retry needs a fresh plan after recovery. See
[Guard Recovery](operator-runbook.md#openbao-edge-guard-recovery).

The operation report must show qualification and rollback outcomes and the
lifecycle keys required for the private source handoff:

| Successful Activation | Reviewed Private Desired-State Commit |
| --- | --- |
| HAProxy | `openbao_haproxy_service_enabled: true`, `openbao_haproxy_service_state: started`, `openbao_haproxy_activation_ready: false` |
| Keepalived | `keepalived_vip_service_enabled: true`, `keepalived_vip_service_state: started`, `openbao_keepalived_activation_ready: false` |

Neither lane automatically mutates or pushes those values. Activation qualifies
runtime state against its immutable pre-activation source; subsequent smoke or
the next edge plan consumes the reviewed private handoff commit. In CI, use the
corresponding fixed smoke job with that revision, not a terminal continuation.
Firewalld readiness and enablement remain a separately approved prerequisite.
These routes do not establish live qualification or authorize normal traffic.
See [OpenBao Edge Plans](operator-runbook.md#openbao-edge-plans) and
[VIP Acceptance](operator-runbook.md#openbao-vip-acceptance).

## Operational Image

This repository does not build or publish an operational job image. Private CI
bindings select a maintained image by immutable registry digest, and the public
components verify its complete reference, architecture, and required toolchain
before fetching `platform-config`.

The qualified dev binding pulls this upstream image directly from GHCR:

```text
ghcr.io/ansible/community-ansible-dev-tools:v26.8.0@sha256:70f705fee2386deb320598ea011812292598111cca85f0107ee9479062628e79
```

The fixed paths require Ansible Core `2.21.x`; RKE2 additionally requires
`ansible.posix` `2.2.2`, while OpenBao status requires no external collection.
Jobs must not install packages or collections at runtime. A mutable tag or local
image name is not an operational identity.

## RPM Repository Trust

The RKE2 role installs native RPMs directly and does not download or execute the
upstream installer script. Private inventory must select an exact
`rke2_version`, native RPM release, SELinux package NEVRA, EL major,
architecture, two HTTPS repository URLs, and an HTTPS signing-key URL with its
reviewed SHA-256 and OpenPGP fingerprint. Full repository URLs are configurable
so an environment can select approved corporate mirrors without changing the
role.

The role downloads the signing key with the configured checksum, verifies its
fingerprint during import, and configures common and version repositories with
both package and repository GPG checks enabled. Both repositories remain
disabled by default and are enabled only for the exact RKE2 package transaction.
The installed node-package NEVRA, SELinux-package NEVRA, and RKE2 binary version
are verified before the service is managed. The role permits upgrades but does
not perform downgrades; selecting a lower package identity fails closed.

Rancher publishes Enterprise Linux packages under `centos/<major>` paths. Rocky
10.0, 10.1, and 10.2 therefore use native `centos/10` RKE2 repositories; the
Rocky minor release remains an independent OS-repository policy. Repository
metadata and runtime container images remain downstream release-trust
boundaries. Immutable snapshots or internally qualified mirrors are required
where signed but mutable upstream repository content is insufficient.

## Smoke Boundaries

`playbooks/rke2-smoke.yml` checks services, Kubernetes node readiness, expected
node count, ingress selection, and worker NodePorts. Its HTTPS NodePort request
uses a node IP with certificate validation disabled and proves only that the
transport endpoint returns the expected response. It is not authenticated TLS
identity evidence and must not be used as evidence for the strict GitLab,
registry, OpenBao, or Kubernetes API trust paths.

`playbooks/rke2-gitlab-runner-smoke.yml` verifies the live manager image,
namespace policy, namespaced non-wildcard RBAC, separate ServiceAccounts,
rendered job constraints, Secret key names, and manager placement on an
inventory-declared agent. It does not inspect Secret values, prove GitLab-side
project or group scope and protection settings, or execute a canary job. Select
GitLab-side availability, tags, protection, and untagged-job policy according to
the consuming projects' trust policy; those settings are operator guidance
outside this implementation's acceptance checks.

Operational jobs must use an immutable `platform-config` commit, an immutable
component commit, a digest-pinned image, a protected private inventory revision,
strict authenticated known hosts, and outside-Git secret files. A reviewed plan
does not authorize deployment after any source, image, inventory, or credential
rotation; cancel the pending pipeline and run a new plan.
