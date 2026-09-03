# RKE2 Operations

`platform-config` provides a fixed launcher and a dedicated CI image source for
reviewed RKE2 bootstrap and convergence plus read-only OpenBao status jobs. The
launcher is not a generic Ansible wrapper: it accepts one operation, one
absolute inventory path, and one absolute controller-variable file.

## Fixed Operations

`scripts/platform-config-operation` exposes only these routes:

| Operation | Commands |
| --- | --- |
| `rke2-bootstrap-plan` | Inventory validation, `ansible.builtin.ping` for `rke2_cluster`, pristine-node preflight, then fixed base RKE2 check mode with diff. |
| `rke2-converge-plan` | Inventory validation, cluster ping, core-health and token-equivalence preflights, then fixed base RKE2 and kube-vip check mode with diff. |
| `rke2-bootstrap` | Inventory validation, cluster ping, pristine-node preflight, serial native-RPM installation, kube-vip convergence, then base and kube-vip smoke checks. |
| `rke2-deploy` | Core-health and token-equivalence preflights, serial RKE2 convergence, kube-vip convergence, then full base and kube-vip smoke checks. |
| `openbao-status` | Inventory validation, `ansible.builtin.ping` for `openbao`, then the strict read-only OpenBao status playbook. |

The launcher does not accept limits, tags, playbook paths, modules, extra vars,
or arbitrary Ansible arguments. CI generates the controller-variable file for
strict per-host SSH identities and clears password-based SSH and become values
without disabling inventory-authorized passwordless privilege escalation.

For attended qualification before CI adoption, follow the complete manual
fresh-install sequence in the [operator runbook](operator-runbook.md). It uses
the same preflight, base, kube-vip, and smoke playbooks with explicit inventory
group limits and requires second-apply idempotency.

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
kube-vip and verifies both layers. Each enabled, started node must recover its local
service and Kubernetes Node `Ready` condition before the next serial host can
start. Server nodes must also recover the supervisor port and local API
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

## Operational Image

`Containerfile.ci` builds the direct-Ansible job image. It pins Ansible Core in
`requirements-ci.txt` and installs the exact collection versions from
`requirements.yml`:

```bash
podman build -f Containerfile.ci -t platform-config-ci:local .
podman run --rm platform-config-ci:local ansible --version
podman run --rm platform-config-ci:local ansible-galaxy collection list
```

Publish the reviewed image through the approved registry workflow and bind jobs
to its registry digest. A local image tag or mutable registry tag is not an
operational identity.

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

Operational jobs must use an immutable `platform-config` commit, an immutable
component commit, a digest-pinned image, a protected private inventory revision,
strict authenticated known hosts, and outside-Git secret files. A reviewed plan
does not authorize deployment after any source, image, inventory, or credential
rotation; cancel the pending pipeline and run a new plan.
