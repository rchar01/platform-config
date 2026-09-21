<div align="center">
  <img src="assets/brand/platform-config-forge-avatar-transparent-512.png" width="256" alt="platform-config logo">
</div>

<h1 align="center">platform-config</h1>

<p align="center">
  Public Ansible configuration for platform hosts, services, and safe example inventories.
</p>

---

`platform-config` configures already-provisioned hosts with Ansible. It contains
public playbooks, roles, helper scripts, examples, and documentation for operating
systems and platform services, including RKE2, OpenBao, registries, GitLab
Runners, and Kubernetes bastion hosts.

Start with the [documentation index](docs/README.md) or the
[operator runbook](docs/operator-runbook.md) for environment bring-up and service
lifecycle procedures.

## Scope

This repository owns host and service configuration. VM templates and OpenTofu
provisioning live in separate repositories; shared human and CI operator commands
belong in `platform-tools`. Bastion runtime commands come from the
`platform-k8s-bastion` submodule rather than copies in Ansible roles.

Only safe examples belong here. Keep real inventories, host/group variables,
access policies, CA files, and non-secret environment configuration in
`../platform-private/config/`. Keep kubeconfigs, tokens, passwords, and private
keys outside Git. Working plans and environment-specific operational notes belong
in `../platform-plans/config/plans/`.

## Requirements

- Podman, Git, and Make on the controller workstation.
- Ansible and lint tooling supplied by `Containerfile.dev`,
  `requirements-dev.txt`, and `requirements.yml`; project Python packages stay
  inside the container.
- The `vendor/platform-k8s-bastion` submodule for default bastion runtime input.
- For real runs: private inventory, authenticated SSH host keys, SSH access,
  secret files, and the [managed-host prerequisites](docs/development.md#managed-host-requirements).
- For PKI exchange: `platform-tools` v4.0.0 or newer and the exact target-installed
  `platform-pki` SHA-256 pinned in private inventory.

## Quick Start

Initialize the runtime submodule and build the tooling container:

```bash
git submodule update --init --recursive
make deps
make help
```

Run local checks through the container-backed Make targets:

```bash
make yamllint
make lint
make test
```

Use `make shell` for an interactive toolbox. For an existing private environment,
the Make targets source its environment file **inside the container**:

```bash
make syntax ENV=dev
```

This requires `../platform-private/config/dev.ansible.env` and the matching
private inventory; `dev` is an example environment name. Follow the
[private workflow](docs/private-workflow.md) and
[operator runbook](docs/operator-runbook.md) before selecting a service check or
apply. Generic targets accept `ENV`, `PLAYBOOK`, `LIMIT`, and `EXTRA_ARGS`; guarded
operational routes have narrower contracts. Direct helper scripts that invoke
Ansible must also run through `./scripts/in-container` or inside `make shell`.

## Verification

| Command | Purpose |
| --- | --- |
| `make help` | List targets and supported variables. |
| `make syntax ENV=dev` | Syntax-check the selected playbook with private inventory. |
| `make lint` / `make yamllint` | Container-backed Ansible and YAML lint checks. |
| `make test` | Complete authoritative **serial** pytest suite. |
| `make verify` | Authoritative serial merge check: toolchain, container boundary, wrapper, lint, YAML, and tests. |
| `make test-parallel` / `make verify-parallel` | Supplemental faster feedback; `TEST_WORKERS` defaults to 2. |

Local lint/default tests use a sanitized container profile without private
configuration, secrets, SSH agents, or container-engine sockets. Parallel checks
do not replace serial `make verify`; offline checks do not establish live service
qualification. See [Development](docs/development.md) and [Testing](docs/testing.md)
for focused suites and opt-in integration checks.

## Operational Entry Points

Use the linked procedures for approvals, exact scope, and recovery. Managed-host
preparation, including the `rocky`-only non-TTY sudo exception, is covered by
[Ansible Host Bootstrap](docs/ansible-host-bootstrap.md).

### RKE2

- **Bootstrap:** both plan and apply require the shared all-node pristine/source
  preflight before host mutation: strict node-side HTTPS, RPM signing-key hash,
  and explicit registry API probes. Required node trust must already be installed.
  API success does not qualify image pulls, token exchange, RPM dependencies, or
  Helm jobs. Follow [source preflight](docs/rke2-operations.md#bootstrap-source-preflight)
  and the separately approved [Rocky CA trust procedure](docs/rocky-ca-trust.md).
- **Host aliases:** prepare the complete cluster separately through the fixed
  [aliases-only plan/apply routes](docs/rke2-host-aliases.md), with all-node guards,
  a zero-change post-check, and node NSS verification. Bootstrap does not repair
  aliases. [Pod DNS and Helm repository trust](docs/rke2-operations.md#static-dns-for-pods)
  are separate private-inventory selections.
- **Convergence:** use the fixed [RKE2 operations](docs/rke2-operations.md) with
  core-health gates, serial convergence, enabled add-on smoke, and zero-change
  post-checks. [RPM metadata-signature checking](docs/rke2-operations.md#rpm-repository-trust)
  defaults on; any explicit private boolean exception retains package signatures,
  key pins, and HTTPS.
- **Storage:** [storage-check/apply](docs/storage-check.md) select one literal
  RKE2 storage host. Apply requires a fresh check, the storage role, a second real
  apply with zero changes, and read-only mounted-state verification. Private CI
  owns per-node confirmation; interruption is not rollback.

Initial OpenBao storage preparation has separate fixed
[`openbao-storage-check`](docs/storage-check.md#openbao-storage-preparation)
and `openbao-storage-apply` routes: exactly three storage-only hosts, one selected
per invocation. Separately approved apply reuses the guarded storage sequence,
including real second-apply idempotence and mounted-state verification.

Optional [deployment Runners](roles/rke2_gitlab_deployment_runners/README.md)
add isolated `apps` and `platform` acceptance profiles, externally owned RBAC,
NetworkPolicies and native Pod admission. Their empty default preserves the
existing Runner. Real job/API acceptance is separate from read-only Ansible smoke;
the initial permissions cover fixed canaries, not general application deployment.
For a temporary registry-free job image, use the documented
[manual preload and Zot handoff](roles/rke2_gitlab_deployment_runners/README.md#temporary-manual-image-preload)
with the private `if-not-present` exception; the public pull-policy default stays `always`.

See the [legacy in-cluster Runner](roles/rke2_gitlab_runner/README.md) for private
Helm repository and checkout-origin overrides, and the docs index for
[host Runner offline preload](docs/README.md#services).

### OpenBao

- **CI preparation and inactive staging:** the four fixed
  [OpenBao preparation routes](docs/openbao-preparation.md) select the complete
  canonical three-host Rocky cluster. Host preparation combines bootstrap/base
  OS, Podman and the lifecycle helper without storage convergence; staging uses
  the pinned public validation CA and existing pristine playbook. All applies
  require fresh checks and zero-change post-checks, with complete phase evidence.
- **CI initial deployment:** seven fixed [PKI and bootstrap routes](docs/openbao-initial-deployment.md)
  provide one-node filesystem issue/activation plans and actions, whole-cluster
  bootstrap start, and zero-change completion qualification before persistence.
  Fixed CA/trust/status inputs and complete phase evidence bind each operation;
  offline signing and the attended initialization/unseal ceremony stay separate.

**Never run ordinary `playbooks/openbao.yml` staging against an active or
initialized cluster**, including as an idempotency check. Use the fixed active
maintenance and acceptance procedures.

- [Edge plans](docs/operator-runbook.md#openbao-edge-plans) bind the complete
  three-host cluster, clean committed source/private inventory, live evidence,
  and execution lane for 1800 seconds. Commit readiness as exactly `true` before
  planning. HAProxy and Keepalived activation each require separate exact TTY
  approval or a matching same-pipeline protected manual CI job. Activation
  verifies staged configuration, CA, SELinux, and firewall state without repair.
  Operator plans stay outside Git in owner-only storage; CI uses restricted artifacts.
- Preserve the reviewed [firewall lifecycle and policy](docs/firewalld.md#haproxy-and-keepalived-lifecycle).
  Disabled firewalld still requires permanent-rule validation but provides no
  host-firewall enforcement; it is not equivalent security. Enabling enforcement
  requires separate approval.
- Follow [VIP acceptance](docs/operator-runbook.md#openbao-vip-acceptance) for
  network, peer VRRP, anti-spoofing, and duplicate-address prerequisites.
  `smoke-openbao` is direct-node/all-three-HAProxy **pre-VIP** smoke.
  `smoke-openbao-vip` requires successful activation and a reviewed
  [active desired-state handoff](docs/operator-runbook.md#required-desired-state-handoff-before-vip-smoke),
  then verifies service state, exact single ownership, strict TLS, resolution, and
  cluster identity. CI needs a new pipeline on the pushed handoff revision.
  [DNS infrastructure is optional](docs/private-workflow.md#openbao-without-dns);
  service-hostname certificate identity remains required.
- Exclude concurrent lifecycle work. Plans are consumed before final preflight;
  retained guards require [reviewed recovery](docs/operator-runbook.md#openbao-edge-guard-recovery),
  never consumed-record deletion or plan reuse. Activation rollback is limited to
  the selected edge service; unknown or unreachable hosts remain unverified.
  The separately approved
  [HAProxy failover/restore check](docs/openbao-failover.md) has an explicit
  retained-record recovery route; a failed proof remains failed after restoration.

Standalone dev acceptance has no monitoring-stack dependency; production
monitoring remains required. Keep traffic acceptance-only until administrator,
audit-rotation, and recovery gates pass and normal onboarding is separately
authorized. The [standalone endpoint release](docs/operator-runbook.md#standalone-dev-endpoint-release)
closes with activation, handoff, VIP smoke, a separately approved HAProxy-owner
failover/restore check, and named-administrator handoff. It does not establish
production/DR readiness or RKE2 workload secret integration.

### Registry

The fixed [registry operations](docs/registry-operations.md) cover fresh host,
storage, dormant Zot, client trust, directory-based PKI and acceptance through
plan/manual GitLab jobs. Private keys remain on the registry host; offline
approval/signing separates request export from certificate activation. Full
registry smoke writes test artifacts. The filesystem lane is initial-issue only.

### Monitoring

The replacement monitoring stack remains gated. The focused
[monitoring HAProxy role](roles/monitoring_haproxy/README.md) verifies bundle
contents and metadata against reviewed inputs before reuse, including in check
mode; drift is rejected rather than repaired. This does not establish full-stack
deployment or dev GitLab qualification.
The host-native [Alloy role](roles/grafana_alloy/README.md#loki-tls-inputs) supports
separate Loki mTLS file references with early input/file checks. The shared
[PKI role](roles/pki_host_local_certificate/README.md#initial-client-request-and-staging)
supports issue-only client requests and authenticated immutable staging. Alloy's
[guarded initial start](roles/grafana_alloy/README.md#guarded-initial-start) consumes
those direct paths with signed inventory binding and failed-start recovery.
Renewal, overlap enforcement and full monitoring delivery qualification remain pending.

## Repository Family

| Repository | Purpose |
| --- | --- |
| [`platform-template-builder`](https://codeberg.org/rch/platform-template-builder) | Builds reusable Proxmox VM templates. |
| [`platform-infra`](https://codeberg.org/rch/platform-infra) | Provisions infrastructure with OpenTofu. |
| [`platform-config`](https://codeberg.org/rch/platform-config) | Configures hosts and services with Ansible. |
| [`platform-k8s-bastion`](https://codeberg.org/rch/platform-k8s-bastion) | Owns bastion runtime commands and operator tools. |
| [`platform-tools`](https://codeberg.org/rch/platform-tools) | Provides shared human and CI tools, including PKI exchange. |
| `platform-ci` | Composes public diagnostics, acceptance, and guarded CI operations. |
| `platform-private` | Holds real environment bindings and non-secret configuration. |
| `platform-plans` | Holds working plans and environment-specific operational notes. |
| [`platform-docs`](https://codeberg.org/rch/platform-docs) | Documents architecture and operations across repositories. |

## Documentation

The [documentation index](docs/README.md) covers setup, service guides, PKI,
storage, RKE2, OpenBao, migrations, and development. Start with the
[operator runbook](docs/operator-runbook.md) for a rollout or the
[development guide](docs/development.md) for repository work.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
