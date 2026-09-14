<div align="center">
  <img src="assets/brand/platform-config-forge-avatar-transparent-512.png" width="256" alt="platform-config logo">
</div>

<h1 align="center">platform-config</h1>

<p align="center">
  Public Ansible configuration for platform hosts, services, and safe example inventories.
</p>

---

`platform-config` configures already-provisioned hosts with Ansible. It
contains public playbooks, roles, examples, helper scripts, and documentation
for production-oriented operating system and service configuration.

The repository is one part of a split platform project. Template building,
infrastructure provisioning, system configuration, Kubernetes bastion tooling,
documentation, and shared helper tools live in separate repositories so each
layer can evolve independently. Site-specific and personal configuration stays
outside this public repository.

## Scope

This repository owns public Ansible code: playbooks, roles, examples, Ansible
support scripts, and documentation. Shared human and CI operator commands belong
in `platform-tools`.

It configures already-provisioned hosts. It does not create VMs, build Proxmox templates, manage OpenTofu state, or store secrets.

Only safe examples belong here. Real inventories, host variables, access policies, CA certificates, and non-secret environment-specific configuration belong in `../platform-private/config/`; real kubeconfigs, tokens, passwords, private keys, and other secrets belong outside Git.

Working plans, test plans, incident notes, and environment-specific operational
notes belong in `../platform-plans/config/plans/`, not in this public repo.

## Requirements

- Podman for the development/tooling container.
- Git and Make for local setup and helper targets.
- Ansible and lint tooling installed inside `Containerfile.dev` from
  `requirements-dev.txt` and `requirements.yml`.
- The `vendor/platform-k8s-bastion` submodule for default bastion runtime input.
- `platform-tools` v4.0.0 or newer for operator-side PKI exchange commands. Pin
  the exact target-installed `platform-pki` SHA-256 in private inventory.
- SSH access, host keys, private inventory, and secret files for real runs.

## Quick Start

Clone submodules and build the local development container:

```bash
git submodule update --init --recursive
make deps
make help
```

Open an interactive toolbox shell when you need to run Ansible or lint tooling
without installing those dependencies on the host:

```bash
make shell
```

For real runs, source the matching private environment file and run a helper
script. `homelab` is one example environment name; use the environment name
from your private configuration layout.

```bash
source ../platform-private/config/homelab.ansible.env
./scripts/run-homelab.sh
```

The helper scripts also accept explicit inventory overrides when needed.

For the full environment bring-up order, SSH key handoff, secrets layout, and service smoke commands, see [Operator runbook](docs/operator-runbook.md).

## Common Commands

```bash
make help
make syntax ENV=dev
make check ENV=dev
make lint
make yamllint
make test
make test-parallel
make verify
make verify-parallel
make syntax-openbao-observers ENV=dev
make deploy-openbao-observers ENV=dev
make smoke-openbao-observers ENV=dev
make deploy-bootstrap-token-issuer-staging ENV=dev LIMIT=k8s-bastion-01 STAGING_MODE=preflight
make smoke-firewalld ENV=dev
make smoke-k8s-bastion ENV=dev
make storage-test-preflight ENV=config-test LIMIT=storage-volume-test-01
```

Most Make targets accept `ENV`, `PLAYBOOK`, `LIMIT`, and `EXTRA_ARGS`. Real
runs require the matching private environment file and inventory.

Managed-host preparation includes a `rocky`-only non-TTY sudo exception and a
detached sudo check. The helper can upgrade its exact previous policy on an
approved rerun; see
[Non-TTY Sudo](docs/ansible-host-bootstrap.md#non-tty-sudo-and-existing-prepared-hosts).

### RKE2 Bootstrap

RKE2 bootstrap plan and apply first require pristine nodes and strict node-side
HTTPS checks of the pinned RPM key and explicit registry mirror APIs, before
host configuration changes. Required CA trust must be preinstalled. See
[Bootstrap Source Preflight](docs/rke2-operations.md#bootstrap-source-preflight)
for the checks and their endpoint-only qualification boundary.
Follow [Prepare Node HTTPS Trust](docs/rke2-operations.md#prepare-node-https-trust)
for the separate controller, node, registry and endpoint-chain responsibilities.

Prepare inventory-declared managed-host aliases separately with the fixed
`rke2-host-aliases-plan` and `rke2-host-aliases-apply` routes. They select the
complete RKE2 cluster and run only common host-alias tasks after all-node guards.
Apply finishes with an unchanged check and node-side NSS verification. See
[RKE2 Host Aliases](docs/rke2-host-aliases.md) for the transport-only JSON contract
and private CI approval boundary.

RKE2 repository metadata-signature verification defaults to enabled. The boolean
`rke2_rpm_repo_gpgcheck` permits an explicit private-inventory exception for both
RKE2 repositories while keeping package signatures, key pins and HTTPS checks.
See [RPM Repository Trust](docs/rke2-operations.md#rpm-repository-trust).

### RKE2 Storage Operations

The fixed `storage-check` and `storage-apply` routes accept one literal RKE2 storage
host per call. Apply first validates transport-only controller JSON and mounted
inventory declarations, then runs a fresh check, the existing storage role, a
second real apply requiring zero changes, and read-only mounted-state verification. Private
CI owns per-node manual confirmation; failed or interrupted runs require review
before another attempt. See [Storage Operations](docs/storage-check.md).

### OpenBao Acceptance

Standalone dev OpenBao acceptance does not depend on the monitoring stack or
OpenBao-hosted observers. Production monitoring is still required. Keep traffic
limited to acceptance checks until named administrator access, local audit
rotation, and recovery gates have been completed and normal onboarding has been
separately authorized. These workflows are not evidence of live qualification.

DNS infrastructure is optional; the service hostname and its certificate DNS SAN
identity remain required. See [OpenBao Without DNS](docs/private-workflow.md#openbao-without-dns)
for private controller, Docker job, and managed-host mappings.

HAProxy and Keepalived require a reviewed firewall lifecycle and policy, not
universal firewalld enablement. Explicit `firewalld_service_enabled: false` with
`firewalld_service_state: stopped` requires actual inactive/boot-disabled state
and offline permanent configuration/rule validation; `true` with `started`
requires actual active/boot-enabled state and correct runtime and permanent rules.
Keep `*_firewalld_manage: true` in either mode. With firewalld off, there is no
host-firewall enforcement from firewalld and its configured allowlists are not
operative; this is not equivalent security or production qualification. The mode
must match reviewed private commits and plan evidence. Enabling enforcement, if
chosen, needs separate approval. See the
[firewall contract](docs/firewalld.md#haproxy-and-keepalived-lifecycle).

`make smoke-openbao ENV=dev LIMIT=openbao` checks strict direct-node status and
all three HAProxy paths only, for the pre-VIP phase. The `platform-tools` facade
`platform-openbao-edge` provides `haproxy-plan`, `haproxy-activate`,
`keepalived-plan`, `keepalived-activate`, `smoke`, and `vip-smoke` through the same
fixed core. The four plan/activation commands require `--plan` alongside
`--source`, `--inventory`, and `--controller-vars`. Operator activation uses exact
TTY approval; CI uses the matching same-pipeline protected manual job without a
TTY. Existing direct interactive Make activation targets remain available.

HAProxy activation starts the verified staged service without package,
configuration, SELinux, or firewall reconvergence. Its built-in-only activation
entry point rechecks staged SELinux client, metrics, and backend port labels and
firewall policy before startup; ordinary staging retains its declared collection
dependencies.
Staging installs a separate public CA copy under `/etc/haproxy`; activation checks
its identity, exact configuration, and SELinux service-domain access without
relabeling OpenBao's private container tree. Path qualification allows ten bounded
strict TLS health requests and requires HTTP 200. Rollback inspects HAProxy after
stopping/disabling it, clears a failed latch only when present, then verifies exact
inactive/disabled state before releasing its guard.
HAProxy plans also require the target-observed SSH peer to be admitted by the
client allowlist, bind that stable observation, and recheck it before startup.
Use direct SSH and stable controller egress; this early check does not replace
the strict HTTPS check from the actual operator or CI job environment.

Plans expire after 1800 seconds and bind clean committed source, private
inventory, environment, lane, and live evidence, plus CI image/project/pipeline
and plan-job identity. Commit approved readiness as exactly true on all hosts
before planning an activation; setting it after a read-only readiness-false plan
invalidates that plan. Operator plans stay outside Git in an existing owner-only
`0700` directory, published as new non-overwritten `0600` files; CI uses a fixed
restricted artifact. Target guards consume plans before final preflight and
exclude only supported HAProxy/Keepalived activations, not other lifecycle work.
Do not run other lifecycle operations concurrently. Retained guards require
reviewed recovery; never delete consumed records or reuse a consumed plan.

The separately approved Keepalived activation starts the staged VIP;
`make smoke-openbao-vip ENV=dev LIMIT=openbao` adds active Keepalived desired and
actual state, repeated exact single-owner checks on the configured interface,
strict service-hostname TLS through the forced VIP and ordinary service-name
resolution (DNS or static host mapping), and cluster identity checks. Run VIP
smoke only after successful activation and the reviewed active desired-state
handoff. Both smoke targets require the complete three-host cluster.

Follow the [OpenBao VIP acceptance procedure](docs/operator-runbook.md#openbao-vip-acceptance)
for network prerequisites, per-activation approval, backup-priority-first startup,
Keepalived-only rollback, and the post-success reviewed private desired-state
commit. Neither operator nor CI activation automatically mutates or pushes private
source; CI qualification, rollback, and reporting remain in CI. See
[OpenBao Edge Plans](docs/operator-runbook.md#openbao-edge-plans) for the two lanes
and [Guard Recovery](docs/operator-runbook.md#openbao-edge-guard-recovery).
Never run the ordinary `playbooks/openbao.yml` staging playbook against an active
or initialized cluster, including as a second apply after activation.

## Platform Project

| Repository | Purpose |
|---|---|
| [`platform-template-builder`](https://codeberg.org/rch/platform-template-builder) | Builds reusable Proxmox VM templates from cloud images. |
| [`platform-infra`](https://codeberg.org/rch/platform-infra) | Provisions platform infrastructure with OpenTofu. |
| [`platform-config`](https://codeberg.org/rch/platform-config) | Configures operating systems and services with Ansible. |
| [`platform-k8s-bastion`](https://codeberg.org/rch/platform-k8s-bastion) | Contains Kubernetes bastion tooling and operational helpers. |
| [`platform-docs`](https://codeberg.org/rch/platform-docs) | Contains architecture notes, runbooks, diagrams, and operational documentation. |
| [`platform-tools`](https://codeberg.org/rch/platform-tools) | Provides shared operator tools, including host-local PKI exchange commands. |

Typical workflow:

```text
platform-template-builder
  -> platform-infra
  -> platform-config
  -> platform-k8s-bastion

platform-tools provides shared human and CI operator commands.
platform-docs documents the design and operations across all repositories.
```

## Documentation

- [Documentation index](docs/README.md)
- [Operator runbook](docs/operator-runbook.md)
- [Ansible host bootstrap](docs/ansible-host-bootstrap.md)
- [Same-workstation PKI layout](docs/pki-local-layout.md)
- [Private workflow](docs/private-workflow.md)
- [Kubernetes bastion and issuer staging validation](docs/k8s-bastion.md)
- [Storage volume acceptance fixture](docs/storage-volume-test.md)
- [RKE2 operations](docs/rke2-operations.md), including the
  [in-cluster Runner](roles/rke2_gitlab_runner/README.md) with a private
  HTTPS Helm repository override and unchanged upstream default
  (an optional HTTPS clone origin preserves checkout through approved proxies)
- [RKE2 storage checks and single-node apply](docs/storage-check.md)
- [RKE2 aliases-only preparation](docs/rke2-host-aliases.md)
- [GitLab Runner offline preload](roles/gitlab_runner/README.md#temporary-offline-preload):
  temporary dedicated trusted-runner `if-not-present` override; the default and
  self-bootstrap remain `always`.
- [Development](docs/development.md)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.
