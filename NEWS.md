# News

This file gives a short, release-oriented view of what changed between versions.

## Unreleased

No user-visible changes yet.

## v2.0.1 - 2026-08-20

This patch fixes controller-local PKI operations when inventory enables Ansible
privilege escalation for managed hosts.

### Fixes

- Prevent controller-local helper source inspection, direct intake, response
  authentication, and evidence-status actions from inheriting the inventory
  connection-level become setting. Target and runner privilege behavior is
  unchanged.

## v2.0.0 - 2026-08-20

This release adds staged HA service operations, complete host-local registry PKI,
expanded runner and storage acceptance, and two required configuration
migrations.

### Upgrade Notes

- Replace legacy OpenBao role variables and automatic startup assumptions with
  the new disabled-by-default staged HA workflow. Review staging, status,
  observer, HAProxy, and rolling-maintenance gates before applying;
  initialization, unsealing, and runtime activation remain operator-controlled.
- Replace `kong_ingress_enabled` with `platform_ingress_controller`. Traefik is
  now the default; selecting Kong or changing an existing cluster's ingress
  controller requires a planned migration.

### Highlights

- Add staged OpenBao HA, Keepalived VIP, HAProxy, observer, status, and guarded
  rolling-maintenance workflows without automating initialization, unsealing, or
  runtime activation.
- Add monitoring HAProxy and external-probe contracts, immutable artifact pins,
  runtime qualification fixtures, and staged mTLS etcd bootstrap and activation.
- Add target-local Zot certificate request collection, authenticated response
  intake, interactive activation and recovery, separate-runner validation,
  deployment evidence export, authenticated terminal signer-outcome import,
  completion status, authenticated host-local Zot TLS custody, direct restricted
  exchange, GitLab package transport, explicit CI gates, fixed access revocation,
  and terminal verification.
- Add Podman and Docker GitLab Runner executors, safe first-runner bootstrap,
  isolated storage-volume acceptance, Rocky alignment, exact Podman package
  pinning, guarded RKE2 kernel preparation, and focused bastion operations.
- Move the default test suite to pytest in sanitized pinned containers while
  retaining focused serial and supplemental parallel verification paths.

## v1.1.0 - 2026-07-25

This release hardens public service configuration, standardizes firewall
readiness, and improves Kubernetes API HA and containerized development.

### Highlights

- Guard Zot registry exposure so broad anonymous access requires an explicit
  isolated-development override; authenticated and source-restricted
  configurations remain the preferred paths.
- Install firewalld and its Python bindings as an explicit baseline while
  keeping the daemon disabled at boot and stopped at runtime by default.
- Add focused firewalld convergence and smoke playbooks plus an enablement guide
  covering offline staging, canary activation, validation, and rollback.
- Run Ansible and lint tooling in a Podman development container with isolated
  writable runtime state.
- Pin kube-vip `v1.2.1`, preserve the upstream `15/10/2`-second
  leader-election policy, and verify reconciliation, readiness, and API access
  in smoke checks while retaining RKE2-managed `spec.set` values when
  Ansible-owned fields already match.
- Align the public examples around thirteen fictional dev service and cluster
  hosts plus one fictional homelab GitLab host, with matching group and host
  variable shapes.
- Add a task-oriented documentation index and clarify monitoring credential
  file permissions.

## v1.0.0 - 2026-07-09

Initial public release of `platform-config`.

### Highlights

- Publish production-oriented Ansible configuration for already-provisioned
  platform hosts.
- Include public playbooks, roles, helper scripts, development checks, and safe
  example inventories.
- Document the repository boundary between public Ansible code, private
  site-specific configuration, outside-Git secrets, and operational plans.
- Pin the Kubernetes bastion runtime as a submodule under
  `vendor/platform-k8s-bastion`.
- Provide role and playbook coverage for base OS configuration, SSH, users,
  packages, firewalld, storage volumes, Podman hosts, GitLab CE, GitLab Runner,
  OpenBao, monitoring, RKE2, kube-vip, Kong ingress, workload load balancing,
  Zot registry, and Kubernetes bastion access.
- Add public documentation for development, inventories, roles, private
  workflow, operator runs, registry operations, rebuild flow, and maintenance
  playbooks.
