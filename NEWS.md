# News

This file gives a short, release-oriented view of what changed between versions.

## Unreleased

No user-visible changes yet.

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
