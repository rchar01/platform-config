# News

This file gives a short, release-oriented view of what changed between versions.

## Unreleased

No user-visible changes yet.

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
- Run Ansible and lint tooling in a Podman development container instead of a
  host Python environment.
- Guard Zot registry exposure so broad anonymous access requires an explicit
  isolated-development override.
- Add public documentation for development, inventories, roles, private
  workflow, operator runs, registry operations, rebuild flow, and maintenance
  playbooks.
