# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added a task-oriented documentation index for setup, configuration, security,
  services, operations, and development references.
- Added a public firewalld readiness and enablement guide covering rule
  ownership, offline staging, canary activation, validation, rollout, rollback,
  and known readiness gaps.
- Added an all-Rocky firewalld smoke check for package availability, Python
  binding imports, disabled boot state, inactive runtime state, and permanent
  configuration validity.
- Added a focused firewalld baseline playbook for targeted convergence without
  applying unrelated base OS roles.

### Changed

- Changed the firewalld baseline to install its Python bindings explicitly and
  remain disabled at boot and stopped at runtime by default.
- Made focused service playbooks establish firewalld tooling before managing
  permanent firewall configuration, with offline and active-runtime support.

## [1.0.0] - 2026-07-09

### Added

- Initial public Ansible configuration repository for already-provisioned
  platform hosts.
- Public roles and playbooks for base OS setup, SSH, users, packages,
  firewalld, storage volumes, Podman hosts, GitLab CE, GitLab Runner, OpenBao,
  monitoring, RKE2, kube-vip, Kong ingress, workload load balancing, Zot
  registry, and Kubernetes bastion access.
- Safe example inventories and private environment file examples for named
  environments such as `dev` and `homelab`.
- Makefile workflow for containerized dependency setup, inventory inspection,
  syntax checks, check-mode runs, apply runs, linting, repository tests, and
  service smoke playbooks.
- Podman development container for Ansible and lint tooling.
- Kubernetes bastion runtime submodule pinned under
  `vendor/platform-k8s-bastion`.
- Public documentation for development, inventories, roles, private workflow,
  operator runs, registry operations, rebuild flow, maintenance playbooks, and
  platform workflow.
- MIT license file.

### Changed

- Positioned the project as production-oriented public Ansible code with
  private, site-specific configuration supplied from outside this repository.
- Clarified that personal or environment-specific values are private inputs,
  while this repository contains reusable public code, examples, and durable
  documentation.

### Security

- Documented boundaries for public examples, private inventories, non-secret
  site configuration, outside-Git secrets, and operational plans.
- Added ignore rules for private inventories, env files, access policies,
  kubeconfigs, certificate/key material, vault files, and private working
  plans.
- Added a Zot registry exposure guard so broad anonymous access requires an
  explicit isolated-development override.
- Hardened the public Zot registry example with htpasswd authentication,
  source-scoped firewalld access, and an access-control policy example.
