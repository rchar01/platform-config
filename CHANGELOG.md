# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Makefile workflow for dependency setup, inventory inspection, syntax checks,
  check-mode runs, apply runs, linting, repository tests, and service smoke
  playbooks.
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
