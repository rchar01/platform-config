# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added a fail-closed GitLab Generic Package request publisher for host-local
  PKI public artifacts, with canonical request, receipt, manifest, CSR,
  signature, trust, status, pagination, partial-resume, and digest validation.

### Security

- Kept PKI leaf keys and GitLab token bytes outside package payloads, command
  arguments, URLs, output, and the public repository; conflicting or ambiguous
  package coordinates fail without deletion or repair.
- Rejected trailing or additional data in CSR and SSH-signature armor and
  metadata drift in pinned package, trust, configuration, and credential sources
  during publication.

## [1.1.0] - 2026-07-25

### Added

- Added a Podman development container and helper scripts for isolated Ansible
  and lint tooling.
- Added authenticated Zot registry smoke coverage for container image push,
  pull, and execution plus Helm OCI chart push and pull workflows.
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

- Moved Make-based Ansible and lint commands from a host virtual environment to
  the Podman development container; `make deps` now builds the container image.
- Changed the firewalld baseline to install its Python bindings explicitly and
  remain disabled at boot and stopped at runtime by default.
- Made focused service playbooks establish firewalld tooling before managing
  permanent firewall configuration, with offline and active-runtime support.
- Pinned kube-vip application `v1.2.1` independently from chart `0.9.9`,
  explicitly preserved the upstream `15/10/2`-second leader-election policy,
  and added deployed image and policy assertions to smoke checks.
- Aligned the public `dev` and `homelab` inventory examples with their current
  role topologies using fictional hosts, supported role inputs, and outside-Git
  placeholders.
- Documented required monitoring password source-file permissions and
  simplified root documentation links around the task-oriented index.

### Fixed

- Fixed containerized Ansible runs to use isolated writable home and runtime
  directories while preserving read-only SSH and private configuration mounts.
- Fixed kube-vip smoke checks that could accept an already-complete DaemonSet
  rollout before RKE2 Helm Controller had reconciled the desired image and
  lease policy.
- Fixed recurring kube-vip manifest drift by preserving RKE2-managed `spec.set`
  values when all Ansible-owned fields already match, while retaining repair
  behavior for invalid content and file metadata.

### Security

- Added a Zot registry exposure guard requiring authentication, managed source
  restrictions, or an explicit isolated-development override before broad
  anonymous access.
- Hardened the public Zot registry example with htpasswd authentication,
  source-scoped firewalld access, and an access-control policy example.

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
