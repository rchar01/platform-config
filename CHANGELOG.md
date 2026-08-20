# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.1] - 2026-08-20

### Fixed

- Fixed controller-local host-local PKI source inspection, direct intake,
  response authentication, and evidence-status actions when inventory enables
  connection-level privilege escalation for managed hosts. Controller tasks now
  explicitly disable both become controls without changing target or runner
  privilege behavior.

## [2.0.0] - 2026-08-20

### Breaking Changes

- Replaced the legacy standalone OpenBao variables and automatic startup with a
  disabled-by-default staged HA interface. Review the new staging, status,
  observer, HAProxy, and rolling-maintenance workflow before migrating an
  existing deployment. Initialization, unsealing, and runtime activation remain
  separate operator-controlled work.
- Replaced `kong_ingress_enabled` with `platform_ingress_controller`. Bundled
  Traefik is now the default ingress controller; selecting Kong or changing an
  existing cluster's controller requires a planned ingress migration.

### Added

- Added staged OpenBao HA, Keepalived VIP, HAProxy, observer, read-only status,
  and guarded rolling-maintenance workflows while keeping initialization,
  unsealing, and runtime activation outside automation.
- Added monitoring HAProxy contracts and staging, locked external health probes,
  immutable artifact identities, runtime qualification fixtures, and a staged
  mTLS etcd lifecycle with preflight, bootstrap, status, and activation gates.
- Added a fail-closed GitLab Generic Package request publisher for host-local
  PKI public artifacts, with canonical request, receipt, manifest, CSR,
  signature, trust, status, pagination, partial-resume, and digest validation.
- Added operator-only host-local Zot PKI playbooks and Make targets for trust,
  request collection, status, response authentication, interactive activation,
  explicit recovery, evidence export, and decision preflight.
- Added fixed target lifecycle and separate-runner validation helpers plus
  protected controller actions for exact request, response, and evidence
  exchange.
- Added direct restricted-SSH PKI exchange, fixed access revocation, explicit CI
  gates, terminal outcome verification, and no-clobber request and evidence
  materialization.
- Added Podman and Docker GitLab Runner executor support, safe first-runner
  bootstrap preflight, and documented manual repository transfer.
- Added isolated storage-volume acceptance and reuse workflows, Rocky
  10.1-to-10.2 alignment, exact Podman RPM pinning, guarded RKE2 kernel
  prerequisite reboot, Kubernetes bastion user-bootstrap controls, and a
  focused bastion Podman playbook.
- Added staging validation for bootstrap-token-issuer v0.3.1 and fail-closed
  translated API egress policy checks.

### Changed

- Added explicit `managed` and `host-local` Zot TLS custody. Host-local custody
  resolves authenticated immutable `fullchain.crt` and `tls.key` paths on the
  target and refuses configuration drift outside the lifecycle transaction.
- Migrated the default repository test suite to pytest, added a sanitized pinned
  test container, and added supplemental parallel verification targets.
- Pinned monitoring, container-runtime, and release artifact identities and made
  volume-group reuse and OverlayFS qualification auditable and fail closed.

### Fixed

- Fixed bootstrap-token-issuer release retrieval, cleanup, rollback identities,
  policy selection, timestamp validation, and bootstrap group checks.
- Fixed storage acceptance privilege, utility, package, reboot-stability,
  SELinux-label, and verification-scope handling.
- Fixed GitLab Runner rollback, runtime kernel-package installation, EFI capacity
  validation, host-alias persistence, and PKI exchange endpoint preparation.
- Removed checkout-layout assumptions from configuration and runner workflows.

### Security

- Kept PKI leaf keys and GitLab token bytes outside package payloads, command
  arguments, URLs, output, and the public repository; conflicting or ambiguous
  package coordinates fail without deletion or repair.
- Rejected trailing or additional data in CSR and SSH-signature armor and
  metadata drift in pinned package, trust, configuration, and credential sources
  during publication.
- Kept host-local leaf keys on the target while binding request, artifact,
  deployment, trust, validation-boundary, runner, and evidence coordinates to
  exact authenticated records.
- Added interactive activation, journaled fail-closed recovery, strict TLS and
  read-only OCI validation from one distinct runner, and fixed public-file
  allowlists for request and evidence transfer.
- Added fixed-account restricted PKI exchange access with root-controlled
  dispatch, exact ownership markers, post-revocation absence checks, and no
  interactive Ansible behavior in unattended CI paths.

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
