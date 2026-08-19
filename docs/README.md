# Documentation

Use this index to find setup, configuration, security, service, and operational
documentation for `platform-config`. Start with the operator runbook for an
environment rollout or the development guide for repository work.

This is a public repository. Documentation contains reusable procedures and
safe examples only. Real inventories and non-secret environment configuration
belong in `../platform-private/config/`; credentials, private keys, kubeconfigs,
and other secrets belong outside Git.

## Start Here

- [Operator Runbook](operator-runbook.md): End-to-end prerequisites, environment
  bring-up order, service application, smoke tests, and day-2 operations.
- [Platform Workflow](workflow.md): Repository responsibilities and the boundary
  between desired state, migrations, maintenance, and rebuilds.
- [Private Workflow](private-workflow.md): Connect public Ansible code to private
  inventories, environment files, access policies, and outside-Git secrets.

## Configuration And Boundaries

- [Inventories](inventories.md): Public inventory examples, private inventory
  layout, host groups, and host or group variables.
- [Storage Volume Acceptance Fixture](storage-volume-test.md): Isolated Phase 2
  preflight, initialization, check-mode, convergence, and reboot acceptance.
- [Roles](roles.md): Summary of the Ansible roles and the configuration each role
  owns.
- [Private Configuration](private-config.md): Short reference for deciding what
  belongs in the public repository, private configuration, or outside-Git storage.
- [Secrets](secrets.md): Short reference for tokens, passwords, private keys,
  kubeconfigs, and outside-Git storage.

## Security And Networking

- [Firewalld Readiness And Enablement](firewalld.md): Inactive baseline, rule
  ownership, offline staging, canary activation, validation, rollout, and rollback.

## Services

- [Registry](registry.md): Zot registry access, host-local certificate lifecycle,
  authentication, OCI smoke tests, client tools, Kubernetes pulls, and
  image-signing considerations.
- [Host-Local Registry PKI Workflow](registry-host-local-pki-workflow.md): Exact
  end-to-end request, offline signing, activation, evidence, terminal outcome,
  recovery, backup, and local-verification procedure.
- [PKI Exchange Setup](pki-exchange-setup.md): Prepare protected transfer-station
  storage, the GitLab project and credentials, pinned target SSH, offline
  workspaces, and optional CI publication.
- [Manual GitLab Runner Deployment](gitlab-runner-manual-deployment.md):
  Reproduce the Podman Quadlet runner service without Ansible, including TLS,
  registration, verification, migration, and Kubernetes-tooling boundaries.
- [GitLab PKI Package Exchange](pki-gitlab-package.md): Exact five-family package
  publication and download behavior, validation, and remaining runtime gates.
- [Kubernetes Bastion](k8s-bastion.md): Bastion prerequisites, runtime source,
  access configuration, installation, issuer staging validation, smoke tests,
  and reconciliation.

## Operations

- [Rebuild](rebuild.md): Host rebuild categories, repository responsibilities,
  service recovery, and Kubernetes node considerations.
- [Migrations](../migrations/README.md): One-time transitions for existing hosts
  that do not belong in normal desired-state convergence.
- [Maintenance Playbooks](../playbooks/maintenance/README.md): Explicit operator
  actions that should not run during routine convergence.

## Development

- [Development](development.md): Podman development container, repository checks,
  Ansible tooling, and managed-host requirements.
- [Testing Guide](testing.md): Reusable Python and Bash test design, execution,
  development-container isolation, and version-pinning strategy.
- [Project README](../README.md): Project scope, requirements, quick start, common
  commands, related repositories, and license.
