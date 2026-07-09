# platform-config

`platform-config` configures operating systems and services with Ansible.

## Platform Project

This repository is one part of a homelab platform project.

The repositories are split by responsibility so that template building, infrastructure provisioning, system configuration, Kubernetes bastion tooling, documentation, and shared helper tools can evolve independently.

| Repository | Purpose |
|---|---|
| [`platform-template-builder`](https://codeberg.org/rch/platform-template-builder) | Builds reusable Proxmox VM templates from cloud images. |
| [`platform-infra`](https://codeberg.org/rch/platform-infra) | Provisions platform infrastructure with OpenTofu. |
| [`platform-config`](https://codeberg.org/rch/platform-config) | Configures operating systems and services with Ansible. |
| [`platform-k8s-bastion`](https://codeberg.org/rch/platform-k8s-bastion) | Contains Kubernetes bastion tooling and operational helpers. |
| [`platform-docs`](https://codeberg.org/rch/platform-docs) | Contains architecture notes, runbooks, diagrams, and operational documentation. |
| [`platform-tools`](https://codeberg.org/rch/platform-tools) | Provides shared optional helper tools used by the platform repositories. |

Typical workflow:

```text
platform-template-builder
  -> platform-infra
  -> platform-config
  -> platform-k8s-bastion

platform-tools provides optional shared helper commands.
platform-docs documents the design and operations across all repositories.
```

## Scope

This repository owns public Ansible code: playbooks, roles, examples, helper scripts, and documentation.

It configures already-provisioned hosts. It does not create VMs, build Proxmox templates, manage OpenTofu state, or store secrets.

Only safe examples belong here. Real inventories, host variables, access policies, CA certificates, and non-secret environment-specific configuration belong in `../platform-private/config/`; real kubeconfigs, tokens, passwords, private keys, and other secrets belong outside Git.

## Quick Start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
ansible-galaxy collection install -r requirements.yml
```

Or use the Make wrapper:

```bash
make deps
make help
```

For real runs, source the matching private environment file and run a helper script:

```bash
source ../platform-private/config/homelab.ansible.env
./scripts/run-homelab.sh
```

The helper scripts also accept explicit inventory overrides when needed.

For the full environment bring-up order, SSH key handoff, secrets layout, and service smoke commands, see [Operator runbook](docs/operator-runbook.md).

## Documentation

- [Private workflow](docs/private-workflow.md)
- [Operator runbook](docs/operator-runbook.md)
- [Kubernetes bastion](docs/k8s-bastion.md)
- [Kubernetes bastion smoke test](playbooks/k8s-bastion-smoke.yml)
- [Registry](docs/registry.md)
- [Migrations](migrations/README.md)
- [Maintenance playbooks](playbooks/maintenance/README.md)
- [Rebuild](docs/rebuild.md)
- [Inventories](docs/inventories.md)
- [Roles](docs/roles.md)
- [Development](docs/development.md)
- [Platform workflow](docs/workflow.md)
