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

This repository owns public Ansible code: playbooks, roles, examples, helper scripts, and documentation.

It configures already-provisioned hosts. It does not create VMs, build Proxmox templates, manage OpenTofu state, or store secrets.

Only safe examples belong here. Real inventories, host variables, access policies, CA certificates, and non-secret environment-specific configuration belong in `../platform-private/config/`; real kubeconfigs, tokens, passwords, private keys, and other secrets belong outside Git.

Working plans, test plans, incident notes, and environment-specific operational
notes belong in `../platform-plans/config/plans/`, not in this public repo.

## Requirements

- Python 3.12+ on the Ansible control node.
- Git and Make for local setup and helper targets.
- Ansible and lint tooling from `requirements-dev.txt`.
- Ansible Galaxy collections from `requirements.yml`.
- The `vendor/platform-k8s-bastion` submodule for default bastion runtime input.
- SSH access, host keys, private inventory, and secret files for real runs.

## Quick Start

Clone submodules and install local dependencies:

```bash
git submodule update --init --recursive
make deps
make help
```

Manual setup is equivalent:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
ansible-galaxy collection install -r requirements.yml
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
make verify
make smoke-k8s-bastion ENV=dev
```

Most Make targets accept `ENV`, `PLAYBOOK`, `LIMIT`, and `EXTRA_ARGS`. Real
runs require the matching private environment file and inventory.

## Platform Project

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

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.
