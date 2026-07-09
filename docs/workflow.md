# Workflow

`platform-config` is one repository in the larger platform workflow.

1. `platform-template-builder` creates reusable Proxmox VM templates.
2. `platform-infra` creates VMs from those templates.
3. `platform-config` configures those VMs with Ansible after they boot.
4. `platform-k8s-bastion` provides scripts and tools installed onto bastion hosts.
5. `platform-private` provides real inventories, host variables, access policies, CA certificates, and non-secret environment config.
6. `~/.config/platform-infrastructure/` or another outside-Git secret store provides admin kubeconfigs, tokens, private keys, and passwords.

OpenTofu state, Proxmox API tokens, VM CPU/RAM/disk lifecycle, and template image downloads belong outside this repository.

The handoff from `platform-infra` to `platform-config` is inventory-shaped data: hostnames, IP addresses, groups, and variables that Ansible can consume from `../platform-private/config/`.

For operator commands, source the matching private env file before running Ansible:

```bash
source ../platform-private/config/homelab.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml
```

## Desired State, Migrations, and Maintenance

`playbooks/site.yml` and roles describe the current desired state. They should be
safe to run repeatedly and should converge a fresh rebuilt host directly to what
it should look like today.

One-time transitions for already-running systems belong in
[`migrations/`](../migrations/README.md). Do not import migrations from
`playbooks/site.yml`.

Operator-triggered actions that are useful but should not run during normal
convergence belong in [`playbooks/maintenance/`](../playbooks/maintenance/README.md).
Examples include controlled reboots, backup checks, restore validation, and
service drain or uncordon procedures.

Rebuild procedures belong in [Rebuild](rebuild.md). A clean rebuilt host should
converge directly to the current desired state unless a service-specific restore
or recovery procedure requires additional steps.

Use this rule when adding automation:

- if it can safely run every day, put it in a role or normal playbook
- if it should run exactly once with operator awareness, put it in `migrations/`
- if it is an on-demand operational procedure, put it in `playbooks/maintenance/`

`playbooks/bootstrap.yml` is imported by `playbooks/site.yml`; despite its name,
it must remain repeatable desired-state automation. Do not add one-time
initialization or migration logic there.
