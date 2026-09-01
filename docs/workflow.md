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

## Managed-Host SSH Handoff

Ansible can configure a new VM only after the VM already provides a working SSH
and Python boundary. `playbooks/bootstrap.yml` is repeatable desired-state
automation; it is not a replacement for initial account and access preparation.

Use this cross-repository workflow for each managed VM:

1. Generate or select one purpose-specific Ed25519 keypair for the VM with
   [`platform-ssh-init`](https://codeberg.org/rch/platform-tools/src/branch/main/docs/ssh-identity-helper.md).
   Use an unencrypted key only when unattended automation such as a protected
   GitLab job requires it. Keep the private key outside Git.
2. Have `platform-infra`, cloud-init, or an approved target-local provisioning
   process install only that VM's public key for the intended automation
   account. The target must also provide an active SSH server, Python 3, and
   passwordless non-interactive sudo when playbooks require become access. For
   the fixed Rocky 10.0 `rocky`/`access_ssh` boundary, transfer
   `scripts/rocky-ansible-host-prepare` and the per-VM public key through the
   authenticated console or provisioning channel, then run its explicit
   `apply` and `check` operations as root.
3. Authenticate the VM's SSH host public key through the console,
   infrastructure authority, or another independent channel. `ssh-keyscan` can
   collect a candidate but cannot authenticate it.
4. Put the real hostname, management address, SSH user, groups, and local
   private-key path in `platform-private`. Keep the private key and the
   authenticated `known_hosts` file outside Git.
5. Verify strict public-key SSH, Python discovery, and `sudo -n` from the
   controller before running a focused Ansible ping or playbook check.
6. For GitLab inventory jobs, give
   [`platform-ssh-ci-bundle`](https://codeberg.org/rch/platform-tools/src/branch/main/docs/ssh-ci-bundle.md)
   the explicit environment, per-host private-key paths, SSH targets, and
   independently authenticated host public keys. It produces the payloads for
   `PLATFORM_CI_SSH_KEY_BUNDLE` and `PLATFORM_CI_SSH_KNOWN_HOSTS`; it does not
   create keys, scan hosts, authenticate trust, contact GitLab, or upload
   variables.
7. Upload both payloads as protected, environment-scoped GitLab File variables
   with expansion disabled. The pinned `ansible-inventory-ping` component,
   documented at `docs/ansible-inventory-ping.md` in the separate `platform-ci`
   repository, resolves the approved inventory scope and stages the matching
   key for each selected host.

Never copy an SSH private key to a managed VM. Passing a public key to the VM
and later supplying its matching private key to an authorized controller or
protected CI job are separate operations with separate custody boundaries.
Rotate one VM's key independently rather than replacing an environment-wide
shared host credential.

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
