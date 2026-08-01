# Maintenance Playbooks

This directory is for operator-triggered maintenance actions that are useful to
automate but should not run as part of normal desired-state convergence.

Maintenance playbooks differ from migrations:

- migrations are one-time changes from an old live state to a new live state
- maintenance playbooks are repeatable operational procedures run only on demand

## Appropriate Maintenance Actions

Use this directory for actions such as:

- OS update orchestration
- reboot checks and controlled reboots
- backup verification
- restore validation
- service drain or uncordon workflows
- health checks that need elevated privileges
- emergency disable or quarantine operations

Do not put normal role tasks here. If a task can safely run every day to describe
the desired state, it belongs in a role or normal playbook.

## Safety Rules

Maintenance playbooks should:

- require explicit operator invocation
- support `--limit` for targeted runs
- use clear play names and task names
- prefer read-only checks before changing state
- validate outcomes before reporting success
- avoid hidden destructive defaults

## Running a Maintenance Playbook

Example:

```bash
source ../platform-private/config/homelab.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/maintenance/example.yml --limit target-host-or-group
```

Replace `example.yml` with a real maintenance playbook when one is added.

Do not import maintenance playbooks from `playbooks/site.yml`.

Available maintenance playbooks:

- `openbao-status.yml`: intentionally fails closed until strict three-node
  service, TLS, health, Raft membership, HAProxy, and firewall checks replace
  the retired standalone status behavior. It never initializes or unseals
  OpenBao.
