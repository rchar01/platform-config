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

- `openbao-status.yml`: performs strict controller-side direct-node TLS health
  and authenticated Raft membership checks for the three-node OpenBao cluster.
  It requires an outside-Git read-only token, does not follow token-bearing
  redirects, and never initializes, unseals, restarts, or reconfigures OpenBao.
  HAProxy, VIP, and firewall connectivity remain separate acceptance gates.
- `openbao-rolling-restart.yml`: explicitly invoked post-initialization
  convergence. It requires all three hosts and a strict healthy baseline, queues
  current standbys before the active node, uses `serial: 1`, aborts on leadership
  drift, pauses after an actual restart for the two-custodian manual unseal, and
  requires strict three-voter recovery before advancing. It never initializes or
  unseals OpenBao and is not imported by `site.yml`.
- `storage-volume-test.yml`: exercises one isolated disposable storage fixture
  through the supported `scripts/storage-volume-test` boundary. It requires an
  exact host, stable by-id/by-path disk, strict SSH, and playbook-owned
  controller-side TTY approvals for initialization and reboot before connection
  policy evaluation. The helper passes no approval variable, so direct playbook
  invocation cannot bypass the prompt.
  It also requires fail-closed pristine/final verification.
  It provides no cleanup path; recreate the fixture VM on partial or ambiguous
  state. See [Storage Volume Acceptance Fixture](../../docs/storage-volume-test.md).
