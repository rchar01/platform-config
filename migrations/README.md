# Migrations

This directory is for one-time operational playbooks that move an existing,
already-running system from an old live state to a new live state.

Normal desired-state roles and `playbooks/site.yml` must not replay historical
upgrade paths. A rebuilt host should converge directly to the current desired
state from inventory and role defaults.

## When To Add a Migration

Add a migration when the change:

- depends on previous live state
- must run with operator awareness
- may be unsafe to run every day
- needs sequencing such as drain, backup, restore, data move, or validation
- should be recorded as applied on a host or service

Do not add a migration for regular package installation, file templates, service
enablement, firewall baseline state, or other tasks that are safe in normal
repeatable roles.

## Naming

Use date-prefixed names that describe the old and new state:

```text
YYYY-MM-short-description.yml
```

Examples:

```text
2026-05-k8s-1.29-to-1.30.yml
2026-06-registry-storage-move.yml
2026-07-runner-token-rotation.yml
```

## Markers

For host-local migrations, use simple marker files under:

```text
/var/lib/platform-config/migrations/
```

Example marker:

```text
/var/lib/platform-config/migrations/2026-05-k8s-1.29-to-1.30.done
```

Migration playbooks should check the marker before changing state and write it
only after validation succeeds.

## Playbook Pattern

Use an explicit marker and fail safely by default:

```yaml
---
- name: Example one-time migration
  hosts: target_group
  become: true
  vars:
    migration_id: 2026-05-example
    migration_marker_dir: /var/lib/platform-config/migrations
    migration_marker: "{{ migration_marker_dir }}/{{ migration_id }}.done"
  tasks:
    - name: Check migration marker
      ansible.builtin.stat:
        path: "{{ migration_marker }}"
      register: migration_marker_stat

    - name: Stop if migration is already applied
      ansible.builtin.meta: end_play
      when: migration_marker_stat.stat.exists

    - name: Ensure migration marker directory exists
      ansible.builtin.file:
        path: "{{ migration_marker_dir }}"
        state: directory
        owner: root
        group: root
        mode: "0755"

    - name: Apply migration steps
      ansible.builtin.debug:
        msg: Replace this task with explicit migration work.

    - name: Write migration marker after validation
      ansible.builtin.copy:
        dest: "{{ migration_marker }}"
        owner: root
        group: root
        mode: "0644"
        content: "applied\n"
```

## Running a Migration

Always run migrations explicitly, with a limit when possible:

```bash
source ../platform-private/config/homelab.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" migrations/YYYY-MM-description.yml --limit target-host-or-group
```

Do not import migrations from `playbooks/site.yml`.

## Available Migrations

- `2026-08-rocky-10.1-to-10.2.yml` aligns one explicitly eligible Rocky Linux
  10.1 host to 10.2 through reviewed standard Rocky repositories. Use only the
  supported `scripts/rocky-minor-alignment` launcher and the private isolated
  `<env>-rocky-alignment` inventory. See
  [Rocky Linux Minor Alignment](../docs/rocky-minor-alignment.md).

## Documentation Checklist

Each migration should state:

- purpose and affected hosts or services
- prerequisites and backup expectations
- exact command to run
- validation steps
- rollback or recovery notes
- marker path or other completion signal
