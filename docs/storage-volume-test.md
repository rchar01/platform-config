# Storage Volume Acceptance Fixture

The Phase 2 storage acceptance workflow exercises the existing `storage_volume`
role against one isolated, disposable Rocky fixture. It is maintenance-only and
is never imported by `playbooks/site.yml` or included in normal convergence.

The public example under `inventories/config-test/` contains exactly one
fictional host. That host belongs only to `rocky` and
`storage_volume_test_hosts`; it deliberately does not belong to
`storage_volume_hosts`. Create the real `config-test` inventory and environment
file under `../platform-private/config/`. Do not add approval variables to either
inventory.

## Fixture Contract

Attach one dedicated, disposable disk of at least 32 GiB and identify it with an
exact `/dev/disk/by-id/...` or `/dev/disk/by-path/...` path. The workflow rejects
kernel names such as `/dev/sdb`, root-device ancestry, children, mounts, `blkid`
or `wipefs` signatures, an existing expected partition or VG, and mounted fixture
mountpoints. Set `storage_volume_test_expected_serial` in private host variables
when the fixture disk has a stable serial that should also be checked.

Initialization creates one partition, PV, and VG, then an 8 GiB XFS baseline LV
at `/srv/config-test/baseline`. It mounts by UUID, retains at least 12 GiB of VG
headroom, and writes a fixed baseline sentinel. Final inventory uses
`initialize: false` and `reuse_existing_vg: true`, keeps that 8 GiB baseline LV,
and adds one missing 4 GiB XFS LV at `/srv/config-test/added` while retaining the
same 12 GiB headroom.

The helper accepts only `preflight`, `initialize`, `check`, `converge`, and
`reboot`. There is no cleanup, reset, or wipe operation. If a disk is partial or
ambiguous, recreate the fixture VM instead of trying to repair it through this
workflow.

## Commands

Set the private paths explicitly on every command. The limit must be the literal
single fixture hostname, not a group or pattern.

```bash
make storage-test-preflight \
  ENV=config-test \
  ENV_FILE=../platform-private/config/config-test.ansible.env \
  INVENTORY=../platform-private/config/inventories/config-test/hosts.yml \
  LIMIT=storage-volume-test-01

make storage-test-initialize \
  ENV=config-test \
  ENV_FILE=../platform-private/config/config-test.ansible.env \
  INVENTORY=../platform-private/config/inventories/config-test/hosts.yml \
  LIMIT=storage-volume-test-01

make storage-test-check \
  ENV=config-test \
  ENV_FILE=../platform-private/config/config-test.ansible.env \
  INVENTORY=../platform-private/config/inventories/config-test/hosts.yml \
  LIMIT=storage-volume-test-01

make storage-test-converge \
  ENV=config-test \
  ENV_FILE=../platform-private/config/config-test.ansible.env \
  INVENTORY=../platform-private/config/inventories/config-test/hosts.yml \
  LIMIT=storage-volume-test-01

make storage-test-reboot \
  ENV=config-test \
  ENV_FILE=../platform-private/config/config-test.ansible.env \
  INVENTORY=../platform-private/config/inventories/config-test/hosts.yml \
  LIMIT=storage-volume-test-01
```

`initialize` prompts on a TTY for exactly:

```text
initialize-storage-test-fixture|HOST|DEVICE
```

`reboot` uses a separate approval:

```text
reboot-storage-test-fixture|HOST|DEVICE
```

The playbook itself prompts on the controller TTY during the selected host play
and compares the exact input before running `ansible-config`, `ssh -G`, or any
remote module. The helper does not authorize either operation and passes no
approval variable. Direct `ansible-playbook` invocation therefore has the same
unavoidable controller-side prompt. Do not persist approval input in inventory.
Reboot also generates a fresh nonce, writes it to both mounts, records the boot ID,
syncs, performs a bounded Ansible reboot, requires a changed boot ID, and checks
the exact nonce after mounts return.

Host-key checking must remain strict. The helper requires effective Ansible
`HOST_KEY_CHECKING=true` from `ansible-config` and rejects unsafe values from all
three inventory and environment SSH argument surfaces, plus the effective SSH
connection-plugin arguments reported by `ansible-config`. The playbook repeats
the effective global and SSH connection-plugin checks and rejects
case-insensitive `StrictHostKeyChecking` values `no`, `false`, `off`, or `0`, and
`UserKnownHostsFile /dev/null`. After valid destructive approval, `ssh -G`
evaluates the target's effective OpenSSH policy; configured OpenSSH `Match exec`
commands may therefore execute at that point as part of policy evaluation.

The Make defaults remain `../platform-private/config/...`. In a coordinated
worktree, set `PLATFORM_CONFIG_PRIVATE_ROOT` to the sibling `platform-private`
checkout if it is not at the wrapper's detected repository-parent location. The
wrapper mounts that root read-only at `/platform-private`. From the container
repository root `/workspace`, the default sibling paths therefore remain
container-visible.

## Evidence

`check` records normalized disk, PV, VG, LV, filesystem, mount, and fstab state
before and after role check mode and requires exact equality. `converge` runs the
playbook twice and requires exactly one fixture recap row with `changed=0`,
`failed=0`, `unreachable=0`, `ignored=0`, and `rescued=0` in the second run.
`reboot` requires post-reboot verification and then a separate convergence with
the same exact clean recap contract.

The pytest coverage is synthetic: it checks source contracts, syntax, guards,
and helper target resolution with mocked Ansible executables. It never contacts a
host or mutates a disk. Only successful execution of the five commands against a
fresh disposable fixture is live acceptance evidence.
