# Storage Check

The fixed `storage-check` route previews storage changes on one RKE2 inventory
host. CI may repeat it sequentially for all members of the reviewed RKE2 scope.
It never applies storage or starts RKE2.

```bash
scripts/platform-config-operation storage-check \
  --inventory /absolute/private/hosts.yml \
  --controller-vars /absolute/outside-git/controller-vars.json \
  --node server-01
```

The node must be a literal inventory hostname, belong to both `rke2_cluster` and
`storage_volume_hosts`, have exactly one server/agent role, and declare nonempty
`storage_volumes`. Groups, patterns, raw IP addresses and undeclared hosts are
rejected before SSH. The controller-vars file must be owner-private and supply
the reviewed SSH key map; normal role checks still validate each storage layout.

The route resolves inventory, pings only that host, and invokes the existing
`playbooks/storage-volumes.yml` with the exact host limit and `--check --diff`.
Check mode reports predicted changes without applying them; creation tasks for
absent LVs in a reused VG are skipped, so it does not predict every future change.
Expected changes are successful plan output, not an idempotence failure. Errors,
unreachable hosts and incomplete summaries fail the check. Only a separately
approved apply may make changes; its second real apply checks idempotence.

Use a qualified controller with Ansible Core 2.21.x, `ansible.posix` 2.2.2 and
`community.general` 12.6.0 for the CI lane. It needs SSH, known-hosts and source
CA files, not cluster or Runner tokens. Keep logs private and coordinate checks
with the same GitLab resource group used by platform mutations: a check is not
reliable evidence while an overlapping apply changes the target.

## OpenBao Storage Preparation

`openbao-storage-check` is a separate fixed check-only route for initial
three-node storage preparation. It validates the entire `openbao_storage` group
before checking one literal `--node`:

```bash
scripts/platform-config-operation openbao-storage-check \
  --inventory /absolute/private/hosts.yml \
  --controller-vars /absolute/outside-git/controller-vars.json \
  --node bao-01
```

All three hosts must belong to `storage_volume_hosts`, declare nonempty
`storage_volumes` and list-valued layouts, and be disjoint from `rocky`,
`container_hosts`, `openbao`, `rke2_cluster`, `rke2_servers` and `rke2_agents`.
This storage-only preparation group does not enroll hosts for OS, runtime or
service convergence. Group-name collisions, IP literals, patterns, missing or
overlapping scope fail before target access, including faults on a different
member from the selected node. Layout values remain private inventory intent.

The route validates and snapshots the transport-only controller JSON described
below before inventory execution, including selected-node key-map coverage.
Complete inventory and ping evidence gate the next phase; the sole playbook is
`playbooks/storage-volumes.yml --limit HOST --check --diff`. Complete successful
single-host evidence is required even when Ansible exits zero. Predicted changes
are allowed; a low count does not prove the new volumes already exist.

CI's `storage-check` component opts in using
`check-operation: openbao-storage-check` with `target-host: all`. It validates
the full three-host scope, stages only its SSH identities, checks each host
sequentially and retains any failure. Private bindings own the protected
environment, immutable sources and Runner routing. Use the same three storage
File-variable types, never OpenBao status/root/unseal credentials. No
`openbao-storage-apply` operation is supplied; existing storage apply remains
RKE2-only. Keep all lifecycle writers excluded during checks.

## Storage Apply

The fixed `storage-apply` route accepts the same single literal hostname and
inventory membership contract. Invoke it only for a separately approved node and
reviewed storage declaration:

```bash
scripts/platform-config-operation storage-apply \
  --inventory /absolute/private/hosts.yml \
  --controller-vars /absolute/outside-git/controller-vars.json \
  --node server-01
```

It executes these fixed phases in order:

1. Validate transport-only controller JSON before executing Ansible inventory,
   then resolve inventory and require every volume's effective state to be
   exactly `mounted` before pinging the selected node. Per-volume `state` takes
   precedence over inventory's `storage_volume_default_mount_state`; the role's
   default is `mounted`. Null, non-string, unresolved template, and other states
   fail preflight rather than first failing mounted-state verification after apply.
2. Run a fresh `playbooks/storage-volumes.yml --limit HOST --check --diff`.
   Proposed changes are allowed. A previous CI check does not replace this check.
3. Apply `playbooks/storage-volumes.yml --limit HOST` using the existing
   `storage_volume` role and its inventory-approved initialization policy.
4. Run the same **real apply** again. Any changed, failed, unreachable, ignored,
   or rescued recap count fails idempotence, even when Ansible exits zero.
5. Run the fixed read-only `playbooks/maintenance/storage-volumes-verify.yml`
   on that node to verify active filesystem identity, type, and mount options.

Complete successful callback evidence gates each subsequent command. Missing
recaps, ignored/rescued errors, command failures, and summary failures fail the
apply route; they cannot authorize a later mutation. Successful final reporting
requires every phase. `storage-check` retains its existing check-only behavior.

There are no list/all selectors, playbook overrides, extra Ansible arguments,
initialization flags, or automatic retries. The second apply is an idempotence
test, not a retry after failure. It can mutate a non-idempotent configuration and
then report failure; it does not roll those changes back. Signals are forwarded
and interruption retains failure status. **Interruption is not rollback.** Review
partial target state before separately authorizing another attempt; do not enable
automatic job retries or concurrent out-of-band storage administration.

### Controller Variables

For **`storage-apply` and `openbao-storage-check`**, `--controller-vars` must be an owner-private JSON
object without duplicate members. YAML is not accepted by this route. Unknown
keys are rejected before `ansible-inventory`, including storage definitions,
devices, initialization settings, and connection endpoint overrides. Storage
intent must come from reviewed inventory, not highest-precedence controller vars.
Every Ansible command receives the same validated `0600` temporary JSON snapshot;
changes to the original file after validation cannot replace that input.

The allowlist matches the generated controller JSON in
`platform-ci/templates/storage-apply.yml`. All keys are optional; `{}` keeps
transport entirely inventory-selected. Direct controllers can supply only the
existing per-host key map, with inventory resolving its key from that map:

```json
{
  "platform_ci_ssh_private_key_files": {
    "server-01": "/absolute/outside-git/ssh/server-01"
  }
}
```

Allowed keys and values:

| Keys | Accepted values |
| --- | --- |
| `platform_ci_ssh_private_key_files` | Hostname-to-absolute-literal-path object covering the selected node; other mapped hosts are allowed. |
| `ansible_ssh_private_key_file` | Exactly `{{ platform_ci_ssh_private_key_files[inventory_hostname] }}`, with that map present. |
| `ansible_ssh_executable` | Absolute literal executable path. |
| `ansible_ssh_args` | Nonempty literal SSH argument string; keep host-key verification enabled and review transport policy. |
| `ansible_ssh_password_mechanism` | Exactly `disable`. |
| `ansible_ssh_pkcs11_provider`, `ansible_ssh_common_args`, `ansible_ssh_extra_args` | Exactly the empty string emitted by CI. |
| `ansible_become_password`, `ansible_become_pass`, `ansible_sudo_pass`, `ansible_su_pass`, `ansible_private_key`, `ansible_password`, `ansible_ssh_pass` | JSON `null` only, clearing password/inline-key inputs as CI does. |

Literal paths and arguments cannot contain Jinja expressions or control
characters. These checks constrain highest-precedence input; they do not qualify
the controller's SSH executable or validate credentials. Existing `storage-check`
and other operation controller-variable contracts are unchanged.

### Approval and CI Ownership

Private CI owns the reviewed per-node check/manual-apply pairs, immutable source
and private inventory bindings, job dependencies, and the shared mutation resource
group. Each launcher invocation selects exactly one node. Use GitLab's native
manual-job confirmation in the UI for the apply boundary. This is a UI confirmation
boundary, **not API-proof approval**: the public launcher does not validate an
approval token or require a TTY, and a caller with execution access can invoke it.
Keep CI and inventory changes in their owning repositories. Review the node's
check output and exact source/inventory revisions before manual apply.

### Verification Coverage

The second apply reuses the role's existing checks rather than duplicating LVM
logic. For reused VGs these establish the stable disk/PV relationship, exact
one-PV VG identity, requested LV sizes, filesystem types, mount destinations,
XFS growth geometry, and required VG reserve. Growth's post-apply assertions
require both the LV and XFS to reach the reviewed target. A pending growth or
missing LV that changes on the second apply fails idempotence. Other layouts
retain their existing role semantics; this route adds no new allocation policy.

The final verifier reuses `verify_mountpoint.yml` to require the intended LV block
identity and filesystem root, then requires an active mount with the declared
filesystem type and explicit kernel options. It accounts for userspace-only
`defaults`, `auto`, `noauto`, `nofail`, and `_netdev`, and checks `exec`, `dev`, and
`suid` by absence of their negative kernel flags. Other declared options must
appear in the active option list; extra kernel-generated options are allowed.
Unusual option aliases may require separate qualification. The role manages the
UUID-backed fstab entry; this route does not test reboot persistence or measure
filesystem geometry for volumes without approved XFS growth.

Only declared storage volumes are managed; this route does not run RKE2 roles or
create RKE2 service directories implicitly. Where a private node layout requires
`/var/lib/rancher/rke2` to remain absent, omission from its storage declaration is
necessary but does not establish absence. There is currently **no built-in
excluded-path prerequisite** in this route. A generic private-inventory list and
read-only pre/post checks would be needed to enforce that requirement here; until
implemented, separate private absence evidence is a required operational gate.
The launcher neither hardcodes a site's layout nor deletes a pre-existing path.
Offline tests do not establish live disk, mount, reboot, or service-path acceptance.
