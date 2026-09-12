# RKE2 Host Aliases

The fixed `rke2-host-aliases-plan` and `rke2-host-aliases-apply` operations prepare
inventory-declared host aliases on the complete `rke2_cluster`. They invoke only
the common alias tasks, with common defaults loaded through `import_role` and
`tasks_from: host_aliases`. They do not install packages, configure kernels or
firewalls, install CA trust, create storage, or install/start RKE2.

## Commands and Scope

Run plan using the reviewed source checkout and private inventory:

```bash
scripts/platform-config-operation rke2-host-aliases-plan \
  --inventory /absolute/private/hosts.yml \
  --controller-vars /absolute/outside-git/controller-vars.json
```

The separately approved apply uses exactly the same inputs:

```bash
scripts/platform-config-operation rke2-host-aliases-apply \
  --inventory /absolute/private/hosts.yml \
  --controller-vars /absolute/outside-git/controller-vars.json
```

These routes accept only `--inventory` and `--controller-vars`, each exactly
once. There are no node, limit, group, playbook, path, extra-argument, or plan-file
selectors. `rke2_cluster` must be nonempty and the exact union of disjoint
`rke2_servers` and `rke2_agents`, with at least one server. Invalid role membership
fails inventory before ping rather than producing an `N/A` role. Every phase
covers every selected host. Neither storage membership, PVs, storage variables,
nor installed RKE2 state is a prerequisite.

## Fixed Phase Contract

Both routes validate and snapshot controller JSON before running Ansible
inventory, validate the complete scope, then run cluster ping and a fresh
`playbooks/rke2-host-aliases.yml --check --diff`. Predicted changes are successful
plan output, including insertion when the managed block is absent. No actual
name-resolution check runs before installation or during check mode.

Apply continues only after complete successful evidence for the fresh check:

1. Apply `playbooks/rke2-host-aliases.yml` once.
2. Run that same playbook with `--check --diff`, requiring `changed=0` on every
   host. This is a read-only prediction, not a second apply.
3. Run `playbooks/rke2-host-aliases-verify.yml`. Each node uses Python's system
   resolver (`socket.getaddrinfo`, NSS on the supported Linux hosts) for every
   declared alias and requires its complete returned address set to equal the
   single declared IP. Missing resolution, wrong IP, or additional IPs fail.

Summary phase names are `inventory`, `connectivity`, `host-aliases-check`, then
for apply: `host-aliases-apply`, `host-aliases-post-check`, `host-aliases-verify`.
The existing per-VM/per-phase summary requires all-host successful recaps before
each subsequent command and at final reporting. Failed, unreachable, ignored,
rescued, missing, empty-success, or unexpected-host evidence fails closed. Both
final phases require zero changes. A previously successful plan job never
replaces apply's fresh check.

## Alias and File Guards

Declare aliases only in reviewed private inventory:

```yaml
platform_host_aliases:
  - address: 192.0.2.61
    names:
      - registry.example.test
      - registry-01.example.test
```

The fixed route requires a nonempty list of mappings containing exactly
`address` and `names`. Addresses must be literal IPv4 or IPv6 strings, without
CIDR or interface scope. Names must form a nonempty list of ASCII hostnames:
1–63 character alphanumeric/hyphen labels, no leading/trailing hyphens, at most
253 characters overall, and no trailing dot or IP-literal names. Names must be
unique across the list, case-insensitively, even if duplicate declarations use
the same address. A name cannot declare multiple desired IPs.

The node-side standard-library guard executes read-only in both check and apply.
It requires a root-user/root-group-owned, non-symlink `/etc` directory and an
existing regular non-symlink `/etc/hosts`, with no group/world write or special
permission bits. Missing or unsafe paths fail; the route does not create or
repair them to pass preflight. It rejects unmatched, reversed, repeated, nested,
or otherwise malformed common block markers. Outside the existing common block,
any desired name mapped to a different IP fails before mutation. Same-IP entries
are allowed. Matching is case-insensitive for names and compares parsed IP
identities, including equivalent IPv6 spellings.

The existing common block is replaced or inserted with `blockinfile`, preserving
unmanaged content, including same-IP entries. An unterminated final line receives
the separator newline needed for insertion. The common task still sets the live
file to root/root `0644`; plan reports any required permission normalization.

Both playbooks use explicit `strategy: linear`, `any_errors_fatal: true`, and no
serial batches. All selected nodes complete the preparation guards before any
node can write aliases. Normal Ansible forks are allowed. The existing common
cloud-init directory/file guards also run across all nodes before its first
write. No full common role or RKE2 role is invoked.

The existing `platform_host_aliases_cloud_init_template` variable retains its
default `/etc/cloud/templates/hosts.redhat.tmpl` and its empty-string opt-out.
Keep `platform_host_aliases_cloud_init_template: ""` in private environments
where cloud-init integration is disabled. A nonempty selector retains ordinary
common behavior: require its trusted directory, and update only an existing safe
template. No new path input is introduced. Ordinary common convergence still
supports empty-list block removal; these preparation routes require aliases.

## Controller JSON Schema

Both aliases routes reuse storage apply's transport-only validator, without its
single-node/storage scope. Input must be an absolute, current-owner, private
regular non-symlink JSON file, containing an object with no duplicate members.
Unknown keys, YAML, Jinja in literal fields, and control characters are rejected
before inventory execution. Every Ansible command receives the same validated
`0600` snapshot, removed with invocation scratch on exit or handled interruption.

All keys are optional; `{}` leaves transport selection to inventory. The exact
allowlist is:

| Keys | Accepted values |
| --- | --- |
| `platform_ci_ssh_private_key_files` | Nonempty hostname-to-absolute-literal-path object. If supplied, it must cover every selected cluster host; additional mapped hosts are allowed. Coverage is checked after inventory, before ping. |
| `ansible_ssh_private_key_file` | Exactly `{{ platform_ci_ssh_private_key_files[inventory_hostname] }}`, with that map present. |
| `ansible_ssh_executable` | Absolute literal executable path. |
| `ansible_ssh_args` | Nonempty literal SSH argument string. Keep reviewed strict host-key verification. |
| `ansible_ssh_password_mechanism` | Exactly `disable`. |
| `ansible_ssh_pkcs11_provider`, `ansible_ssh_common_args`, `ansible_ssh_extra_args` | Exactly the empty string. |
| `ansible_become_password`, `ansible_become_pass`, `ansible_sudo_pass`, `ansible_su_pass`, `ansible_private_key`, `ansible_password`, `ansible_ssh_pass` | JSON `null` only. |

This is the same field/value contract used by
`platform-ci/templates/storage-apply.yml`, extended only to require key-map
coverage of the complete RKE2 scope. Alias declarations, cloud template paths,
connection endpoints, become overrides, and arbitrary variables cannot be
supplied through controller JSON. The checks constrain controller input; they
do not qualify SSH executables or credentials.

## Approval, Failure, and Qualification

Private CI owns reviewed source/inventory/image pins, plan/manual-apply job
dependencies, and native manual-job confirmation. This launcher does not issue
or validate approval tokens or require a TTY. Native UI confirmation is not
API-proof approval. Review the full plan and bindings before approving apply.
Use the same mutation resource group as other operations and prohibit concurrent
out-of-band host-file/cloud-init administration during preparation. The all-host
barrier does not lock other root writers or make writes across hosts atomic.

There are no automatic mutation retries or rollback. Command failures and
signals retain failure status and prevent later phases. Failure after apply,
including a wrong NSS result, may leave aliases installed; inspect partial state
before separately authorizing another attempt. Neither route edits private
inventory or commits/pushes desired state.

Bootstrap source preflight remains strict and read-only: it never repairs
aliases or installs trust. Successful alias verification proves only current
node-side resolution, not HTTPS, registry authentication/image pulls, RPM
dependencies, Helm access, reboot persistence, or RKE2 readiness. The focused
offline tests described in [Development](development.md) use sandbox files and
do not qualify private hosts or authorize live mutation.
