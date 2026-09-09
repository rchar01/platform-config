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
Check mode reports proposed LV/filesystem/mount changes without applying them.
Expected changes are successful plan output, not an idempotence failure. Errors,
unreachable hosts and incomplete summaries fail the check. Only a separately
approved apply may make changes; post-apply idempotence is a later check.

Use a qualified controller with Ansible Core 2.21.x, `ansible.posix` 2.2.2 and
`community.general` 12.6.0 for the CI lane. It needs SSH, known-hosts and source
CA files, not cluster or Runner tokens. Keep logs private and coordinate checks
with the same GitLab resource group used by platform mutations: a check is not
reliable evidence while an overlapping apply changes the target.
