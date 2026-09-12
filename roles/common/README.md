# common

Applies basic OS defaults shared by platform hosts: timezone, simple directories, optional managed `/etc/hosts` aliases, baseline logrotate settings, and an optional message of the day.

## Host Aliases

Use `platform_host_aliases` for temporary name resolution before internal DNS
exists. The role manages only its own marked block in `/etc/hosts` and leaves
other entries untouched. On Rocky cloud images, it also maintains the same block
in `/etc/cloud/templates/hosts.redhat.tmpl` so cloud-init regeneration preserves
the aliases across reboot.

```yaml
platform_host_aliases:
  - address: 192.0.2.61
    names:
      - registry.example.test
      - registry-01.example.test
```

Set `platform_host_aliases_cloud_init_template: ""` on systems where cloud-init
must not be integrated. A configured path is modified only when it exists as a
safe root-owned regular file beneath a root-owned, non-writable directory. To
stop managing a template that already contains the marked block, first converge
with `platform_host_aliases: []`; clear the template path only after that cleanup
run.

The shared `tasks/host_aliases.yml` entry point contains the same alias and
cloud-init tasks used at their original position in ordinary common convergence.
The fixed [RKE2 Host Aliases](../../docs/rke2-host-aliases.md) playbook imports only
that entry point with common defaults, after route-specific all-node preflight.
It does not run timezone, directory, logrotate, or message-of-the-day tasks.

That preparation route requires a nonempty, strictly typed alias list, safe
existing `/etc/hosts`, unambiguous common markers, and no unmanaged entry mapping
a desired name to a different IP. Same-IP unmanaged entries remain untouched.
It preserves the existing cloud-init selector, including the explicit empty
string opt-out. Ordinary common convergence still supports empty-list removal;
the fixed preparation route does not accept empty lists. Applied NSS resolution
is checked by the separate read-only `host_aliases_verify` entry point, only
after apply and never during check mode.

## Logrotate

By default the role enables `compress` in `/etc/logrotate.conf` so rotated system logs do not accumulate uncompressed on the root filesystem.

```yaml
platform_logrotate_manage: true
platform_logrotate_compress: true
```

Set `platform_logrotate_compress: false` only when a host has a specific reason to keep rotated logs uncompressed.
