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

## Logrotate

By default the role enables `compress` in `/etc/logrotate.conf` so rotated system logs do not accumulate uncompressed on the root filesystem.

```yaml
platform_logrotate_manage: true
platform_logrotate_compress: true
```

Set `platform_logrotate_compress: false` only when a host has a specific reason to keep rotated logs uncompressed.
