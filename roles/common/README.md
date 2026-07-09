# common

Applies basic OS defaults shared by platform hosts: timezone, simple directories, optional managed `/etc/hosts` aliases, baseline logrotate settings, and an optional message of the day.

## Host Aliases

Use `platform_host_aliases` for temporary name resolution before internal DNS exists. The role manages only its own marked block in `/etc/hosts` and leaves other entries untouched.

```yaml
platform_host_aliases:
  - address: 192.0.2.61
    names:
      - registry.example.test
      - registry-01.example.test
```

## Logrotate

By default the role enables `compress` in `/etc/logrotate.conf` so rotated system logs do not accumulate uncompressed on the root filesystem.

```yaml
platform_logrotate_manage: true
platform_logrotate_compress: true
```

Set `platform_logrotate_compress: false` only when a host has a specific reason to keep rotated logs uncompressed.
