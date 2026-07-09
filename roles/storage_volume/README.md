# storage_volume

Manages LVM-backed persistent storage volumes from inventory variables.

The role expects private inventories to provide explicit stable disk paths such as `/dev/disk/by-id/...` or `/dev/disk/by-path/...`. It creates an LVM partition, volume group, logical volume, XFS filesystem by default, and a UUID-based `/etc/fstab` mount entry.

By default the role derives the LVM PV partition as `<device>-part1`, which matches common `/dev/disk/by-id/...` and `/dev/disk/by-path/...` partition symlinks. Set `pv_device` explicitly when an environment uses different partition symlink naming.

First-time disk initialization is guarded by `initialize: true`. If the target disk already has child devices, filesystem signatures, or partition signatures, the role fails instead of formatting it.

Example:

```yaml
storage_volumes:
  - name: registry_data
    device: /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1
    vg_name: data
    lv_name: zot
    mountpoint: /var/lib/zot
    initialize: true
```

Default mount options are `defaults,rw,nosuid,nodev,relatime`. Add `noexec` per volume only when the service is known to support it.
