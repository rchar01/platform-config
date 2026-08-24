# storage_volume

Manages LVM-backed persistent storage volumes from inventory variables.

The role expects private inventories to provide explicit stable disk paths such as `/dev/disk/by-id/...` or `/dev/disk/by-path/...`. It creates an LVM partition, volume group, logical volume, XFS filesystem by default, and a UUID-based `/etc/fstab` mount entry.

By default the role derives the LVM PV partition as `<device>-part1`, which matches common `/dev/disk/by-id/...` and `/dev/disk/by-path/...` partition symlinks. Set `pv_device` explicitly when an environment uses different partition symlink naming.

First-time disk initialization is guarded by `initialize: true`. If the target disk already has child devices, filesystem signatures, or partition signatures, the role fails instead of formatting it.

`initialize: true` grants permission to initialize a verified blank disk; it is
not a request to format on every run. After the expected partition, LVM, and
filesystem exist, repeated convergence is idempotent and does not reformat the
volume. Keep it enabled for disposable or automatically rebuildable data disks,
where a blank replacement should initialize automatically. Use
`initialize: false` for persistent or sensitive data disks that require a
separate reviewed initialization decision after replacement. Unexpected disk
content fails closed under either policy.

Before any storage mutation and again immediately before mounting, the role
checks the target mountpoint. An absent or empty unmounted directory is safe. A
nonempty directory is accepted only when it is already mounted from the exact
intended LV filesystem root; a subdirectory bind, unrelated block device,
symlink, non-directory, or nonempty unmounted directory fails closed. The role
does not copy, remove, or migrate existing mountpoint contents. Prepare paths
such as `/var/lib/containers` before rootful services create state there, or use
a separately reviewed data migration.

For several bounded logical volumes on one disk, define one
`storage_volume_layouts` entry and reference it from each volume. The layout owns
the stable device, VG, capacity, required unallocated headroom, and one explicit
initialization decision. The role rejects duplicate devices, VGs, LVs, or
mountpoints; validates the allocation sum before making changes; and verifies VG
free space after convergence. `capacity_gib` is a lower bound checked against the
live disk, not permission to consume the whole device.

To add logical volumes to a reviewed existing one-PV VG, set
`reuse_existing_vg: true` and explicitly set `initialize: false` on the layout.
Before any LV change, the role resolves the stable source and PV paths, requires
the expected disk/partition relationship, and verifies the PV and VG identities
and exact one-PV membership. It inspects all requested existing LVs and their
filesystems, rejects size or filesystem mismatches, and rejects an existing LV
mounted anywhere other than its declared mountpoint. It requires enough live VG
free space for missing requested LVs, approved growth, and `required_free_gib`.
Reuse mode never partitions or changes VG membership. Check mode runs these
read-only checks but does not create or grow an LV or filesystem.

Existing-LV growth is disabled unless a volume sets `grow_from_size_gib` to its
reviewed current size and `size_gib` to a larger target. Growth is limited to an
existing XFS filesystem mounted at its declared mountpoint in a reused VG;
`lv_size` cannot override the reviewed `size_gib` target. The
preflight accepts only the extent-rounded source or target LV size, verifies the
XFS geometry, and reserves the growth delta before mutation. It also accepts an
interrupted state where the LV reached its target but XFS still has its source
size. Shrinking, missing growth-marked LVs, intermediate sizes, and other
filesystems fail closed. After successful growth, removing
`grow_from_size_gib` returns the volume to ordinary exact-target management.

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

After mounting, the role restores the policy-defined SELinux type on the mount
root. This is intentionally non-recursive so service-managed labels below the
mount, such as Podman's `container_file_t`, remain unchanged.

Bounded multi-volume example:

```yaml
storage_volume_layouts:
  - name: service_data
    device: /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1
    vg_name: service_data
    capacity_gib: 20
    required_free_gib: 4
    initialize: false
    reuse_existing_vg: true

storage_volumes:
  - name: service_primary
    layout: service_data
    lv_name: primary
    grow_from_size_gib: 6
    size_gib: 8
    mountpoint: /srv/service/primary
  - name: service_staging
    layout: service_data
    lv_name: staging
    size_gib: 2
    mountpoint: /srv/service/staging
```

Set the layout's `initialize` value to `true` only in reviewed private inventory
after the stable device and empty state have been confirmed. Layout-backed
volumes intentionally cannot override disk, VG, partition, PV, or initialization
settings individually.

Do not set `reuse_existing_vg` for a new disk. Existing-VG reuse supports one
partition-backed PV whose canonical parent is the configured source disk. It
fails closed when the requested PV belongs to another VG, the VG has additional
PVs, an existing requested LV has an unapproved size or filesystem, or live free
space cannot satisfy missing allocations, approved growth, and required
headroom. An ordinary existing requested LV may be unmounted or mounted only at
its declared mountpoint; approved XFS growth requires it to be mounted there.
The preflight is a safety check against reviewed topology, not a migration or VG
repair mechanism; stop concurrent storage administration while applying it.
