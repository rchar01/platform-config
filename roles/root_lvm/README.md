# root_lvm

Converges an LVM-backed root filesystem to the desired host layout declared in inventory.

This role is for VM templates that leave the guest root partition and root LV smaller than the declared boot disk. Infrastructure still owns the virtual boot disk size, such as `disk_gb` in the VM definition. This role owns the guest OS state needed after first boot: partition size, PV size, root LV size, and filesystem size.

For example, when infrastructure declares a 25G boot disk and the template boots with an 8G root LV, this role converges the guest root layout to consume the usable capacity of that declared disk.

The role is disabled by default. Private inventories must opt in and provide stable disk paths, the root partition number, PV device, VG name, and LV path.

Example:

```yaml
root_lvm_enabled: true
root_lvm_disk: /dev/disk/by-path/pci-0000:06:05.0-scsi-0:0:0:0
root_lvm_partition_number: 4
root_lvm_pv_device: /dev/disk/by-path/pci-0000:06:05.0-scsi-0:0:0:0-part4
root_lvm_vg_name: rocky
root_lvm_lv_path: /dev/rocky/lvroot
root_lvm_consume_free: true
```

When `root_lvm_consume_free` is true, the root LV and filesystem consume available free space in the configured VG after the partition and PV are resized.
