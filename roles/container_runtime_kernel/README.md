# container_runtime_kernel

Provides the generic OverlayFS kernel prerequisite for container-runtime hosts.
The role installs `container_runtime_kernel_packages` (default: `kmod`) before
using `/usr/sbin/modinfo` and `/usr/sbin/modprobe`. The managed host must provide
systemd and a supported package manager.

By default, `container_runtime_overlayfs_policy_exception_enabled: true` installs,
enables, and starts the auditable systemd oneshot unit
`platform-container-runtime-overlayfs-exception.service`. The unit loads OverlayFS
with `/usr/sbin/modprobe --ignore-install overlay`, then the role verifies
`/sys/module/overlay`. This narrowly bypasses a configured `install overlay ...`
policy without editing or removing any file under `/etc/modprobe.d`. The unit is
wanted by `sysinit.target` so the module is available before normal runtime
services start.

Set `container_runtime_overlayfs_policy_exception_enabled: false` to require
normal `modprobe overlay` policy instead. Before removing an existing managed
exception unit, the role rejects install overrides and blacklists, loads
OverlayFS through the normal command, and verifies the loaded module. A denial
fails closed and leaves the working exception unit in place. The role never
unloads OverlayFS and does not configure a container runtime or storage driver.

Check mode verifies module availability and disabled-mode policy, then reports
the current unit and module state. It does not load a module or change files and
services.
