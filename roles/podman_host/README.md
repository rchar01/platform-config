# podman_host

Prepares hosts to run Podman-managed service containers.

The role depends on `container_runtime_kernel`, installs one exact Podman RPM,
creates the system Quadlet directory at `/etc/containers/systemd`, and manages
`podman.socket`. The dependency ensures OverlayFS is loaded for every
`podman_host` invocation. Its policy exception is enabled by default; see the
[`container_runtime_kernel` role](../container_runtime_kernel/README.md) for the
fail-closed opt-out behavior.

Inventory must set `podman_host_package_nevra` to an exact x86_64 Podman NEVRA,
including epoch. The role supports deliberate downgrades, verifies the installed
RPM identity, installs `python3-dnf-plugin-versionlock`, and atomically replaces
only Podman entries in `/etc/dnf/plugins/versionlock.list`. Unrelated locks and
comments remain intact. The role rejects bare package names before package or
socket changes.

The exact RPM must remain available from an enabled approved repository for a
fresh install, reinstall, or downgrade. Versionlock constrains normal DNF
transactions; it does not retain RPM payloads and can be bypassed by deliberately
disabling DNF plugins. Promote Podman by qualifying a new NEVRA, updating
inventory, converging the role, and running container-runtime smoke checks.

The socket is disabled and stopped by default because service roles should run
containers through systemd units unless inventory explicitly enables the API
socket. The kernel prerequisite does not alter Podman packages, Quadlets, socket
settings, or the Podman storage driver.

`podman_host_storage_contract_enabled` optionally requires an exact dedicated
XFS mount at `podman_host_storage_mountpoint` before Podman or its API socket is
used. The contract verifies an exec-capable `ftype=1` filesystem and requires
effective rootful Podman storage to use `overlay` at `podman_host_graphroot`.
The role validates storage created by another role; it does not partition,
format, mount, migrate, or remove container state.

This role does not deploy application containers. Service roles such as
`zot_registry`, `openbao`, and `gitlab_runner` own their own configuration,
environment files, Quadlet unit templates, firewall rules, and service lifecycle.
