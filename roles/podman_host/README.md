# podman_host

Prepares hosts to run Podman-managed service containers.

The role depends on `container_runtime_kernel`, installs Podman, creates the
system Quadlet directory at `/etc/containers/systemd`, and manages
`podman.socket`. The dependency ensures OverlayFS is loaded for every
`podman_host` invocation. Its policy exception is enabled by default; see the
[`container_runtime_kernel` role](../container_runtime_kernel/README.md) for the
fail-closed opt-out behavior.

The socket is disabled and stopped by default because service roles should run
containers through systemd units unless inventory explicitly enables the API
socket. The kernel prerequisite does not alter Podman packages, Quadlets, socket
settings, or the Podman storage driver.

This role does not deploy application containers. Service roles such as
`zot_registry`, `openbao`, and `gitlab_runner` own their own configuration,
environment files, Quadlet unit templates, firewall rules, and service lifecycle.
