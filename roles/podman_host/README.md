# podman_host

Prepares hosts to run Podman-managed service containers.

The role installs Podman, creates the system Quadlet directory at `/etc/containers/systemd`, and manages `podman.socket`. The socket is disabled and stopped by default because service roles should run containers through systemd units unless inventory explicitly enables the API socket.

This role does not deploy application containers. Service roles such as `zot_registry`, `openbao`, `gitlab_runner`, and `monitoring_stack` should own their own configuration, environment files, Quadlet unit templates, firewall rules, and service lifecycle.
