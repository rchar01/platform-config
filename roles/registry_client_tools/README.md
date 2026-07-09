# registry_client_tools

Installs pinned client tools used by registry smoke tests on `registry_clients` hosts.

Current tooling:

- Helm `v4.2.2` from `get.helm.sh`, installed at `/usr/local/bin/helm` with a pinned SHA-256 checksum.

This role intentionally does not install Podman. Registry client hosts that need runnable image smoke tests should also be `container_hosts`, where `podman_host` installs Podman.
