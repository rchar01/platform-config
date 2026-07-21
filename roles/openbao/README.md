# openbao

Deploys OpenBao as a system Podman Quadlet service.

The role owns OpenBao configuration, TLS deployment from private source paths, persistent Raft storage under `/var/lib/openbao/data`, the `openbao.container` Quadlet unit, service lifecycle, and source-scoped permanent firewalld rich rules for `8200/tcp`. It expects `podman_host` to prepare Podman and `/etc/containers/systemd`; `playbooks/openbao.yml` applies both roles.

The official OpenBao image runs the server as UID `100` and GID `1000`, so the role pins the Quadlet user and grants that identity access to data and TLS key files through `openbao_container_uid` and `openbao_container_gid`. The generated systemd service sets `MemorySwapMax=0` as container-level hardening.

When `openbao_firewalld_manage` is true, the role manages permanent
source-scoped rich rules with offline-capable module operations. Rules are also
applied immediately when inventory explicitly configures firewalld to run.

This role intentionally does not initialize or unseal OpenBao. Initialization and unseal operations require explicit operator action and must not be imported from `playbooks/site.yml`.

Certificate private keys, unseal keys, root tokens, recovery keys, and any real CA material must stay outside public Git.

Example:

```yaml
openbao_tls_cert_src: "{{ lookup('ansible.builtin.env', 'PLATFORM_INFRASTRUCTURE_CONFIG_DIR') }}/openbao/dev/tls.crt"
openbao_tls_key_src: "{{ lookup('ansible.builtin.env', 'PLATFORM_INFRASTRUCTURE_CONFIG_DIR') }}/openbao/dev/tls.key"
openbao_firewalld_allowed_sources:
  - 192.0.2.10/32
```
