# zot_registry

Deploys a Zot OCI registry as a system Podman Quadlet service.

The role owns Zot configuration, TLS, optional htpasswd deployment from private source paths, optional Zot UI extension configuration, the `zot.container` Quadlet unit, service lifecycle, and firewalld registry access. It expects `podman_host` to prepare Podman and `/etc/containers/systemd`; `playbooks/registry.yml` applies both roles.

Default behavior listens on host port `443/tcp`, forwards to Zot's container port `5000`, stores registry blobs under `/var/lib/zot/data`, keeps the Zot UI disabled, and requires TLS source files when `zot_registry_tls_enabled` is true.

Set `zot_registry_ui_enabled: true` to enable Zot's web UI on the same HTTPS listener as the registry API. This also enables Zot's required `search` extension. Set `zot_registry_firewalld_allowed_sources` to one or more CIDRs to restrict registry and UI access with source-scoped rich rules instead of opening the port broadly.

Certificate private keys, htpasswd files, and any real CA material must stay outside public Git. Public examples should use documentation-safe paths and values only.

When `zot_registry_firewalld_manage` is true and firewalld is installed but stopped, the role manages permanent rules only. Smoke checks use `firewall-offline-cmd`, so hosts need the standard firewalld offline tooling installed.

Example:

```yaml
zot_registry_host_port: 443
zot_registry_tls_cert_src: "{{ lookup('ansible.builtin.env', 'PLATFORM_INFRASTRUCTURE_CONFIG_DIR') }}/registry/dev/tls.crt"
zot_registry_tls_key_src: "{{ lookup('ansible.builtin.env', 'PLATFORM_INFRASTRUCTURE_CONFIG_DIR') }}/registry/dev/tls.key"
zot_registry_ui_enabled: true
zot_registry_firewalld_allowed_sources:
  - 192.0.2.0/24
zot_registry_smoke_validate_certs: false
```
