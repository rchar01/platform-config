# zot_registry

Deploys a Zot OCI registry as a system Podman Quadlet service.

The role owns Zot configuration, TLS, optional htpasswd deployment from private source paths, optional Zot UI extension configuration, the `zot.container` Quadlet unit, service lifecycle, and firewalld registry access. `playbooks/registry.yml` applies the `firewalld` and `podman_host` foundations before this role.

Default active behavior listens on host port `443/tcp`, forwards to Zot's container port `5000`, stores registry blobs under `/var/lib/zot/data`, and keeps the Zot UI disabled. `zot_registry_tls_cert_src` and `zot_registry_tls_key_src` must be a complete pair or both empty; derived managed custody requires the pair, while predecessor-free dormant issuance requires both empty.

TLS custody is not an inventory choice. With no authenticated active version, `pki_host_local_certificate_operation: issue` derives dormant custody, `migrate` derives managed custody, and `renew` fails closed. Dormant convergence renders the canonical TLS configuration and Quadlet but requires absent managed TLS destinations and keeps Zot masked and stopped. Once the lifecycle root exists, the role requires the exact shipped root-owned `0755` helper and invokes its read-only operation-aware `zot-custody` command under the shared lifecycle lock. During normal v4 convergence only, the exact root-owned `0755` v2.0.0-v2.0.2 helper (SHA-256 `3044058c3d4884a3ab1d51f1dc128a5c84407e387d2805fa99087c65d98eb280`) and v3 helper (SHA-256 `9b6c62c6380fb1ab00e0a10dc5905ec4f88af2b57b503c1b44ec4db497b68fb3`) are trusted predecessors: the role replaces either with the shipped helper, refreshes target metadata, and requires the current SHA-256 `3d446de2d3e56314ca70e881b5354a2c341566f17a6e4472f58faced92daa7c0` before custody selection. Check mode does not perform this upgrade. A completed activation selects only the authenticated immutable `fullchain.crt` and `tls.key` paths bound by the active and rollback records.

Lifecycle lookup inputs are `zot_registry_tls_host_local_state_root`, `zot_registry_tls_host_local_pending_root`, `zot_registry_tls_host_local_versions_root`, `zot_registry_tls_host_local_service`, `zot_registry_tls_host_local_target`, and `zot_registry_tls_host_local_zot_config_path`. The target defaults to the exact inventory hostname; helper, Zot configuration, managed TLS, and `registry-dev` lifecycle paths are fixed. Apart from the pinned predecessor upgrades above, helper failure, source or installed checksum drift, unsafe metadata, unresolved journals, malformed or ambiguous state, and configuration mismatch fail closed and are never reinterpreted as another custody mode. The lifecycle helper remains the sole owner of host-local Zot configuration changes, so normal convergence previews and refuses host-local configuration drift. Zot serves the authenticated full chain so strict external validation can observe the intermediate certificate.

The role refuses to deploy a broadly reachable anonymous registry. Enable `zot_registry_auth_enabled`, set `zot_registry_firewalld_allowed_sources` to one or more CIDRs while `zot_registry_firewalld_manage` is true, or explicitly set `zot_registry_allow_insecure_anonymous_access: true` for isolated development only.

Set `zot_registry_ui_enabled: true` to enable Zot's web UI on the same HTTPS listener as the registry API. This also enables Zot's required `search` extension. Set `zot_registry_firewalld_allowed_sources` to one or more CIDRs to restrict registry and UI access with source-scoped rich rules instead of opening the port broadly.

Certificate private keys, htpasswd files, and any real CA material must stay outside public Git. Public examples should use documentation-safe paths and values only.

When `zot_registry_firewalld_manage` is true and firewalld is installed but stopped, the role manages permanent rules offline. The focused registry playbook installs the standard firewalld tooling and Python bindings before this role runs.

Example:

```yaml
zot_registry_host_port: 443
zot_registry_tls_cert_src: "{{ lookup('ansible.builtin.env', 'PLATFORM_INFRASTRUCTURE_CONFIG_DIR') }}/registry/dev/tls.crt"
zot_registry_tls_key_src: "{{ lookup('ansible.builtin.env', 'PLATFORM_INFRASTRUCTURE_CONFIG_DIR') }}/registry/dev/tls.key"
zot_registry_auth_enabled: true
zot_registry_auth_htpasswd_src: "{{ lookup('ansible.builtin.env', 'PLATFORM_INFRASTRUCTURE_CONFIG_DIR') }}/registry/dev/htpasswd"
zot_registry_ui_enabled: true
zot_registry_firewalld_allowed_sources:
  - 192.0.2.0/24
zot_registry_smoke_validate_certs: false
```
