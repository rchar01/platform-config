# zot_registry

Deploys a Zot OCI registry as a system Podman Quadlet service.

The role owns Zot configuration, TLS, optional htpasswd deployment from private source paths, optional Zot UI extension configuration, the `zot.container` Quadlet unit, service lifecycle, and firewalld registry access. `playbooks/registry.yml` applies the `firewalld` and `podman_host` foundations before this role.

Default active behavior listens on host port `443/tcp`, forwards to Zot's container port `5000`, stores registry blobs under `/var/lib/zot/data`, and keeps the Zot UI disabled. `zot_registry_tls_cert_src` and `zot_registry_tls_key_src` must be a complete pair or both empty. A fresh host-local `issue` starts with both empty and keeps Zot dormant until activation; `renew` applies only to authenticated active host-local state.

TLS custody is not an inventory choice. With no authenticated active version,
`pki_host_local_certificate_operation: issue` derives dormant custody. An
authenticated active version derives host-local custody for either `issue` or
`renew`; a renewal request derives its predecessor from that active state.
Dormant convergence renders the canonical TLS configuration and Quadlet,
requires absent managed TLS destinations, and keeps Zot masked and stopped. The
role installs the shipped lifecycle helper as `root:root` mode `0755`, then uses
its read-only `zot-custody` result under the shared lifecycle lock. Completed
activation selects only the authenticated immutable `fullchain.crt` and
`tls.key` paths bound by target state. Predecessor workflow state is not
migrated; it requires separately authorized reset or target recreation.

Lifecycle lookup inputs are `zot_registry_tls_host_local_state_root`, `zot_registry_tls_host_local_pending_root`, `zot_registry_tls_host_local_versions_root`, `zot_registry_tls_host_local_service`, `zot_registry_tls_host_local_target`, and `zot_registry_tls_host_local_zot_config_path`. The target defaults to the exact inventory hostname; helper, Zot configuration, managed TLS, and `registry-dev` lifecycle paths are fixed. Unsafe helper source or destination metadata, helper failure, unresolved journals, malformed or ambiguous state, and configuration mismatch fail closed and are never reinterpreted as another custody mode. The lifecycle helper remains the sole owner of host-local Zot configuration changes, so normal convergence previews and refuses host-local configuration drift. Zot serves the authenticated full chain so strict external validation can observe the intermediate certificate.

The role refuses to deploy a broadly reachable anonymous registry. Enable `zot_registry_auth_enabled`, set `zot_registry_firewalld_allowed_sources` to one or more CIDRs while `zot_registry_firewalld_manage` is true, or explicitly set `zot_registry_allow_insecure_anonymous_access: true` for isolated development only.

Set `zot_registry_ui_enabled: true` to enable Zot's web UI on the same HTTPS listener as the registry API. This also enables Zot's required `search` extension. Set `zot_registry_firewalld_allowed_sources` to one or more CIDRs to restrict registry and UI access with source-scoped rich rules instead of opening the port broadly.

Certificate private keys, htpasswd files, and any real CA material must stay outside public Git. Public examples should use documentation-safe paths and values only.

When `zot_registry_firewalld_manage` is true and firewalld is installed but stopped, the role manages permanent rules offline. The focused registry playbook installs the standard firewalld tooling and Python bindings before this role runs.

Example:

```yaml
zot_registry_host_port: 443
pki_host_local_certificate_operation: issue
zot_registry_tls_cert_src: ""
zot_registry_tls_key_src: ""
zot_registry_auth_enabled: true
zot_registry_auth_htpasswd_src: "{{ lookup('ansible.builtin.env', 'PLATFORM_INFRASTRUCTURE_CONFIG_DIR') }}/registry/dev/htpasswd"
zot_registry_ui_enabled: true
zot_registry_firewalld_allowed_sources:
  - 192.0.2.0/24
zot_registry_smoke_validate_certs: false
```
