# k8s_bastion_access

Installs Kubernetes bastion runtime scripts from `platform-k8s-bastion` and configures the bastion host.

The default source layout is the `platform-config` vendor submodule:

- `vendor/platform-k8s-bastion/runtime`

This role owns the host configuration previously handled by bootstrap scripts: external tool downloads, runtime command installation, `/etc/bastion` files, login profile, systemd services, timers, policy-driven user bootstrap orchestration, and optional cluster RBAC binding for policy groups.

The supported `k8s-bastion-access.yml` playbook applies `podman_host` before this
role. `podman_host` owns Podman packages and the shared container-runtime kernel
prerequisite; this role owns the remaining bastion OS packages and runtime
configuration.

The role targets a clean Rocky host. It does not provision VMs, manage Proxmox/OpenTofu resources, or clean up existing Kubernetes node state.

Real kubeconfigs, final rendered policy files, CA files, and tokens belong in `platform-private`, not this public repository.

Policy rendering is out of scope for this role. Set `k8s_bastion_policy_src` to the complete access policy file that should be installed on the host.

Set `k8s_bastion_manage_cluster_rbac: true` to bind policy groups whose `namespaces` list contains `all` to `k8s_bastion_cluster_admin_role`. Namespace-scoped RBAC is intentionally rejected until the policy-to-RBAC model is implemented.

Normal user bootstrap is disabled by default. Select exactly one initial mode
with `k8s_bastion_initial_user_bootstrap_mode`: `disabled`, `online`, or
`offline`. `online` obtains one short-lived initial credential per eligible
non-admin user; `offline` writes synthetic scaffolding without issuer/API calls.
Policy admins are excluded because `k8s_bastion_bootstrap_admin_kubeconfigs`
installs their separately supplied admin kubeconfig.

`k8s_bastion_enable_automatic_user_bootstrap` separately controls login recovery
and the bootstrap daemon. It accepts booleans and Ansible boolean-compatible
values, is normalized with `bool`, and defaults to `false`. Phase 1 rejects every
truthy value because the pinned runtime does not exclude policy admins from
login recovery. Keep it false until a released `platform-k8s-bastion` runtime
adds that enforcement and this role's dependency gate is deliberately updated.

For restricted networks, use `k8s_bastion_external_tools` and `k8s_bastion_download_environment` to point downloads at an internal artifact mirror or proxy.
