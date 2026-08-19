# Monitoring etcd

Disabled-by-default convergence contract for the dedicated three-member etcd
cluster used only by Patroni.

This slice locks the official etcd `3.6.14` image by immutable index digest,
requires an explicit UID/GID `10001` runtime override because the upstream image
declares root, and renders a host-network Quadlet with a read-only root,
no-new-privileges, and no Linux capabilities. The etcd configuration requires
mutual TLS for both client and peer traffic, exactly three canonical members,
one exact local identity, and direct node DNS advertisements.

`monitoring_etcd_converge` explicitly enables inactive foundation staging while
`monitoring_etcd_service_enabled` must remain `false` and
`monitoring_etcd_service_state` must remain `stopped`. Convergence requires the
pre-existing `/srv/monitoring/etcd` mount, verifies the exact image, publishes
configuration and PKI as a content-addressed bundle, installs a disabled
Quadlet, and owns source-scoped firewall and persistent SELinux policy.
After successful staging, obsolete unreferenced bundles are removed so retired
private keys do not accumulate on the host.

The role does not initialize, erase, restore, compact, defragment, replace, or
start an etcd member. Cluster bootstrap and every destructive or active
operation remain separate cluster-wide maintenance gates.

`playbooks/monitoring-etcd.yml` is the focused staging lane. It requires all
three monitoring hosts, validates every inactive contract and controller PKI
input before quiescing, then applies `firewalld`, `podman_host`, and this role in
order. `monitoring_etcd_orchestration_ready` authorizes only stopped foundation
staging; it does not authorize bootstrap or activation.

`playbooks/maintenance/monitoring-etcd-bootstrap-preflight.yml` is read-only. It
requires all three staged hosts, pristine dedicated XFS mounts, absent bootstrap
markers, exact rendered files and image identity, inactive generated services,
and one consistent cross-host cluster contract. Its readiness gate does not
authorize starting or initializing etcd.

Real member addresses, DNS names, the cluster token, and TLS source paths belong
in private inventory or an outside-Git secret store. Normal convergence must
never reset an existing data directory or silently form a replacement cluster.
