# Inventories

This repository supports multiple environments through separate inventories.

Public examples:

```text
inventories/homelab/
inventories/dev/
inventories/config-test/
```

Committed files use the `.example` suffix. They document shape only. Fictional
example hostnames are independent of site-specific names used by commands
against private inventories. Real inventory files belong in `platform-private`,
normally under:

```text
../platform-private/config/inventories/<environment>/
```

Expected private layout:

```text
platform-private/
+-- config/
    +-- inventories/
        +-- homelab/
        |   +-- hosts.yml
        |   +-- group_vars/
        |   +-- host_vars/
        +-- dev/
            +-- hosts.yml
            +-- group_vars/
            +-- host_vars/
```

The production-grade private workflow is described in [Private Workflow](private-workflow.md).

The `config-test` public example is a deliberately isolated storage acceptance
fixture. It contains exactly one fictional host in only `rocky` and
`storage_volume_test_hosts`, never `storage_volume_hosts`, and contains no
approval variable. Its 32 GiB final contract retains an existing 8 GiB baseline
LV, adds a missing 4 GiB LV through guarded VG reuse, and requires 12 GiB of free
VG headroom. See [Storage Volume Acceptance Fixture](storage-volume-test.md).

To add a host:

1. Add the host to the private `hosts.yml` under the right environment.
2. Put it in the required groups, such as `rocky`, `storage_clients`, or `k8s_bastion`.
3. Add private host-specific variables under `host_vars/` if required.
4. Keep secrets, kubeconfigs, tokens, private keys, and private certificates out of this repository and private Git.

The dev public example models the intended 17-host topology, including three
fictional `openbao` hosts and three fictional `monitoring` hosts. Those six hosts
are deliberately absent from `container_hosts`, `storage_volume_hosts`, and
`monitoring_targets` in the example. Private inventory must activate replacement
groups only after the owning implementation gate passes:

1. Add service groups only after their playbooks no longer invoke retired roles.
2. Add container-runtime membership only after the replacement runtime contract is safe.
3. Add storage membership only after stable-device review, check mode, and explicit initialization approval.
4. Add `monitoring_targets` only after authenticated ingress and the Phase 7 test collector pass.

The OpenBao and monitoring examples include disabled Keepalived cluster maps and
matching per-host instances. Their fictional `150`, `140`, and `130` priorities
select the preferred order, while a 300-second preemption delay prevents immediate
automatic failback. Real interfaces, peers, VRIDs, priorities, and VIPs belong in
private inventory and must remain disabled until their activation gates pass.

The focused `playbooks/monitoring-haproxy.yml` lane can stage only the host-native
monitoring proxy on all three monitoring nodes. Set
`monitoring_haproxy_orchestration_ready` only after every policy, backend, PKI,
firewalld, and SELinux input is complete; the staging contract requires HAProxy
to remain disabled and stopped. This does not unblock combined monitoring
convergence or authorize VIP activation.

The focused `playbooks/monitoring-etcd.yml` lane similarly requires all three
monitoring nodes and applies firewalld, Podman, and the dedicated Patroni etcd
foundation in that order. Keep `monitoring_etcd_orchestration_ready` false until
the dedicated mounts, exact runtime package, member map, source-scoped firewall,
SELinux policy, and outside-Git node PKI inputs are complete. Staging keeps every
member disabled and stopped; it does not authorize bootstrap, restore, member
replacement, Patroni use, or combined monitoring convergence.

After stopped staging, set `monitoring_etcd_bootstrap_preflight_ready` only for
the separate read-only bootstrap preflight. Private inventory must also provide
the exact active `monitoring_etcd_data_mount_source`; the public example leaves
it empty deliberately. The preflight accepts only a pristine XFS mount, an
absent bootstrap marker, exact staged bundle and PKI evidence, no etcd runtime
activity, and one consistent contract across all three hosts. Passing preflight
still does not authorize initialization or service startup.

Set the separate `monitoring_etcd_bootstrap_ready` gate only for the explicitly
invoked initial-bootstrap maintenance playbook. The operator must type the exact
three-host and cluster-signature approval in a real TTY. Successful bootstrap
forms and qualifies the three-voter cluster, stops every member again, and writes
root-only completion markers; it does not enable etcd or authorize Patroni.
Failure preserves data and requires diagnosis before any recovery action.

Set `monitoring_etcd_activation_ready` only after all three bootstrap markers are
present and reviewed. Persistent activation requires an exact TTY approval and
renders boot enablement only after the initialized cluster reaches stable direct
mTLS health. The separate status workflow never consumes this gate. Ordinary
staging remains an explicit deactivation path and must not be used as routine
convergence for an active cluster.

The focused OpenBao staging playbook owns Podman installation directly, so
OpenBao nodes do not require `container_hosts` membership. Use the explicit
`playbooks/maintenance/openbao-registry-remaps.yml` path to maintain Podman
registry remaps on an active cluster without making `site.yml` mutate the
runtime before the staging lifecycle gate. That maintenance path changes only
the registry drop-in. Storage remains a separate destructive boundary: add real
nodes to `storage_volume_hosts` only after stable-device review and explicit
initialization approval. Set `openbao_orchestration_ready` only after the
resulting mounts and every remaining role input are complete.

Keep `openbao_bootstrap_ready`, `openbao_audit_migration_ready`,
`openbao_bootstrap_complete_ready`, and `openbao_haproxy_activation_ready` false
by default. Open only the gate for the current attended transition, close it
after success, and then record the active OpenBao or HAProxy service state in
private inventory. Keep Keepalived stopped until monitoring observer and canary
acceptance is available.

The same three OpenBao hosts also model the independent external monitoring
observer role. `openbao_observers_orchestration_ready` gates convergence, while
the required boolean `openbao_observers_activate` is the single source for the
Alloy service and every configured probe timer state. Stage with activation
false, review the complete validated Alloy configuration, then activate only
after the monitoring VIP endpoints, PostgreSQL primary identity, per-host Garage
bucket/key, and Mimir remote-write receiver are ready. Real endpoint policy stays
in private inventory; CA files, client keys, credentials, and tokens remain
outside Git. Configure `platform_external_probe_vip_ownership` only on hosts that
can own that VIP in their local kernel; OpenBao observer hosts must not claim
node-local ownership of the monitoring VIP. This observer workflow does not
initialize or activate OpenBao.

The legacy OpenBao inventory group was `vault`. The replacement API is
`openbao`; do not add a compatibility alias without a demonstrated consumer.

Example run:

```bash
source ../platform-private/config/homelab.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml
```
