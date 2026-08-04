# Inventories

This repository supports multiple environments through separate inventories.

Public examples:

```text
inventories/homelab/
inventories/dev/
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

The focused OpenBao staging playbook owns Podman installation directly, so
OpenBao nodes do not require `container_hosts` membership. Storage remains a
separate destructive boundary: add real nodes to `storage_volume_hosts` only
after stable-device review and explicit initialization approval. Set
`openbao_orchestration_ready` only after the resulting mounts and every remaining
role input are complete.

The legacy OpenBao inventory group was `vault`. The replacement API is
`openbao`; do not add a compatibility alias without a demonstrated consumer.

Example run:

```bash
source ../platform-private/config/homelab.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml
```
