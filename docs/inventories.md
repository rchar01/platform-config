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

Example run:

```bash
source ../platform-private/config/homelab.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml
```
