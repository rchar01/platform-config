# Rebuild

This runbook describes how to recreate hosts from a clean VM and converge them
to the current desired state.

The rebuild path is intentionally different from migrations. A rebuilt host
should not replay historical upgrade steps. It should receive the current VM
shape from `platform-infra`, current configuration from private inventory, and
current desired OS/service state from `platform-config`.

## Repository Responsibilities

```text
platform-template-builder
  builds current reusable VM templates

platform-infra
  creates VM CPU, RAM, disk, network, cloud-init, and inventory-shaped outputs

platform-config
  applies current desired OS and service state with Ansible

platform-private
  provides real inventories, group vars, host vars, access policies, and CA files

outside-Git secret store
  provides kubeconfigs, private keys, tokens, passwords, and other secrets
```

Do not add VM lifecycle, OpenTofu, Proxmox, or template-building logic to this
repository.

## Rebuild Categories

### Stateless

Use this path for hosts that can be recreated from config alone.

Pattern:

1. Recreate the VM with `platform-infra`.
2. Confirm private inventory points at the new host address and SSH user.
3. Run `playbooks/site.yml` or a focused desired-state playbook.
4. Run the relevant smoke or validation playbook.
5. Remove the old VM only after validation succeeds.

Examples:

- Kubernetes bastion host runtime and host configuration
- disposable runners, once registration is automated or token input is ready
- generic baseline Rocky hosts

### Stateful

Use this path for hosts that own persistent data.

Pattern:

1. Confirm a usable backup or existing storage volume is available.
2. Recreate the VM with `platform-infra`.
3. Run `playbooks/site.yml` or a focused desired-state playbook.
4. Restore or reattach data according to the service runbook.
5. Validate service health and data integrity.
6. Keep rollback information until the new host is accepted.

Examples:

- registries
- databases
- NFS-backed application hosts
- Kubernetes control-plane nodes

Stateful restore procedures belong in service runbooks or explicit maintenance
playbooks, not inside normal desired-state roles.

## Generic Rebuild Flow

1. Prepare private inputs.

   Verify `../platform-private/config/<env>.ansible.env`, inventory, group vars,
   host vars, policy files, and outside-Git secrets are current.

2. Recreate infrastructure.

   Use `platform-infra` to create or replace the VM. Keep Ansible OS/service
   configuration out of `platform-infra`.

3. Verify Ansible can reach the host.

   ```bash
   source ../platform-private/config/dev.ansible.env
   ansible -i "$PLATFORM_CONFIG_INVENTORY" target-host -m ping
   ```

4. Dry-run the desired state.

   ```bash
   ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml --limit target-host --check --diff
   ```

5. Apply current desired state.

   ```bash
   ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml --limit target-host
   ```

6. Run focused validation.

   Use a service-specific smoke playbook when available. For bastion hosts, run:

   ```bash
   ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/k8s-bastion-smoke.yml --limit target-host
   ```

7. Perform service-specific restore if needed.

   Restore data only after the host baseline is correct. Use maintenance
   playbooks or service runbooks for restore validation.

## Kubernetes Bastion Rebuild

The current Kubernetes bastion host is treated as a clean Rocky host configured
by Ansible. It is not a Kubernetes node conversion path.

Inputs required before rebuild:

- private inventory entry in `../platform-private/config/inventories/<env>/`
- `k8s_bastion_policy_src` pointing at the final rendered access policy
- `k8s_bastion_ca_src` pointing at the cluster CA certificate
- `k8s_bastion_admin_kubeconfig_src` pointing at an outside-Git admin kubeconfig
- vendored or overridden `k8s_bastion_runtime_src`

Recommended rebuild command sequence:

```bash
source ../platform-private/config/dev.ansible.env
ansible -i "$PLATFORM_CONFIG_INVENTORY" k8s-bastion-01 -m ping
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/k8s-bastion-access.yml --limit k8s-bastion-01 --check --diff
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/k8s-bastion-access.yml --limit k8s-bastion-01
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/k8s-bastion-smoke.yml --limit k8s-bastion-01
```

Manual validation after apply:

- SSH into the bastion host and confirm the login profile renders correctly.
- Run `bastion-version`.
- Run `kubectl version --client`.
- Confirm expected systemd timers with `systemctl list-timers 'bastion-*'`.
- Test one non-admin user credential path before handing the host to operators.

## Kubernetes Nodes

Kubernetes node rebuild policy depends on node role.

Worker nodes are usually disposable:

1. Recreate VM.
2. Apply current node desired state.
3. Join the current cluster directly.
4. Validate node readiness.

Control-plane nodes are stateful and need a separate procedure for etcd,
certificates, and kubeadm state. Do not encode control-plane recovery into a
normal daily role.

## Migrations Are Not Rebuilds

Use `migrations/` for existing machines that must move through a live-state
transition, such as Kubernetes minor upgrades, storage moves, or token rotation.

A fresh VM should receive the current desired version directly when that is safe
for the service. Sequential upgrade history belongs in migration playbooks and
service runbooks, not in `playbooks/site.yml`.
