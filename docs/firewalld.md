# Firewalld Readiness And Enablement

This guide describes how `platform-config` prepares firewalld rules while the
daemon is disabled, how to add rules, and how to enable enforcement safely in a
future environment rollout.

This repository contains reusable public Ansible code and safe examples only.
Real hostnames, addresses, network ranges, access policy, and environment
configuration belong under `../platform-private/config/`. The example addresses
in this guide use the RFC 5737 documentation range `192.0.2.0/24` and must not
be copied into a real environment.

## Current Baseline

The `firewalld` role currently:

- installs `firewalld` and `python3-firewall`;
- verifies that the managed host's Ansible Python interpreter can import the
  firewalld bindings;
- manages the firewalld systemd enabled and runtime states;
- defaults to disabled at boot and stopped at runtime;
- supports generic service and port rules when rule management is active; and
- tracks generic services and ports in a managed manifest so stale generic
  entries can be pruned.

Focused service roles use permanent, offline-capable firewalld operations.
They can therefore write permanent service rules while the daemon is stopped.
When inventory opts into active enforcement, those same role tasks also update
the runtime configuration immediately.

The inactive baseline is intentional preparation, not network enforcement.
Permanent rules do not filter traffic while firewalld is stopped.

## Configuration Variables

Use the explicit service variables in private inventory:

```yaml
firewalld_service_enabled: false
firewalld_service_state: stopped
```

For future active enforcement, set both values:

```yaml
firewalld_service_enabled: true
firewalld_service_state: started
```

`firewalld_enabled` remains a compatibility shorthand that derives both
values, but the explicit variables make the boot and runtime policy clear.

The baseline role also exposes:

| Variable | Purpose |
|---|---|
| `firewalld_services` | Generic firewalld service names to enable. |
| `firewalld_ports` | Generic ports such as `8443/tcp` to enable. |
| `firewalld_manage_rules` | Controls baseline generic service and port management. It defaults to true only when the configured runtime state is active. |
| `firewalld_prune_managed` | Prunes stale generic services and ports recorded in the baseline role's manifest. |

For example, an active environment could declare generic rules in its private
inventory:

```yaml
firewalld_services:
  - ssh
firewalld_ports:
  - 8443/tcp
```

The baseline role does not manage its generic rule lists by default while the
daemon is stopped. Do not force `firewalld_manage_rules: true` solely to stage
generic rules without first testing that workflow. Service-specific roles are
the supported offline staging path in the current inactive baseline.

## Service Rule Ownership

Service roles own rules that are specific to the services they deploy. Keep
real values in private group or host variables.

| Role | Primary firewall variables | Rule shape |
|---|---|---|
| `zot_registry` | `zot_registry_firewalld_manage`, `zot_registry_firewalld_port`, `zot_registry_firewalld_allowed_sources` | Broad port or source-scoped rich rules. |
| Staged `openbao` role | `openbao_firewalld_manage`, `openbao_backend_allowed_sources`, canonical cluster members | Reconciled direct-backend and peer-only cluster rules; no active playbook invokes this role yet. |
| `openbao_haproxy` | `openbao_haproxy_firewalld_manage`, client and stats allowed-source lists | Reconciled source-scoped client and metrics listener rules; role and service remain disabled by default. |
| `node_exporter` | `node_exporter_firewalld_manage`, `node_exporter_firewalld_allowed_sources` | Source-scoped rich rules. |
| Retired `monitoring_stack` role | `monitoring_stack_firewalld_manage`, Grafana and Loki allowed-source lists | Legacy source-scoped rules; no active playbook invokes this role. |
| `rke2` | `rke2_firewalld_manage`, cluster and API source lists, API ports | Cluster and API rich rules. |
| `gitlab_ce` | `gitlab_ce_firewalld_manage`, `gitlab_ce_firewalld_ports` | Broad service ports. |
| `haproxy_workload_lb` | `haproxy_workload_lb_firewalld_manage`, `haproxy_workload_lb_firewalld_ports` | Broad listener ports. |
| `keepalived_vip` | `keepalived_vip_firewalld_manage`, instance `peers` | Reconciled peer-scoped IPv4 rich rules for VRRP protocol `112`; service activation remains disabled by default. |

Prefer source-scoped rules when a service does not need broad client access.
For example, a private registry configuration can use a documentation-only
CIDR like this:

```yaml
# Real values belong in ../platform-private/config/inventories/example/.
zot_registry_firewalld_allowed_sources:
  - 192.0.2.0/24
```

Apply the service's focused playbook after changing its firewall variables.
The focused playbooks establish the firewalld package and Python prerequisites
before service roles manage rules.

## Readiness Checklist

Do not enable enforcement until all of these conditions are satisfied for the
target host or host group:

- Every required inbound flow has an identified source, destination, protocol,
  and port.
- Ansible SSH access is explicitly preserved; do not rely on an unverified
  distribution default.
- Required cluster, monitoring, registry, load-balancer, and administrative
  paths are represented in private inventory.
- Broad rules are intentional and source-scoped alternatives have been
  considered.
- The firewalld default zone is known and each relevant network interface is
  assigned to the expected zone.
- Permanent configuration passes `firewall-offline-cmd --check-config`.
- Focused service smoke tests pass while the permanent rules are staged.
- A canary host and a working out-of-band console or equivalent recovery path
  are available.
- The rollback values and commands are prepared before activation.

Current role tasks do not declare an explicit zone, so rules use firewalld's
default zone. Confirm the default zone and interface assignment as part of the
policy review.

## Stage Rules While Inactive

Keep the inactive baseline in private inventory while defining service rules:

```yaml
firewalld_service_enabled: false
firewalld_service_state: stopped
```

For each affected service, run a check, apply, smoke test, and second apply.
The following uses public example names; substitute a real private environment
and playbook:

```bash
make check ENV=example PLAYBOOK=playbooks/registry.yml
make apply ENV=example PLAYBOOK=playbooks/registry.yml
make smoke-registry ENV=example
make apply ENV=example PLAYBOOK=playbooks/registry.yml
```

The second apply should report `changed=0` unless a documented task refreshes
runtime state. Inspect permanent configuration on the managed host:

```bash
sudo firewall-offline-cmd --check-config
sudo firewall-offline-cmd --get-default-zone
sudo firewall-offline-cmd --zone=public --list-all
```

Replace `public` with the reviewed target zone. Run the inactive baseline smoke
test before activation:

```bash
make smoke-firewalld ENV=example LIMIT=example-host
```

`make smoke-firewalld` intentionally asserts that firewalld is disabled and
inactive. It is not an active-enforcement test and should not be run after the
canary has been enabled unless failure is the expected result.

Verify the permanent management-access rule separately before activation. For
standard SSH in the reviewed zone:

```bash
sudo firewall-offline-cmd --zone=public --query-service=ssh
```

The command must report `yes`. For a custom SSH port, query that port instead:

```bash
sudo firewall-offline-cmd --zone=public --query-port=2222/tcp
```

If the required management rule is absent, do not start firewalld. The baseline
role currently starts the daemon before it processes generic rules. Declare the
same service or port in `firewalld_services` or `firewalld_ports`, then stage it
while the daemon is still stopped:

```bash
sudo firewall-offline-cmd --zone=public --add-service=ssh
sudo firewall-offline-cmd --zone=public --query-service=ssh
```

Use `--add-port=PORT/PROTOCOL` and `--query-port=PORT/PROTOCOL` for a custom SSH
listener. The subsequent active baseline apply adopts the inventory declaration
into its managed manifest. This one-time transition step is necessary until the
baseline role supports generic offline staging directly.

## Enable A Canary

Select one non-production or otherwise low-risk host with console recovery.
Do not continue unless the permanent management-access query in the previous
section succeeds. Override the canary's private host variables:

```yaml
firewalld_service_enabled: true
firewalld_service_state: started
```

Check and apply only the focused baseline to that host:

```bash
make check ENV=example PLAYBOOK=playbooks/firewalld.yml LIMIT=example-host
make apply ENV=example PLAYBOOK=playbooks/firewalld.yml LIMIT=example-host
```

Then apply the host's focused service playbook so all service-owned rules are
confirmed against the running daemon:

```bash
make apply ENV=example PLAYBOOK=playbooks/registry.yml LIMIT=example-host
```

Verify the active and permanent state on the managed host:

```bash
systemctl is-enabled firewalld
systemctl is-active firewalld
sudo firewall-cmd --state
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --zone=public --list-all
sudo firewall-cmd --permanent --zone=public --list-all
sudo firewall-offline-cmd --check-config
```

Run the applicable service smoke tests from `platform-config`. Also test each
required connection from an authorized source and confirm that representative
unauthorized sources cannot connect. A successful local service check alone
does not prove that the network policy is correct.

After live checks pass, reboot the canary during an approved maintenance
window. Confirm that firewalld starts automatically, SSH remains available,
rules remain effective, and all focused service smoke tests still pass.

## Roll Out By Host Group

Promote the two active service variables from canary host variables to the
appropriate private group variables only after the canary passes. Roll out one
host group at a time with `LIMIT`, preserving cluster serial order where a
playbook defines it.

For each group:

1. Run the relevant playbooks in check mode.
2. Apply the focused firewalld and service playbooks.
3. Verify enabled, active, permanent, and runtime rule state.
4. Run positive and negative connectivity tests.
5. Run every affected service smoke test.
6. Apply again and confirm idempotency before continuing.

Do not change all environments at once. Development, pre-production, and
production policies may require different source ranges and exposure.

## Rollback

If Ansible connectivity remains available, restore the inactive values in
private inventory and apply the focused baseline:

```yaml
firewalld_service_enabled: false
firewalld_service_state: stopped
```

```bash
make apply ENV=example PLAYBOOK=playbooks/firewalld.yml LIMIT=example-host
```

If firewall policy blocks Ansible or SSH, use the approved out-of-band console
to stop firewalld temporarily:

```bash
sudo systemctl stop firewalld
```

Restore connectivity, correct the private policy, and converge the host again.
Do not leave an emergency runtime change as the final state.

## Known Readiness Gaps

The code provides a strong foundation for future enablement, but these items
must be addressed or explicitly accepted before fleet-wide enforcement:

- Active enforcement has not yet been exercised across the fleet.
- The current firewalld smoke playbook validates only the inactive baseline.
- Baseline generic service and port rules are not staged by default while the
  daemon is stopped. The management-access rule must be verified and, when
  necessary, staged offline before activation.
- The baseline manifest prunes generic services and ports, but service-specific
  source-scoped rich rules do not share that manifest. Removing a source from
  inventory may require explicit stale-rule cleanup.
- Rule tasks currently rely on the firewalld default zone rather than an
  explicitly managed zone and interface policy.

Treat these as rollout requirements, not reasons to bypass check mode, canary
testing, connectivity validation, or console recovery.
