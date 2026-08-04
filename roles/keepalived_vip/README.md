# keepalived_vip

Installs and configures the shared host-native Keepalived VIP foundation used by
the OpenBao and monitoring HA designs. The role is disabled by default, and its
service remains disabled and stopped by default even after configuration is
enabled.

The role enforces these initial IPv4 VRRP invariants:

- every instance starts as `BACKUP` and delays automatic priority-based failback
  for five minutes by default;
- priorities are limited to `1..254` so address-owner preemption is impossible;
- callers provide one canonical cluster mapping keyed by inventory hostname;
  the role derives the local router ID and validates the assigned source address,
  peer set, and per-instance priority while rejecting cluster duplicates;
- unicast peers are explicit, unique, and exclude the local source address;
- the primary interface and a zero-weight, `init_fail` script are hard faults;
- the script tracks only the local HAProxy service, required listener ports, and
  VRRP interfaces, never application leadership or backend health;
- configuration is validated with the selected Keepalived binary before atomic
  replacement; and
- VRRP protocol `112` is accepted only from configured peers when firewalld
  management is enabled, with obsolete role-owned peer rules removed on later
  convergence.

The caller must provide an exact package NEVRA from the accepted target
repository transaction. A disposable Rocky Linux 10.1 check on 2026-07-31
resolved `keepalived-0:2.2.8-9.el10.x86_64`; this observation is not target-host
or immutable-repository evidence.

Example inputs:

```yaml
keepalived_vip_enabled: true
keepalived_vip_package_nevra: keepalived-0:2.2.8-9.el10.x86_64
keepalived_vip_preempt_delay: 300
keepalived_vip_cluster_members:
  - name: openbao-01
    router_id: bao-1
    instances:
      OPENBAO:
        source_address: 192.0.2.63
        priority: 150
  - name: openbao-02
    router_id: bao-2
    instances:
      OPENBAO:
        source_address: 192.0.2.64
        priority: 140
  - name: openbao-03
    router_id: bao-3
    instances:
      OPENBAO:
        source_address: 192.0.2.65
        priority: 130
keepalived_vip_track_service: haproxy.service
keepalived_vip_track_ports:
  - 8200
keepalived_vip_instances:
  - name: OPENBAO
    interface: eth0
    virtual_router_id: 51
    priority: 150
    source_address: 192.0.2.63
    peers:
      - 192.0.2.64
      - 192.0.2.65
    vip: 192.0.2.200/24
```

Leave `keepalived_vip_service_enabled: false` and
`keepalived_vip_service_state: stopped` until the owning service plan has passed
direct-backend, HAProxy, network, firewall, and observer gates. The role does not
perform runtime failback, failure injection, or VIP activation testing.

The default 300-second `preempt_delay` requires a recovered preferred node to
remain eligible while observing a lower-priority owner before it can reclaim the
VIP. This suppresses rapid failback when the preferred node repeatedly enters
`FAULT`, but no finite delay prevents switching if it stays healthy longer than
the delay and then fails again.

Callers must run the repository's `firewalld` role first so its package and
Python dependencies exist before this role stages peer-scoped VRRP rules.

Node-local ownership metrics and the shared external observer integration remain
owned by the planned `platform_external_probe` slice. They must be detect-only
and must not feed observations back into VRRP eligibility.
