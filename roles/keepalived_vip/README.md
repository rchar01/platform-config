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
direct-backend, HAProxy, network, and firewall gates. Standalone development
OpenBao acceptance does not depend on observers; production monitoring remains
required. The owning activation playbook, not normal role convergence, performs
VIP qualification. Failure injection and runtime failback qualification remain
separately authorized operations.

The default 300-second `preempt_delay` requires a recovered preferred node to
remain eligible while observing a lower-priority owner before it can reclaim the
VIP. This suppresses rapid failback when the preferred node repeatedly enters
`FAULT`, but no finite delay prevents switching if it stays healthy longer than
the delay and then fails again.

Callers must run the repository's `firewalld` role first so its package and
Python dependencies exist before this role stages peer-scoped VRRP rules.
Lifecycle selectors are strict booleans, even when this role is disabled.
`keepalived_vip_service_state` accepts only `stopped` or `started`, and boot
enablement must be true exactly when the state is `started`. Disabled callers
cannot request activation. Active convergence with managed firewall policy
requires enabled/started firewalld inventory settings and an actually active
firewalld service before any convergence. Repository-policy validation runs only
in the normal enabled convergence path, not as an implicit role dependency.
The explicit `firewalld_service_enabled` and `firewalld_service_state` values
are authoritative; the legacy `firewalld_enabled` default-source flag is not an
additional activation gate.
Immediately before active service management and again inside the reload handler,
the shared read-only `runtime_firewall_guard.yml` requires running firewalld and
every current peer's exact runtime rich rule. It queries the default zone, matching
the role's existing firewall management. Loss of connectivity, firewalld, or a
required rule prevents the service operation; an earlier passing guard is not
reused as evidence.

## Activation Entry Points

OpenBao uses `playbooks/maintenance/openbao-keepalived-activate.yml`, shared with
the HAProxy schema-1 plan/action contract (TTL 1800 seconds). The
`platform-tools` facade exposes `keepalived-plan` and `keepalived-activate` with
required `--source`, `--inventory`, `--controller-vars`, and `--plan`; the existing
Make activation target remains direct interactive. Plan mode is read-only and
allows readiness false. Activation requires
`openbao_keepalived_activation_ready: true` as an exact boolean on every host.
Commit that reviewed declaration before planning an approved activation; a later
readiness change invalidates the plan's private inventory SHA.

Plans bind clean committed source/private inventory identity, environment,
hosts, evidence, and lane, plus CI image/project/pipeline/plan-job identity.
Operator approval is exact and TTY-bound; CI uses a matching same-pipeline
protected manual job with no terminal continuation. Operator plans stay outside
Git, published as new `0600` files in an existing current-owner `0700`
non-symlink directory without overwrite. CI uses only its fixed restricted
artifact. Plan files and evidence must not enter public documentation.

The owning playbook acquires the shared target-root guard at
`/var/lib/platform-config/openbao-edge-guard` on every host and consumes the plan
before final preflight. Its `active/owner.json` and permanent
`consumed/<plan_id>` records coordinate only supported HAProxy/Keepalived
activations, not root, out-of-band changes, or rolling maintenance. Prohibit
concurrent other lifecycle work. Partial acquisition, interruption, unknown
rollback, or unverified release retains affected records for reviewed recovery.
Success or per-host verified rollback releases only owned active guards; no
automatic unlock, consumed-record deletion, or consumed-plan retry is permitted.
Use a fresh plan after recovery. See
[Guard Recovery](../../docs/operator-runbook.md#openbao-edge-guard-recovery).

The owning activation playbook must run this read-only entry point on every
candidate before approval and again immediately after approval, without normal
role convergence between those observations:

```yaml
- name: Observe staged Keepalived activation candidates
  ansible.builtin.include_role:
    name: keepalived_vip
    tasks_from: activation_preflight.yml
```

Run with target privileges sufficient to inspect root-owned configuration, query
RPM and firewalld, and execute `runuser`. Configuration must be enabled and track
`haproxy.service`; Keepalived must actually be inactive and boot-disabled while
HAProxy must actually be active and boot-enabled. This entry point never installs
packages, writes templates, reloads systemd, starts services, or repairs firewall
policy. The preflight wrapper explicitly disables inherited `ignore_errors` and
`ignore_unreachable` for its entire task chain. Callers must use that wrapper,
not its internal task files, and must not override or bypass these protections.

Preflight verifies the exact installed NEVRA, package ownership of the selected
binary, SHA-256 RPM header identity, and non-configuration package files using
`rpm -V --noscripts --noconfig`. Configuration, script, and drop-in must be regular
root:root files with the role's exact modes and SHA-256 equality to freshly
rendered current inventory. It also checks native configuration and Bash syntax,
executes readiness as the configured script user/group, and requires up
interfaces, exact source addresses, VIP routes through the configured interfaces,
and VIP absence across **all** local IPv4 interfaces, not just the VRRP interface.
Managed firewall mode additionally requires a valid current manifest, active
firewalld, and every expected peer rule in both runtime and permanent policy.

Activation supports the native service contract observed directly from
`keepalived-0:2.2.8-9.el10.x86_64`: `keepalived.service`, executable
`/usr/sbin/keepalived`, default config `/etc/keepalived/keepalived.conf`, packaged
fragment `/usr/lib/systemd/system/keepalived.service`, and only the role-owned
`/etc/systemd/system/keepalived.service.d/platform.conf` drop-in. Noncanonical
service paths are rejected, even if their files happen to match the templates.
The fragment must belong to the exact verified RPM. The loaded manager's
`FragmentPath`, `DropInPaths`, and `NeedDaemonReload` must match those files with
no additional drop-ins or pending reload. Its `ExecStart` must be the single
native `/usr/sbin/keepalived --dont-fork $KEEPALIVED_OPTIONS` command.

The only allowed environment file is `/etc/sysconfig/keepalived`, and its only
non-comment, nonempty line must be exactly `KEEPALIVED_OPTIONS="-D"`. This rejects
alternate config files, network namespaces, and options that retain VIPs on stop
without evaluating environment content as a shell script. The loaded unit must
have empty `Environment`, `PassEnvironment`, and `UnsetEnvironment` properties.
The unit and sysconfig must be regular root:root files with mode `0644`; both
checksums are bound into approval evidence. This deliberately narrow contract
rejects unreviewed vendor-unit or local option changes instead of guessing their
semantics. Unit and property formats were checked in a disposable container using
the exact Keepalived RPM and systemd `257-23.el10_2.2.rocky.0.1`; that does not
qualify a completely pinned Rocky 10.1 environment or managed-host networking.

Successful preflight publishes `keepalived_vip_activation_observation` containing
`inventory_host`, `instances`, `cluster_members`, `service_name`, artifact paths,
`package_nevra`, `package_checksum`, `binary_checksum`, `config_checksum`,
`script_checksum`, `drop_in_checksum`, `unit_checksum`, `sysconfig_checksum`,
`systemd_properties`, `firewalld_manage`, and
`firewalld_manifest_checksum` (`unmanaged` when not managed). `package_checksum`
is the installed RPM header SHA-256, not the digest of a downloaded RPM file or
independent provenance evidence. All artifact checksums are SHA-256. A new pass
clears the previous observation before validation and only publishes the complete
observation on success. The caller must preserve the first complete observation,
bind approval to it, and require equality with the second observation on every
host before starting any service. These are point-in-time checks, not a lock
against concurrent changes or a substitute for cluster-wide ownership checks.

For recovery, use `tasks_from: activation_rollback.yml`. It resets
`keepalived_vip_activation_rollback_confirmed` to false, stops and boot-disables
Keepalived, requires observed inactive/disabled service states, and proves every
configured VIP absent on all local interfaces. Only then does it set the fact to
true. Ordinary failures are rescued with confirmation false; unreachable hosts
must also be treated as unconfirmed by the caller. Check mode cannot confirm
rollback. The service observation loop and every individual result must succeed,
be reachable and unskipped, and contain the exact expected return code and state.
A later successful observation cannot erase an earlier unreachable result.
The owning playbook must aggregate confirmations across the entire
candidate set and fail/report recovery as incomplete if any fact is false or
missing, or any host is unreachable. Rollback does not delete addresses manually,
alter other services, or claim successful cluster-wide recovery itself.

After successful OpenBao VIP activation, review and commit
`keepalived_vip_service_enabled: true`, `keepalived_vip_service_state: started`,
and `openbao_keepalived_activation_ready: false` in private desired state before
VIP smoke. Neither operator nor CI automatically mutates or pushes that source.
CI qualification, rollback, and reporting remain in CI, and reports must show
these lifecycle handoff keys. Firewall readiness/enablement remains a separate
prerequisite. Do not rerun pristine OpenBao staging on an active cluster.

Focused synthetic checks (no managed hosts or private configuration):

```bash
PLATFORM_CONFIG_CONTAINER_PROFILE=test ./scripts/in-container python -m pytest -q tests/python/test_keepalived_vip_render.py
```

These execute the Ansible task chains with real template rendering, file metadata,
checksums, and Bash syntax checks in an isolated user namespace. RPM, systemd,
network, native Keepalived validation, and script-identity execution use controlled
doubles. Integration fixtures relocate canonical paths only in scratch role
copies; separate tests exercise the unchanged canonical-path guards. These checks
do not establish live service, native package, or network readiness.

Node-local ownership metrics and the shared external observer integration remain
owned by the planned `platform_external_probe` slice. They must be detect-only
and must not feed observations back into VRRP eligibility.
