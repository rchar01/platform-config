# openbao_haproxy

Stages the dedicated host-native HAProxy policy for the three-node OpenBao HA
design. The role and service are disabled and stopped by default. The guarded
`playbooks/openbao.yml` staging path invokes the role only when the complete
three-node ownership contract is explicitly ready and every service remains
disabled and stopped.

The role owns:

- an exact HAProxy `3.0` package identity supplied by accepted inventory;
- raw TCP passthrough from wildcard host port `8200` to canonical node port
  `18200` without terminating client TLS, with the approved client CIDRs enforced
  by HAProxy as well as firewalld;
- independent HTTPS checks that accept only `/v1/sys/health` status `200` and
  require CA trust, node-specific SNI, and node-specific certificate identity;
- a source-restricted built-in Prometheus endpoint exposing only `/metrics`;
- atomic native candidate validation before replacing `haproxy.cfg`;
- disabled/stopped service lifecycle controls; and
- reconciled source-scoped client and metrics firewalld rules.

On SELinux-enforcing hosts, the role labels only HAProxy's current client and
metrics listener ports. It does not automatically remove old port labels because
SELinux port mappings are global policy and the role cannot safely infer exclusive
ownership. Review an obsolete mapping separately before removing it. The role
does not label OpenBao's direct backend port, which HAProxy connects to but does
not bind.

Do not use `standbyok=true`. Status `429` standbys, `501` uninitialized nodes,
and `503` sealed nodes must remain ineligible for client routing. The `check-ssl`
server option applies TLS only to HAProxy's health checks. The server lines do
not use `ssl`, so normal client TLS remains end-to-end between the client and
OpenBao.

Provide the same canonical member list consumed by the `openbao` role, the
installed OpenBao CA path, shared service DNS name, and private source CIDRs.
For example:

```yaml
openbao_haproxy_enabled: true
openbao_haproxy_package_nevra: haproxy-0:3.0.5-6.el10_2.1.x86_64
openbao_haproxy_client_allowed_sources:
  - 192.0.2.0/24
openbao_haproxy_stats_bind_address: 192.0.2.63
openbao_haproxy_stats_allowed_sources:
  - 192.0.2.128/25
openbao_haproxy_service_enabled: false
openbao_haproxy_service_state: stopped
```

Real package transactions, addresses, DNS names, and CIDRs belong in private
inventory. Keep HAProxy stopped until direct OpenBao TLS and health behavior are
qualified. Keep Keepalived disabled until HAProxy listeners, backend selection,
network, and firewall gates pass and its separate activation is approved.
Standalone development OpenBao acceptance does not depend on observers;
production monitoring remains required. This role never initializes or unseals
OpenBao and never activates a VIP.

The guarded activation play checks and records each node's exact installed
package, validated configuration checksum, backend CA checksum, and managed
firewalld manifest checksum before approval, then requires unchanged evidence
immediately before enabling the service. Each preflight also checks that the
target Ansible Python can import firewalld bindings and records fresh dependency
readiness without installing packages or running firewall convergence. Rollback
is confirmed per host only after systemd reports HAProxy both inactive and
disabled; failed or unreachable checks remain explicitly unverified.

The activation playbook accepts `service_facts` state `stopped` or `inactive`
for disabled edge services: systemd units absent from `list-units` can report
the raw `inactive` state. Failed, unknown, or missing facts still fail closed.
Failure diagnostics show the observed edge state/status and firewalld state;
this does not relax the separate running-firewall prerequisite.

The activation playbook shares the schema-1 plan/action contract with Keepalived:
TTL 1800 seconds, clean committed source/private inventory identity, and exact
environment, hosts, evidence, and lane binding, plus CI
image/project/pipeline/plan-job identity. `platform-tools` owns the
`platform-openbao-edge haproxy-plan` and `haproxy-activate` facade commands; both
require `--source`, `--inventory`, `--controller-vars`, and `--plan`. The existing
Make activation target remains direct interactive. Operator activation requires
exact TTY approval; CI uses the matching same-pipeline protected manual job with
no terminal continuation.

Read-only plan mode allows readiness false. Activation requires
`openbao_haproxy_activation_ready: true` as an exact boolean on every host;
commit the reviewed declaration before planning the approved activation. A
later readiness change invalidates the private SHA. Leave HAProxy and Keepalived
desired disabled/stopped for HAProxy activation. Operator plans stay outside
every Git repository in new `0600` files under an existing current-owner `0700`
non-symlink directory, with no overwrite; CI uses only its fixed restricted
artifact.

The owning playbook acquires target-root guards at
`/var/lib/platform-config/openbao-edge-guard` on every host and consumes the plan
before final preflight. `active/owner.json` and permanent `consumed/<plan_id>`
records coordinate only supported HAProxy/Keepalived activation, not root,
out-of-band changes, or rolling maintenance. Prohibit concurrent other lifecycle
work. Partial acquisition, interruption, unknown rollback, or unverified release
retains affected records for reviewed recovery. Success or per-host verified
rollback releases only owned active guards. There is no automatic unlock or
consumed-record deletion; retries require fresh plans after recovery. See
[Guard Recovery](../../docs/operator-runbook.md#openbao-edge-guard-recovery).

After success, review and commit `openbao_haproxy_service_enabled: true`,
`openbao_haproxy_service_state: started`, and
`openbao_haproxy_activation_ready: false` in private desired state. Neither lane
automatically mutates or pushes those values. CI qualification, rollback, and
reporting remain in CI, with lifecycle handoff keys in reports. Firewall
readiness and enablement remain separate prerequisites. Do not rerun pristine
OpenBao staging on an active cluster; use pre-VIP smoke before the separately
approved Keepalived plan and activation.

`openbao_haproxy_enabled: false` means the role does not own HAProxy state; it
does not stop a potentially unrelated HAProxy service. Deactivate this role by
first converging `openbao_haproxy_service_enabled: false` and
`openbao_haproxy_service_state: stopped`. Keep firewalld and SELinux management
enabled through that convergence rather than abandoning previously managed
policy.
