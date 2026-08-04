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
firewall, observer, and canary gates pass. This role never initializes or
unseals OpenBao and never activates a VIP.

`openbao_haproxy_enabled: false` means the role does not own HAProxy state; it
does not stop a potentially unrelated HAProxy service. Deactivate this role by
first converging `openbao_haproxy_service_enabled: false` and
`openbao_haproxy_service_state: stopped`. Keep firewalld and SELinux management
enabled through that convergence rather than abandoning previously managed
policy.
