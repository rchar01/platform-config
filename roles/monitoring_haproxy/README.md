# Monitoring HAProxy

Validation-only foundation for the replacement monitoring HAProxy policy.

The role is disabled by default. In this slice, setting
`monitoring_haproxy_enabled: true` validates the locked frontend contract but
does not install packages, render files, manage SELinux or firewalld, or touch a
service. `monitoring_haproxy_service_enabled` must remain `false` and
`monitoring_haproxy_service_state` must remain `stopped`.

Validated inputs include:

- exact HAProxy NEVRA and fixed HTTPS/PostgreSQL client ports;
- unique service DNS names and restricted metrics binding;
- outside-Git frontend/client/backend TLS source paths;
- exact escape-free RFC2253 subject-DN role mappings;
- observed literal Loki, Mimir, Alertmanager, and operator method/path routes;
- a dedicated management-source allowlist for operator routes;
- unique, network-normalized `/24`-or-narrower source CIDRs, with operator
  sources contained by the outer HTTPS policy; and
- an explicit contract-readiness gate.

Backend topology, service health wiring, package repository immutability,
configuration rendering, lifecycle management, and target activation remain
blocked. Real PKI stays outside Git and is produced through `platform-tools`;
the role never generates production certificates.

Subject DNs must be unique. Multiple explicitly listed identities may map to the
same least-privilege role, including individual collectors, browser users, and
operators. Membership is an exact identity allowlist; role-name uniqueness is
not an authorization boundary.
