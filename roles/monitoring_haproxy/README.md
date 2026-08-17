# Monitoring HAProxy

Validation-only foundation for the replacement monitoring HAProxy policy.

The role is disabled by default. In this slice, setting
`monitoring_haproxy_enabled: true` validates the locked frontend contract but
does not install packages, render files, manage SELinux or firewalld, or touch a
service. `monitoring_haproxy_service_enabled` must remain `false` and
`monitoring_haproxy_service_state` must remain `stopped`.

Validated inputs include:

- exact HAProxy NEVRA and fixed HTTPS/PostgreSQL client ports;
- three unique HAProxy-owned listener ports and exact private backend definitions
  for Grafana, Loki, Mimir, integrated Alertmanager, S3, and PostgreSQL;
- exactly three uniquely named IPv4 targets and lowercase FQDN TLS server
  identities per backend;
- no backend collision with an HAProxy-owned listener, with integrated
  Alertmanager required to share Mimir's exact port and target topology and no
  unrelated services sharing backend ports;
- unique service DNS names and restricted metrics binding;
- outside-Git frontend/client/backend TLS source paths;
- exact escape-free RFC2253 subject-DN role mappings;
- observed literal Loki, Mimir, Alertmanager, and operator method/path routes;
- a mandatory least-privilege `monitoring_probe` identity with host-scoped
  `GET /api/health` for Grafana and `GET /ready` for Loki and Mimir;
- a separate `monitoring_s3_probe` identity limited to `DELETE`, `GET`, and
  `PUT` on the S3 hostname, with Garage credentials retaining bucket/object
  authorization;
- a dedicated management-source allowlist for operator routes;
- unique, network-normalized `/24`-or-narrower source CIDRs, with operator
  sources contained by the outer HTTPS policy; and
- an explicit contract-readiness gate.

Service health wiring, package repository immutability, configuration rendering,
lifecycle management, and target activation remain blocked. Backend ports,
addresses, names, and TLS identities have no public defaults and must come from
private inventory. Real PKI stays outside Git and is produced through
`platform-tools`; the role never generates production certificates.

Subject DNs must be unique. Multiple explicitly listed identities may map to the
same least-privilege role, including individual collectors, browser users, and
operators. Membership is an exact identity allowlist; role-name uniqueness is
not an authorization boundary.
