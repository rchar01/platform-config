# Monitoring HAProxy

Validation and offline-rendering foundation for the replacement monitoring
HAProxy policy.

The role is disabled by default. In this slice, setting
`monitoring_haproxy_enabled: true` validates the locked frontend contract but
does not install packages, write rendered files, manage SELinux or firewalld, or
touch a service. Reviewable HAProxy and identity-map templates are exercised
only by isolated test fixtures. `monitoring_haproxy_service_enabled` must remain `false` and
`monitoring_haproxy_service_state` must remain `stopped`.

Validated inputs include:

- exact HAProxy NEVRA and fixed HTTPS/PostgreSQL client ports;
- three unique HAProxy-owned listener ports and exact private backend definitions
  for Grafana, Loki, Mimir, integrated Alertmanager, S3, and PostgreSQL;
- exactly three uniquely named IPv4 targets and lowercase FQDN TLS server
  identities per TLS backend, except Garage S3's one node-local
  `127.0.0.1` plaintext target;
- role-owned status-only health policy: Grafana `GET /api/health`, Loki/Mimir
  and integrated Alertmanager `GET /ready`, Garage Admin `GET /health` on a
  separate loopback port, and Patroni `HEAD /primary` on a separate HTTPS port;
- no backend collision with an HAProxy-owned listener, with integrated
  Alertmanager required to share Mimir's exact port and target topology and no
  unrelated services sharing backend ports;
- unique service DNS names and restricted metrics binding;
- outside-Git frontend/client/backend TLS source paths;
- exact escape-free RFC2253 subject-DN role mappings;
- observed literal Loki, Mimir, and Alertmanager method/path routes plus
  service-qualified operator routes;
- a mandatory least-privilege `monitoring_probe` identity with host-scoped
  `GET /api/health` for Grafana and `GET /ready` for Loki and Mimir;
- a separate `monitoring_s3_probe` identity limited to `DELETE`, `GET`, and
  `PUT` on the S3 hostname, with Garage credentials retaining bucket/object
  authorization;
- a dedicated management-source allowlist for operator routes;
- unique, network-normalized `/24`-or-narrower source CIDRs, with operator
  sources contained by the outer HTTPS policy; and
- an explicit contract-readiness gate.

Package repository immutability, target-side TLS installation, configuration
deployment, lifecycle management, and target activation remain blocked. Backend
service/health ports, addresses, names, and TLS identities have no public
defaults and must come from private inventory. Real PKI stays outside Git and is
produced through `platform-tools`; the role never generates production
certificates.

Subject DNs must be unique. Multiple explicitly listed identities may map to the
same least-privilege role, including individual collectors, browser users, and
operators. Membership is an exact identity allowlist; role-name uniqueness is
not an authorization boundary.
