# Monitoring HAProxy

Host-native lifecycle and policy enforcement for the replacement monitoring
HAProxy tier.

The role is disabled by default. When explicitly enabled and contract-ready, it
installs the exact approved HAProxy NEVRA, preserves unrelated entries in the
shared DNF versionlock list, copies outside-Git PKI, renders the policy, and
validates the complete candidate with HAProxy before publication. Configuration,
the identity map, and PKI are published as one content-addressed generation
under `/etc/haproxy/monitoring-bundles`; an atomic
`/etc/haproxy/monitoring-current` pointer selects the generation used by the
package-standard `/etc/haproxy/haproxy.cfg` symlink. A failed active reload
restores the prior generation pointer.

Every reused or newly published generation must contain exactly the seven
expected files. Before native validation or pointer selection, the role compares
SHA-256 digests with the controller PKI and final-path template rendering and
requires exact file ownership/modes, regular non-symlink files with one hard link,
and a root-owned `0750` generation directory. These checks also run in check mode
for existing generations. Drift rejects the generation without repairing its
contents or switching pointers; only a newly published invalid generation is
removed by the publication failure path. Exclude concurrent out-of-band bundle
edits: these observations are not a filesystem lock.

The role also adds required SELinux HTTP port labels and reconciles only its own
manifest-backed firewalld rich rules. Activation requires coherent `started` and
enabled service selectors plus live managed-firewall readiness. The default
`stopped` and disabled selectors support offline staging without starting
HAProxy.

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

Backend service/health ports, addresses, names, and TLS identities have no
public defaults and must come from private inventory. Real PKI stays outside Git
and is produced through `platform-tools`; the role never generates production
certificates. Enabling the role in a playbook and authorizing managed-host
activation remain separate rollout decisions.

The agreed [monitoring PKI direction](../../docs/pki-exchange-setup.md#monitoring-pki-direction)
will reuse OpenBao's host-local key custody and signed exchange model with
monitoring-specific profiles and adapters. This role still consumes controller
PKI source files; target-local issuance and bundle handoff are not implemented.
Any future handoff must preserve the seven-file integrity/atomic-selection
contract without exporting host keys or adding a competing active selector.
Loki and Mimir writers require distinct client identities; their certificates
do not replace HAProxy's frontend or backend TLS identities.

`playbooks/monitoring-haproxy.yml` is the focused three-node staging lane. It
requires all monitoring members, validates the role contracts, confirms that
controller PKI sources are safe regular files, stops any existing HAProxy, and
converges the new role with HAProxy still disabled and stopped. Package and
target-runtime failures can still leave an intentionally quiesced proxy for
operator inspection. The lane does not make `playbooks/monitoring.yml` a
successful combined-stack convergence path or activate the monitoring VIP.

Subject DNs must be unique. Multiple explicitly listed identities may map to the
same least-privilege role, including individual collectors, browser users, and
operators. Membership is an exact identity allowlist; role-name uniqueness is
not an authorization boundary.

Run `make test-monitoring-haproxy-capabilities` for rendered policy behavior and
`make test-monitoring-haproxy-rocky` for package, bundle, rollback, firewall,
service, check-mode, and idempotency coverage in disposable Rocky systemd.

The default-suite bundle regressions run the real Ansible bundle entry point in
an isolated root namespace, with synthetic PKI and native validation stubbed:

```bash
PLATFORM_CONFIG_CONTAINER_PROFILE=test ./scripts/in-container python -m pytest -n 0 -x --durations=10 \
  tests/python/test_monitoring_haproxy_bundle.py
```

They cover byte/metadata drift, missing/extra files, symlinks/hard links, pointer
preservation, idempotency, and check mode. Native PKI parsing and service behavior
remain covered by the separate disposable Rocky checks.
