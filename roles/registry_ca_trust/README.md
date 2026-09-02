# registry_ca_trust

Installs a digest-pinned reviewed registry CA into the Rocky Linux system trust
store. The role is disabled when `registry_ca_trust_source` and
`registry_ca_trust_sha256` are empty.

```yaml
registry_ca_trust_source: /absolute/reviewed/registry-ca.pem
registry_ca_trust_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The source is pinned on the controller by `platform_pki_reviewed_ca`; CA bytes
are installed as `root:root` mode `0644`. Enabled applies always refresh system
trust when the anchor changes. A pending marker survives refresh failure so the
next apply retries the refresh and reports the recovered trust change. The role
records that pending state before changing the anchor and clears it only after a
successful install and any required refresh.

Consumers that must restart after a trust change may set
`registry_ca_trust_defer_marker_clear: true`, retain the marker through their
health checks, and remove it only after convergence. The RKE2 dependency uses
this mode so a failure before restart or readiness remains recoverable.

The RKE2 role includes this role as an optional dependency. A reviewed public CA
may be tracked in private inventory under
`config/files/registry/<environment>/ca-bundle.crt` and referenced through
`registry_ca_trust_source`. Empty source and digest values preserve the no-op
default. In no-op mode the role does not inspect or verify preinstalled trust;
another managed baseline must guarantee trust on every current and replacement
node. This registry-wide source convention can serve other managed registry
clients. When trust changes on a started RKE2 node, the existing RKE2 restart
and readiness path applies the new system trust.
