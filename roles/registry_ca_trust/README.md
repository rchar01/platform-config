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
trust so a prior refresh failure is retried, but report changed only when the
anchor installation changed.
