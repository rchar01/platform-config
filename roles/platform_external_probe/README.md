# platform_external_probe

Contributes strict, detect-only HTTPS probes, a read-only PostgreSQL primary
probe, and node-local VIP ownership metrics to the one Grafana Alloy process on
an observer VM. The role is disabled by default. It never installs, starts,
reloads, or independently configures Alloy, and probe results never repair,
promote, fence, or change Keepalived eligibility.

The owning playbook must include this role before `grafana_alloy`, then pass
`platform_external_probe_alloy_fragment` as
`grafana_alloy_feature_config`. The Alloy process role validates the complete
candidate before replacing `/etc/alloy/config.alloy`.

Example staged composition:

```yaml
- name: Build strict external probe contribution
  ansible.builtin.include_role:
    name: platform_external_probe

- name: Own the single Alloy process and complete configuration
  ansible.builtin.include_role:
    name: grafana_alloy
  vars:
    grafana_alloy_feature_config: "{{ platform_external_probe_alloy_fragment }}"
```

Both roles and their service/timer controls remain disabled by default. The
private inventory must explicitly configure the output, TLS files, targets, and
activation state.

Disabling this role stops the previously managed ownership timer and PostgreSQL
timer/collector, then removes their last metrics files. Keeping the PostgreSQL
probe staged with its timer stopped also removes its evidence. Disabling the
native Alloy owner similarly stops Alloy only
when its platform-managed systemd drop-in and the exact native RPM unit prove
prior ownership, then removes that drop-in and reloads systemd. A Quadlet owner
that has superseded the native unit is not stopped or overridden. Remove
ownership collection in a converged disabled state before deleting its inventory
contract.

Every HTTPS target requires:

- a unique safe name and service label;
- an `https://` address with a DNS/IPv4-style authority, optional numeric port
  from `1` through `65535`, and an optional unencoded safe path;
- no credentials, query, fragment, whitespace, control characters, IPv6 literal,
  or percent-encoded path;
- separate `dns`, `vip`, or `direct` address-mode identity;
- matching strict TLS `server_name` and HTTP `Host` values;
- an absolute CA path and optional complete client-certificate/key pair;
- explicit accepted status codes; and
- positive and negative body regular expressions.

Monitoring HTTP targets may instead select one role-owned semantic `profile`:

| Profile | Required service and path | Success policy |
| --- | --- | --- |
| `grafana_health` | `grafana`, `/api/health` | HTTP `200`, database `ok`, exact Grafana `13.1.3` version |
| `loki_ready` | `loki`, `/ready` | HTTP `200`, complete body matching `ready` for Loki `3.7.6` |
| `mimir_ready` | `mimir`, `/ready` | HTTP `200`, complete body matching `ready` for Mimir `3.1.4` |

Profile targets still provide the private address, address mode, CA, SNI/Host,
and optional client identity, but omit caller-supplied status and body policy.
Validation rejects unknown profiles, service/path mismatches, and attempts to
override the locked policy. Generic targets remain available for strict services
such as OpenBao whose explicit policy is supplied by the owning playbook.

The embedded Alloy `1.18.1` blackbox exporter supports regular-expression body
checks, not semantic JSON parsing. For OpenBao, exact HTTP `200` plus required
`initialized`, `sealed`, and `standby` predicates provides the planned active-node
signal, but malformed JSON with matching text remains a documented limitation.
The same limitation applies to Grafana: its profile requires the locked version
and database `ok` snippets, but does not structurally parse the response as JSON.

The optional PostgreSQL primary probe is not an HTTP profile. A hardened
five-second oneshot uses a PostgreSQL 18 `psql` client to connect through the
production VIP DNS name on port `5432` with `verify-full`, GSS encryption
disabled, a required client certificate, and no PostgreSQL authentication
challenge. It runs only:

```sql
SELECT NOT pg_catalog.pg_is_in_recovery();
```

The session sets `default_transaction_read_only=on`, clears `search_path`, uses
a four-second process/connect timeout and three-second statement timeout, and
accepts only exact `t` or `f` output. Exact `t` publishes primary and query
success as `1`; exact `f` publishes primary `0` and query success `1`; connection,
TLS, authentication, timeout, and malformed-output failures publish both as `0`
when the collector can complete publication. Every result includes an
observation timestamp. The oneshot removes prior evidence before execution, so
hard collector or publication failure cannot preserve a stale success sample.

Private deployment must supply a dedicated certificate-authenticated PostgreSQL
`LOGIN` role and database with only `CONNECT`, plus a `hostssl` `cert` HBA rule
that maps the observer certificate to that exact role. The role must have no
schema/object privileges and cannot inherit them. `require_auth=none` rejects
password and other PostgreSQL authentication challenges while permitting TLS
client-certificate authentication; `sslcertmode=require` requires the client
certificate. The host package owner supplies exact PostgreSQL 18 `psql`, and
outside-Git inputs supply the CA, client certificate, and unencrypted restricted
client key. This Ansible role only validates and references those inputs; it does
not install packages, create database roles, configure HBA, or install TLS files.

```yaml
platform_external_probe_postgresql_primary:
  name: postgresql_primary
  service: postgresql
  address_mode: vip
  host: postgres.monitoring.example.invalid
  port: 5432
  database: observer
  user: monitoring_probe
  ca_file: /etc/platform-pki/postgresql-ca.crt
  client_cert_file: /run/platform-secrets/postgresql-probe.crt
  client_key_file: /run/platform-secrets/postgresql-probe.key
```

The PostgreSQL timer remains disabled until the production endpoint, dedicated
identity, Alloy remote write, and deployed observer gates pass. This read-only
signal proves only that the VIP endpoint reached a non-recovery PostgreSQL
server. It does not prove write durability, synchronous-replica health, Patroni
leadership, acknowledged-write preservation, promotion timing, or fencing.

VIP ownership is observed from exact kernel address presence on the configured
interface. A hardened oneshot/timer writes fresh timestamped Prometheus textfile
metrics atomically. Keepalived service state is supporting evidence only. Leave
the timer disabled until Alloy remote write and observer acceptance gates pass.
Unexpected collector failures remove the previous textfile so stale ownership is
not presented as current evidence; consumers must still require a fresh
observation timestamp.

Each VIP ownership entry requires an `endpoint` that names exactly one configured
`address_mode: vip` probe target with the same service and literal VIP address:

```yaml
platform_external_probe_vip_ownership:
  - service: monitoring
    endpoint: monitoring_vip
    instance: MONITORING
    interface: eth0
    vip: 192.0.2.200
```

Blackbox samples expose stable `observer`, `environment`, `service`, `endpoint`,
and `address_mode` labels. PostgreSQL primary metrics use the same bounded
identity labels. Every ownership metric exposes `service`, `node`,
`environment`, `endpoint`, `instance`, `interface`, and literal `vip` labels so
consumers can correlate endpoint results with exact node-local ownership. Keep
these values bounded and stable; do not put URLs, credentials, or dynamic error
details in labels.

Real endpoints and policy belong in `platform-private/config`; CA, client-key,
token, and other credential files remain outside Git. This role only references
their installed absolute paths.
