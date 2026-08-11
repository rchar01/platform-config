# platform_external_probe

Contributes strict, detect-only HTTPS probes and node-local VIP ownership metrics
to the one Grafana Alloy process on an observer VM. The role is disabled by
default. It never installs, starts, reloads, or independently configures Alloy,
and probe results never repair, promote, fence, or change Keepalived eligibility.

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

Disabling this role stops a previously managed ownership timer and removes its
last metrics file. Disabling the native Alloy owner similarly stops Alloy only
when its platform-managed systemd drop-in and the exact native RPM unit prove
prior ownership, then removes that drop-in and reloads systemd. A Quadlet owner
that has superseded the native unit is not stopped or overridden. Remove
ownership collection in a converged disabled state before deleting its inventory
contract.

Every HTTPS target requires:

- a unique safe name and service label;
- an `https://` address without embedded credentials;
- separate `dns`, `vip`, or `direct` address-mode identity;
- matching strict TLS `server_name` and HTTP `Host` values;
- an absolute CA path and optional complete client-certificate/key pair;
- explicit accepted status codes; and
- positive and negative body regular expressions.

The embedded Alloy `1.18.1` blackbox exporter supports regular-expression body
checks, not semantic JSON parsing. For OpenBao, exact HTTP `200` plus required
`initialized`, `sealed`, and `standby` predicates provides the planned active-node
signal, but malformed JSON with matching text remains a documented limitation.

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
and `address_mode` labels. Every ownership metric exposes `service`, `node`,
`environment`, `endpoint`, `instance`, `interface`, and literal `vip` labels so
consumers can correlate endpoint results with exact node-local ownership. Keep
these values bounded and stable; do not put URLs, credentials, or dynamic error
details in labels.

Real endpoints and policy belong in `platform-private/config`; CA, client-key,
token, and other credential files remain outside Git. This role only references
their installed absolute paths.
