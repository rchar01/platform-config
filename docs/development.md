# Development

Use the Podman development container for Ansible and lint tooling. This keeps
Python packages, Ansible collections, and linters out of the host environment.

```bash
make deps
make shell
```

The repository Makefile wraps the container and common Ansible operations:

```bash
make help
make syntax ENV=dev
make verify
```

Required local tools:

- Podman on the workstation or CI runner
- Git and Make
- Ansible from `requirements-dev.txt`, installed inside `Containerfile.dev`
- pytest and direct test dependencies from `requirements-test.txt`, installed inside `Containerfile.dev`
- Ansible Galaxy collections from `requirements.yml`, installed inside `Containerfile.dev`
- Git when using `vendor/platform-k8s-bastion` as a submodule

Useful checks:

```bash
make inventory ENV=dev
make syntax ENV=dev
make syntax ENV=dev PLAYBOOK=playbooks/k8s-bastion-access.yml
make lint
make yamllint
make check-dev-toolchain
make check-test-container-profile
make check-container-wrapper
make test
make test-parallel
make verify-parallel
make test-keepalived-vip-rocky
make test-podman-host-rocky
make test-platform-external-probe-alloy
make test-openbao-haproxy-rocky
make test-monitoring-haproxy-capabilities
make test-monitoring-artifact-identities
make test-monitoring-etcd-image
make test-monitoring-etcd-cluster
make test-monitoring-garage-cluster
make test-monitoring-garage-loki
make test-monitoring-garage-loki-cluster
make test-monitoring-garage-mimir
make test-monitoring-grafana-postgresql
make test-openbao-image
make test-openbao-rocky
```

`ansible-lint`, `yamllint`, and `make test` are development checks. They are not required on managed hosts. These Make targets use the development image through a sanitized test profile: the public repository is mounted read-only at `/workspace`, invocation-local writable state is overlaid at `/workspace/.ansible`, and private configuration, SSH files, the external secret store, the SSH agent, and the Podman socket are not exposed. Their configuration excludes `.ansible/` and the vendored bastion runtime.

`make check-dev-toolchain` reports the Python, pytest, Ansible, lint, shell, crypto, and GNU utility versions used by tests and runs `python -m pip check`. `make check-test-container-profile` verifies the sanitized mount, identity, cache, executable-scratch, and secret-isolation contract. `make check-container-wrapper` verifies success, failure, SIGINT/SIGTERM interruption status, and temporary-state cleanup. All three checks are included in `make verify`.

`make test` runs the complete authoritative pytest suite serially. PKI helper
tests feature-probe `unshare -Ur` and fail when effective namespace root is
unavailable instead of silently skipping required coverage. `make test-parallel`
runs tests not marked `serial` with `TEST_WORKERS=2` by default, then runs the
timing-sensitive child-process tests serially. The two selections are disjoint
and together cover the same collected tests as `make test`. For faster local
feedback, `make verify-parallel` runs the same toolchain, container-boundary,
wrapper, lint, and YAML checks as `make verify`, but uses `make test-parallel`.
It is supplemental; run serial `make verify` as the authoritative merge check.

Run `make deps` after changing `Containerfile.dev`, `requirements-dev.txt`, `requirements-test.txt`, or `requirements.yml`. The generic container wrapper builds only when the local image is absent; it does not detect a stale existing image.

`make test-keepalived-vip-rocky` is an opt-in integration check outside
`make verify`. It downloads packages, starts a rootless disposable Rocky 10.1
systemd container with `NET_ADMIN` for a dummy interface, keeps Keepalived stopped,
and verifies role convergence, candidate rejection, and stale peer-rule removal.

`make test-podman-host-rocky` is also opt-in. It installs the exact approved
Podman package in a privileged disposable Rocky 10.1 systemd container, verifies
check-mode non-mutation, keeps the API socket disabled, exercises native Quadlet
generation without starting the generated service, and requires idempotency.

`make test-openbao-image` is also opt-in. It pulls the exact approved OpenBao
`2.6.1` `linux/amd64` manifest, verifies its version and non-root identity, and
runs the generated native configuration validator against valid and invalid
rendered HCL without starting a server.

`make test-openbao-rocky` installs Podman in a privileged disposable Rocky 10.1
systemd container, stages the role with its service disabled, verifies check
mode, idempotency, mount rejection, and atomic candidate preservation, then
explicitly starts an uninitialized node, requires TLS health status `501`, and
returns it to an idempotent disabled state without initialization side effects.
The deactivation path also removes seeded persistent systemd enablement and
proves a failed pre-Quadlet staging attempt remains masked across daemon reload.

`make test-platform-external-probe-alloy` downloads the official Alloy `1.18.1`
AMD64 RPM and converges both staged roles in a disposable Rocky systemd
container. It verifies SHA-256 and exact package identity, disabled service/timer
lifecycle, native complete-config validation and candidate preservation,
idempotency, exact kernel VIP ownership metrics, and runtime blackbox results
against controlled strict TLS, redirect, status, body, and client-certificate
fixtures.

`make test-monitoring-artifact-identities` is a Phase 0 identity check for the
exact Garage, Loki, Mimir, and Grafana image candidates recorded in
`tests/fixtures/monitoring-artifacts/candidates.json`. It resolves each mutable
qualification tag from one registry response, verifies the locked index and
Linux/AMD64 manifest digests, pulls through the immutable index reference, and
checks platform, configured user, entrypoint, command, and native version output
under a read-only, capability-free container. The same lock records Alloy's
exact RPM identity and distinguishes normally stabilized candidates from recent
patches selected for focused qualification under the security-update policy. This
target proves artifact identity only; it does not prove Garage S3 semantics,
Loki/Mimir/Grafana compatibility, signatures, provenance, or production
readiness.

`make test-monitoring-garage-cluster` forms an invocation-local Garage `2.3.0`
cluster from the locked immutable image. It runs three explicit non-root,
read-only-root containers in distinct zones, commits one RF=3 consistent layout,
and uses real AWS Signature Version 4 requests to verify object operations,
query signing, ranges, wrong-secret rejection, and denied cross-bucket read,
write, and delete behavior without side effects. It then requires read/write
continuity with one node stopped, a `503` without quorum plus post-recovery object
absence, and full three-node health after restart. This disposable lane does not
prove Loki/Mimir compatibility, HAProxy TLS forwarding, data-volume replacement,
partition behavior, disk-full or corruption recovery, backup/restore, or
production capacity.

`make test-monitoring-garage-loki` extends that exact RF=3 lane with Loki
`3.7.6` in isolated single-process `target=all` mode. It sends a native log
canary, queries it, flushes TSDB data to a dedicated Garage bucket, then starts
Loki with empty local state and requires the canary to remain queryable from
Garage-backed storage. Cross-bucket denied writes in both credential directions
must remain absent. The harness-only settings disable Loki tenancy, use one
in-memory ring member, and use plaintext S3 on the invocation-local network;
they are not deployment defaults and do not prove the planned three-node Loki
ring, retention, compaction, or failure behavior.

`make test-monitoring-garage-loki-cluster` is a separate opt-in extension of
the same Garage bootstrap. It runs the locked Loki `3.7.6` index digest
`sha256:efd47c67f9bac88ca29bcf8cb997d9ab29d1848bd0aff579282295542a745952`
as three hardened `target=all` containers with stable identities and distinct
persistent WAL, token, and compactor paths. The check requires all three
`/ready` endpoints, exact member names from the JSON memberlist response, and
three active ingester, scheduler, ruler, and compactor ring members from
metrics. It also requires exactly one process to report the stable active
compactor metric. A canary written to one node must be queryable through
another; after a retained-state node is stopped and both survivors report it
unhealthy, a second write must succeed and both canaries must remain queryable
through the other survivor. Restarting the same
container must preserve its token hashes, rejoin without a manual memberlist
operation, restore all readiness and ring evidence, and query both canaries.
The fixture uses separate expired and retained streams, a 24-hour retention
period, and short compactor, deletion, and index-resynchronization intervals. It
requires a compactor-produced TSDB index, successful compaction, retention-marker
and sweeper metrics, and a reduced Garage chunk count while both current
canaries remain queryable. The lane then restarts all three members with empty
local state and requires both retained canaries to recover from Garage while the
expired canary remains absent. Disabled tenancy, plaintext internal S3, short
failure-detection and lifecycle timing, local ruler storage, and the isolated
bridge are harness-only settings, not deployment defaults. The lane does not
prove production retention periods, TLS or authentication, partitions,
replacement, capacity, backup/restore, disk-full, or corruption behavior.

`make test-monitoring-garage-mimir` extends the RF=3 lane with three hardened
Mimir `3.1.4` `target=all` containers using stable memberlist identities,
distinct zones and local state, and replication factor three for the ingester,
store-gateway, and integrated Alertmanager rings. A dependency-free Prometheus
remote-write client sends one canary under full health and another while one
member is stopped; cross-node queries must return both. The stopped container
must retain its ingester and store-gateway token hashes, rejoin all six checked
rings, and query both canaries after restart. The lane also requires ruler alert
delivery, replicated mutable Alertmanager silence state, complete TSDB block
objects covering the node-loss write, and recovery of both canaries, ruler and
Alertmanager configuration, the silence, and the alert after all three local
state directories are erased. A separate canary initially nine minutes old must
first produce a complete block under a fixture-only 10-minute retention policy.
The lane requires a successful multi-block compaction event, a retention mark
whose block and `maxTime` match that canary, a positive block-cleaner metric, an
exact-ULID physical deletion event, and absence of both the block-local and
global-marker Garage objects. Current samples must remain queryable, and the
fresh-state restart must recover them without recovering the expired sample.
Separate least-privilege Garage credentials and buckets isolate blocks, ruler,
and Alertmanager storage and all cross-bucket writes must remain denied and
absent. Disabled tenancy, short synchronization, deletion, retention, and
failure-detection intervals, and plaintext S3 on an invocation-local bridge are
harness-only settings, not deployment defaults. The lane does not prove
production retention periods, concurrent-writer conditional semantics,
partitions, replacement, capacity, backup/restore, disk-full, or corruption
behavior.

`make test-monitoring-grafana-postgresql` runs a three-member qualification with
the locked Grafana `13.1.3` image against the locally qualified Linux/AMD64
PostgreSQL `18.4` and Patroni `4.1.4` candidate digest from the sibling
`postgres-patroni` repository. It first starts a separate process that must
reject an untrusted PostgreSQL CA, then starts all three Grafana members against
one empty database and requires exactly 713 unique successful migrations with
no failed migration. The lane
deliberately holds Grafana's PostgreSQL advisory migration lock and requires a
restarted contender's structured log to report lock acquisition failure. It
then releases the lock under a bounded 20-attempt `on-failure` restart policy
and requires duplicate-free migrations before all three processes become
healthy. The lane creates a dashboard through Grafana's HTTP API, requires it
from every member, proves two-member continuity while one Grafana process is
stopped, and then recovers that member. It also recreates one Grafana process
with empty local state, disconnects PostgreSQL from the application network,
observes database degradation, reconnects PostgreSQL, and requires all three
Grafana processes and the dashboard to recover. The invocation-local bridge
and PKI, single PostgreSQL member, direct application ports, generated
credentials, and short timeouts are harness-only settings. The lane pulls the
immutable Grafana and etcd references and requires
`localhost/postgres-patroni:dev` at the recorded candidate digest; build the
PostgreSQL image in `../postgres-patroni` first. It does not prove PostgreSQL HA
failover or process restart, HAProxy/VIP behavior, production PKI,
backup/restore, capacity, or managed-host deployment.

`make test-openbao-haproxy-rocky` installs the approved exact HAProxy `3.0`
package in a disposable Rocky systemd container. It verifies check mode, exact
package downgrade, atomic candidate preservation, staged/active/disabled
lifecycle, reconciled firewall policy, strict active-only TLS backend selection
and switch, hostname rejection, and restricted built-in metrics.

`make test-monitoring-haproxy-capabilities` is a Phase 0 mechanism check, not a
production role test. It installs exact HAProxy `3.0.5` in a disposable Rocky
container and uses synthetic, invocation-local certificates and services to
exercise global frontend mTLS, CRL rejection, exact RFC2253 subject-DN maps,
method/path separation, Grafana host/method policy, representative SigV4 input
preservation, tenant-header replacement, backend mTLS plus CA/SNI/name
verification, raw PostgreSQL TCP selected by a separate Patroni HTTPS `/primary`
check, restricted metrics, and native candidate rejection. The initial contract
forces HTTP/1.1;
private ports and observed Loki/Mimir/Alertmanager route allowlists remain
unresolved production inputs. Fixture PKI does not replace `platform-tools`:
real CA state and issued service material stay outside Git and use the maintained
`platform-tools` workflows.

`make test-monitoring-etcd-image` is also a Phase 0 qualification check. It
resolves the official etcd `3.6.14` multi-platform index and `linux/amd64`
manifest from one registry response, then pulls the selected platform through
the immutable index reference and rejects malformed configuration. It runs one
disposable member as explicit UID/GID `10001`, with no capabilities and a
read-only root filesystem, before checking liveness, readiness, legacy health,
and an invocation-local write/read. The official image declares root as its
default user, so future Quadlets must retain the tested explicit override.

`make test-monitoring-etcd-cluster` extends that local-only evidence with three
independently persisted members on an internal Podman network and invocation-local
synthetic PKI. It requires peer and client mTLS, rejects a client without a
certificate, verifies three voters and one leader, proves writes continue after
leader loss, confirms the restarted member reuses its data directory and catches
up acknowledged data, and requires that no write is acknowledged while two
members are stopped. A timed-out proposal may still commit after quorum returns.
The check does not qualify snapshots, member replacement, real PKI, target
networking, or Patroni behavior.

`make verify` also exercises synthetic strict OpenBao health and Raft status
predicates. The fixtures require one active node, two standbys, three voters,
one matching leader, and stable repeated observations while rejecting sealed,
split-cluster, non-voter, leader-mismatch, and changing-index states. These
fixtures do not replace live initialized-cluster qualification.

The default suite also checks the maintenance-only OpenBao rolling contract:
explicit confirmation, full-cluster selection, standby-first inventory order,
`serial: 1`, leadership-drift aborts, conditional manual-unseal pauses, and
strict voter recovery before advancing. The disposable Rocky test separately
proves that unchanged active convergence reports no restart requirement.

The OpenBao staging scenario uses shadow roles to prove exact firewalld, Podman,
OpenBao, HAProxy, and Keepalived order. It rejects malformed or partially selected
clusters, an unready ownership contract, invalid component configuration, and
any requested service activation before a role can mutate a host. It does not
exercise real packages or services.

Operational and interactive dev-container commands mount this repository writable at `/workspace`. If
`../platform-private` exists next to the repository, it is mounted read-only at
`/platform-private` so the default relative private paths still work from
`/workspace`. If `~/.config/platform-infrastructure` exists, it is mounted
read-only under the container home so env files that derive outside-Git secret
paths from `$HOME` continue to work.

Automated lint and default test targets use the sanitized profile described
above instead of these operational mounts. Host-Podman integration targets stay
outside the dev container, remain opt-in, and use the Bash drivers under
`tests/integration/`.

See [Operator Runbook](operator-runbook.md) for the full homelab and dev bring-up sequence.

## Managed Host Requirements

Managed hosts need:

- Linux with systemd
- Python 3 for Ansible execution
- SSH access for the Ansible user
- sudo or root privilege escalation
- outbound HTTPS access or a configured corporate proxy/mirror for external CLI downloads
- writable `/usr/local/bin`, `/usr/local/sbin`, `/usr/local/lib/bastion`, `/etc/bastion`, and `/etc/systemd/system`

The `k8s_bastion_access` role installs required OS packages where possible, including Podman and runtime support packages.
