# Maintenance Playbooks

This directory is for operator-triggered maintenance actions that are useful to
automate but should not run as part of normal desired-state convergence.

Maintenance playbooks differ from migrations:

- migrations are one-time changes from an old live state to a new live state
- maintenance playbooks are repeatable operational procedures run only on demand

## Appropriate Maintenance Actions

Use this directory for actions such as:

- OS update orchestration
- reboot checks and controlled reboots
- backup verification
- restore validation
- service drain or uncordon workflows
- health checks that need elevated privileges
- emergency disable or quarantine operations

Do not put normal role tasks here. If a task can safely run every day to describe
the desired state, it belongs in a role or normal playbook.

## Safety Rules

Maintenance playbooks should:

- require explicit operator invocation
- support `--limit` for targeted runs
- use clear play names and task names
- prefer read-only checks before changing state
- validate outcomes before reporting success
- avoid hidden destructive defaults

## Running a Maintenance Playbook

Example:

```bash
source ../platform-private/config/homelab.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/maintenance/example.yml --limit target-host-or-group
```

Replace `example.yml` with a real maintenance playbook when one is added.

Do not import maintenance playbooks from `playbooks/site.yml`.

Available maintenance playbooks:

- `openbao-bootstrap-start.yml`: requires exact pristine staged state, a
  private readiness gate, full-cluster limit, canonical member DNS resolution,
  and unchanged two-pass evidence before starting three uninitialized sealed
  processes without boot enablement. It writes only non-secret pending markers;
  Shamir shares and the initial root token never enter Ansible. Start or marker
  publication failure stops and remasks every reachable member and removes any
  partial pending markers.
- `openbao-audit-migrate.yml`: one-time, resumable migration for a pending
  cluster created before declarative auditing. It requires a full-cluster limit,
  a private readiness gate attesting that an approved root session found no
  API-created audit devices, and unchanged pending evidence. Check mode performs
  the read-only preflight; normal mode validates and installs `audit.hcl`, sends
  `SIGHUP` without a restart, verifies both audit files and direct-node health,
  and binds the audit checksum into each pending marker. It never accepts an
  OpenBao token or prompts after the operator invokes normal mode.
- `openbao-bootstrap-complete.yml`: after the two-custodian five-share,
  threshold-three ceremony, verifies unchanged pending evidence, two
  declarative file audit devices, and strict stable three-voter state before
  publishing active markers and generated boot enablement. Its readiness gate
  authorizes normal mode; check mode performs authenticated read-only
  qualification and skips all publication. It never prompts, initializes, or
  unseals OpenBao.
- `openbao-haproxy-activate.yml`: requires exact active OpenBao markers and
  strict status, binds exact staged package/configuration/CA/firewall evidence
  to TTY approval, requires inactive Keepalived and active firewalld, and checks
  routing through every node-local HAProxy. Failure rolls back only reachable
  HAProxy services and reports unreachable hosts as unverified.
- `openbao-status.yml`: performs strict controller-side direct-node TLS health
  and authenticated Raft and audit checks for the three-node OpenBao cluster,
  including exact agreement between all active markers and runtime cluster ID.
  It requires an outside-Git read-only token, does not follow token-bearing
  redirects, and never initializes, unseals, restarts, or reconfigures OpenBao.
  HAProxy, VIP, and firewall connectivity remain separate acceptance gates.
- `openbao-registry-remaps.yml`: applies only `podman_registry_remaps` after
  requiring an exact explicit three-host limit and validating each host's
  observed active lifecycle plus cross-host cluster identity. It changes no
  Podman package, storage, socket, kernel, or OpenBao service state and is not
  imported by `site.yml`.
- `openbao-rolling-restart.yml`: explicitly invoked post-initialization
  convergence. It requires exact active lifecycle, unchanged image and PKI,
  absent host-local transactions, all three hosts, and a strict healthy baseline.
  It queues current standbys before the active node, uses `serial: 1`, snapshots
  marker-bound files in a root-only transaction directory, and aborts on
  leadership drift. After an actual restart it emits the voter identity for the
  external two-custodian unseal and boundedly polls only direct TLS health. Strict
  recovery precedes deterministic marker refresh, active lifecycle revalidation,
  and per-voter transaction removal. A failure before a voter's revalidation
  retains that voter's transaction and stops before the next voter. After a voter
  is independently recovered and exact, its transaction is removed to avoid
  retaining root-only TLS key copies; later failures do not recreate prior voter
  snapshots. There is no automatic rollback or stale cleanup. The playbook never
  initializes or unseals OpenBao and is not imported by `site.yml`. Its explicit
  privileged caller-selected active-maintenance mode is reserved for this fixed
  playbook, always reruns strict active preflight, and is not a general PKI or
  custody mode. It cannot change listener selection, CA, certificate, key, or
  lifecycle active/rollback records.
- `openbao-active-check.yml`: requires an explicit exact three-host limit, active
  lifecycle and strict status, then runs the OpenBao role only in Ansible check
  mode. It applies the same unchanged-image and PKI guard and never enters rolling
  maintenance. Its privileged caller-selected active-maintenance mode is reserved
  for this fixed playbook, always reruns strict active preflight, and is not a
  general PKI or custody mode. Ordinary `openbao.yml` explicitly rejects that
  mode.
- `storage-volume-test.yml`: exercises one isolated disposable storage fixture
  through the supported `scripts/storage-volume-test` boundary. It requires an
  exact host, stable by-id/by-path disk, strict SSH, and playbook-owned
  controller-side TTY approvals for initialization and reboot before connection
  policy evaluation. The helper passes no approval variable, so direct playbook
  invocation cannot bypass the prompt.
  It also requires fail-closed pristine/final verification.
  It provides no cleanup path; recreate the fixture VM on partial or ambiguous
  state. See [Storage Volume Acceptance Fixture](../../docs/storage-volume-test.md).
- `monitoring-etcd-bootstrap-preflight.yml`: performs the strictly read-only
  all-three-node pristine-storage, staged-artifact, runtime-absence, image,
  firewall, SELinux, and cross-host identity gate for the dedicated Patroni etcd
  cluster. Passing it does not authorize startup.
- `monitoring-etcd-bootstrap.yml`: reruns that preflight around an exact
  controller-side TTY approval, temporarily starts all three members, requires
  two stable direct-node mTLS health observations, then stops every member before
  atomically publishing root-only completion evidence. It never enables etcd or
  removes data. Failed or partial bootstrap state requires diagnosis rather than
  an automatic retry.
- `monitoring-etcd-activate.yml`: requires three consistent bootstrap markers,
  exact TTY approval, immediate revalidation, stable health, and exact generated
  boot enablement. Failed transitions restore the inactive Quadlet and stop all
  reachable members without changing markers or data.
- `monitoring-etcd-status.yml`: strictly checks active marker, bundle, Quadlet,
  service, container, membership, leadership, and endpoint health state. It is
  read-only and does not require activation authorization.
