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
make test-shell
make test-python
make test-keepalived-vip-rocky
make test-podman-host-rocky
make test-platform-external-probe-alloy
make test-openbao-haproxy-rocky
make test-monitoring-haproxy-capabilities
make test-monitoring-etcd-image
make test-monitoring-etcd-cluster
make test-openbao-image
make test-openbao-rocky
```

`ansible-lint`, `yamllint`, and `make test` are development checks. They are not required on managed hosts. These Make targets use the development image through a sanitized test profile: the public repository is mounted read-only at `/workspace`, invocation-local writable state is overlaid at `/workspace/.ansible`, and private configuration, SSH files, the external secret store, the SSH agent, and the Podman socket are not exposed. Their configuration excludes `.ansible/` and the vendored bastion runtime.

`make check-dev-toolchain` reports the Python, pytest, Ansible, lint, shell, crypto, and GNU utility versions used by tests and runs `python -m pip check`. `make check-test-container-profile` verifies the sanitized mount, identity, cache, executable-scratch, and secret-isolation contract. `make check-container-wrapper` verifies success, failure, SIGINT/SIGTERM interruption status, and temporary-state cleanup. All three checks are included in `make verify`.

During the Python migration, `make test` remains the authoritative legacy shell
suite and `make test-shell` is its explicit coexistence alias. `make test-python`
runs the pytest harness plus migrated scenarios through the same sanitized test
container profile; `make verify` runs both suites.
A legacy scenario remains in `tests/run-all.sh` until its case-level mapping,
positive and negative behavior, failure diagnostics, and no-mutation behavior
have passed beside the Python replacement on the same source revision.

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

`make test-platform-external-probe-alloy` downloads the official Alloy `1.18.0`
AMD64 RPM and converges both staged roles in a disposable Rocky systemd
container. It verifies SHA-256 and exact package identity, disabled service/timer
lifecycle, native complete-config validation and candidate preservation,
idempotency, exact kernel VIP ownership metrics, and runtime blackbox results
against controlled strict TLS, redirect, status, body, and client-certificate
fixtures.

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
outside the dev container and remain opt-in.

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
