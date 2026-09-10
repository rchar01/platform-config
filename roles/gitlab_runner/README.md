# GitLab Runner

This role registers one GitLab Runner and runs its manager as a rootful system
Podman Quadlet. The runner authentication token is read from an outside-Git file
on the control node. GitLab Runner generates `/etc/gitlab-runner/config.toml` on
the managed host; the role does not template or expose its token-bearing
contents.

The default executor is `shell`. Jobs then run inside the persistent manager
container, and the role keeps the Podman API socket disabled and unmounted.

## Docker Executor

The opt-in Docker executor uses Podman's Docker-compatible API to create
disposable build, helper, and service containers. The permanent manager receives
the rootful Podman socket; job containers do not.

```yaml
podman_host_socket_enabled: true

gitlab_runner_executor: docker
gitlab_runner_podman_socket_enabled: true
gitlab_runner_docker_image: >-
  docker.io/library/alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
gitlab_runner_docker_helper_image: >-
  registry.gitlab.com/gitlab-org/gitlab-runner/gitlab-runner-helper:x86_64-v18.11.3@sha256:571952e633d345c74af6458eda2948da99cf5315ce9017e1cab22a4c2226887c
gitlab_runner_docker_extra_hosts:
  - gitlab.example.invalid:192.0.2.10
```

Docker mode also enforces:

- a local Unix endpoint matching the manager-side socket path;
- digest-pinned default and helper images;
- a string pull policy of `always` (default) or `if-not-present`;
- `FF_NETWORK_PER_BUILD = true`;
- `privileged = false`; and
- container-only cache volumes with no host bind or socket mount.

`gitlab_runner_docker_extra_hosts` adds duplicate-free `hostname:IPv4`
mappings to every helper, build, and service container. Use it when static host
records are required because containers created through the Docker-compatible
API do not inherit the manager host's `/etc/hosts`.

The manager Quadlet adds:

```ini
Requires=podman.socket
After=podman.socket
RequiresMountsFor=/etc/gitlab-runner /var/lib/gitlab-runner /var/lib/containers
Volume=/run/podman/podman.sock:/run/podman/podman.sock
SecurityLabelDisable=true
```

The Podman storage mount is added to `RequiresMountsFor` only when the optional
`podman_host` storage contract is enabled.

The label exception applies only to the manager and is required for its Podman
API access under SELinux. The rootful API is host-root-equivalent if the manager
is compromised. Restrict this mode to protected runners serving trusted
projects. Never add the socket to `gitlab_runner_docker_volumes`; a read-only
Unix socket mount still permits mutating API calls.

GitLab documents `podman-plugins` as required when service containers need
network aliases. The qualified Rocky Linux 10.1 repositories do not currently
provide that package, so service aliases are outside this feature until an
approved package source is available. Use an `aardvark-dns` release newer than
`1.10.0`.

### Temporary Offline Preload

For an approved temporary offline-preload workflow targeting Podman `5.4.0`, a
dedicated protected runner serving only trusted projects may override private
inventory with:

```yaml
gitlab_runner_docker_pull_policy: if-not-present
```

Keep `always` for shared runners. `if-not-present` reuses local images without a
registry authorization check; restrict access to the runner and its image store.
Preload the reviewed job, helper, and any service images into the **rootful Podman
store used by the manager's API socket**, and verify local lookup of each exact
`repository@sha256:...` reference used by the jobs/configuration (including any
tag in the configured reference). A matching tag or an image in a controller's
or rootless user's store is insufficient. Preserve the reviewed digests and TLS
verification. A missing image still triggers a pull; this policy is not
`never` and does not itself make the runner network-independent.

For an existing runner, pause/drain jobs and take a root-only backup of
`/etc/gitlab-runner/config.toml` outside Git. Make a reviewed **in-place** edit of
the existing `[runners.docker]` pull policy to `"if-not-present"` (or the equivalent
one-element array `["if-not-present"]`), preserving the registration token and
all other settings. Match the private inventory declaration before convergence
and ensure the manager has loaded the reviewed configuration before resuming
jobs. If `allowed_pull_policies` is explicitly configured, review it to permit
the selected policy too; the role does not manage that optional field.
No force registration is needed when the complete managed contract already
matches; keep `gitlab_runner_force_register: false`. Changing inventory alone
still fails closed on registered-config drift. The role does not automatically
edit the registered pull policy. Restore `always` in both places
when the temporary exception ends.

[Self-bootstrap](../../docs/gitlab-runner-self-bootstrap.md) remains
`always`-only; its separate preflight rejects this override. This role validation
does not qualify live Runner image lookup or job execution on Podman `5.4.0`.

## Manager Concurrency

`gitlab_runner_concurrent` defaults to `1` and accepts only a positive integer
(for example, `gitlab_runner_concurrent: 3`); booleans and strings are rejected.
It manages the top-level `concurrent` job ceiling across the manager's runners,
not per-runner `limit` or `request_concurrency` (parallel job requests).
Choose capacity for the VM's CPU, memory, storage, and other busy services;
raising the ceiling does not reserve resources or establish safe job capacity.

The role reconciles this value after fresh/forced registration and on existing
matching registrations without force registration or a concurrency-only restart
notification. Runner 18.11.3 natively checks configuration for reload every three
seconds. Only the integer token is replaced atomically on the target, preserving
the authentication token, unknown TOML fields, comments, and line endings.
The file must be root-owned, mode `0600`, regular, single-link, and not a symlink;
target Python 3.11+ supplies `tomllib`. One unquoted positive decimal
`concurrent = N` assignment before the first table is required. Missing,
malformed, quoted-key, noncanonical numeric, or ambiguous multiline formatting
fails closed for reviewed target-local correction.

Concurrency drift uses the existing root-only backup, rollback, and deferred
cleanup transaction. Serialize applies and other configuration writers; the
pre-publication stat recheck detects observed replacement/token rotation but is
not a universal writer lock. Check mode predicts existing-file changes without
writing; fresh/forced check mode skips reconciliation of the not-yet-generated
configuration.

## Registration

The role registers only when `config.toml` is absent, unless
`gitlab_runner_force_register` is true. Forced registration stops the service,
creates a temporary root-only same-directory backup, deletes the complete local
configuration, and recreates the one declared registration. If registration
fails, the role restores the previous file and its prior active service state
before failing. An incomplete automatic restore retains the root-only
`.config.toml.ansible-*` recovery artifact. Use force only as a controlled
one-time migration with a separate operator rollback backup, then immediately
return it to false. Forced registration also requires a literal Ansible limit
equal to the one selected inventory hostname; broad or patterned limits fail
before the role reads the registration token or changes the host.

Rollback covers Runner-owned configuration, CA, Quadlet, service state, and the
Podman socket state captured before convergence. Successfully converged shared
Podman packages and `container_runtime_kernel` prerequisites intentionally
remain in place; they are host runtime prerequisites rather than Runner state.

The role reads only the non-secret managed contract from an existing
`config.toml`. It fails before changing the manager Quadlet when the file does
not contain exactly the one declared executor identity or when Docker host,
image, privilege, pull policy, extra hosts, volumes, or networking differ.
The role does not reconcile this drift automatically; its re-registration path
requires explicit force. A reviewed matching in-place policy edit is described
under [Temporary Offline Preload](#temporary-offline-preload). Tokens are neither
returned nor logged by this preflight.

Runner tags are server-side GitLab settings for pre-created runner
authentication tokens. `gitlab_runner_tags` documents intended tags but does not
change them during registration.

## Secrets

Keep runner tokens, SSH private keys, and kubeconfigs outside Git. Docker jobs
that deploy over SSH should receive protected, environment-scoped GitLab
file-type variables such as `SSH_PRIVATE_KEY` and `SSH_KNOWN_HOSTS`; do not use a
static runner volume.

## Key Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `gitlab_runner_executor` | `shell` | Selects the one registered executor |
| `gitlab_runner_concurrent` | `1` | Positive integer manager-wide concurrent job ceiling |
| `gitlab_runner_token_src` | empty | Outside-Git token file on the control node |
| `gitlab_runner_tls_ca_cert_sha256` | empty | Exact SHA-256 of the configured outside-Git CA file |
| `gitlab_runner_podman_socket_enabled` | `false` | Mounts the role-managed rootful Podman socket into the manager |
| `gitlab_runner_podman_socket_host_path` | `/run/podman/podman.sock` | Host socket path |
| `gitlab_runner_podman_socket_container_path` | `/run/podman/podman.sock` | Manager-side socket path |
| `gitlab_runner_docker_host` | manager socket Unix URL | Docker-compatible Podman endpoint |
| `gitlab_runner_docker_image` | empty | Required immutable default image in Docker mode |
| `gitlab_runner_docker_helper_image` | empty | Required immutable GitLab helper image in Docker mode |
| `gitlab_runner_docker_pull_policy` | `always` | Exactly string `always` or `if-not-present`; the latter is a dedicated trusted-runner exception |
| `gitlab_runner_docker_network_per_build` | `true` | Required Podman service networking mode |
| `gitlab_runner_docker_extra_hosts` | `[]` | Static `hostname:IPv4` mappings for helper, build, and service containers |
| `gitlab_runner_docker_volumes` | `[/cache]` | Container-only persistent volumes; host binds are rejected |
| `gitlab_runner_force_register` | `false` | Destructive one-time local re-registration switch |

See [GitLab Runner Self-Bootstrap](../../docs/gitlab-runner-self-bootstrap.md)
when the first managed runner must temporarily act as its own Ansible control
node. See
[Manual GitLab Runner Deployment](../../docs/gitlab-runner-manual-deployment.md)
for the non-Ansible fallback and the
[Operator Runbook](../../docs/operator-runbook.md) for normal rollout and smoke
procedures.
