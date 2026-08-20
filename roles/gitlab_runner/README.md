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
```

Docker mode also enforces:

- a local Unix endpoint matching the manager-side socket path;
- a digest-pinned default image;
- `pull_policy = "always"`;
- `FF_NETWORK_PER_BUILD = true`;
- `privileged = false`; and
- container-only cache volumes with no host bind or socket mount.

The manager Quadlet adds:

```ini
Volume=/run/podman/podman.sock:/run/podman/podman.sock
SecurityLabelDisable=true
```

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

## Registration

The role registers only when `config.toml` is absent, unless
`gitlab_runner_force_register` is true. Forced registration stops the service,
creates a temporary root-only same-directory backup, deletes the complete local
configuration, and recreates the one declared registration. If registration
fails, the role restores the previous file and its prior active service state
before failing. An incomplete automatic restore retains the root-only
`.config.toml.ansible-*` recovery artifact. Use force only as a controlled
one-time migration with a separate operator rollback backup, then immediately
return it to false.

Rollback covers Runner-owned configuration, CA, Quadlet, service state, and the
Podman socket state captured before convergence. Successfully converged shared
Podman packages and `container_runtime_kernel` prerequisites intentionally
remain in place; they are host runtime prerequisites rather than Runner state.

The role reads only the non-secret managed contract from an existing
`config.toml`. It fails before changing the manager Quadlet when the file does
not contain exactly the one declared executor identity or when Docker host,
image, privilege, pull policy, volumes, or networking differ. Executor changes
therefore require explicit force registration. Tokens are neither returned nor
logged by this preflight.

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
| `gitlab_runner_token_src` | empty | Outside-Git token file on the control node |
| `gitlab_runner_podman_socket_enabled` | `false` | Mounts the role-managed rootful Podman socket into the manager |
| `gitlab_runner_podman_socket_host_path` | `/run/podman/podman.sock` | Host socket path |
| `gitlab_runner_podman_socket_container_path` | `/run/podman/podman.sock` | Manager-side socket path |
| `gitlab_runner_docker_host` | manager socket Unix URL | Docker-compatible Podman endpoint |
| `gitlab_runner_docker_image` | empty | Required immutable default image in Docker mode |
| `gitlab_runner_docker_pull_policy` | `always` | Required shared-runner pull policy |
| `gitlab_runner_docker_network_per_build` | `true` | Required Podman service networking mode |
| `gitlab_runner_docker_volumes` | `[/cache]` | Container-only persistent volumes; host binds are rejected |
| `gitlab_runner_force_register` | `false` | Destructive one-time local re-registration switch |

See [GitLab Runner Self-Bootstrap](../../docs/gitlab-runner-self-bootstrap.md)
when the first managed runner must temporarily act as its own Ansible control
node. See
[Manual GitLab Runner Deployment](../../docs/gitlab-runner-manual-deployment.md)
for the non-Ansible fallback and the
[Operator Runbook](../../docs/operator-runbook.md) for normal rollout and smoke
procedures.
