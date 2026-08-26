# Manual GitLab Runner Deployment

This guide reproduces the GitLab Runner service managed by the
[`gitlab_runner`](../roles/gitlab_runner/) Ansible role without running Ansible.
It is intended for a controlled migration or a host that cannot use the normal
inventory workflow. Prefer the role for hosts that remain managed by
`platform-config`.

The default design runs GitLab Runner as a system Podman Quadlet with:

- `docker.io/gitlab/gitlab-runner:alpine-v18.11.3@sha256:904cc94dc8417152685f62c4c1a1add19ad2d82947ca7aead844895e16128f1e`;
- the shell executor;
- persistent configuration under `/etc/gitlab-runner`;
- persistent runner data under `/var/lib/gitlab-runner`;
- no Docker or Podman socket; and
- no privileged build support.

The commands are a version-specific snapshot of
[`defaults/main.yml`](../roles/gitlab_runner/defaults/main.yml) and
[`gitlab-runner.container.j2`](../roles/gitlab_runner/templates/gitlab-runner.container.j2).
Compare those sources before use and update this guide when the role image,
paths, or Quadlet template changes.

A runner tagged `k8s` is intended for Kubernetes-related jobs, but it is not a
GitLab Kubernetes executor. Shell jobs run inside the persistent runner
container. The `image:` keyword in `.gitlab-ci.yml` does not provide a job
image to the shell executor.

The role also provides an explicit Podman-backed Docker executor. It keeps the
same permanent manager Quadlet but creates disposable build, helper, and service
containers for jobs. Only the manager receives the rootful Podman API socket.

## Scope And Security

This procedure installs the runner service only. It does not reproduce the
base OS, SSH, firewall, time synchronization, storage, or other configuration
managed by the rest of `platform-config`.

Run only trusted projects on this shell executor. Create a separate runner for
each environment, use environment-specific tags, and restrict protected
workloads in GitLab. Do not reuse a development runner token for another
environment.

Do not add real environment data to this public repository. Store public CA
certificates in approved private configuration or the protected outside-Git PKI
export used by the environment. Keep these values outside all Git repositories:

- runner authentication tokens;
- CA private keys and passphrases; and
- kubeconfigs and Kubernetes credentials.

Real hostnames, addresses, and access policy belong in private configuration.

The runner never needs GitLab's TLS private key.

## Inputs

Collect these inputs before changing the target host:

| Input | Example |
|---|---|
| GitLab URL | `https://gitlab.example.test` |
| Runner name | `example-k8s-runner-01` |
| Runner tags | `example`, `linux-amd64`, `k8s` |
| Runner token | A pre-created `glrt-...` authentication token |
| Runner image | A reviewed `gitlab-runner@sha256:...` reference |
| Public CA certificate | Only when the runner image does not trust GitLab's issuer |

Use a DNS name present in the GitLab certificate's subject alternative names.
Trusting the issuing CA does not fix a hostname mismatch.

## 1. Create The Runner In GitLab

Create a group or project runner in the GitLab UI before registering the host.
Configure its tags on the GitLab runner object, for example:

```text
example, linux-amd64, k8s
```

Disable untagged jobs when the runner must serve only explicitly selected jobs.
Apply protected-runner and project-locking controls appropriate to the target
environment. Store the resulting `glrt-...` token in a secret manager or other
outside-Git secret store.

Do not put the token in shell history. The interactive registration command
below prompts for it.

## 2. Prepare The Host

The target must be a Linux host with systemd, Podman, outbound HTTPS access to
GitLab, and sufficient storage for build workspaces and caches. On Rocky Linux,
install Podman and keep its API socket disabled:

```bash
sudo dnf install -y podman
sudo systemctl disable --now podman.socket
```

Create the same directories and modes used by the role:

```bash
sudo install -d -o root -g root -m 0750 /etc/gitlab-runner
sudo install -d -o root -g root -m 0750 /etc/gitlab-runner/certs
sudo install -d -o root -g root -m 0755 /var/lib/gitlab-runner
sudo install -d -o root -g root -m 0755 /etc/containers/systemd
```

Mount any approved dedicated filesystem at `/var/lib/gitlab-runner` before
registration. Do not initialize an unidentified disk to reproduce another
environment's LVM layout.

## 3. Decide TLS Trust

Test GitLab from the target runner host without bypassing certificate
verification:

```bash
curl --fail --show-error https://gitlab.example.test/users/sign_in
```

Do not use `--insecure` for this test.

If GitLab uses a publicly trusted certificate and the test succeeds, continue
without a custom CA file. Host success does not guarantee that the runner image
has the same trust store; registration in step 5 is the definitive check.

If GitLab uses a private CA, obtain the public root CA and any required
intermediate certificates from a trusted administrator or controlled PKI
export. Do not copy GitLab's TLS private key. Install the verified CA bundle:

```bash
sudo install -o root -g root -m 0644 /trusted/source/gitlab-ca.crt \
  /etc/gitlab-runner/certs/gitlab-ca.crt
```

Verify every certificate in the bundle through an independent trusted channel.
Inspect the first certificate and then test the complete bundle:

```bash
openssl x509 \
  -in /etc/gitlab-runner/certs/gitlab-ca.crt \
  -noout -subject -issuer -fingerprint -sha256

curl --fail --show-error \
  --cacert /etc/gitlab-runner/certs/gitlab-ca.crt \
  https://gitlab.example.test/users/sign_in
```

Do not trust a certificate retrieved from the unauthenticated endpoint unless
its fingerprint is independently authenticated. If GitLab uses a self-signed
server certificate, that authenticated public certificate can be the trust
file.

## 4. Pull The Runner Image

Pull the same image version declared by the role:

```bash
sudo podman pull docker.io/gitlab/gitlab-runner:alpine-v18.11.3@sha256:904cc94dc8417152685f62c4c1a1add19ad2d82947ca7aead844895e16128f1e
```

Use this version for the initial migration. Upgrade separately after the
migrated runner passes its smoke job. Environments requiring immutable image
selection should mirror and digest-pin the qualified image through their
normal image-approval process.

## 5. Register The Runner

Register interactively when GitLab uses publicly trusted TLS:

```bash
sudo podman run --rm -it \
  --entrypoint gitlab-runner \
  --volume /etc/gitlab-runner:/etc/gitlab-runner:Z \
  --volume /var/lib/gitlab-runner:/home/gitlab-runner:Z \
  docker.io/gitlab/gitlab-runner:alpine-v18.11.3@sha256:904cc94dc8417152685f62c4c1a1add19ad2d82947ca7aead844895e16128f1e \
  register \
  --url https://gitlab.example.test \
  --name example-k8s-runner-01 \
  --executor shell
```

Enter the pre-created `glrt-...` token when prompted.

For private CA trust, add this registration argument:

```text
--tls-ca-file /etc/gitlab-runner/certs/gitlab-ca.crt
```

Registration writes `/etc/gitlab-runner/config.toml`. Treat that file as a
secret because it contains runner authentication material. Do not print or
commit it.

If registration reports `x509: certificate signed by unknown authority`, the
runner image does not trust GitLab's issuer. Return to step 3 and install the
authenticated public CA bundle. Do not disable TLS verification.

## 6. Install The Quadlet

Create `/etc/containers/systemd/gitlab-runner.container` with the same content
rendered by the Ansible role:

```ini
[Unit]
Description=GitLab Runner
Wants=network-online.target
After=network-online.target

[Container]
Image=docker.io/gitlab/gitlab-runner:alpine-v18.11.3@sha256:904cc94dc8417152685f62c4c1a1add19ad2d82947ca7aead844895e16128f1e
ContainerName=gitlab-runner
Volume=/etc/gitlab-runner:/etc/gitlab-runner:Z
Volume=/var/lib/gitlab-runner:/home/gitlab-runner:Z

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

The `:Z` labels are required for these private SELinux bind mounts on the
supported Rocky Linux hosts.

### Optional Podman-Backed Docker Executor

Use this mode only for a protected runner serving trusted projects. The rootful
Podman API is host-root-equivalent if the manager is compromised.

Enable the system socket:

```bash
sudo dnf install -y podman
sudo systemctl enable --now podman.socket
```

GitLab documents `podman-plugins` as required for service-container network
aliases. The qualified Rocky Linux 10.1 repositories do not currently provide
that package, so do not use service aliases until an approved package source is
available.

Register one Docker executor with an immutable fallback image:

```bash
sudo podman run --rm -it \
  --entrypoint gitlab-runner \
  --volume /etc/gitlab-runner:/etc/gitlab-runner:Z \
  --volume /var/lib/gitlab-runner:/home/gitlab-runner:Z \
  docker.io/gitlab/gitlab-runner:alpine-v18.11.3@sha256:904cc94dc8417152685f62c4c1a1add19ad2d82947ca7aead844895e16128f1e \
  register \
  --url https://gitlab.example.test \
  --name example-k8s-runner-01 \
  --executor docker \
  --docker-host unix:///run/podman/podman.sock \
  --docker-image docker.io/library/alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 \
  --docker-helper-image registry.gitlab.com/gitlab-org/gitlab-runner/gitlab-runner-helper:x86_64-v18.11.3@sha256:571952e633d345c74af6458eda2948da99cf5315ce9017e1cab22a4c2226887c \
  --docker-pull-policy always \
  --docker-volumes /cache \
  --feature-flags FF_NETWORK_PER_BUILD:true
```

Add the socket to the manager Quadlet, not to Docker job volumes:

```ini
[Container]
Image=docker.io/gitlab/gitlab-runner:alpine-v18.11.3@sha256:904cc94dc8417152685f62c4c1a1add19ad2d82947ca7aead844895e16128f1e
ContainerName=gitlab-runner
Volume=/etc/gitlab-runner:/etc/gitlab-runner:Z
Volume=/var/lib/gitlab-runner:/home/gitlab-runner:Z
Volume=/run/podman/podman.sock:/run/podman/podman.sock
SecurityLabelDisable=true
```

Do not add either socket path to `[runners.docker].volumes`. Mounting a Unix
socket read-only does not make its API read-only. A job with the rootful socket
could create privileged containers or mount host paths even when its own
`privileged` setting is false.

The manager automatically creates and removes per-job containers. Job
containers receive GitLab's temporary `CI_JOB_TOKEN`, not the manager's runner
authentication token or `/etc/gitlab-runner/config.toml`.

## 7. Start And Verify The Service

Generate the systemd unit and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gitlab-runner.service
```

Run the same local checks as the repository smoke playbook:

```bash
sudo systemctl is-active gitlab-runner.service
sudo test -f /etc/gitlab-runner/config.toml
sudo podman exec gitlab-runner gitlab-runner verify --delete=false
```

If a check fails, inspect bounded recent service logs without publishing their
contents to a public issue:

```bash
sudo journalctl -u gitlab-runner.service --since '-15 minutes'
```

Confirm in GitLab that the runner is online and has only the intended tags and
project or group assignments.

## 8. Run A Smoke Job

Run a minimal job from an authorized project with all environment-specific
tags. For example:

```yaml
runner-smoke:
  tags:
    - example
    - linux-amd64
    - k8s
  script:
    - git --version
```

Confirm that the intended runner executes the job. Do not proceed with
environment credentials until tag selection, protected-runner policy, and
project assignment have been validated.

## 9. Provide Kubernetes Tooling Deliberately

The repository does not install `kubectl`, Helm, or other deployment tools in
the manager image. In default shell mode, a job-level `image:` declaration does
not add those tools. In Docker mode, select a qualified digest-pinned job image
that contains the required tools; the manager socket still remains unavailable
inside that job.

Before running Kubernetes jobs, choose and qualify one explicit approach:

- build a digest-pinned runner image based on the approved GitLab Runner image
  and add only the required tool versions;
- install a native runner and its tools on a dedicated host, accepting the
  reduced isolation; or
- design a separate GitLab Kubernetes executor.

Provide Kubernetes credentials through protected GitLab CI variables or an
approved outside-Git secret mechanism. Use a narrowly scoped service account;
do not give the runner a cluster-admin kubeconfig by default.

## Migration And Rollback

For a different environment, create and register a new runner rather than
copying `/etc/gitlab-runner/config.toml` or reusing another environment's token.
Start with an empty `/var/lib/gitlab-runner` unless an approved migration
explicitly requires old workspaces or caches.

Keep the old runner available but prevent duplicate job selection while the
new runner completes its smoke job. If validation fails, disable and stop the
new service:

```bash
sudo systemctl disable --now gitlab-runner.service
```

Restore job selection to the old runner. Remove the old GitLab runner object
and host data only after the new runner has passed normal and failure-path jobs
and the rollback window has closed.

## Ansible Variable Mapping

The manual values correspond to these role variables:

| Manual setting | Role variable |
|---|---|
| Runner image | `gitlab_runner_image` |
| GitLab URL | `gitlab_runner_gitlab_url` |
| Runner name | `gitlab_runner_name` |
| Token source file | `gitlab_runner_token_src` |
| Executor | `gitlab_runner_executor` |
| Optional CA source | `gitlab_runner_tls_ca_cert_src` |
| Optional CA source SHA-256 | `gitlab_runner_tls_ca_cert_sha256` |
| Configuration directory | `gitlab_runner_config_dir` |
| Data directory | `gitlab_runner_data_dir` |
| Manager Podman socket | `gitlab_runner_podman_socket_enabled` |
| Docker API endpoint | `gitlab_runner_docker_host` |
| Docker fallback image | `gitlab_runner_docker_image` |
| Docker helper image | `gitlab_runner_docker_helper_image` |
| Docker pull policy | `gitlab_runner_docker_pull_policy` |
| Additional registration flags | `gitlab_runner_registration_extra_args` |

Runner tags must be configured on the pre-created runner in GitLab. A host that
remains in the `gitlab_runners` inventory group can be changed by a later
Ansible run, so either keep its private inventory aligned with the manual state
or return ownership to the role.

For the normal managed workflow and repository smoke commands, see the
[Operator Runbook](operator-runbook.md#dev-bring-up).
