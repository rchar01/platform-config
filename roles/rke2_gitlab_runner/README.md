# RKE2 GitLab Runner Role

This role installs one GitLab Runner manager into RKE2 through the RKE2 Helm
Controller. It is disabled by default and follows the bootstrap-server manifest
pattern used by `rke2_kube_vip`.

When enabled, the role requires a pre-created GitLab Runner authentication token
and reviewed GitLab CA file outside Git. It reconciles those values into separate
Kubernetes Secrets; the static HelmChart manifest references those Secret names.

The Runner uses the Kubernetes executor with one concurrent job, explicit
namespace-scoped RBAC, digest-pinned manager/helper/job images, a separate job
ServiceAccount without an API token, and required affinity that excludes RKE2
control-plane nodes. Privileged containers, host paths, runtime sockets, host
networking, and arbitrary Runner configuration are not supported.

Set `rke2_gitlab_runner_enabled: true` and provide:

- `rke2_gitlab_runner_gitlab_url`
- `rke2_gitlab_runner_token_src`
- `rke2_gitlab_runner_tls_ca_cert_src`
- `rke2_gitlab_runner_tls_ca_cert_sha256`
- `rke2_gitlab_runner_name`
- chart version `0.88.3`, which the role currently requires
- reviewed image pins when they deliberately differ from the public defaults

`rke2_gitlab_runner_chart_repo` defaults to `https://charts.gitlab.io`. Override
it in private inventory for an internal Helm repository. It must be a
credential-free HTTPS URL; ordinary repository paths, valid explicit ports and
an optional trailing slash are supported. Chart `gitlab-runner` and version
`0.88.3` remain fixed. Smoke compares the live repository with the same setting,
using the upstream default when the variable is absent from inventory.

Verify both `index.yaml` and the exact archive URL selected by its version entry.
Changing the repository URL does not enforce a chart checksum or provide Helm-job
CA trust. The internal source must be accessible and trusted by the Helm
Controller job; container-image registry trust alone is not sufficient. Do not
put credentials in this URL or disable TLS verification.

For a repository requiring a private CA, explicitly set both
`rke2_gitlab_runner_chart_repo_ca_src` and
`rke2_gitlab_runner_chart_repo_ca_sha256` in private inventory. Both are strings
and default to empty, which omits `spec.repoCA`. The source is a controller-local
canonical absolute path using only letters, digits, `_`, `-`, `.`, and `/`, with
no empty, `.` or `..` components. Select a reviewed PEM CA file, not a private key;
its contents are published in the HelmChart. The checksum is exactly 64 hex
digits (either case). Keep the real file and pin in private configuration.

Before mutation, including in check mode, the role uses controller-side stat and
slurp to require a nonempty regular non-symlink file of at most 1 MiB, checks its
SHA-256, and hashes the exact decoded slurp content again. The template serializes
those bytes as `spec.repoCA` with JSON quoting, preserving line endings and final
newlines. Smoke verifies the live repository and exact CA SHA-256, or absence of
`repoCA` when unconfigured. This uses the `repoCA` support in helm-controller
0.17.1 shipped with the approved RKE2 v1.35.5+rke2r2 baseline.

Repository CA selection is independent of `rke2_gitlab_runner_tls_ca_cert_src`
and its pin: those still populate the Runner's GitLab `certsSecretName` Secret.
Neither setting infers the other, changes node/registry trust, or bypasses TLS
verification. A matching live field is not proof of a successful chart download;
qualify the actual Helm job and chart source separately.

`rke2_gitlab_runner_clone_url` is an optional credential-free HTTPS origin for
job repository checkout when GitLab advertises a different hostname. Its empty
default omits `clone_url` and preserves existing behavior. A nonempty value may
include a valid port and trailing slash, but no repository path, credentials,
query or fragment. Smoke checks the configured override or its expected absence.
Qualify DNS and certificate trust from the helper/job network. This does not
rewrite platform-config's separate CI source fetch, artifact endpoints or LFS
URLs, and does not add host aliases or disable certificate verification.

The token source must be a regular non-symlink file with mode `0400` or `0600`
and one `glrt-...` value without a trailing newline. The role reads it only on
the controller under `no_log`.

`rke2_gitlab_runner_enabled: false` skips all management. It does not uninstall
an existing release. Removal requires a separately reviewed maintenance design.

Use `playbooks/rke2-gitlab-runner-smoke.yml` after convergence. Smoke validates
the live image, namespace policy, RBAC, ServiceAccounts, configuration, and
manager placement on an inventory-declared RKE2 agent. GitLab-side project
or group scope, tags, protected status, and untagged-job policy remain
operator-managed guidance. Neither the role nor smoke inspects or enforces those
GitLab settings.
