# RKE2 GitLab Runner Role

This role installs one GitLab Runner manager into RKE2 through the RKE2 Helm
Controller. It is disabled by default and follows the bootstrap-server manifest
pattern used by `rke2_kube_vip`.

When enabled, the role requires a pre-created GitLab Runner authentication token
and reviewed GitLab CA file outside Git. It reconciles those values into separate
Kubernetes Secrets; the static HelmChart manifest contains only Secret names.

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
Changing the repository does not enforce a chart checksum or provide Helm-job
CA trust. The internal source must be accessible and trusted by the Helm
Controller job; container-image registry trust alone is not sufficient. Do not
put credentials in this URL or disable TLS verification.

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
