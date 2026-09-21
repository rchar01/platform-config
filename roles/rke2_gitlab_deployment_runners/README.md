# RKE2 GitLab Deployment Runners

This dormant, additive role installs exactly two Kubernetes-executor Runner
managers: `apps` and `platform`. It owns their namespaces, ServiceAccounts,
NetworkPolicies, RBAC, native Pod admission policies, authentication/CA Secrets
and bootstrap-server HelmChart sources. An empty `rke2_gitlab_deployment_runners: []` skips credential reads,
target filesystem inspection and Kubernetes API calls, including in smoke. It
does not prune previously installed instances.

The strict no-services / exact-job-image boundary uses native Kubernetes 1.35
[`ValidatingAdmissionPolicy`](https://v1-35.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
and bindings, without a webhook or extra controller.
Runner allowlists alone are insufficient: in `v18.11.3`, `services_limit` is
Docker-only, and `VerifyAllowedImage` exempts internal images from both image
and service allowlists. The fixed policies below close that admission gap. See upstream
[Kubernetes image checks](https://gitlab.com/gitlab-org/gitlab-runner/-/blob/v18.11.3/executors/kubernetes/kubernetes.go)
and [allowlist exemptions](https://gitlab.com/gitlab-org/gitlab-runner/-/blob/v18.11.3/common/allowed_images.go).

## Configuration

Keep real declarations in private inventory and authentication tokens outside
Git. The nonempty instance list must contain exactly these two profiles; each
mapping accepts **only** `profile`, `name`, `manager_namespace`, `job_namespace`
and `token_src`:

```yaml
rke2_gitlab_deployment_runners:
  - profile: apps
    name: apps-deployment
    manager_namespace: apps-runner-managers
    job_namespace: apps-runner-jobs
    token_src: /outside-git/apps-runner.token
  - profile: platform
    name: platform-deployment
    manager_namespace: platform-runner-managers
    job_namespace: platform-runner-jobs
    token_src: /outside-git/platform-runner.token
```

Names and token paths must be distinct. Tokens are canonical `glrt-...` values
without trailing newlines in regular, non-symlink `0400`/`0600` files, at most
512 bytes. Source paths use canonical absolute paths with letters, digits,
underscores, dots, hyphens and slashes.

The two token **values** must also differ. Before any reconciliation, the role
compares the validated inputs and reads only the fixed installed legacy
authentication Secret `gitlab-runner/rke2-gitlab-runner-token`. Neither new value
may match its known nonempty `runner-token`. An absent legacy Secret or an empty
legacy authentication value supplies no comparison value; malformed existing
Secret shape or noncanonical nonempty tokens fail closed. No legacy controller
file is read or changed. All token reads, validation and comparisons use `no_log`.

Different token bytes do **not** prove distinct GitLab Runner records: operators
must separately review record identity, project assignment, tags and protection
settings. This role neither enumerates other Secrets nor calls the GitLab API.

All common settings below use the prefix **`rke2_gitlab_deployment_runner_`**:

| Suffix | Default / requirement when enabled |
| --- | --- |
| `gitlab_url` | Required credential-free HTTPS origin |
| `clone_url` | Empty; optional credential-free HTTPS checkout origin |
| `tls_ca_cert_src` / `tls_ca_cert_sha256` | Required reviewed GitLab CA source and exact SHA-256 |
| `chart_repo` | `https://charts.gitlab.io`; HTTPS indexed repository, optional path |
| `chart_repo_ca_src` / `chart_repo_ca_sha256` | Both empty; optional paired, independent Helm repository CA selection |
| `chart_version` | Fixed `0.88.3` |
| `manager_image` | Legacy role's digest-pinned `alpine-v18.11.3` manager |
| `helper_image` | Legacy role's digest-pinned `x86_64-v18.11.3` helper |
| `job_image` | Empty and required: scheme-free `registry/repository[:tag]@sha256:<64 hex>` tool image |
| `pull_policy` | `always`; exactly `always` or `if-not-present`, applied to both executor policy and its singleton allowlist |
| `acceptance_namespace` | Empty and required: apps ConfigMap acceptance namespace |
| `platform_acceptance_namespace` | Empty and required: platform's CI-created canary Namespace name |
| `egress` | Empty and required: list of exact `{address: IPv4literal, ports: [TCP integers]}` mappings |

The four manager/job namespaces and both acceptance names must all be distinct,
valid namespace names, excluding `default`, `gitlab-runner` and every `kube-*`
name. The role creates the four executor namespaces and apps acceptance namespace
with enforce/audit/warn **baseline** Pod Security Admission labels pinned to
`v1.35`. These compiled namespace declarations remain baseline. CI creates the
platform canary namespace with its separate enforce/audit/warn **restricted**
`v1.35` labels; the role never precreates it or the acceptance CRD.

CA files must be nonempty regular non-symlink PEM files of at most 1 MiB, with no
private key. The exact decoded bytes are checked against the SHA-256 before
publication. GitLab CA bytes populate the manager's CA Secret; optional Helm CA
bytes populate `HelmChart.spec.repoCA`. These are independent selections.

The job image must contain `kubectl`, `sh` and `git` and support the selected
runner/helper environment. Input validation establishes digest syntax only;
runtime tool availability and strict TLS access require separate qualification.
Clone origin selection affects Runner checkout, not controller source access.

### Temporary Manual Image Preload

While a registry such as Zot is being prepared, an operator may preload the
reviewed job image and select this private inventory exception:

```yaml
rke2_gitlab_deployment_runner_pull_policy: if-not-present
```

The default remains `always`. The exception applies to both profiles' job,
helper and supported init containers; manager Pods retain `imagePullPolicy:
Always`. Missing images still trigger a pull. Exact image pins, admission,
namespaces and permissions are unchanged.

Before enabling jobs:

1. Verify the OCI archive checksum and transfer it manually to every eligible
   worker. Import into **RKE2's containerd `k8s.io` store**, not Podman. RKE2
   supports [tarball imports](https://docs.rke2.io/add-ons/import-images) through
   `/var/lib/rancher/rke2/agent/images` with its default data directory.
2. Select `rke2_gitlab_deployment_runner_job_image` as an exact
   `repository@sha256:...` reference. Verify CRI lookup of that full reference on
   every worker and qualify a workload using the local image without registry
   access. Import success or a local tag alone does not prove digest lookup;
   an archive checksum or image config ID is not the manifest digest.
3. Ensure the pinned helper image is preloaded or pullable on those workers.
   Manager and Helm installation images still require their own availability.
4. Bind both CI acceptance profiles' `expected-image` inputs to the same exact
   job image. The component inherits the configured Runner policy and needs no
   job-level pull-policy override. Apply through the reviewed external workflow,
   require smoke and a zero-change post-check, then run both acceptance profiles.

Node replacement or image garbage collection can require another manual import.
The role and CI do not transfer/import images or publish to a registry.

### Switching to Zot

After manual publication, verify the **destination** repository digest and
worker strict-TLS/authenticated pull access as applicable. Do not infer that
digest from the archive checksum or the earlier local import. Pause job intake
and finish existing jobs; image changes must satisfy the existing retained-Pod
guards. Update private `rke2_gitlab_deployment_runner_job_image` and both CI
`expected-image` bindings together, then restore
`rke2_gitlab_deployment_runner_pull_policy: always`. Review the plan, apply,
verify rollout/smoke and a zero-change post-check, and repeat apps/platform
acceptance. The CI component needs no registry-specific code or push credentials.

## Fixed Execution and Permission Contract

For each profile, release and manager ServiceAccount are `rke2-gitlab-<profile>`;
job ServiceAccount is `rke2-gitlab-<profile>-job`. Both accounts and manager/job
pods mount Kubernetes tokens. Jobs use projected automatic ServiceAccount
tokens. Helm has `rbac.create: false` and `serviceAccount.create: false`, and
references these externally owned accounts.

Managers have the existing executor Role's exact permissions, scoped to their
own job namespace through a cross-namespace RoleBinding. Each job namespace is
fixed and namespace/ServiceAccount overrides are disabled. The image allowlist
selects the exact tool image and the service allowlist selects no valid image;
native admission also enforces the Pod shape despite Runner's internal-image exemptions. Manager and
job capabilities are dropped, privileged execution and privilege escalation are
disabled, and required affinity excludes control-plane nodes. Concurrency is one;
manager and build/helper resource bounds follow the legacy role.

- **Apps jobs:** ConfigMap `create` in `acceptance_namespace`; `get`, `patch` and
  `delete` only on `runner-acceptance` there. No general deployment permissions.
- **Platform jobs:** Namespace `create`; `get` and `delete` only on
  `platform_acceptance_namespace`. CRD `create`; `get`, `patch` and `delete` only
  on `runnerchecks.acceptance.platform.example`. No Namespace patch/update,
  wildcard, cluster-admin or general RBAC/ServiceAccount/Secret mutation grants.

Kubernetes RBAC **cannot name-bound CREATE**. These approved create grants allow
other names of the same resource kinds. The fixed CI acceptance operation owns
the harmless namespaced `RunnerCheck` CRD (`acceptance.platform.example`, plural
`runnerchecks`), with a simple structural schema and no webhook/controller. CI
owns the apps ConfigMap and platform Namespace/CRD exercise and label/UID-guarded
cleanup. This role does not create custom-resource instances or the CRD.

Each of the four executor namespaces has one all-pod NetworkPolicy denying all
ingress and allowing only fixed DNS plus selected egress. DNS is UDP/TCP 53 to
pods labeled `k8s-app=kube-dns` in the namespace labeled
`kubernetes.io/metadata.name=kube-system`. Each configured address becomes an
exact IPv4 `/32` with the selected TCP ports; raw policy fragments are rejected.
Select API service and endpoint addresses, GitLab and other necessary targets
privately. CNI/DNAT behavior and actual connectivity require live qualification.
Neither jobs nor managers can mutate these policies through the granted RBAC.

### Native Job Pod Admission

Each profile owns a cluster-scoped `ValidatingAdmissionPolicy` and matching
`ValidatingAdmissionPolicyBinding`, both named `rke2-gitlab-<profile>-job-pods`.
The policy and binding both select only that profile's job namespace using the
Kubernetes-managed `kubernetes.io/metadata.name` label. Manager, acceptance and
legacy namespaces are outside this scope. There are no caller-supplied CEL
expressions, policy fragments or policy flags.

The fixed core/v1, Namespaced rules match `CREATE` and `UPDATE` on `pods` and
`pods/ephemeralcontainers`, with `matchPolicy: Exact`, `failurePolicy: Fail` and
binding `validationActions: [Deny]`. They require:

- exactly `rke2-gitlab-<profile>-job` as the Pod ServiceAccount;
- exactly two ordinary containers: `build` with the reviewed job-image pin and
  `helper` with the reviewed helper-image pin;
- zero or one init container, only `init-permissions` with the helper pin and
  no container-level `restartPolicy` (thus no restartable init sidecar); and
- no ephemeral containers or additional service containers.

Runner `v18.11.3`'s `buildPermissionsInitContainer` uses `init-permissions` and
`getHelperImage()`, which honors the configured helper-image pin. The optional
`init-build-uid-gid-collector` is outside this fixed contract and will be denied.
The policy does not constrain job commands; jobs intentionally execute approved
CI scripts inside the pinned build/helper environment.

Ownership preflight covers both policies and bindings before writes. Apply
reconciles them before either manager's HelmChart publication, requires the
current policy generation's native CEL type checking without warnings, and runs
positive/negative server-side dry-run Pod requests as each manager identity.
Negative results count only when they name this policy and its expected rejection
message; unrelated RBAC, transport or other admission failures do not count.

Admission is not retroactive. All existing job Pods, including completed and
terminating Pods, are inspected before writes and freshly before admission proof
and publication. Incompatible Pods cause failure; the role never deletes them.
Exclude concurrent lifecycle changes during convergence. Updates to image pins
can therefore require separately reviewed draining of old jobs.

## Entry Points and Ownership

Use the fixed playbooks with the complete `rke2_servers` scope:

- `playbooks/rke2-gitlab-deployment-runners.yml`
- `playbooks/rke2-gitlab-deployment-runners-smoke.yml`

Both run linearly with `any_errors_fatal`. All server declarations must match;
the leader is the first inventory server and must agree with an explicitly set
`rke2_bootstrap_host`. Server and agent groups must both be nonempty and disjoint,
and their union must exactly equal the nonempty declared `rke2_cluster` group.
Role members outside that cluster and unroled cluster members are rejected;
topology validation precedes target filesystem, credential and API reads. No base RKE2 convergence
or role dependencies run. Partial limits and serial subsets are rejected.

Every server's fixed manifest ancestry and both source paths are guarded before
writes. Existing files must be root-owned `0644`, regular, single-link, bounded
and component-owned. Secondary-server sources are rejected. The bootstrap server
alone publishes `/var/lib/rancher/rke2/server/manifests/rke2-gitlab-apps.yaml` and
`rke2-gitlab-platform.yaml`. RKE2's injected `spec.set` is ignored for source drift.

All externally managed live objects require the `platform-config` managed-by,
`rke2-gitlab-deployment-runners` part-of and matching profile component labels.
Existing manager Deployment/ConfigMap objects require the exact Helm release
ownership. Preflight rejects foreign ownership before writing either profile.
API reconciliation uses resource-version-bound replacement; it does not adopt
foreign resources. Exclude concurrent external mutations during convergence.

Check mode performs read-only preflight and reports predicted changes. Apply
reconciles the API prerequisites, Secrets and static HelmChart files; existing
managers restart when their Secrets change. Helm convergence is asynchronous:
run standalone smoke after publication and rollout have completed.

Smoke is task-only and resolves role defaults in a separate namespace, preserving
inventory precedence. `defaults/unused.yml` is intentionally empty: selecting it
prevents `include_role` from implicitly loading `defaults/main.yml`; `entry.yml`
instead resolves that file into a private dictionary. It reads no controller
credentials. In addition to ownership metadata, it reads bounded authentication
projections from the two installed token Secrets and the exact known legacy
Secret. New tokens must be nonempty, canonical and distinct, and must not match
the known nonempty legacy value. The printer accepts only an Opaque Secret with
exactly `runner-token` and empty `runner-registration-token` data; output is at
most 690 characters and base64 must round-trip canonically. CA Secret payloads
are not read. Empty declarations skip every API read, including legacy inspection.
It checks live policy/RBAC/account state, exact Helm values,
repository CA pin, successful Helm Job, Deployment rollout, executor config,
worker placement and two ready manager samples ten seconds apart with stable UID
and unchanged nonnegative restart counts; recovered historical restarts are
accepted. Impersonated `auth can-i` probes include ServiceAccount groups
and positive/negative manager/job scopes, cross-namespace access and own-RBAC
mutation, including admission-policy mutation. Smoke also checks exact live CEL,
binding, scope and ownership, current-generation type-check results, existing job
Pod shape, and positive/negative server-side dry-run admission. These API requests
do not persist Pods or execute containers. When an existing job Pod is available,
a UID/resourceVersion-bound dry-run patch also verifies denial through the
`ephemeralcontainers` UPDATE subresource. With no job Pod, smoke explicitly
reports that this subresource runtime probe was not exercised. Smoke does not
inspect GitLab API settings or submit GitLab jobs.

## Offline Verification

```bash
PLATFORM_CONFIG_CONTAINER_PROFILE=test ./scripts/in-container timeout 1800s \
  python -m pytest -n 0 -x --durations=10 \
  tests/python/test_rke2_gitlab_deployment_runners.py \
  tests/python/test_rke2_gitlab_deployment_runner_admission.py
```

The fixtures execute the real Ansible task chain with isolated target paths and
a stateful fake kubectl, covering default/preload policies and smoke drift
rejection. They establish orchestration and rendering behavior;
they do not evaluate Kubernetes CEL or establish live admission enforcement,
Helm/chart compatibility, networking, token projection, GitLab protection settings
or acceptance-job success. Native policy compilation and actual API admission
remain pending until an authorized live apply/smoke run. Live dry-run admission
does not itself qualify a real Runner job.

Focused `tests/python/test_rke2_gitlab_deployment_runner_stability.py` runs the
production stability assertions directly, including recovered historical restart
counts, without waiting for the sampling window or repeating full convergence.

Optional `tests/python/test_rke2_gitlab_deployment_runner_helm_render.py` uses real
Helm **4.2.2** and the digest-checked **0.88.3** chart for both profiles. Supply
already verified, container-accessible artifacts through
`PLATFORM_CONFIG_TEST_HELM` and `PLATFORM_CONFIG_TEST_GITLAB_RUNNER_CHART`. This test
never downloads artifacts and skips when both paths are absent. It renders the
actual role template through Ansible, runs local `helm template`, and checks the
result through the production manager smoke assertions. It checks external
accounts and Secrets, absence of chart-owned RBAC/accounts/Secrets, image pins,
security context, resources, affinity, token mounting and executor TOML. Chart
0.88.3 omits Deployment replicas; the fixture models Kubernetes 1.35's documented
one-replica default and supplies synthetic readiness fields. This qualifies local
chart rendering, not deployment readiness or job execution.
