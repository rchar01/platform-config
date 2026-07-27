# Kubernetes Bastion

The Kubernetes bastion split is:

```text
platform-k8s-bastion:
  public scripts and helper commands

platform-tools:
  optional access-policy validation and rendering helpers

platform-config:
  Ansible installation and configuration logic

platform-private:
  real non-secret cluster-specific values

~/.config/platform-infrastructure/config:
  local secret inputs such as admin kubeconfigs
```

`platform-config` installs runtime files and host configuration with the `k8s_bastion_access` role. This is the single repository document for the Ansible side of the bastion workflow.

The role targets a clean Rocky host that already exists and is reachable over SSH. It does not provision the VM, configure Proxmox/OpenTofu resources, or convert an existing Kubernetes node into a bastion host.

Default runtime source layout:

```yaml
k8s_bastion_runtime_src: "{{ playbook_dir }}/../vendor/platform-k8s-bastion/runtime"
```

Add the runtime repository as a submodule when `platform-config` is a git repository:

```bash
git submodule add https://codeberg.org/rch/platform-k8s-bastion vendor/platform-k8s-bastion
git submodule update --init --recursive
```

For local-only submodule setup, pinned tag updates, and `git submodule status` troubleshooting, see [`vendor/README.md`](../vendor/README.md).

The role checks that `k8s_bastion_runtime_src` exists on the control machine before copying files. Keep the default path rooted at `playbook_dir` so delegated localhost checks and local file lookups resolve the same source tree.

Ansible owns these host changes:

- installing OS packages
- downloading external CLI tools from configurable URLs
- copying bastion commands and libraries into `/usr/local`
- installing `/etc/bastion/access-policy.yaml`
- installing `/etc/bastion/admin.kubeconfig`
- installing `/etc/bastion/ca.crt`
- installing `/etc/profile.d/bastion-login.sh`
- installing and enabling bastion systemd services and timers

Corporate proxies and internal artifact mirrors can be configured by overriding `k8s_bastion_external_tools` or `k8s_bastion_download_environment` in private inventory.

Ansible expects `k8s_bastion_policy_src` to point at the final rendered access policy. Policy rendering and environment overlay merging happen before Ansible or outside this repository. Use `platform-bastion-policy` from `platform-tools` when you want a shared validator/renderer for that pre-render step.

## Managed Host Requirements

Bastion hosts need:

- a clean Rocky Linux installation
- Linux with systemd
- Python 3 for Ansible execution
- sudo/root privilege escalation
- writable `/usr/local/bin`, `/usr/local/sbin`, `/usr/local/lib/bastion`, `/etc/bastion`, and `/etc/systemd/system`
- outbound HTTPS access or private inventory overrides for a corporate artifact proxy/mirror

The role installs OS packages from `k8s_bastion_os_packages` and downloads external tools from `k8s_bastion_external_tools`.

## External Tool Mirrors

Use `k8s_bastion_download_environment` for proxy variables:

```yaml
k8s_bastion_download_environment:
  https_proxy: http://proxy.example:8080
  http_proxy: http://proxy.example:8080
  no_proxy: localhost,127.0.0.1,.internal
```

Default external tool entries pin SHA256 checksums, and `k8s_bastion_external_tools_require_checksums` defaults to `true`. Use `k8s_bastion_external_tools` to replace upstream URLs with internal artifact mirror URLs, and include a matching checksum for every replacement artifact:

```yaml
k8s_bastion_external_tools:
  - name: kubectl
    type: raw
    filename: kubectl
    url: https://artifacts.example.internal/kubernetes/v1.29.15/linux/amd64/kubectl
    checksum: sha256:3473e14c7b024a6e5403c6401b273b3faff8e5b1fed022d633815eb3168e4516
    install_as: kubectl
```

Archive entries support a `binaries` list that maps paths inside the archive to installed command names.

If you override tool versions or architectures, update the corresponding `checksum` values at the same time. Checksums must use Ansible `sha256:<64 hex>` format.

Local artifact installation is not a separate supported mode. For restricted networks, mirror the artifacts internally and point `k8s_bastion_external_tools` at those mirror URLs.

## Install Lifecycle

The role runs these phases:

- preflight checks for the vendored runtime and private input files
- OS package installation
- external CLI downloads
- runtime command and library installation
- `/etc/bastion` policy, admin kubeconfig, and CA installation
- login profile installation
- policy-driven local group and kubeconfig bootstrap
- systemd service and timer installation
- command validation

Do not put real kubeconfigs or cluster tokens in `platform-k8s-bastion`, `platform-config`, or private Git. Keep admin kubeconfigs under `~/.config/platform-infrastructure/config/` and reference them from private inventory variables. See [Private Workflow](private-workflow.md) for the production-grade private layout and env sourcing flow.

The role asserts `k8s_bastion_runtime_expected_version` against the runtime
source `VERSION` file before copying local runtime files as root-owned
executables. Override the expected version only when intentionally testing a
different runtime source.

Shared admin kubeconfig distribution is supported for environments that choose
that model. User-owned copies are persistent cluster-admin credentials; demotion
cleanup removes copies that byte-match the managed source, but exposed admin
kubeconfigs still require external rotation.

```yaml
k8s_bastion_policy_src: ../platform-private/config/files/k8s-bastion/homelab/access-policy.yaml
k8s_bastion_admin_kubeconfig_src: "{{ k8s_bastion_local_secret_config_dir }}/k8s-bastion/homelab/admin.kubeconfig"
k8s_bastion_ca_src: ../platform-private/config/files/k8s-bastion/homelab/ca.crt
```

`k8s_bastion_policy_src` must reference the complete access policy that should be installed as `/etc/bastion/access-policy.yaml`. This role does not merge public base policy, private base policy, or environment overlays.

Validate and render a private source policy before an Ansible run when needed:

```bash
platform-bastion-policy validate \
  --input ../platform-private/config/files/k8s-bastion/homelab/access-policy.yaml

platform-bastion-policy render-host \
  --input ../platform-private/config/files/k8s-bastion/homelab/access-policy.yaml \
  --output /tmp/k8s-bastion-access-policy.yaml
```

Then point private inventory at the rendered host policy:

```yaml
k8s_bastion_policy_src: /tmp/k8s-bastion-access-policy.yaml
```

## Apply Workflow

Use the private environment file for the target environment:

```bash
source ../platform-private/config/dev.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml --limit k8s-bastion-01
```

For a focused bastion-only run:

```bash
source ../platform-private/config/dev.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/k8s-bastion-access.yml --limit k8s-bastion-01
```

Use `--check --diff` for the first dry run, but expect command-driven bootstrap tasks to have limited check-mode value.

After a successful apply, run the Ansible smoke test:

```bash
source ../platform-private/config/dev.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/k8s-bastion-smoke.yml --limit k8s-bastion-01
```

## Smoke Tests

After applying to a clean Rocky bastion host, `playbooks/k8s-bastion-smoke.yml` verifies the main installed commands, required files, and enabled systemd units. Manual checks are still useful for diagnostics:

```bash
bastion-version
kubectl version --client
helm version
systemctl status bastion-bootstrapd.service
systemctl list-timers 'bastion-*'
test -f /etc/bastion/access-policy.yaml
test -f /etc/bastion/admin.kubeconfig
test -f /etc/bastion/ca.crt
```

Also test an SSH login to confirm `/etc/profile.d/bastion-login.sh` shows kubeconfig, certificate, and cluster status information.

For user credential flow, validate the expected bootstrap or renewal path for one non-admin test user before handing the host to operators.

## Bootstrap Token Issuer Staging Validation

`playbooks/bootstrap-token-issuer-staging.yml` is an operator-triggered release
gate. It is intentionally excluded from `site.yml` and must never be used as
routine convergence. The workflow runs on exactly one `k8s_bastion` host and
has three explicit modes:

- `preflight` verifies identifiable workflow and exact source, public image and
  OCI chart provenance, private values rendering, cluster version, API access,
  existing release rollback state, and ServiceAccount/RBAC readiness. It does
  not invoke Helm mutation and may run from a dirty workflow checkout for review.
- `rollback_rehearsal` deploys the candidate, verifies rollout, running digest,
  and runtime commit, then injects a controlled failure. It restores the
  captured Helm revision and digest or uninstalls a first installation. The
  play returns failure after writing rejected-run evidence; this is expected.
- `validate` deploys and leaves the candidate only after all upstream staging
  assertions and cleanup checks pass. A post-mutation failure enters explicit
  rollback.

Both mutating modes require a clean committed `platform-config` checkout so the
recorded workflow revision identifies the code that changed staging.

The private inventory must provide every environment-specific input. Required
candidate inputs include the exact source repository, tag and commit; public
image reference, digest, and revision label; public chart reference and digest;
release manifest URL and version; expected Kubernetes minor; namespace and
release name; kubeconfig path and context; private values source; and an
immutable negative-test image containing `sh`, `getent`, and `curl`. The
candidate values must provide the real bootstrap API URL, cluster name,
NetworkPolicy CIDRs, and the selected ServiceAccount/RBAC ownership model.
CNIs that enforce Kubernetes Service traffic after destination translation may
also require a private supplemental NetworkPolicy allowing only the real API
server endpoint CIDRs and port. Set
`bootstrap_token_issuer_staging_supplemental_network_policy_src` and
`bootstrap_token_issuer_staging_supplemental_network_policy_name`; rollback
restores a previous policy or deletes a first-install policy.

The fixed public v0.3.1 inputs are:

```yaml
bootstrap_token_issuer_staging_source_repo: https://codeberg.org/rch/bootstrap-token-issuer.git
bootstrap_token_issuer_staging_source_tag: v0.3.1
bootstrap_token_issuer_staging_source_commit: 4d5dc06fe485a5e33fceb49d1a195dac30ff4bb8
bootstrap_token_issuer_staging_version: 0.3.1
bootstrap_token_issuer_staging_image_ref: codeberg.org/rch/bootstrap-token-issuer:0.3.1
bootstrap_token_issuer_staging_image_digest: sha256:54d261dd1c9534c496ef30c5b9d4e4e45cc7385ef1343a8230df65db921a1c9e
bootstrap_token_issuer_staging_image_revision: 4d5dc06fe485a5e33fceb49d1a195dac30ff4bb8
bootstrap_token_issuer_staging_chart_ref: codeberg.org/rch/charts/bootstrap-token-issuer:0.3.1
bootstrap_token_issuer_staging_chart_digest: sha256:767c9ad9ef1e8ca58fa98f92f7f0890860778f4f72d43162eefaaa5e8ad41980
bootstrap_token_issuer_staging_chart_source_commit: 4d5dc06fe485a5e33fceb49d1a195dac30ff4bb8
bootstrap_token_issuer_staging_release_manifest_url: https://codeberg.org/rch/bootstrap-token-issuer/releases/download/v0.3.1/release-manifest.json
```

The workflow pins the tagged evidence schema checksum to
`e8c4d616d147c4cb6ca0b5acbb235ee207fe3732c1a3dae5453db15307df222e`.
The release manifest must report chart archive SHA-256
`eeeb71042de519387c5e992b261b6b0842f463ef2cedfa71b3b950ebc10c1028`.

Private inventory supplies
`bootstrap_token_issuer_staging_environment_label`,
`bootstrap_token_issuer_staging_expected_kubernetes_minor`,
`bootstrap_token_issuer_staging_namespace`,
`bootstrap_token_issuer_staging_release_name`,
`bootstrap_token_issuer_staging_admin_kubeconfig`,
`bootstrap_token_issuer_staging_kube_context`,
`bootstrap_token_issuer_staging_private_values_src`, and, for mutating modes,
`bootstrap_token_issuer_staging_negative_test_image`.

The bastion `kubectl` client must match the selected Kubernetes test lane. The
public role retains the 1.29 default; a 1.35 environment must override both
`k8s_bastion_kubectl_version` and its pinned
`k8s_bastion_kubectl_checksum`.

Keep the admin kubeconfig outside Git. Keep real values under
`platform-private`; the role copies them into a mode-0700 remote temporary
directory and suppresses all tasks that can expose values, endpoints, logs,
token IDs, Secrets, bearer tokens, or kubeconfigs. The public v0.3.1 source,
image, chart, release manifest, and digests are immutable release inputs, not
private configuration.

Run non-mutating preflight first:

```bash
make deploy-bootstrap-token-issuer-staging \
  ENV=dev \
  LIMIT=k8s-bastion-01 \
  STAGING_MODE=preflight
```

After separate authorization for cluster mutation, rehearse rollback and then
run the accepting validation:

```bash
make deploy-bootstrap-token-issuer-staging \
  ENV=dev \
  LIMIT=k8s-bastion-01 \
  STAGING_MODE=rollback_rehearsal

make deploy-bootstrap-token-issuer-staging \
  ENV=dev \
  LIMIT=k8s-bastion-01 \
  STAGING_MODE=validate
```

Before Helm is invoked, the role captures release presence, Helm revision,
rendered resources, running image digest, and the bootstrap-token Secret set.
Cleanup removes only the exact credential, CSR, Pod namespace, and temporary
files created by the run. Existing releases use `helm rollback` and verify both
rollout health and the restored image digest. First installs use `helm
uninstall` and verify that the release and every resource in the rendered
candidate manifest are absent. Shared ServiceAccounts and RBAC omitted from the
candidate manifest are preserved.

Redacted JSON evidence is written by default to
`.artifacts/bootstrap-token-issuer-staging-result.json`, an ignored local path.
The role validates it with the checksum-pinned schema and confirms the exact
acquired source commit contains the same schema.
Move environment-specific evidence and execution notes to the private
`platform-plans` workspace; do not commit them here. A successful `preflight`
produces a schema-valid non-accepting result because runtime assertions are
`not_run`. Only `validate` can produce an accepting `pass` result.

## Idempotency

The role is designed for repeated Ansible runs:

- package, file, template, runtime copy, sudoers, and systemd tasks are idempotent
- external tool downloads are idempotent when URLs, filenames, and checksums are stable
- set `k8s_bastion_external_tools_require_checksums` to require pinned artifact checksums in preflight
- archive extraction is skipped when installed binaries already exist and the artifact did not change
- stale previously managed runtime commands and external tools are pruned from managed manifests when pruning is enabled
- user group bootstrap reports changed only when the runtime command creates groups or adds users to groups
- stale policy-managed group memberships are removed when `k8s_bastion_reconcile_policy_access` is true; this includes groups removed from policy but still present in the previous managed
  policy access manifest
- user bootstrap kubeconfigs are generated only for users that have neither `~/.kube/config` nor `~/.kube/bootstrap`, unless `k8s_bastion_force_bootstrap_user_kubeconfigs` is true
- admin kubeconfig bootstrap reports changed only when it installs an admin kubeconfig or removes a bootstrap kubeconfig
- copied admin kubeconfigs are removed from users that no longer belong to `k8s_bastion_admin_group` in policy when `k8s_bastion_reconcile_policy_access` is true

Live credential workflows can still change cluster-side state. Do not force user bootstrap repeatedly in real cluster mode unless you intentionally want new bootstrap tokens.
