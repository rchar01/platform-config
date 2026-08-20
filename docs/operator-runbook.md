# Operator Runbook

This runbook describes the local operator flow for using `platform-config` with the sibling private configuration repository and the VM lifecycle owned by `platform-infra`.

## Repository Order

Run the platform in this order:

1. `platform-template-builder` builds Proxmox templates.
2. `platform-infra` creates or updates VMs and injects cloud-init SSH public keys.
3. `platform-config` configures the already-running VMs with Ansible.
4. `platform-k8s-bastion` supplies the bastion runtime installed by `platform-config`.

`platform-config` does not create VMs, generate cloud-init SSH keys, inject public keys, manage OpenTofu state, or store secrets.

Public examples in this document use RFC 5737 documentation IPs such as `192.0.2.0/24` and example hostnames such as `gitlab.example.test`. Replace them with real values from `../platform-private/config/` or your outside-Git secret store before running commands.

## Current Coverage vs Future Phases

This runbook is complete for the currently implemented homelab and unaffected dev
services. The rebuilt OpenBao service role foundation is staged and its strict
read-only direct-node status gate is available. OpenBao-hosted monitoring
observers now have a separate guarded stage/activate/smoke workflow, but their
real endpoints remain unavailable until monitoring is deployed. OpenBao service
activation, initialization, and HA smoke remain blocked. Monitoring etcd now has
separate inactive staging, read-only preflight, and confirmation-gated initial
bootstrap workflows, but none run merely by merging this repository. The
remaining monitoring services and active HA handoff are still blocked. Do not
use `site.yml` to bypass the phased handoff.

| Area | Environment | Status | Runbook Coverage |
|---|---|---|---|
| Proxmox template prerequisite | shared | implemented in `platform-template-builder` | prerequisite commands and handoff notes |
| VM provisioning | homelab, dev | implemented in `platform-infra` | key handoff and plan/apply flow |
| Base OS | homelab, dev | implemented | full bring-up commands |
| Persistent storage | homelab, dev | implemented | full bring-up commands |
| Podman host foundation | homelab, dev | implemented | full bring-up and smoke commands |
| GitLab CE | homelab | implemented | full bring-up, smoke, and root password handling |
| Zot registry | dev | implemented | full bring-up and smoke commands |
| OpenBao HA | dev | service foundation, read-only status, and observer orchestration staged | immutable image, direct-node role and status, inventory, bounded storage, and guarded monitoring observers; no active OpenBao service apply or HA smoke command |
| GitLab runners | dev | implemented | full bring-up and smoke commands |
| Monitoring HA | dev | etcd staging and bootstrap implemented; replacement otherwise blocked | guarded stopped etcd formation only; Patroni, Garage, Loki, Mimir, Grafana, active ingress, and collectors remain unavailable |
| RKE2 and bundled Traefik | dev | implemented | full bring-up and smoke commands for the base cluster and default ingress controller |
| kube-vip API HA | dev | implemented | RKE2 HelmChart-based API VIP commands and smoke checks |
| Kong ingress controller | dev | optional | alternative RKE2 HelmChart-based classic Ingress controller with fixed NodePorts |
| External workload load balancer | dev | implemented | native HAProxy VM commands and smoke checks through the selected ingress controller's NodePorts |
| Kubernetes bastion live integration | dev | implemented | cluster access workflow and smoke checks |

## Template Prerequisite

Build and smoke-test the Proxmox template before running `platform-infra`. The current private environments use the Rocky 10.1 template from `platform-template-builder`.

For full template-builder setup, see `../platform-template-builder/README.md` and `../platform-template-builder/docs/proxmox-requirements.md`.

Install `platform-tools` once per its README before running these commands. The platform runbooks assume installed helper commands such as `platform-ssh-init` and `platform-pki` are available on `PATH`, typically under `~/.local/bin`.

From `platform-template-builder`:

```bash
command -v platform-ssh-init
make init-ssh TEMPLATE=rocky-10.1 CONFIG_ROOT=../platform-private/template-builder
make init-ssh TEMPLATE=rocky-10.1 CONFIG_ROOT=../platform-private/template-builder SSH_TEST=1
make check-tools TEMPLATE=rocky-10.1 CONFIG_ROOT=../platform-private/template-builder
make validate TEMPLATE=rocky-10.1 CONFIG_ROOT=../platform-private/template-builder
make build TEMPLATE=rocky-10.1 CONFIG_ROOT=../platform-private/template-builder
```

Smoke-test the template with a temporary IP that is not part of the homelab or dev workload ranges:

```bash
make smoke-test TEMPLATE=rocky-10.1 CONFIG_ROOT=../platform-private/template-builder \
  SMOKE_TEST_IPV4=<temporary-ip/cidr> \
  SMOKE_TEST_GATEWAY=<gateway-ip> \
  SMOKE_TEST_DNS=<dns-ip> \
  SMOKE_TEST_SSH_KEY=~/.ssh/<cloud-init-test-key>
```

Confirm the private `platform-infra` tfvars point at the validated template VM ID before applying infrastructure:

```hcl
template_vm_id = <validated-template-vm-id>
```

Replace the placeholder with the current local validated value. Check `../platform-private/infra/<env>.tfvars` and the Proxmox template before changing it.

## Local Setup

Run from the `platform-config` repository root:

```bash
make deps
make help
```

`make deps` builds the Podman development container with Ansible, lint tooling, and Ansible Galaxy collections from the repository requirements files.

## Version Pinning And Updates

Application and platform software installed directly by `platform-config` must be version-pinned and configurable. Normal convergence should reproduce the declared version and stay idempotent; updates should happen only after changing the version variable intentionally, applying the relevant playbook, running the smoke playbook, and running a second apply with `changed=0` expected.

Examples of pinned software include container image tags, downloaded external tools with checksums, Node Exporter release versions, the vendored bastion runtime version, and the RKE2 version. RKE2 specifically fails preflight unless `rke2_version` is set, unless `rke2_allow_unpinned: true` is used for an intentional one-off discovery install.

OS package installation is different: roles expose package lists as variables, and private inventory may use exact package specs where appropriate, but reproducible RPM versions are only reliable when the enabled repositories are pinned, snapshotted, or protected with versionlock. Do not treat a bare package name from a moving OS repo as a reproducible version pin.

Controlled update flow:

```bash
make check ENV=dev PLAYBOOK=playbooks/<service>.yml
make apply ENV=dev PLAYBOOK=playbooks/<service>.yml
make smoke-<service> ENV=dev
make apply ENV=dev PLAYBOOK=playbooks/<service>.yml
```

For RKE2, update `rke2_version` in the private environment, keep the server and agent play serial order from `playbooks/rke2.yml`, then run `make smoke-rke2 ENV=dev` and a final idempotency apply.

## Private Environment Files

The normal private files are:

```text
../platform-private/config/homelab.ansible.env
../platform-private/config/dev.ansible.env
```

Each file exports only path and environment selection values:

```bash
export PLATFORM_PRIVATE_CONFIG_ROOT="$HOME/Projects/public/platform-private/config"
export PLATFORM_INFRASTRUCTURE_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure/config"
export PLATFORM_CONFIG_ENVIRONMENT="homelab"
export PLATFORM_CONFIG_INVENTORY="$PLATFORM_PRIVATE_CONFIG_ROOT/inventories/homelab/hosts.yml"
```

Use a new shell or source the matching file when switching environments:

```bash
source ../platform-private/config/homelab.ansible.env
source ../platform-private/config/dev.ansible.env
```

The Makefile sources the selected `ENV_FILE` automatically for Ansible commands. Native Ansible commands still need the env file sourced manually.

## SSH Key Handoff

Cloud-init SSH keys are created during the `platform-infra` workflow, not by `platform-config`.

From `platform-infra`:

```bash
make init-ssh ENV=homelab PRIVATE=1
make init-ssh ENV=dev PRIVATE=1
```

That target calls `platform-tools` through `platform-ssh-init` and creates one local keypair per VM:

```text
~/.ssh/platform-infra-<env>-<vm-key>-cloud-init_ed25519
~/.ssh/platform-infra-<env>-<vm-key>-cloud-init_ed25519.pub
```

For example:

```text
~/.ssh/platform-infra-homelab-gitlab-example-cloud-init_ed25519
~/.ssh/platform-infra-dev-registry-example-cloud-init_ed25519
```

`platform-infra` reads the `.pub` file and injects it into the VM through cloud-init. Its `ansible_inventory_map` output includes the private key path for handoff to `platform-config`:

```bash
cd ../platform-infra/environments/homelab
source ../../../platform-private/infra/homelab.tofu.env
~/.local/bin/tofu output ansible_inventory_map
```

`platform-config` consumes that value through inventory:

```yaml
ansible_ssh_private_key_file: ~/.ssh/platform-infra-homelab-gitlab-example-cloud-init_ed25519
```

Do not commit private SSH keys or generated public keys to any repository.

## Outside-Git Secret Store

Durable configuration secrets belong outside Git under the local platform
namespace. Short-lived PKI passphrase files are the exception and should come
from temporary secret-manager mounts:

```text
~/.config/platform-infrastructure/
```

Current expected paths include:

```text
~/.config/platform-infrastructure/pki/export/ansible/ca/root-ca.crt
~/.config/platform-infrastructure/pki/export/ansible/services/gitlab-example/fullchain.crt
~/.config/platform-infrastructure/pki/export/ansible/services/gitlab-example/tls.key
~/.config/platform-infrastructure/pki/export/ansible/services/registry-example/fullchain.crt
~/.config/platform-infrastructure/pki/export/ansible/services/registry-example/tls.key
~/.config/platform-infrastructure/pki/export/ansible/services/openbao-example-01/fullchain.crt
~/.config/platform-infrastructure/pki/export/ansible/services/openbao-example-01/tls.key
~/.config/platform-infrastructure/config/rke2/dev/cluster-token
~/.config/platform-infrastructure/config/k8s-bastion/dev/admin.kubeconfig
```

Runner tokens, GitLab root passwords, OpenBao root or unseal material, kubeconfigs, private keys, and service passwords must not be committed.

## TLS Material

The current first-iteration environments use `platform-tools` PKI service certificates with DNS/IP SANs because internal DNS is not available yet. Use `platform-tools` 1.2.0 or newer so encrypted CA keys can be used non-interactively through restricted passphrase files.

The PKI source of truth lives under:

```text
~/.config/platform-infrastructure/pki/
```

The exported Ansible input files live under:

```text
~/.config/platform-infrastructure/pki/export/ansible/
```

Use exported `fullchain.crt` files for services and `ca/root-ca.crt` for clients that need to trust those services. Do not point Ansible at `services/<name>/certs/tls.crt` unless the service explicitly handles an intermediate chain another way.

Current service names:

| Service | Certificate Consumer | Client Trust Consumers |
|---|---|---|
| `gitlab-example` | Example GitLab CE | Example GitLab runners |
| `registry-example` | Example Zot registry | Example RKE2/containerd |
| `openbao-example-01..03` | Future OpenBao HA nodes | Shared service DNS and each node's internal DNS; issuance remains blocked pending HA PKI review |

Provide CA passphrases through short-lived secret-manager files outside the PKI
tree. The following paths are examples; each file must be readable by the
invoking user, mode `0600` or stricter, and contain a first line of at least 16
characters with non-whitespace content:

```text
/run/secrets/platform-pki-root-pass
/run/secrets/platform-pki-intermediate-pass
```

Do not store passphrase files beside the encrypted CA keys. Keeping both in the
same PKI tree causes backups to contain the key and its passphrase together.

For installations created from an older version of this runbook, migrate in
stages. First provision the replacement secret-manager files without removing
the existing files. Confirm that each replacement unlocks its CA key:

```bash
openssl pkey \
  -in ~/.config/platform-infrastructure/pki/root-ca/private/root-ca.key \
  -passin file:/run/secrets/platform-pki-root-pass \
  -noout -check
openssl pkey \
  -in ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.key \
  -passin file:/run/secrets/platform-pki-intermediate-pass \
  -noout -check
```

Only after both checks pass, move the old passphrase files to an owner-only
quarantine outside `pki/`, preserving their original CA-relative locations:

```bash
(
  set -euo pipefail
  umask 077

  legacy_root="$HOME/.config/platform-infrastructure/legacy"
  root_source="$HOME/.config/platform-infrastructure/pki/root-ca/private/root-ca.pass"
  intermediate_source="$HOME/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass"

  [[ -f $root_source && ! -L $root_source ]]
  [[ -f $intermediate_source && ! -L $intermediate_source ]]
  root_identity=$(stat -c '%d:%i' "$root_source")
  intermediate_identity=$(stat -c '%d:%i' "$intermediate_source")
  [[ ! -L $legacy_root ]]
  install -d -m 700 "$legacy_root"
  legacy_dir=$(mktemp -d "$legacy_root/pki-passphrases-$(date +%Y%m%d)-XXXXXX")
  printf 'Migration quarantine: %s\n' "$legacy_dir"
  trap 'status=$?; if (( status != 0 )); then printf "Migration failed; inspect and reconcile %s before retrying.\n" "$legacy_dir" >&2; fi' EXIT
  install -d -m 700 "$legacy_dir/root-ca/private" \
    "$legacy_dir/intermediate-ca/private"

  root_copy="$legacy_dir/root-ca/private/root-ca.pass"
  intermediate_copy="$legacy_dir/intermediate-ca/private/intermediate-ca.pass"
  install -m 600 "$root_source" "$root_copy"
  install -m 600 "$intermediate_source" "$intermediate_copy"
  cmp --silent "$root_source" "$root_copy"
  cmp --silent "$intermediate_source" "$intermediate_copy"
  [[ $(stat -c '%d:%i' "$root_source") == "$root_identity" ]]
  [[ $(stat -c '%d:%i' "$intermediate_source") == "$intermediate_identity" ]]
  rm -- "$root_source" "$intermediate_source"
  trap - EXIT
  printf 'Quarantined passphrases under %s\n' "$legacy_dir"
)
```

Keep the quarantine until CA operations have succeeded with the replacement
secret source and recovery has been proven. Encrypted backups created before
migration may contain both keys and passphrases; retain them as sensitive
recovery material or remove them according to the reviewed backup-retention
policy. Never retain a plain backup containing both.

After replacement-secret CA operations and recovery validation succeed,
explicitly retire the quarantine through the approved secret-disposal process;
do not leave plaintext passphrase copies there indefinitely. Review encrypted
backups and other copies containing the quarantined files under the same
retention decision before declaring the migration complete.

Initial PKI setup:

```bash
platform-pki init
platform-pki root-create \
  --name "Example Platform Root CA" \
  --org "Example Platform" \
  --country "XX" \
  --root-pass-file /run/secrets/platform-pki-root-pass
platform-pki intermediate-create \
  --name "Example Platform Intermediate CA" \
  --org "Example Platform" \
  --country "XX" \
  --root-pass-file /run/secrets/platform-pki-root-pass \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
```

Define and review services in the canonical private source at
`../platform-private/pki/services.yml`:

```yaml
services:
  gitlab-example:
    common_name: gitlab.example.test
    dns:
      - gitlab.example.test
    ips:
      - 192.0.2.51
    days: 397

  registry-example:
    common_name: registry.example.test
    dns:
      - registry.example.test
    ips:
      - 192.0.2.61
    days: 397

```

Install the reviewed snapshot into the protected runtime namespace before
issuing or renewing certificates:

```bash
platform-pki inventory-install \
  --private-repo /absolute/path/to/platform-private
```

Issue and export service certificates:

```bash
platform-pki service-issue gitlab-example \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
platform-pki service-issue registry-example \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
platform-pki service-verify gitlab-example
platform-pki service-verify registry-example
platform-pki export-ansible --force
```

After issuing or renewing, deploy the exported files with the matching playbooks:

```bash
make apply ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make apply ENV=dev PLAYBOOK=playbooks/gitlab-runners.yml
make apply ENV=dev PLAYBOOK=playbooks/registry.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
```

Run the matching smoke checks:

```bash
make smoke-gitlab
make smoke-runners ENV=dev
make smoke-registry ENV=dev
make smoke-rke2 ENV=dev
```

## PKI Operations

List service certificate expiry:

```bash
platform-pki list-expiry --warn-days 90 --critical-days 30
```

Print one service certificate:

```bash
platform-pki print-cert registry-example
```

Renew a service certificate while reusing the existing service private key:

```bash
platform-pki service-renew registry-example \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
platform-pki service-verify registry-example
platform-pki export-ansible --force
make apply ENV=dev PLAYBOOK=playbooks/registry.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
make smoke-registry ENV=dev
make smoke-rke2 ENV=dev
```

Rotate a service private key and certificate when the key may be exposed or a rotation is intentionally scheduled:

```bash
platform-pki service-renew registry-example \
  --rotate-key \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
platform-pki service-verify registry-example
platform-pki export-ansible --force
make apply ENV=dev PLAYBOOK=playbooks/registry.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
make smoke-registry ENV=dev
make smoke-rke2 ENV=dev
```

Use the same pattern for GitLab, but include runner trust deployment:

```bash
platform-pki service-renew gitlab-example \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
platform-pki service-verify gitlab-example
platform-pki export-ansible --force
make apply ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make apply ENV=dev PLAYBOOK=playbooks/gitlab-runners.yml
make smoke-gitlab
make smoke-runners ENV=dev
```

Do not issue or renew replacement OpenBao certificates from this generic flow.
The HA PKI gate requires three node-specific certificates, a shared service DNS
SAN, per-node internal DNS SANs, and reviewed trust distribution before any
service apply.

Back up the PKI state after initial CA creation, after issuing certificates, and after every renewal or key rotation:

```bash
platform-pki backup --age-recipient "$AGE_RECIPIENT"
```

Plain backups are allowed only with an explicit override and still contain secrets:

```bash
platform-pki backup --allow-plain-backup
```

If service IPs or hostnames change, update and review
`../platform-private/pki/services.yml`, install the new snapshot with
`platform-pki inventory-install`, renew the affected certificate, export again,
apply the matching service role, and run the matching smoke check. Root or
intermediate CA rotation is a separate trust-rollover operation and should not
be treated as a normal service certificate renewal.

### Host-Local Zot Certificate Workflow

This operator-only workflow keeps the leaf private key on one registry target.
Configure the real one-host inventory, reviewed five-file trust, reviewed CA,
validation boundary, protected controller exchange root, and a distinct
read-only runner in private or outside-Git configuration. See
[Host-Local Registry PKI Workflow](registry-host-local-pki-workflow.md) for the
complete request, controlled-media approval/signing, response activation,
evidence, signer decision, outcome import, recovery, backup, and verification
sequence. See [Registry](registry.md#host-local-pki-development) for the detailed
trust and lifecycle contract.

Bootstrap target trust once, then create or resume the target-local request. The
default direct mode publishes coordinates but moves no bytes through Ansible:

```bash
make apply ENV=dev PLAYBOOK=playbooks/registry-pki-trust.yml \
  LIMIT=registry-example
make registry-pki-request ENV=dev LIMIT=registry-example
platform-pki direct-exchange request-pull \
  /outside-git/pki-endpoints/registry-example.json <request-id> \
  /outside-git/pki-exchange/intake/request-<request-id>
PLATFORM_CONFIG_PKI_EXCHANGE_ROOT=/outside-git/pki-exchange \
make registry-pki-request-intake ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> REQUEST_SHA256=<request-sha256> \
  CSR_SHA256=<csr-sha256> CSR_SPKI_SHA256=<csr-spki-sha256> \
  TRANSPORT_HOST_KEY_SHA256=<transport-host-key-sha256> \
  REQUEST_DIR=/platform-pki-exchange/intake/request-<request-id>
make registry-pki-status ENV=dev LIMIT=registry-example
```

Move the public request through the separately approved controlled-media and
offline-signing process. Place the returned exact six-file response in a
protected controller directory, authenticate it without target mutation, and
push it to the fixed direct ingress before activating it with one separate
runner:

```bash
make registry-pki-response-check ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  RESPONSE_DIR=/outside-git/protected-response
platform-pki direct-exchange response-push \
  /outside-git/pki-endpoints/registry-example.json <request-id> \
  <artifact-sha256> /outside-git/protected-response
make registry-pki-activate ENV=dev LIMIT=registry-example \
  RUNNER_LIMIT=registry-validator-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256>
```

Activation prompts for exactly:

```text
activate SERVICE REQUEST_ID ARTIFACT_SHA256
```

If authenticated status reports recovery is required, run only the explicit
journal-bound recovery action:

```bash
make registry-pki-recover ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256>
```

If recovery reports `publish-rolled-back-evidence`, validate the restored
predecessor locally and from the reviewed runner and publish its exact evidence:

```bash
make registry-pki-publish-rolled-back-evidence ENV=dev \
  LIMIT=registry-example RUNNER_LIMIT=registry-validator-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256>
```

After successful activation, prepare, pull, and authenticate the exact evidence,
then perform a fresh separate-runner decision preflight. After the offline
decision, push the exact outcome before importing it:

```bash
make registry-pki-evidence-export ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  DEPLOYMENT_SHA256=<deployment-sha256>
platform-pki direct-exchange evidence-pull \
  /outside-git/pki-endpoints/registry-example.json <request-id> \
  <artifact-sha256> <deployment-sha256> \
  /outside-git/pki-exchange/intake/evidence-<deployment-sha256>
PLATFORM_CONFIG_PKI_EXCHANGE_ROOT=/outside-git/pki-exchange \
make registry-pki-evidence-intake ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  DEPLOYMENT_SHA256=<deployment-sha256> \
  EVIDENCE_DIR=/platform-pki-exchange/intake/evidence-<deployment-sha256>
make registry-pki-status ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  DEPLOYMENT_SHA256=<deployment-sha256>
make registry-pki-decision-preflight ENV=dev LIMIT=registry-example \
  RUNNER_LIMIT=registry-validator-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  DEPLOYMENT_SHA256=<deployment-sha256>
platform-pki direct-exchange outcome-push \
  /outside-git/pki-endpoints/registry-example.json <request-id> \
  <artifact-sha256> <deployment-sha256> <outcome-sha256> \
  /outside-git/pki-exchange/intake/outcome-<outcome-sha256>
make registry-pki-outcome-import ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  DEPLOYMENT_SHA256=<deployment-sha256> \
  OUTCOME_SHA256=<outcome-sha256>
```

Only after an active version authenticates successfully, change the target's
private Zot inventory to `zot_registry_tls_custody: host-local`, set
`zot_registry_tls_host_local_target` to the exact inventory hostname, and run
normal registry convergence. Signing, response and outcome retrieval from
external media, renewal, and live enablement remain separate operations. Outcome
import is the explicit command above; never select a latest package or infer its
coordinates. Require status `complete` and `signer_outcome_state=finalized` for
a finalized active candidate. An authenticated abandoned outcome is terminal
history but never authority for selecting the abandoned candidate as active;
current import supports that terminal status for no predecessor and authenticated
managed-migration rollback. Finalized managed predecessors must exactly match
rollback certificate/SPKI/public-chain state and use `none` for unavailable
managed history fields. Managed rollback abandonment must also match signed
served identity evidence to the restored Zot-selected public chain. Host-local
predecessors remain unsupported until target history records all required
predecessor evidence.
The current workflow always reports `renewal_eligible=false`; authenticated
renewal completion remains unsupported.

Direct outcome import never transfers the package through Ansible. It consumes
only the exact fixed-spool package created by `outcome-push` and never stats,
opens, reads, hashes, stages, or transfers a
candidate/version/restored-managed private-key file. Managed rollback validation
parses the restored Zot TLS path object but accesses only its public certificate
chain. In Ansible check mode the controller still authenticates the complete
six-file package, but only canonical scalar coordinates reach the target's
read-only preflight over Ansible's safely quoted, become-aware low-level
connection path; no module payload, temporary transfer, or package copy is
created. The target authenticates active state from public version,
signed request/response, artifact/certificate, and available signed evidence
without enumerating or accessing the version private key. If an interruption
leaves immutable outcome
history without `accepted-outcome`, status fails closed; rerun the same command
with the same exact pins to complete no-clobber pointer publication. If the
action reports a retained `/var/tmp/.platform-pki-outcome-*` stage, preserve it
as failure evidence, verify no import remains active, and inspect it through the
approved host-local PKI recovery procedure. Remove only the exact reported
canonical path after attribution; never use wildcard cleanup. A retained
`.accepted-outcome-stage-*` under the lifecycle state root also blocks import as
ambiguous state and requires the same exact-path review before recovery.

## Make Targets

Common commands:

```bash
make inventory ENV=homelab
make inventory ENV=dev
make ping ENV=homelab
make ping ENV=dev
make syntax ENV=homelab
make syntax ENV=dev
make check ENV=dev PLAYBOOK=playbooks/registry.yml
make apply ENV=dev PLAYBOOK=playbooks/registry.yml
```

Useful variables:

```text
ENV        Environment name: homelab or dev
PLAYBOOK   Playbook to run, default playbooks/site.yml
LIMIT      Optional Ansible --limit value
EXTRA_ARGS Extra flags passed to Ansible
REQUEST_ID Exact 32-character host-local PKI request ID
ARTIFACT_SHA256 Exact host-local PKI artifact digest
DEPLOYMENT_SHA256 Exact host-local PKI deployment digest
OUTCOME_DIR Exact protected six-file signer-outcome directory
OUTCOME_SHA256 Exact host-local PKI outcome manifest digest
RESPONSE_DIR Exact protected six-file response directory
RUNNER_LIMIT Exact separate read-only validation runner host
```

Examples:

```bash
make check ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make apply ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make smoke-gitlab
make smoke-container ENV=dev
make smoke-registry ENV=dev
```

The `smoke-firewalld` target verifies the disabled and inactive baseline. See
[Firewalld Readiness And Enablement](firewalld.md) before defining a live
policy or enabling enforcement on a canary host.

Use the Make `LIMIT` variable with an example host such as `gitlab-example` when a
run should target only one host.

Native equivalents remain supported:

```bash
./scripts/in-container sh -c '. ../platform-private/config/dev.ansible.env && ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml --check --diff'
```

## Container Runtime Kernel Policy

Podman and RKE2 require OverlayFS. By default, the public
`container_runtime_kernel` role enables the explicit
`platform-container-runtime-overlayfs-exception.service`, which loads the
module with `modprobe --ignore-install overlay` without changing third-party
files under `/etc/modprobe.d`. This is an intentional, auditable exception for
container-runtime hosts whose baseline replaces normal module loading with an
`install overlay ...` command.

Private inventory can disable the managed exception where normal host policy
already permits OverlayFS:

```yaml
container_runtime_overlayfs_policy_exception_enabled: false
```

The role proves normal policy can load OverlayFS before removing an existing
managed exception unit. An install override or blacklist fails closed and
preserves the working unit. The role never unloads OverlayFS and never changes
the Podman storage driver.

After applying a container-runtime playbook, verify the selected policy state
through the relevant smoke target. Enabled mode must show the managed unit as
enabled and active; disabled mode must show it absent. Both modes require
`/sys/module/overlay`.

## Homelab Bring-Up

Homelab owns shared homelab services such as GitLab CE. Dev may depend on them, but dev does not configure them.

Prerequisites from `platform-infra`:

```bash
cd ../platform-infra
make deps
make env ENV=homelab PRIVATE=1
make init-ssh ENV=homelab PRIVATE=1
make validate ENV=homelab
cd environments/homelab
source ../../../platform-private/infra/homelab.tofu.env
~/.local/bin/tofu plan
~/.local/bin/tofu apply
```

Configure homelab from `platform-config`:

```bash
make inventory ENV=homelab
make ping ENV=homelab
make check ENV=homelab PLAYBOOK=playbooks/base-os.yml
make apply ENV=homelab PLAYBOOK=playbooks/base-os.yml
make apply ENV=homelab PLAYBOOK=playbooks/base-os.yml
make smoke-firewalld ENV=homelab
make check ENV=homelab PLAYBOOK=playbooks/storage-volumes.yml
make apply ENV=homelab PLAYBOOK=playbooks/storage-volumes.yml
make apply ENV=homelab PLAYBOOK=playbooks/storage-volumes.yml
make check ENV=homelab PLAYBOOK=playbooks/container-runtime.yml
make apply ENV=homelab PLAYBOOK=playbooks/container-runtime.yml
make apply ENV=homelab PLAYBOOK=playbooks/container-runtime.yml
make smoke-container ENV=homelab
make check ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make apply ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make apply ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make smoke-gitlab
```

GitLab CE is available at the URL configured in private inventory. In public examples this is shown as:

```text
https://gitlab.example.test
```

### GitLab First Login

Use the built-in GitLab administrator account for the first login:

```text
Username: root
URL: https://gitlab.example.test
```

If the first iteration uses a self-signed certificate, trust the certificate from your outside-Git store or accept the browser warning only after confirming the certificate fingerprint matches your generated certificate.

Retrieve the generated GitLab `root` password only from the host and store it outside Git:

```bash
ssh -i ~/.ssh/platform-infra-homelab-gitlab-example-cloud-init_ed25519 rocky@gitlab.example.test \
  'sudo grep "Password:" /var/lib/gitlab/config/initial_root_password'
```

After first login, change the `root` password immediately, create named admin users, and store long-lived credentials outside Git. The generated password file is temporary and may be removed by GitLab after the first day and restart/reconfigure cycle.

## Dev Bring-Up

Dev owns dev services and runners. It only requires homelab GitLab CE to be reachable.

Prerequisites from `platform-infra`:

```bash
cd ../platform-infra
make deps
make env ENV=dev PRIVATE=1
make init-ssh ENV=dev PRIVATE=1
make validate ENV=dev
cd environments/dev
source ../../../platform-private/infra/dev.tofu.env
~/.local/bin/tofu plan
~/.local/bin/tofu apply
```

Configure dev from `platform-config`:

```bash
make inventory ENV=dev
make ping ENV=dev
make check ENV=dev PLAYBOOK=playbooks/base-os.yml
make apply ENV=dev PLAYBOOK=playbooks/base-os.yml
make apply ENV=dev PLAYBOOK=playbooks/base-os.yml
make smoke-firewalld ENV=dev
make check ENV=dev PLAYBOOK=playbooks/storage-volumes.yml
make apply ENV=dev PLAYBOOK=playbooks/storage-volumes.yml
make apply ENV=dev PLAYBOOK=playbooks/storage-volumes.yml
make check ENV=dev PLAYBOOK=playbooks/container-runtime.yml
make apply ENV=dev PLAYBOOK=playbooks/container-runtime.yml
make apply ENV=dev PLAYBOOK=playbooks/container-runtime.yml
make smoke-container ENV=dev
make check ENV=dev PLAYBOOK=playbooks/registry.yml
make apply ENV=dev PLAYBOOK=playbooks/registry.yml
make apply ENV=dev PLAYBOOK=playbooks/registry.yml
make smoke-registry ENV=dev
```

The combined monitoring phase playbook intentionally fails at this point. The
focused monitoring etcd lane can stage all three members while disabled and
stopped after private inventory supplies the exact topology, PKI, XFS source,
firewall, and SELinux contract. Staging, preflight, and bootstrap are separate
operator decisions:

```bash
make check ENV=dev PLAYBOOK=playbooks/monitoring-etcd.yml LIMIT=monitoring
make apply ENV=dev PLAYBOOK=playbooks/monitoring-etcd.yml LIMIT=monitoring
make apply ENV=dev PLAYBOOK=playbooks/maintenance/monitoring-etcd-bootstrap-preflight.yml LIMIT=monitoring
make apply ENV=dev PLAYBOOK=playbooks/maintenance/monitoring-etcd-bootstrap.yml LIMIT=monitoring
```

The bootstrap command requires a real TTY and an exact approval containing all
three selected hosts and the observed cluster-signature digest. It reruns the
read-only preflight immediately after approval, starts all three members only for
initial formation, requires two stable mTLS health observations, and stops all
members before publishing completion markers. It does not enable etcd or
authorize Patroni. Do not retry after partial state; preserve the data and
diagnose it through a separately reviewed recovery procedure.

After reviewing all three completion markers, set
`monitoring_etcd_activation_ready: true` and persist the initialized cluster:

```bash
make activate-monitoring-etcd ENV=dev LIMIT=monitoring
make status-monitoring-etcd ENV=dev LIMIT=monitoring
```

Activation requires another exact TTY approval. Any failed start, persistent
Quadlet transition, or final health gate restores the inactive Quadlet on every
reachable member. A successful activation is live and boot-enabled, but does not
authorize Patroni until the separate PostgreSQL implementation and acceptance
gates exist. Both commands require an explicit limit that selects exactly the
three monitoring hosts and no other inventory hosts. Activation is a one-shot
inactive-to-active transition: after success use status rather than rerunning
activation. If a host was unreachable or the transition left partial state,
reconcile that state through a separately reviewed recovery procedure before any
retry.

The OpenBao playbook can stage its complete three-node foundation, but only after inventory,
strict SSH trust, generic baseline, approved storage initialization, PKI, package,
network, and source-policy inputs pass their gates. Set
`openbao_orchestration_ready: true` only with all three component roles enabled
and all OpenBao, HAProxy, and Keepalived services disabled and stopped. Then use:

```bash
make check ENV=dev PLAYBOOK=playbooks/openbao.yml
make apply ENV=dev PLAYBOOK=playbooks/openbao.yml
# Run a second apply to confirm idempotency.
make apply ENV=dev PLAYBOOK=playbooks/openbao.yml
```

This stages configuration and permanent offline firewall policy; it does not
initialize or unseal OpenBao, start a service, run observers, or assign the VIP.
On apply, all-host component input validation completes before the playbook
disables and stops any existing Keepalived, HAProxy, and OpenBao services, then
temporarily masks OpenBao and starts role convergence. A failed staging run
leaves OpenBao masked; successful convergence unblocks the newly disabled unit.
Do not use `site.yml` while monitoring remains blocked.

The external monitoring probes and the one native Alloy process on each OpenBao
host have a separate fresh-start workflow. It is not an OpenBao service
activation path and never initializes, unseals, joins, restores, promotes, or
changes either VIP. Recreate pre-start development VMs rather than adding legacy
state migration logic.

Keep `openbao_observers_activate: false` for the first convergence. Set
`openbao_observers_orchestration_ready: true`, `platform_external_probe_enabled:
true`, and `grafana_alloy_enabled: true` only after all three hosts have their
outside-Git CA, client identities, Garage credentials, exact PostgreSQL 18
client, authenticated monitoring VIP endpoints, and Mimir remote-write path.
The playbook requires all three canonical OpenBao hosts and derives every Alloy
service and configured probe timer state from the one activation selector.

```bash
make syntax-openbao-observers ENV=dev
make check ENV=dev PLAYBOOK=playbooks/openbao-observers.yml
make deploy-openbao-observers ENV=dev
# Run a second staged apply to confirm idempotency.
make deploy-openbao-observers ENV=dev
```

After staged configuration review, set `openbao_observers_activate: true` in
private inventory and run:

```bash
make deploy-openbao-observers ENV=dev
make smoke-openbao-observers ENV=dev
# Confirm active desired-state idempotency.
make deploy-openbao-observers ENV=dev
```

Observer smoke requires Alloy readiness, the exact RPM identity, native complete
configuration validation, successful blackbox results, active configured timers,
fresh evidence for any genuinely node-local VIP ownership collector, one
read-only PostgreSQL primary result, and one successful unambiguous Garage
PUT/GET/digest/DELETE canary on every observer. The public OpenBao-host example
does not claim node-local ownership of the monitoring VIP because that VIP is
owned by monitoring nodes. Observer smoke does not replace strict OpenBao status
or OpenBao HA smoke. The existing `smoke-openbao` target remains blocked.

Before configuring dev GitLab runners, confirm homelab GitLab is reachable from the runner hosts:

```bash
./scripts/in-container sh -c '. ../platform-private/config/dev.ansible.env && ansible -i "$PLATFORM_CONFIG_INVENTORY" gitlab_runners -m uri -a "url=https://gitlab.example.test/users/sign_in validate_certs=false status_code=200"'
```

Runner authentication tokens are created in GitLab and stored outside Git. Do not put runner tokens in public examples, plain private vars, shell history, or logs.

When the first managed runner must configure itself before another Ansible
control node is available, follow
[GitLab Runner Self-Bootstrap](gitlab-runner-self-bootstrap.md). That workflow
keeps the full host baseline under Ansible while the runner host temporarily
acts as both controller and managed node.

For a controlled host that cannot use the normal Ansible workflow, follow
[Manual GitLab Runner Deployment](gitlab-runner-manual-deployment.md). The
manual procedure reproduces only the runner service, not the complete managed
host baseline.

Create GitLab group runners before running the runner playbook. Use pre-created runner authentication tokens from the GitLab UI; these usually start with `glrt-`. Recommended group runner tags are:

| Runner | Tags |
|---|---|
| registry runner | `dev`, `linux-amd64`, `registry` |
| Kubernetes runner | `dev`, `linux-amd64`, `k8s`, `docker` |

Store the token files outside Git and restrict them to the local owner:

```bash
mkdir -p ~/.config/platform-infrastructure/config/gitlab-runners/dev
chmod 700 ~/.config/platform-infrastructure/config/gitlab-runners/dev
chmod 600 ~/.config/platform-infrastructure/config/gitlab-runners/dev/*.token
```

Expected token paths:

```text
~/.config/platform-infrastructure/config/gitlab-runners/dev/registry-runner-example.token
~/.config/platform-infrastructure/config/gitlab-runners/dev/k8s-runner-example.token
```

Configure dev GitLab runners:

```bash
make check ENV=dev PLAYBOOK=playbooks/gitlab-runners.yml
make apply ENV=dev PLAYBOOK=playbooks/gitlab-runners.yml
# Run a second apply to confirm idempotency.
make apply ENV=dev PLAYBOOK=playbooks/gitlab-runners.yml
make smoke-runners ENV=dev
```

The default runner remains a shell executor inside the persistent manager
container and has no runtime socket. An opted-in Docker executor mounts the
rootful Podman API socket into the manager only and creates disposable build,
helper, and service containers per job. It requires a digest-pinned fallback
image, `FF_NETWORK_PER_BUILD`, and `privileged = false`. Never put the socket or
a static SSH key in Docker job volumes; use protected GitLab file variables for
deployment SSH credentials. Container-image build capability remains a separate
explicit design and is not enabled by this executor mode.

The retired single-host Prometheus/Loki/Grafana stack is no longer deployable.
Keep `monitoring_targets` empty until authenticated Loki and Mimir ingress,
source policy, and a test collector pass the replacement plan's Phase 7 gate.

RKE2 uses a shared cluster token stored outside Git:

```text
~/.config/platform-infrastructure/config/rke2/dev/cluster-token
```

Configure the six-node Kubernetes path with focused playbooks. Do not use
`site.yml` or `scripts/run-dev.sh` while the monitoring phase remains blocked.

```bash
make check ENV=dev PLAYBOOK=playbooks/rke2.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
make smoke-rke2 ENV=dev
# Run a second apply to confirm idempotency.
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
```

RKE2 uses the dev Zot registry through `registries.yaml`. On Enterprise Linux 10, the role installs `kernel-modules-extra` for `br_netfilter`; `overlay` is provided by `kernel-modules-core`. After its guarded kernel transition, RKE2 consumes the shared container-runtime OverlayFS policy and continues to own `br_netfilter` plus the Kubernetes networking sysctls. Set `rke2_reboot_for_kernel_modules: true` only where the role may perform a controlled serial reboot when the installed module package targets a newer kernel. On clean nodes, the role verifies the exact boot target and module availability after reboot before installing or starting RKE2. An installed node must be active, API-healthy where applicable, and Kubernetes `Ready` before reboot; it must return `Ready` before the serial play advances.

Kernel transitions use `/var/lib/rke2-kernel-reboot-target` to record the exact expected kernel and `/var/lib/rke2-kernel-reboot-readiness` to retain pending cluster-readiness validation for an existing node. An interruption after the target marker is written but before reboot fails closed on the next run; boot the recorded target, verify both required modules, and rerun the role. Clean nodes need only complete that kernel verification. For existing nodes, a retained readiness marker automatically resumes the service, API, and Kubernetes `Ready` gates without issuing another reboot. Remove the target marker manually only after the recorded kernel and modules are verified, and remove the readiness marker only after the installed node is healthy and `Ready`.

Set `platform_ingress_controller: traefik` for the default bundled RKE2 controller or `platform_ingress_controller: kong` for the optional Kong alternative. RKE2 releases before 1.36 require the explicit `ingress-controller: traefik` setting; the role renders it rather than relying on release-dependent defaults. Bundled Traefik uses a managed `HelmChartConfig` to expose fixed worker NodePorts `30080` and `30443` without also binding host ports `80` and `443`.

RKE2 must be pinned with `rke2_version` in the private environment. The default role preflight rejects unpinned installs; use `rke2_allow_unpinned: true` only for a deliberate temporary discovery run, then pin the discovered version immediately before normal convergence.

kube-vip API HA is installed after the base RKE2 cluster through an RKE2 `HelmChart` manifest written by `playbooks/rke2-kube-vip.yml`. Keep it API-only for this phase; workload service load balancing and ingress remain separate later work.

```bash
make check ENV=dev PLAYBOOK=playbooks/rke2-kube-vip.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2-kube-vip.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2-kube-vip.yml
make smoke-rke2-kube-vip ENV=dev
```

The private environment must set the API VIP, the server interface that reaches that VIP, and pinned kube-vip chart and application image versions. The role explicitly configures the upstream `15/10/2`-second lease duration, renewal deadline, and retry period to tolerate transient API or etcd latency. It verifies the VIP is already in `rke2_tls_sans`, validates the leader-election timing relationships, and confirms that each RKE2 server routes the VIP through the configured interface.

Kong is an explicit alternative selected with `platform_ingress_controller: kong`. The RKE2 role then configures `ingress-controller: none`, and the separate Kong phase installs a pinned HelmChart after kube-vip. This mode supports classic Kubernetes `Ingress` only; Gateway API CRDs and `Gateway`/`HTTPRoute` resources are deferred. Kong exposes the same fixed proxy NodePorts so the external load-balancer contract does not change. With the default Traefik selection, do not apply the Kong installation phase; run its smoke playbook only to verify Kong resources are absent.

Apply and smoke-test the RKE2 selector change before running the Kong playbook. The Kong role fails closed if packaged Traefik resources still exist.

Do not change the selector on an existing cluster as an ordinary convergence operation. First migrate application `Ingress` resources to the destination class, explicitly uninstall the previous controller, confirm `30080` and `30443` are free, and then apply the destination controller. Deleting only an RKE2 manifest file does not uninstall resources previously applied from it.

```bash
make smoke-kong-ingress ENV=dev
```

Only when Kong is selected and its private pins are configured:

```bash
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
make smoke-rke2 ENV=dev
make check ENV=dev PLAYBOOK=playbooks/kong-ingress.yml
make apply ENV=dev PLAYBOOK=playbooks/kong-ingress.yml
make apply ENV=dev PLAYBOOK=playbooks/kong-ingress.yml
make smoke-kong-ingress ENV=dev
```

The dev external workload load balancer uses native HAProxy on a VM outside RKE2. It forwards to the selected ingress controller's worker NodePorts so dev mirrors the production F5-to-worker-node pattern.

```bash
make check ENV=dev PLAYBOOK=playbooks/workload-lb.yml
make apply ENV=dev PLAYBOOK=playbooks/workload-lb.yml
# Run a second apply to confirm idempotency.
make apply ENV=dev PLAYBOOK=playbooks/workload-lb.yml
make smoke-workload-lb ENV=dev
```

After the cluster exists, copy or extract the admin kubeconfig to the outside-Git secret store:

```text
~/.config/platform-infrastructure/config/k8s-bastion/dev/admin.kubeconfig
```

## Dev Kubernetes Bastion Integration

Apply bastion integration after the RKE2 cluster and its access inputs exist.

Required inputs:

```text
~/.config/platform-infrastructure/config/k8s-bastion/dev/admin.kubeconfig
../platform-private/config/files/k8s-bastion/dev/ca.crt
../platform-private/config/files/k8s-bastion/dev/access-policy.yaml
```

Expected commands:

```bash
make check ENV=dev PLAYBOOK=playbooks/k8s-bastion-access.yml
make apply ENV=dev PLAYBOOK=playbooks/k8s-bastion-access.yml
make apply ENV=dev PLAYBOOK=playbooks/k8s-bastion-smoke.yml
```

Use the Make `LIMIT` variable with the target host's private inventory name
when the run should target only that bastion host.

See [Kubernetes Bastion](k8s-bastion.md) for the role-specific workflow and safety notes.

## Day-2 Operations

### Credentials

Manage application credentials in the application or an approved secret store, not in public Ansible vars.

GitLab CE:

```bash
ssh -i ~/.ssh/platform-infra-homelab-gitlab-example-cloud-init_ed25519 rocky@gitlab.example.test \
  'sudo grep "Password:" /var/lib/gitlab/config/initial_root_password'
```

After the first login, change the `root` password and create named admin users. Store long-lived credentials outside Git. The generated initial password file is temporary.

OpenBao:

```text
The standalone deployment is retired. The replacement HA playbook is blocked and
no initialization or unseal workflow is available through normal convergence.
```

After an initialized three-node cluster and a dedicated least-privilege status
identity exist, store its token in an owner-private file outside Git and set
`openbao_status_token_src` to that absolute controller path in private inventory.
The token policy needs only:

```hcl
path "sys/storage/raft/configuration" {
  capabilities = ["read"]
}
```

Run the read-only direct-node and Raft gate with:

```bash
make status-openbao ENV=dev LIMIT=openbao
```

The gate requires strict TLS, one active node, two standbys, exactly three
expected voters, one matching leader, and stable repeated Raft observations. It
does not initialize, unseal, restart, or reconfigure OpenBao, and it is not an
HAProxy or VIP smoke check.

After the cluster has been initialized and live qualification explicitly allows
a configuration change that may restart voters, use the maintenance-only path:

```bash
make roll-openbao ENV=dev LIMIT=openbao
```

The command requires the complete three-host group and an initially strict
healthy cluster. It snapshots the current active node, queues both standbys
first, and processes one host at a time. If leadership changes relative to that
plan, the run aborts before converging the affected host. After an actual restart
it stops for two approved custodians to manually unseal that node, then
independently requires all three healthy voters before continuing. Pressing
Enter never substitutes for the status gate. Do not run this workflow before
cluster initialization or use it to initialize, join, unseal, restore, or reset
OpenBao.

Runner tokens:

```text
Create in GitLab, store outside Git, and rotate from GitLab when exposed or no longer needed.
```

Grafana credentials for the replacement platform remain outside Git and are not
consumed until the HA role and named-account bootstrap workflow exist.

### Backups

Backup automation is not implemented in `platform-config` yet. Until a dedicated backup role or repository exists, treat these paths as critical data sources:

| Service | Host | Data Path |
|---|---|---|
| GitLab CE | `gitlab.example.test` | `/var/lib/gitlab` |
| Zot registry | `registry.example.test` | `/var/lib/zot` |
| OpenBao HA | `openbao-example-01..03` | Bounded Raft, two audit, and staging filesystems; backup automation pending |
| Monitoring HA | `monitoring-example-01..03` | Bounded per-service filesystems; backup automation pending |
| RKE2 | `rke2-server-example-01..03.example.test`, `rke2-agent-example-01..03.example.test` | `/var/lib/rancher/rke2` |

Do not assume service data can be recreated from Ansible alone. For stateful services, validate backups before destructive rebuilds.

### Rebuild And Recovery

Use [Rebuild](rebuild.md) for generic host rebuild rules. Short version:

1. Recreate the VM with `platform-infra`.
2. Confirm Ansible inventory and SSH key paths match the new VM.
3. Apply base OS, storage, and service playbooks in order.
4. Restore or reattach stateful data according to the service runbook.
5. Run the relevant smoke playbook.

Do not encode one-time restore or migration logic in `site.yml`. Use maintenance playbooks or service runbooks for restore validation.

### Certificate Rotation

For the current self-signed certificates:

1. Generate a replacement certificate/key pair outside Git.
2. Confirm SANs include the IPs and hostnames used by clients.
3. Apply the owning service playbook.
4. Run the service smoke playbook.
5. Update any clients that pin the old certificate.

### Host Key Changes

If a VM is rebuilt and SSH host keys change, remove only the affected local
known-hosts entry after authenticating the replacement fingerprint through a
trusted console or equivalent path:

```bash
ssh-keygen -R 192.0.2.51
```

Enroll the independently authenticated key using an approved SSH trust workflow.
Do not trust unauthenticated `ssh-keyscan` output by itself or disable host key
checking globally.

## Full Site Runs

Use phase playbooks for first bring-up and for risky changes. Dev `site.yml` is
currently blocked because it imports the fail-closed OpenBao and monitoring
transition playbooks. Use it only after every imported playbook has accepted
inputs and the replacement service roles exist.

```bash
make check ENV=homelab
make apply ENV=homelab
```

Run the same apply command a second time to confirm idempotency. The expected steady-state result is `changed=0` unless a service legitimately refreshes runtime state.

## Verification Before Commit

Run from `platform-config`:

```bash
make syntax ENV=homelab
make syntax ENV=dev
make verify
./scripts/in-container yamllint ../platform-private/config/inventories/homelab ../platform-private/config/inventories/dev ../platform-private/config/plans
git diff --check
```

For implemented service changes, also run the matching smoke playbook against
the environment that owns the service. OpenBao-hosted observer smoke is
available separately; OpenBao HA and monitoring HA smoke targets remain
intentionally blocked.
