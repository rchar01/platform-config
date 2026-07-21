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

This runbook is complete for the currently implemented homelab and dev services. Future phases are documented as prerequisites and placeholders until their roles and playbooks exist.

| Area | Environment | Status | Runbook Coverage |
|---|---|---|---|
| Proxmox template prerequisite | shared | implemented in `platform-template-builder` | prerequisite commands and handoff notes |
| VM provisioning | homelab, dev | implemented in `platform-infra` | key handoff and plan/apply flow |
| Base OS | homelab, dev | implemented | full bring-up commands |
| Persistent storage | homelab, dev | implemented | full bring-up commands |
| Podman host foundation | homelab, dev | implemented | full bring-up and smoke commands |
| GitLab CE | homelab | implemented | full bring-up, smoke, and root password handling |
| Zot registry | dev | implemented | full bring-up and smoke commands |
| OpenBao install/status | dev | implemented | full bring-up and read-only status smoke commands |
| GitLab runners | dev | implemented | full bring-up and smoke commands |
| Monitoring | dev | implemented | full bring-up and smoke commands for VM monitoring |
| RKE2 | dev | implemented | full bring-up and smoke commands for the base cluster |
| kube-vip API HA | dev | implemented | RKE2 HelmChart-based API VIP commands and smoke checks |
| Kong ingress controller | dev | implemented | RKE2 HelmChart-based classic Ingress controller with fixed NodePorts |
| External workload load balancer | dev | implemented | native HAProxy VM commands and smoke checks through Kong NodePorts |
| Kubernetes bastion live integration | dev | not implemented yet | placeholder and existing bastion docs only |

## Template Prerequisite

Build and smoke-test the Proxmox template before running `platform-infra`. The current private environments use the Rocky 10.1 template from `platform-template-builder`.

For full template-builder setup, see `../platform-template-builder/README.md` and `../platform-template-builder/docs/proxmox-requirements.md`.

Install `platform-tools` once per its README before running these commands. The platform runbooks assume installed helper commands such as `platform-ssh-init` and `platform-pki-init` are available on `PATH`, typically under `~/.local/bin`.

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

Secrets belong outside Git under the local platform namespace:

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
~/.config/platform-infrastructure/pki/export/ansible/services/openbao-example/fullchain.crt
~/.config/platform-infrastructure/pki/export/ansible/services/openbao-example/tls.key
~/.config/platform-infrastructure/pki/root-ca/private/root-ca.pass
~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass
~/.config/platform-infrastructure/config/rke2/dev/cluster-token
~/.config/platform-infrastructure/config/k8s-bastion/dev/admin.kubeconfig
~/.config/platform-infrastructure/config/monitoring/dev/grafana-admin-password
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
| `openbao-example` | Example OpenBao | None yet |

The CA passphrase files must be outside Git and mode `0600` or stricter:

```bash
install -d -m 700 ~/.config/platform-infrastructure/pki/root-ca/private
install -d -m 700 ~/.config/platform-infrastructure/pki/intermediate-ca/private
openssl rand -out ~/.config/platform-infrastructure/pki/root-ca/private/root-ca.pass -base64 48
openssl rand -out ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass -base64 48
chmod 600 ~/.config/platform-infrastructure/pki/root-ca/private/root-ca.pass
chmod 600 ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass
```

Initial PKI setup:

```bash
platform-pki-init
platform-pki-root-create \
  --name "Example Platform Root CA" \
  --org "Example Platform" \
  --country "XX" \
  --root-pass-file ~/.config/platform-infrastructure/pki/root-ca/private/root-ca.pass
platform-pki-intermediate-create \
  --name "Example Platform Intermediate CA" \
  --org "Example Platform" \
  --country "XX" \
  --root-pass-file ~/.config/platform-infrastructure/pki/root-ca/private/root-ca.pass \
  --intermediate-pass-file ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass
```

Define services in `~/.config/platform-infrastructure/pki/inventory/services.yml`:

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

  openbao-example:
    common_name: openbao.example.test
    dns:
      - openbao.example.test
    ips:
      - 192.0.2.63
    days: 397
```

Issue and export service certificates:

```bash
platform-pki-service-issue gitlab-example \
  --intermediate-pass-file ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass
platform-pki-service-issue registry-example \
  --intermediate-pass-file ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass
platform-pki-service-issue openbao-example \
  --intermediate-pass-file ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass
platform-pki-service-verify gitlab-example
platform-pki-service-verify registry-example
platform-pki-service-verify openbao-example
platform-pki-export-ansible --force
```

After issuing or renewing, deploy the exported files with the matching playbooks:

```bash
make apply ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make apply ENV=dev PLAYBOOK=playbooks/gitlab-runners.yml
make apply ENV=dev PLAYBOOK=playbooks/registry.yml
make apply ENV=dev PLAYBOOK=playbooks/openbao.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
```

Run the matching smoke checks:

```bash
make smoke-gitlab
make smoke-runners ENV=dev
make smoke-registry ENV=dev
make smoke-openbao ENV=dev
make smoke-rke2 ENV=dev
```

## PKI Operations

List service certificate expiry:

```bash
platform-pki-list-expiry --warn-days 90 --critical-days 30
```

Print one service certificate:

```bash
platform-pki-print-cert registry-example
```

Renew a service certificate while reusing the existing service private key:

```bash
platform-pki-service-renew registry-example \
  --intermediate-pass-file ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass
platform-pki-service-verify registry-example
platform-pki-export-ansible --force
make apply ENV=dev PLAYBOOK=playbooks/registry.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
make smoke-registry ENV=dev
make smoke-rke2 ENV=dev
```

Rotate a service private key and certificate when the key may be exposed or a rotation is intentionally scheduled:

```bash
platform-pki-service-renew registry-example \
  --rotate-key \
  --intermediate-pass-file ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass
platform-pki-service-verify registry-example
platform-pki-export-ansible --force
make apply ENV=dev PLAYBOOK=playbooks/registry.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
make smoke-registry ENV=dev
make smoke-rke2 ENV=dev
```

Use the same pattern for GitLab, but include runner trust deployment:

```bash
platform-pki-service-renew gitlab-example \
  --intermediate-pass-file ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass
platform-pki-service-verify gitlab-example
platform-pki-export-ansible --force
make apply ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make apply ENV=dev PLAYBOOK=playbooks/gitlab-runners.yml
make smoke-gitlab
make smoke-runners ENV=dev
```

Use the same pattern for OpenBao:

```bash
platform-pki-service-renew openbao-example \
  --intermediate-pass-file ~/.config/platform-infrastructure/pki/intermediate-ca/private/intermediate-ca.pass
platform-pki-service-verify openbao-example
platform-pki-export-ansible --force
make apply ENV=dev PLAYBOOK=playbooks/openbao.yml
make smoke-openbao ENV=dev
```

Back up the PKI state after initial CA creation, after issuing certificates, and after every renewal or key rotation:

```bash
platform-pki-backup --age-recipient "$AGE_RECIPIENT"
```

Plain backups are allowed only with an explicit override and still contain secrets:

```bash
platform-pki-backup --allow-plain-backup
```

If service IPs or hostnames change, update `~/.config/platform-infrastructure/pki/inventory/services.yml`, renew the affected certificate, export again, apply the matching service role, and run the matching smoke check. Root or intermediate CA rotation is a separate trust-rollover operation and should not be treated as a normal service certificate renewal.

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
```

Examples:

```bash
make check ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make apply ENV=homelab PLAYBOOK=playbooks/gitlab.yml
make smoke-gitlab
make smoke-container ENV=dev
make smoke-registry ENV=dev
make smoke-openbao ENV=dev
```

Use the Make `LIMIT` variable with an example host such as `gitlab-01` when a
run should target only one host.

Native equivalents remain supported:

```bash
./scripts/in-container sh -c '. ../platform-private/config/dev.ansible.env && ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml --check --diff'
```

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
make check ENV=dev PLAYBOOK=playbooks/openbao.yml
make apply ENV=dev PLAYBOOK=playbooks/openbao.yml
make apply ENV=dev PLAYBOOK=playbooks/openbao.yml
make smoke-openbao ENV=dev
```

Before configuring dev GitLab runners, confirm homelab GitLab is reachable from the runner hosts:

```bash
./scripts/in-container sh -c '. ../platform-private/config/dev.ansible.env && ansible -i "$PLATFORM_CONFIG_INVENTORY" gitlab_runners -m uri -a "url=https://gitlab.example.test/users/sign_in validate_certs=false status_code=200"'
```

Runner authentication tokens are created in GitLab and stored outside Git. Do not put runner tokens in public examples, plain private vars, shell history, or logs.

Create GitLab group runners before running the runner playbook. Use pre-created runner authentication tokens from the GitLab UI; these usually start with `glrt-`. Recommended group runner tags are:

| Runner | Tags |
|---|---|
| registry runner | `dev`, `linux-amd64`, `registry` |
| Kubernetes runner | `dev`, `linux-amd64`, `k8s` |

Store the token files outside Git and restrict them to the local owner:

```bash
mkdir -p ~/.config/platform-infrastructure/config/gitlab-runners/dev
chmod 700 ~/.config/platform-infrastructure/config/gitlab-runners/dev
chmod 600 ~/.config/platform-infrastructure/config/gitlab-runners/dev/*.token
```

Expected token paths:

```text
~/.config/platform-infrastructure/config/gitlab-runners/dev/registry-runner-01.token
~/.config/platform-infrastructure/config/gitlab-runners/dev/k8s-runner.token
```

Configure dev GitLab runners:

```bash
make check ENV=dev PLAYBOOK=playbooks/gitlab-runners.yml
make apply ENV=dev PLAYBOOK=playbooks/gitlab-runners.yml
# Run a second apply to confirm idempotency.
make apply ENV=dev PLAYBOOK=playbooks/gitlab-runners.yml
make smoke-runners ENV=dev
make check ENV=dev PLAYBOOK=playbooks/monitoring.yml
make apply ENV=dev PLAYBOOK=playbooks/monitoring.yml
# Run a second apply to confirm idempotency.
make apply ENV=dev PLAYBOOK=playbooks/monitoring.yml
make smoke-monitoring ENV=dev
make check ENV=dev PLAYBOOK=playbooks/rke2.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
# Run a second apply to confirm idempotency.
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
make smoke-rke2 ENV=dev
```

The first runner iteration uses the shell executor inside containerized GitLab Runner services. It does not mount Docker or Podman sockets and does not enable privileged image-build support. BuildKit, Buildah, or rootless Podman build support belongs in a later explicit phase.

The first monitoring iteration monitors VMs only. It installs Node Exporter on `monitoring_targets` and runs Prometheus plus Grafana on the `monitoring` host. In the current dev inventory, Prometheus binds to localhost port `9091` to avoid Cockpit on `9090`. Kubernetes scraping is a later monitoring expansion. Store the Grafana admin password outside Git at:

```text
~/.config/platform-infrastructure/config/monitoring/dev/grafana-admin-password
```

RKE2 uses a shared cluster token stored outside Git:

```text
~/.config/platform-infrastructure/config/rke2/dev/cluster-token
```

RKE2 uses the dev Zot registry through `registries.yaml`. The role manages required `br_netfilter`/`overlay` kernel modules and Kubernetes networking sysctls. If package updates installed a newer kernel and the running kernel lacks those modules, reboot the affected RKE2 nodes before applying the role again.

RKE2 must be pinned with `rke2_version` in the private environment. The default role preflight rejects unpinned installs; use `rke2_allow_unpinned: true` only for a deliberate temporary discovery run, then pin the discovered version immediately before normal convergence.

kube-vip API HA is installed after the base RKE2 cluster through an RKE2 `HelmChart` manifest written by `playbooks/rke2-kube-vip.yml`. Keep it API-only for this phase; workload service load balancing and ingress remain separate later work.

```bash
make check ENV=dev PLAYBOOK=playbooks/rke2-kube-vip.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2-kube-vip.yml
make apply ENV=dev PLAYBOOK=playbooks/rke2-kube-vip.yml
make smoke-rke2-kube-vip ENV=dev
```

The private environment must set the API VIP, the server interface that reaches that VIP, and the pinned kube-vip chart version. The kube-vip role verifies the VIP is already in `rke2_tls_sans` and that each RKE2 server routes the VIP through the configured interface.

The Kong ingress controller is installed after kube-vip as a separate RKE2 HelmChart-based add-on. This first phase supports classic Kubernetes `Ingress` only; Gateway API CRDs and `Gateway`/`HTTPRoute` resources are deferred. Kong exposes fixed proxy NodePorts so external load balancers can target worker node IPs.

```bash
make check ENV=dev PLAYBOOK=playbooks/kong-ingress.yml
make apply ENV=dev PLAYBOOK=playbooks/kong-ingress.yml
make apply ENV=dev PLAYBOOK=playbooks/kong-ingress.yml
make smoke-kong-ingress ENV=dev
```

The dev external workload load balancer uses native HAProxy on a VM outside RKE2. It forwards to Kong worker NodePorts so dev mirrors the production F5-to-worker-node pattern.

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

## Future Phases

The following sections define the expected workflow shape for planned phases. They are not executable until the named roles and playbooks exist.

### Dev Kubernetes Bastion Integration

Status: not implemented yet.

Real bastion integration waits for the RKE2 cluster and real cluster inputs.

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

Use the Make `LIMIT` variable with the example bastion host `k8s-bastion-01`
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
Installed and running, but intentionally uninitialized and sealed until a manual or guarded maintenance procedure exists.
```

Runner tokens:

```text
Create in GitLab, store outside Git, and rotate from GitLab when exposed or no longer needed.
```

Grafana:

```text
The generated admin password is stored outside Git under ~/.config/platform-infrastructure/config/monitoring/dev/grafana-admin-password. Change it through Grafana after first login if this instance becomes more than a lab service.
```

### Backups

Backup automation is not implemented in `platform-config` yet. Until a dedicated backup role or repository exists, treat these paths as critical data sources:

| Service | Host | Data Path |
|---|---|---|
| GitLab CE | `gitlab.example.test` | `/var/lib/gitlab` |
| Zot registry | `registry.example.test` | `/var/lib/zot` |
| OpenBao | `openbao.example.test` | `/var/lib/openbao` |
| future monitoring | `monitoring.example.test` | `/var/lib/monitoring` |
| future RKE2 | `k8s-node-01..06.example.test` | `/var/lib/rancher` |

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

If a VM is rebuilt and SSH host keys change, refresh only the affected local known-hosts entries:

```bash
ssh-keygen -R 192.0.2.51
ssh-keyscan -H 192.0.2.51 >> ~/.ssh/known_hosts
```

Use the target host IP for the rebuilt VM. Do not disable host key checking globally.

## Full Site Runs

Use phase playbooks for first bring-up and for risky changes. Use `site.yml` once the environment is already converged enough that every imported playbook has required inputs.

```bash
make check ENV=homelab
make apply ENV=homelab
make check ENV=dev
make apply ENV=dev
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

For service changes, also run the matching smoke playbook against the environment that owns the service.
