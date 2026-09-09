# Private Workflow

Use this document for production-grade local operator runs with private configuration from `platform-private` and local secrets from `~/.config/platform-infrastructure/`.

For the full command sequence, including `platform-infra` handoff, per-environment bring-up order, service smoke checks, and GitLab root password handling, see [Operator Runbook](operator-runbook.md).

`platform-config` is public. It contains Ansible code, safe examples, helper scripts, and documentation only.

Real non-secret environment configuration belongs in the sibling private repository:

```text
../platform-private/config/
```

## Boundary

Public `platform-config` may contain:

- roles
- playbooks
- helper scripts
- safe `.example` inventories and variables
- non-secret defaults
- documentation

Private `platform-private/config` contains real non-secret operational inputs:

- real inventories
- real `group_vars` and `host_vars`
- private hostnames or IPs when sensitive
- SSH user and connection details
- CA certificates
- access policies
- optional `container.hostaliases` entries in `hostname:IPv4` form for private
  names required by development-container controller checks
- vault-encrypted secrets

Local outside-Git config contains secret material such as real admin kubeconfigs, token files, vault password files, and private keys:

```text
~/.config/platform-infrastructure/config/
```

Do not commit real inventories, kubeconfigs, tokens, passwords, private keys, private certificates, private host configuration, or vault password files to `platform-config`.

## Expected Layout

```text
platform-private/
  config/
    container.hostaliases
    homelab.ansible.env
    dev.ansible.env
    inventories/
      homelab/
        hosts.yml
        group_vars/
        host_vars/
      dev/
        hosts.yml
        group_vars/
        host_vars/
    files/
      k8s-bastion/
        homelab/
          access-policy.yaml
          ca.crt
        dev/
          access-policy.yaml
          ca.crt
    vault/
      homelab.yml
      dev.yml

~/.config/platform-infrastructure/
  config/
    k8s-bastion/
      homelab/
        admin.kubeconfig
      dev/
        admin.kubeconfig
```

The `*.ansible.env` files should set paths and environment selection only. Do not put secret values in them.

## Environment Files

Run commands from the `platform-config` repository root. The examples use the
sibling private repository by default; set `PLATFORM_PRIVATE_CONFIG_ROOT` to an
absolute config-directory path before sourcing a file when using another
layout.

Homelab example:

```bash
export PLATFORM_PRIVATE_CONFIG_ROOT="${PLATFORM_PRIVATE_CONFIG_ROOT:-../platform-private/config}"
export PLATFORM_INFRASTRUCTURE_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure/config"
export PLATFORM_CONFIG_ENVIRONMENT="homelab"
export PLATFORM_CONFIG_INVENTORY="$PLATFORM_PRIVATE_CONFIG_ROOT/inventories/homelab/hosts.yml"
```

Dev example:

```bash
export PLATFORM_PRIVATE_CONFIG_ROOT="${PLATFORM_PRIVATE_CONFIG_ROOT:-../platform-private/config}"
export PLATFORM_INFRASTRUCTURE_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure/config"
export PLATFORM_CONFIG_ENVIRONMENT="dev"
export PLATFORM_CONFIG_INVENTORY="$PLATFORM_PRIVATE_CONFIG_ROOT/inventories/dev/hosts.yml"
```

Source the matching file before native Ansible operations:

```bash
source ../platform-private/config/homelab.ansible.env
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml
```

Use a new shell or source the matching env file whenever switching environments.

## Helper Scripts

The helper scripts source the matching private env file automatically when it exists:

```bash
./scripts/run-homelab.sh
./scripts/run-dev.sh
./scripts/ansible-ping.sh
```

The repository Makefile provides the same environment-aware operations with documented targets:

```bash
make help
make inventory ENV=homelab
make ping ENV=dev
make check ENV=dev PLAYBOOK=playbooks/registry.yml
make apply ENV=homelab PLAYBOOK=playbooks/gitlab.yml
```

Explicit environment variables or command-line inventory arguments still take precedence:

```bash
PLATFORM_CONFIG_INVENTORY=../platform-private/config/inventories/homelab/hosts.yml \
  ./scripts/run-homelab.sh --check --diff
```

```bash
./scripts/run-dev.sh --inventory ../platform-private/config/inventories/dev/hosts.yml --check
```

## OpenBao Without DNS

DNS infrastructure is optional for OpenBao; the service hostname and its TLS
identity are required. Keep `openbao_service_dns` set to the reviewed service
hostname present in the certificate's DNS SANs. Static host mappings change
address resolution, not certificate identity or CA trust. For VIP qualification,
the service name must resolve only to the configured VIP from the actual
controller or CI job environment.

Use the existing mechanism for each resolution context, with real values kept
in private configuration. The examples below use the SAN service hostname
`bao.example.invalid` and documentation-only VIP `192.0.2.86`:

1. **Development-container controller:** put one whitespace-free `hostname:IPv4`
   mapping per line in `../platform-private/config/container.hostaliases`:

   ```text
   bao.example.invalid:192.0.2.86
   ```

   `scripts/in-container` reads this optional file in its development profile
   and passes the mappings to Podman. For a different file, export its host-side
   path **before launching** the wrapper or Make target:

   ```bash
   export PLATFORM_CONFIG_CONTAINER_HOST_ALIASES_FILE="$PWD/../platform-private/config/container.hostaliases"
   ./scripts/in-container getent ahostsv4 bao.example.invalid
   ```

   Setting the variable inside an already-running container, or in an env file
   sourced only after launch, is too late. The sanitized test profile does not
   load private aliases.

2. **GitLab Runner Docker jobs, helpers, and services:** set the existing private
   Runner variable; these containers do not inherit the manager host's
   `/etc/hosts`:

   ```yaml
   gitlab_runner_docker_extra_hosts:
     - bao.example.invalid:192.0.2.86
   ```

   Append to the existing list and preserve its other mappings.

   Updating an existing registration requires a controlled one-time
   `gitlab_runner_force_register: true` apply from a separate controller while
   the Runner is paused and idle. Keep a separate operator rollback backup and
   use a literal `--limit` (Make `LIMIT`) equal to that one Runner's exact
   inventory hostname, then immediately return force registration to false.
   See [Runner registration](../roles/gitlab_runner/README.md#registration).

3. **Managed hosts:** use private `platform_host_aliases` entries with `address`
   and `names` through the `common` role for host-local `/etc/hosts` resolution,
   including required canonical node names. This is separate from controller
   and Docker job mappings; it does not configure either container context.

Keep public alias defaults empty. Existing `getent` and `curl` checks accept
NSS host mappings; no DNS-free flag is needed. A successful lookup proves only
name resolution, not routing, TLS, service health, or VIP ownership. Use pre-VIP
`smoke-openbao` before Keepalived activation; run `smoke-openbao-vip` only after
successful activation and the reviewed active desired-state handoff described
in [OpenBao VIP Acceptance](operator-runbook.md#openbao-vip-acceptance).

## Rocky Repository Policy

Repository files remain externally managed. Private inventory may enable the
`rocky_repository_policy` role with the exact effective DNF release version,
repository IDs, origins, local signing-key URLs, and signature-check settings.
Origins require HTTPS unless private inventory explicitly enables the temporary
HTTP `baseurl` exception; mirrorlists, metalinks, and signing keys remain strict.
The policy must not contain credentials. Package-consuming roles invoke this
read-only gate before DNF operations; they do not repair drift.

Validate one host without running package roles:

```bash
make check ENV=dev \
  PLAYBOOK=playbooks/maintenance/rocky-repository-policy.yml \
  LIMIT=dev-example-01
```

This check reads configured DNF repositories without refreshing metadata. It
does not prove repository reachability, package availability, immutable content,
or signing-key bytes. Keep policy disabled on a host until its exact repository
state and SSH identity have been reviewed.

## Kubernetes Bastion Inputs

Private inventory should point the bastion role at private non-secret files and outside-Git secret files:

```yaml
k8s_bastion_policy_src: ../platform-private/config/files/k8s-bastion/homelab/access-policy.yaml
k8s_bastion_admin_kubeconfig_src: "{{ k8s_bastion_local_secret_config_dir }}/k8s-bastion/homelab/admin.kubeconfig"
k8s_bastion_ca_src: ../platform-private/config/files/k8s-bastion/homelab/ca.crt
```

`k8s_bastion_policy_src` must be the final rendered access policy. Policy rendering and private overlay merging happen before Ansible or outside this repository.

When using the shared renderer from `platform-tools`, validate and render the private source policy before running Ansible:

```bash
platform-bastion-policy validate \
  --input ../platform-private/config/files/k8s-bastion/homelab/access-policy.yaml

platform-bastion-policy render-host \
  --input ../platform-private/config/files/k8s-bastion/homelab/access-policy.yaml \
  --output /tmp/k8s-bastion-access-policy.yaml

platform-bastion-policy render-csr-configmap \
  --input ../platform-private/config/files/k8s-bastion/homelab/access-policy.yaml \
  --name bastion-csr-policy \
  --namespace bastion-system \
  --output /tmp/bastion-csr-policy.configmap.yaml
```

`platform-tools` renders files only. `platform-config` still owns installing the host policy and applying Kubernetes resources through explicit playbook or operator workflow steps.

## Secrets

Do not store unencrypted secret values in this repository.

For production-grade private workflow, keep high-value credentials outside Git under `~/.config/platform-infrastructure/`, in an approved secret manager, or encrypted with Ansible Vault/SOPS when they must live in `platform-private`. The private repository may contain non-secret paths, access policies, CA certificates, and environment-specific config.

Never commit:

- raw private keys
- vault password files
- runner registration tokens
- registry passwords
- kubeconfigs for real clusters
- Kubernetes certificates or service account tokens
- OpenBao tokens
- private CA key material
- production service passwords

For strict OpenBao status checks, keep the dedicated read-only token in an
owner-private `0600` file under the outside-Git secret store. Private
inventory may reference its absolute path through `openbao_status_token_src`,
but must not contain the token value. Use
`~/.config/platform-infrastructure/config/openbao/<environment>/status.token`.
The status identity needs only `read` on `sys/storage/raft/configuration` and
`read` plus `sudo` on `sys/audit`; the token is read on the controller and is
not copied to an OpenBao node.

## Validation

After sourcing the environment file:

```bash
ansible-inventory -i "$PLATFORM_CONFIG_INVENTORY" --graph
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml --syntax-check
```

For a first run against a clean host, start with:

```bash
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml --check --diff
```

Then apply from the selected environment only after confirming the target hosts and variables are correct.

After a successful bastion apply, run the smoke playbook:

```bash
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/k8s-bastion-smoke.yml --limit k8s-bastion-01
```

The smoke playbook is non-changing and checks installed commands, required `/etc/bastion` files, and enabled bastion systemd units.
