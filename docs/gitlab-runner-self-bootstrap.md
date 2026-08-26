# GitLab Runner Self-Bootstrap

Use this procedure when the first managed GitLab Runner host must configure
itself before a normal workstation or CI Ansible controller is available. The
host temporarily acts as both:

- the Ansible control node, where the repositories and outside-Git inputs are
  available; and
- the managed node, which Ansible reaches over SSH from the repository's Podman
  development container.

This procedure does not provision the VM, create its initial account, or create
the runner in GitLab. Those steps must be complete before configuration starts.
For a controlled host that cannot run the Ansible workflow, use
[Manual GitLab Runner Deployment](gitlab-runner-manual-deployment.md), which
configures only the runner service and not the complete host baseline.

## Security Boundary

This is an operator-attended recovery/bootstrap procedure, not a CI or
unattended automation entry point. Run each export, preflight, and convergence
command interactively, review its complete output, and stop on any unexpected
state. Runtime deliberately does not try to detect CI or enforce a TTY; operator
attendance is a procedural requirement.

Keep real inventory in the sibling private configuration repository. Keep
tokens, private keys, and other secrets outside every Git repository. Use
fictional values from this guide only as examples.

The Docker executor gives the persistent runner manager access to the rootful
Podman API socket. That socket is host-root-equivalent if the manager is
compromised. Restrict this design to protected runners serving trusted projects,
and never mount the socket or a static deployment key into job containers.

The bootstrap checkout and credentials are control-plane assets. They are not
job workspaces and must not be exposed through runner volumes. GitLab Runner
checks out each project separately for its job.

## Clean Host Contract

Establish the following conditions before the first Ansible command.

### Initial User And Privilege

- A normal administrative account, such as the cloud-init user, exists with a
  writable home directory and interactive shell.
- The account can use rootless Podman.
- `sudo -n true` succeeds without prompting for a password.
- The account can reach itself through the VM's managed network address over
  SSH.
- `sshd` is enabled and running.
- Python 3 is available for Ansible modules.
- The account's home directory and `/tmp` have enough space for Ansible
  temporary files and the development image.

Do not assume that a dedicated `ansible` account already exists. The `users`
role creates that account only when private inventory explicitly enables
`users_manage_ansible_user`. It is valid to retain the initial cloud-init user
as `ansible_user` when that is the reviewed access model.

Choose access ownership explicitly before running `playbooks/bootstrap.yml`:

- keep `users_manage_ansible_user: false` when cloud-init or another approved
  system remains responsible for the initial account and authorized key; or
- enable Ansible ownership and declare every durable authorized key. Include
  the key used by the active bootstrap session until a second connection with
  the intended durable access has succeeded. Before the steady-state apply,
  remove a temporary key from the owning private inventory variables so
  Ansible removes it from the managed account.

The users role can manage authorized keys exclusively. An incomplete key list
can remove the only working access path even though the already-open SSH session
continues long enough for the play to finish.

### Controller Tools

The bootstrap account must be able to run:

- Podman;
- Git;
- Make; and
- an OpenSSH client.

Ansible and its collections do not need to be installed on the host. `make
deps` builds the pinned development image defined by `Containerfile.dev`.

Prefer to install the same exact Podman NEVRA that private inventory will
declare before starting self-bootstrap. Replacing or downgrading the host's
Podman package while the Ansible control container is active is an avoidable
bootstrap risk. The exact package must remain available from an enabled,
approved repository.

### Dedicated Controller Filesystem

The normal home-directory controller remains supported. When a reviewed
bootstrap design provides a dedicated persistent filesystem, select it with
`CONTROLLER_ROOT` to enable the stricter gate. The selected path must be the
exact mountpoint of a current-user-owned, block-backed XFS filesystem mounted
read-write without `noexec`. Both source trees and the effective rootless
Podman graphroot must be below that path and backed by the same filesystem.
Nested mounts and group- or other-writable path components are rejected.

Prepare the filesystem, source layout, subordinate IDs, and rootless Podman
configuration before running preflight. The account needs contiguous
subordinate UID and GID ranges of at least 65,536 IDs plus working `newuidmap`
and `newgidmap` helpers. Use the package-provided runtime default at
`/run/user/<uid>/containers` when it resolves correctly. If the qualified
package selects its `/tmp` fallback despite a valid login runtime directory,
configure `runroot` to that exact `/run/user/<uid>/containers` path. Run
preflight from the account's normal passwd home and default XDG
data/configuration locations. Transient `HOME`, `XDG_RUNTIME_DIR`,
`XDG_CONFIG_HOME`, or `XDG_DATA_HOME` overrides fail the strict gate.

For example, a fictional selected root could contain:

```text
/srv/example-bootstrap/
+-- containers/
|   +-- storage/
+-- source/
    +-- platform-config/
    +-- platform-private/
```

Clone into that `source` directory or extract the history-free archive there.
For this selected-root model, replace the home-directory extraction shown later
in this guide with:

```bash
controller_root=/srv/example-bootstrap
export_name=platform-bootstrap-example.tgz
sudo install -d -o "$(id -u)" -g "$(id -g)" -m 0700 \
  "$controller_root/source"
tar -C "$controller_root/source" -xzf "/tmp/$export_name"
cd "$controller_root/source/platform-config"
```

Update the account's complete `$HOME/.config/containers/storage.conf`, not a
minimal replacement snippet. Retain the reviewed storage driver and every
required `[storage.options]` setting, and set `storage.graphroot` to
`/srv/example-bootstrap/containers/storage`. Omit `storage.runroot` when the
effective package default is correct; otherwise set it only to the current
account's exact `/run/user/<uid>/containers` path. Changing rootless storage
after it contains images or containers is a separate migration operation; do
not copy or repoint populated state casually.

When Ansible must create the dedicated controller filesystem, bootstrap first
from the account's normal home without `CONTROLLER_ROOT`. Converge storage,
remove the temporary rootless development image and storage through a reviewed
cleanup, then configure the new empty graphroot, transfer a fresh source export,
and rebuild with `CONTROLLER_ROOT`. A controller cannot initially run from the
filesystem it is expected to create.

On an SELinux host, the containers-storage contract requires an exact fcontext
equivalence from the canonical rootful storage source
`/var/lib/containers/storage`, followed by a recursive relabel. This applies
the standard container-storage labels to the selected rootless graphroot; it
does not redirect either rootless or rootful Podman storage. For the fictional
path above:

```bash
sudo semanage fcontext -a -e \
  /var/lib/containers/storage \
  /srv/example-bootstrap/containers/storage
sudo restorecon -R -v /srv/example-bootstrap/containers/storage
```

The strict preflight validates the effective Podman graphroot, per-user
configuration, exact runtime-directory runroot, helpers and ID mappings, mount
identity and options, SELinux enforcing state, equivalence policy, and
effective labels. It does not create, relabel, mount, or rewrite any of them.
Omitting `CONTROLLER_ROOT` preserves the existing environment-neutral checks.

### Operating System

The current runner path expects:

- a supported Rocky Linux release on `x86_64`;
- systemd as the service manager;
- DNF and RPM;
- a running kernel that provides OverlayFS, either loaded or available as a
  module; and
- repositories that provide the configured base packages, `kmod`, Chrony,
  firewalld, its Python bindings, the DNF versionlock plugin, and the exact
  Podman NEVRA.

When private inventory enables `rocky_repository_policy`, every package-consuming
role first validates the exact effective DNF release version, repository IDs,
origins, local signing keys, and signature-check settings. HTTPS is required
unless private inventory explicitly enables the temporary HTTP `baseurl`
exception. The validation does not edit repository files or refresh metadata.

Run any OS migration that reboots and performs post-reboot verification from an
external controller. A development container on the managed VM is terminated by
that reboot and cannot reconnect to verify the new release or publish the
migration completion marker. Target self-bootstrap may resume after the
external migration has completed successfully.

Keep the system clock sufficiently accurate for HTTPS before Chrony is
configured. Preserve the normal Rocky SELinux model; the Podman and runner roles
manage their required labels and narrow exception explicitly.

The `common` role expects a safe root-owned cloud-init hosts template at
`/etc/cloud/templates/hosts.redhat.tmpl`. For an image without that template,
set this in private inventory instead of creating a fake file:

```yaml
platform_host_aliases_cloud_init_template: ""
```

The role also expects the normal Rocky `/etc/logrotate.conf` file.

### Network And Name Resolution

The bootstrap host needs:

- a stable address reachable from its rootless Podman container;
- working DNS, routing, and HTTPS CA trust;
- access to both Git repositories;
- access to the GitLab endpoint;
- access to approved OS package repositories;
- access to registries for the development, runner, helper, and job images; and
- access to Debian package mirrors, PyPI, and Ansible Galaxy while building the
  development image, unless that image is imported from an approved source.

Use a GitLab URL whose hostname or IP is present in the service certificate's
subject alternative names. Installing the issuing CA does not fix a hostname
mismatch.

## Self-SSH

The development container is the Ansible control node. Consequently,
`ansible_connection: local` is unsafe for this workflow: `localhost` would be
the development container, not the VM host.

Use one reviewed authentication method:

- deliberately forward an SSH agent for the duration of bootstrap; or
- create a dedicated temporary bootstrap key on the VM and authorize its public
  key for the initial account.

The container wrapper mounts a valid `SSH_AUTH_SOCK` and the bootstrap user's
`~/.ssh` directory. Record the VM host key in `~/.ssh/known_hosts` only after
comparing its fingerprint with an independent console or equivalent trusted
source. Do not disable strict host-key checking.

Some self-bootstrap hosts cannot reach their own managed address through the
rootless Podman bridge, or use SELinux labels that intentionally prevent the
tooling container from reading reviewed bind-mounted source. For that bounded
development-container case, explicitly enable the required exceptions before
invoking the wrapper, or declare these exact literal assignments in the selected
private environment file:

```bash
export PLATFORM_CONFIG_CONTAINER_SELINUX_LABEL_DISABLE=true
export PLATFORM_CONFIG_CONTAINER_HOST_NETWORK=true
```

Both variables accept only `true` or `false`, default to `false`, and are
rejected by the sanitized test profile. `label=disable` removes SELinux process
separation only from the disposable tooling container; it does not disable host
SELinux. Host networking shares the host network namespace and must be enabled
only when the reviewed self-connection path requires it. Keep strict SSH host
key checking and the normal outside-Git secret boundary enabled. The attended
self-bootstrap preflight reads only these two literal boolean assignments from a
validated environment file before it starts the tooling container; it does not
source that shell file on the host.

The resulting connection path is:

```text
bootstrap shell
  -> rootless Podman development container
  -> SSH to the VM's managed address
  -> passwordless sudo
  -> managed host
```

Before running Ansible, verify the same path with an explicit SSH command from
the development container:

```bash
./scripts/in-container sh -c \
  'ssh -o IdentitiesOnly=yes \
    -i "$HOME/.ssh/example-self-bootstrap_ed25519" \
    example-user@192.0.2.50 \
    "sudo -n true && python3 --version"'
```

When using an agent instead of a named identity file, omit `-i` and remove
`IdentitiesOnly=yes` if the intended key is available only through that agent.

## Repository And Secret Layout

Use reviewed revisions of the public and private repositories as siblings:

```text
bootstrap/
+-- platform-config/
+-- platform-private/
```

Cloning both repositories remains supported. When the VM must not receive Git
history, create the project-specific history-free export from the reviewed clean
`platform-config` checkout on the source host. The selected private environment
file and inventory must both be tracked at the private repository's clean
`HEAD`:

```bash
environment=example
export_archive="$HOME/platform-bootstrap-${environment}.tgz"

make runner-self-bootstrap-export \
  ENV="$environment" \
  EXPORT_ARCHIVE="$export_archive"

scp "$export_archive" "$export_archive.sha256" \
  example-user@192.0.2.50:/tmp/
```

The helper exports only tracked files from each repository's exact `HEAD`, adds
deterministic manifests containing the source commits and per-file integrity
metadata, creates an owner-only archive, and writes an owner-only SHA-256
sidecar. It refuses dirty source trees, existing output paths, and untracked or
symlinked selected private inputs. It does not read or include the outside-Git
secret root. The Runner bootstrap does not use the Kubernetes bastion runtime,
so the public repository manifest records the submodule commit but the export
does not include submodule content.

The archive still contains private, environment-specific, non-secret
configuration. Protect it as a control-plane asset and transfer it only through
an approved channel. On the target VM, verify the archive before extraction,
then extract it as the bootstrap user:

```bash
cd /tmp
export_name=platform-bootstrap-example.tgz
sha256sum -c "$export_name.sha256"
install -d -m 0700 "$HOME/bootstrap"
tar -C "$HOME/bootstrap" -xzf "$export_name"
cd "$HOME/bootstrap/platform-config"
```

Do not edit the extracted trees. The self-bootstrap preflight accepts either the
existing clean Git-worktree contract or these manifest-backed exports and fails
on malformed metadata or missing, changed, symlink-substituted, or extra files.
After successful bootstrap, remove the transferred archive and sidecar.

The wrapper discovers the sibling private repository and mounts it read-only
inside the development container. The private environment file and inventory
remain under:

```text
platform-private/config/
+-- example.ansible.env
+-- inventories/
    +-- example/
        +-- hosts.yml
        +-- group_vars/
        +-- host_vars/
```

Install only the required outside-Git files on the bootstrap host:

```text
~/.config/platform-infrastructure/
+-- config/
|   +-- gitlab-runners/
|       +-- example/
|           +-- runner.token
+-- pki/
    +-- export/
        +-- ansible/
            +-- ca/
                +-- root-ca.crt
```

The runner token file must be a regular file with mode `0400` or `0600`. Omit
the CA source when GitLab uses a publicly trusted issuer. Never clone or copy an
entire secret store when only these bounded inputs are required.

## Private Inventory Contract

Use real values only in the private repository. A bootstrap runner normally
belongs to these groups:

```yaml
---
all:
  children:
    rocky:
      hosts:
        example-runner-01:
          ansible_host: 192.0.2.50

    container_hosts:
      hosts:
        example-runner-01:

    gitlab_runners:
      hosts:
        example-runner-01:

    storage_volume_hosts:
      hosts: {}
```

The corresponding private variables must provide:

- the actual SSH user and authentication path or agent policy;
- timezone and any required host aliases;
- the exact approved Podman NEVRA;
- the reachable GitLab URL and optional digest-pinned CA source;
- digest-pinned runner manager, Docker fallback, and helper images;
- Docker executor and manager-only Podman socket settings;
- runner name and intended tags; and
- the outside-Git token source path.

When a private CA source is configured, record the exact file-byte digest from
`sha256sum` as `gitlab_runner_tls_ca_cert_sha256`. The role verifies that digest
both before and after installing the certificate; a certificate fingerprint is
not the same value.

Runner tags are configured on the pre-created GitLab runner object. Inventory
documents the intended tags but does not update them server-side.

## Storage Gate

Choose and review one storage model before convergence.

### Root Filesystem

Leave the host out of `storage_volume_hosts`. The runner role creates
`/var/lib/gitlab-runner`, and rootful Podman uses `/var/lib/containers`. Confirm
that the root filesystem has enough capacity for images, writable layers,
workspaces, and caches.

### New Dedicated Disk

Use only a stable `/dev/disk/by-id/...` or `/dev/disk/by-path/...` source. Before
setting `initialize: true`, independently verify that the disk:

- is not the OS disk;
- has no child partitions;
- has no filesystem, partition, RAID, or LVM signatures; and
- has enough capacity for every declared LV plus required free headroom.

For the automated self-bootstrap preflight, declare the disk through a named
`storage_volume_layouts` entry with positive `capacity_gib`, per-volume
`size_gib`, and reviewed `required_free_gib`. Unbounded direct volume definitions
are valid for the role but intentionally fail this bootstrap readiness gate
because the helper cannot prove a minimum dedicated-disk capacity from them.

Decide explicitly whether the dedicated layout owns
`/var/lib/gitlab-runner`, `/var/lib/containers`, or both. Docker executor image
and container-layer growth is primarily under `/var/lib/containers`; dedicating
only the runner data directory does not move that storage pressure off root.

Configure storage before starting the rootful runner runtime. The rootless
development container uses the bootstrap user's storage and must not place data
under a rootful mountpoint that will later be covered.

### Existing LVM Volume Group

Set `reuse_existing_vg: true` with explicit `initialize: false` only after
confirming the role's reuse contract. The stable partition must be the VG's one
PV, the VG must have no additional PVs, and every existing requested LV must
match its declared non-shrinking size, filesystem, and mountpoint. Never reuse
the OS VG for runner data.

An unmounted future mountpoint must be absent or empty. A nonempty mountpoint is
valid only when it is already backed by the exact declared LV, as with a mounted
`/var`. For `grow_from_size_gib`, the readiness gate accepts only the
extent-rounded reviewed source or target LV size, requires the LV at its exact
mountpoint, and includes pending growth in the VG free-space calculation.

The optional `root_lvm` role is a separate decision. It is disabled by default
and expands only a precisely declared existing LVM-backed root layout; it does
not convert a non-LVM root filesystem or shrink storage.

## Clean Runner State

The preferred initial state has no existing:

- `/etc/gitlab-runner/config.toml`;
- runner Quadlet or `gitlab-runner.service`;
- runner manager container;
- rootful Podman job state under a future storage mountpoint; or
- unsafe Podman versionlock path.

An absent versionlock file is acceptable. An existing file must be a safe
root-owned regular file. If an existing runner configuration is present, the
role validates its declared executor contract and refuses incompatible changes
without an explicit controlled force-registration procedure.

## Preflight

The operator-attended host-side
`scripts/gitlab-runner-self-bootstrap-preflight` helper verifies
the clean-host contract without running Ansible check mode or applying changes.
It provides four explicit operations:

- `inspect` checks the host, repositories, tools, clean runner state, and
  operator-provided free-space gates;
- `build` runs inspection, uses the selected development image when it already
  exists in the bootstrap user's local Podman store, otherwise builds it, and
  verifies the container toolchain and mount boundary;
- `connect` runs inspection, requires an existing development image, validates
  the exact private inventory host, storage and secret metadata, strict
  self-SSH, passwordless become, GitLab TLS, exact Podman NEVRA, and focused
  playbook syntax; and
- `all` runs `inspect`, `build`, and `connect` in order.

Select reviewed positive integer minimums for the filesystem containing the
rootless controller storage and for the managed root filesystem. Then run the
phases separately. Run one command at a time, and stop to resolve every
`[FAIL]` before continuing to the next phase:

```bash
environment=example
runner_host=example-runner-01
controller_root=/srv/example-bootstrap
read -r -p 'Minimum controller free GiB: ' controller_min_gib
read -r -p 'Minimum managed-root free GiB: ' root_min_gib

make runner-self-bootstrap-inspect \
  ENV="$environment" LIMIT="$runner_host" \
  MIN_CONTROLLER_FREE_GIB="$controller_min_gib" \
  MIN_ROOT_FREE_GIB="$root_min_gib" \
  CONTROLLER_ROOT="$controller_root"

make runner-self-bootstrap-build \
  ENV="$environment" LIMIT="$runner_host" \
  MIN_CONTROLLER_FREE_GIB="$controller_min_gib" \
  MIN_ROOT_FREE_GIB="$root_min_gib" \
  CONTROLLER_ROOT="$controller_root"

make runner-self-bootstrap-connect \
  ENV="$environment" LIMIT="$runner_host" \
  MIN_CONTROLLER_FREE_GIB="$controller_min_gib" \
  MIN_ROOT_FREE_GIB="$root_min_gib" \
  CONTROLLER_ROOT="$controller_root"
```

After all three individual phases pass, run the complete aggregate gate:

```bash
make runner-self-bootstrap-all \
  ENV="$environment" LIMIT="$runner_host" \
  MIN_CONTROLLER_FREE_GIB="$controller_min_gib" \
  MIN_ROOT_FREE_GIB="$root_min_gib" \
  CONTROLLER_ROOT="$controller_root"
```

Do not start Ansible convergence unless this final command reports:

```text
Failed: 0
Result: READY
```

Both repositories must be clean by default. For an exceptional reviewed local
change, invoke the script directly with `--allow-dirty`; the Make targets do not
weaken the clean-worktree gate. The helper reports private host and disk
metadata, so do not paste its output into public issues.

When private inventory is incomplete, run the standalone fact collector directly
on the target as root. Replace `ansible` only when a different automation account
is intended. Shell redirection occurs before `sudo`, so the report remains owned
by the connected operator account; `umask 077` makes it owner-only.

```bash
umask 077
report="$HOME/rocky-runner-bootstrap-facts-$(date -u +%Y%m%dT%H%M%SZ).json"
sudo python3 ./scripts/rocky-runner-bootstrap-facts \
  --controller-user ansible > "$report"
python3 -m json.tool "$report" >/dev/null
printf 'Private fact report: %s\n' "$report"
```

The collector writes one JSON document to standard output and a privacy warning
to standard error. It records host identity, addresses, current Rocky/DNF and
repository state, signing-key identity, block/LVM/filesystem topology, relevant
mount policy, automation-account readiness, SSH public-key fingerprints,
container storage configuration, and Podman/Runner unit and path state. It does
not print private keys, public-key bodies, Runner configuration, complete
`fstab`, or unrelated mount entries. URL userinfo, query strings, fragments,
recognized credential path forms, bearer values, and sensitive assignments are
redacted; repository URLs must still be reviewed before reuse.

The fixed command set does not invoke network clients, DNF metadata loading or
package transactions, Podman, LVM/filesystem mutation, mount operations, reboots,
or service state changes. It tries only bounded, fixed `findmnt` and `lsblk`
compatibility profiles, reads the mount table first, and does not inspect,
measure, or traverse paths on automount or non-allowlisted filesystems. Configured
NSS, PAM, logging, and audit integrations may still observe normal account and
`sudo` lookups. Keep the report outside Git and public issue trackers. Provide it
only through the approved private evidence channel.

The report describes current guest state. It cannot prove hypervisor snapshot
scope, choose desired LV sizes, identify an unconfigured HTTPS 10.2 mirror, or
establish GitLab-side Runner scope and token readiness. Those remain separate
operator decisions and evidence gates.

The individual observational commands remain useful when only a small evidence
subset is needed:

```bash
hostnamectl --static
cat /etc/os-release
uname -m
python3 --version
podman --version
git --version
make --version
sudo -n true
ip -brief address
ip route
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL
findmnt /
df -h /
rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' podman
dnf repoquery --qf '%{name}-%{epoch}:%{version}-%{release}.%{arch}' podman
```

Do not publish real addresses, disk identities, repository endpoints, or SSH
fingerprints with the evidence.

## Convergence

Using the environment, host, and capacity gates selected during preflight,
re-run the complete readiness check immediately before convergence:

```bash
make runner-self-bootstrap-all \
  ENV="$environment" LIMIT="$runner_host" \
  MIN_CONTROLLER_FREE_GIB="$controller_min_gib" \
  MIN_ROOT_FREE_GIB="$root_min_gib" \
  CONTROLLER_ROOT="$controller_root"
```

Converge users and SSH first:

```bash
make check ENV="$environment" PLAYBOOK=playbooks/bootstrap.yml LIMIT="$runner_host"
make apply ENV="$environment" PLAYBOOK=playbooks/bootstrap.yml LIMIT="$runner_host"
```

Before closing the original session, open a second connection through the
development container with the intended durable identity and confirm
`sudo -n true`. Update private inventory so `ansible_user` and its identity-file
or agent policy select that durable access path. If Ansible owns the authorized
keys, also remove the temporary public key from its desired key list. Prove the
inventory-selected connection, then repeat the bootstrap playbook so it removes
the temporary authorized key and verifies steady-state access:

```bash
make ping ENV="$environment" LIMIT="$runner_host"
make apply ENV="$environment" PLAYBOOK=playbooks/bootstrap.yml LIMIT="$runner_host"
```

Apply the base OS in isolation and repeat it to verify steady-state behavior:

```bash
make check ENV="$environment" PLAYBOOK=playbooks/base-os.yml LIMIT="$runner_host"
make apply ENV="$environment" PLAYBOOK=playbooks/base-os.yml LIMIT="$runner_host"
make apply ENV="$environment" PLAYBOOK=playbooks/base-os.yml LIMIT="$runner_host"
make smoke-firewalld ENV="$environment" LIMIT="$runner_host"
```

If dedicated storage was approved, converge it before the container runtime:

```bash
make check ENV="$environment" PLAYBOOK=playbooks/storage-volumes.yml LIMIT="$runner_host"
make apply ENV="$environment" PLAYBOOK=playbooks/storage-volumes.yml LIMIT="$runner_host"
make apply ENV="$environment" PLAYBOOK=playbooks/storage-volumes.yml LIMIT="$runner_host"
```

Converge and verify the rootful container runtime:

```bash
make check ENV="$environment" PLAYBOOK=playbooks/container-runtime.yml LIMIT="$runner_host"
make apply ENV="$environment" PLAYBOOK=playbooks/container-runtime.yml LIMIT="$runner_host"
make apply ENV="$environment" PLAYBOOK=playbooks/container-runtime.yml LIMIT="$runner_host"
make smoke-container ENV="$environment" LIMIT="$runner_host"
```

Finally, register and verify the runner:

```bash
make check ENV="$environment" PLAYBOOK=playbooks/gitlab-runners.yml LIMIT="$runner_host"
make apply ENV="$environment" PLAYBOOK=playbooks/gitlab-runners.yml LIMIT="$runner_host"
make apply ENV="$environment" PLAYBOOK=playbooks/gitlab-runners.yml LIMIT="$runner_host"
make smoke-runners ENV="$environment" LIMIT="$runner_host"
```

Use focused phase playbooks for first bring-up. Do not use `site.yml` while any
imported environment phase remains intentionally blocked.

Confirm in GitLab that the runner is online and has only the intended scope,
protection, and tags. Then run a minimal job selected by all environment-specific
tags before providing deployment credentials or privileged workloads.

## Cleanup And Ongoing Ownership

After successful smoke and job validation:

1. Verify a durable approved access path before removing bootstrap access.
2. When Ansible owns the account, remove a temporary public key from private
   desired state and converge `playbooks/bootstrap.yml` with the durable
   inventory-selected identity before deleting the temporary private key.
3. When cloud-init or another external system owns the account, remove a
   temporary authorized key through that owning workflow, then delete its
   private key.
4. Disconnect any deliberately forwarded SSH agent before the runner begins
   accepting jobs.
5. Remove temporary repository credentials or replace them with bounded
   read-only credentials required for maintenance.
6. Keep the runner token source available with owner-only permissions when this
   host remains its own Ansible controller; future role preflight requires the
   source file even when registration already exists.
7. Keep the public and private checkouts inaccessible to runner job volumes.

For later operation from another control node, transfer only the private
inventory and outside-Git inputs through approved channels. Do not copy the
managed host's generated `/etc/gitlab-runner/config.toml` to register another
runner.
