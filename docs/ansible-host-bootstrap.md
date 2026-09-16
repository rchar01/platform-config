# Ansible Host Bootstrap

Prepare an existing VM for Ansible, then hand its SSH identity to an approved
controller or GitLab job. This guide uses fictional names and documentation
addresses, not a live environment. Replace them with reviewed private values.

| Input | Example |
| --- | --- |
| Environment | `dev` |
| Inventory host | `node-01` |
| VM static hostname | `node-01.example.test` |
| VM management address | `192.0.2.21` |
| Controller source address | `192.0.2.10` |
| Controller hostname as evaluated by SSH | `controller.example.test` |
| SSH port | `22` |

An inventory alias is not necessarily the VM's static hostname. Verify the
controller source address as seen by the VM, especially for containerized jobs
and NAT. Do not infer it from the Runner's management address.

## Prerequisites And Custody

- The operator has `platform-ssh-init` and `platform-ssh-ci-bundle` from
  [platform-tools](https://codeberg.org/rch/platform-tools).
- The target-local helper supports the fixed Rocky Linux 10.0, `x86_64`, Python
  3.12-or-newer baseline with SELinux enforcing. It prepares `rocky` with the
  comment `Platform Ansible automation account` and membership in an existing
  `access_ssh` group.
- Required OS tools, sudo, and an enabled and active OpenSSH server must already
  exist. The helper does not install packages, create `access_ssh`, start or edit
  SSH, alter repositories, change networking, or configure the workload.
- Use an authenticated console or approved provisioning channel for initial
  target access. Review any failed SSH-policy check; do not disable corporate
  access mechanisms merely to make a check pass.
- Keep automation private keys, generated bundles, and authenticated host-key
  records outside Git. Real inventory and non-secret environment configuration
  belong in `platform-private`.

Two different keys are involved: the operator-generated automation public key
authorizes `rocky` on the VM; the VM's SSH host public key authenticates the VM to
the controller. Never substitute one for the other, and never copy the automation
private key to the managed VM.

## 1. Generate The Automation Key

On the trusted operator workstation, as the ordinary operator user, run:

```bash
(
  set -eu
  key="$HOME/.ssh/platform-config-dev-node-01-ansible_ed25519"

  if [ -e "$key" ] || [ -L "$key" ] ||
     [ -e "$key.pub" ] || [ -L "$key.pub" ]; then
    printf 'Existing key path; stop and review: %s\n' "$key" >&2
    exit 1
  fi

  platform-ssh-init \
    --key-path "$key" \
    --comment 'platform-config dev node-01 ansible' \
    --empty-passphrase

  ssh-keygen -E sha256 -lf "$key.pub"
)
```

The empty passphrase is intentional for unattended CI. Protect the private file
with mode `0600`. Generate a distinct keypair for each additional VM; do not reuse
one environment-wide key. Existing-key adoption and rotation require separate
review. See the
[SSH identity helper contract](https://codeberg.org/rch/platform-tools/src/branch/main/docs/ssh-identity-helper.md).

## 2. Transfer Public Artifacts

From the reviewed `platform-config` checkout, record the helper's digest:

```bash
sha256sum scripts/rocky-ansible-host-prepare
```

Through the authenticated provisioning channel, transfer only:

- `scripts/rocky-ansible-host-prepare`, staged as
  `/root/rocky-ansible-host-prepare`, root-owned and executable (`0755`).
- The generated `.pub` file, staged as
  `/root/node-01-ansible_ed25519.pub`, root-owned with mode `0644` or `0600`.

Both paths must be regular files, not symlinks. The supplied key must be singly
linked and below root-controlled directories. Its fingerprint must match the
operator's record. Do not transfer the private file without the `.pub` suffix.

On the authenticated VM console, as root, compare the helper against the digest
recorded on the workstation:

```bash
helper=/root/rocky-ansible-host-prepare
expected_sha256='<reviewed-64-character-SHA256>'
printf '%s  %s\n' "$expected_sha256" "$helper" | sha256sum --check --strict -
```

Stop if comparison fails. A digest received only alongside an unauthenticated
download does not establish trust.

## 3. Check And Prepare The VM

Run on the VM console as root. Use the same Bash session for these commands:

```bash
helper=/root/rocky-ansible-host-prepare
connection=(
  --expected-hostname node-01.example.test
  --public-key-file /root/node-01-ansible_ed25519.pub
  --controller-address 192.0.2.10
  --controller-hostname controller.example.test
  --server-address 192.0.2.21
  --server-port 22
)

"$helper" check "${connection[@]}"
```

`check` does not prepare the account. A missing `rocky` account means the VM is
not ready for Ansible yet; inspect the report before approving `apply`. A printed
host key alone is not a readiness result.

After reviewing prerequisites and confirming the intended VM and public key:

```bash
"$helper" apply "${connection[@]}" \
  --confirm node-01.example.test:rocky
```

`apply` creates the locked account and its access-group membership, checks the
effective SSH policy, installs the per-VM public key and passwordless sudo
policy, and verifies permissions and SELinux labels. It stops on conflicts rather
than replacing an unrelated account or key. A failure can leave partial state;
review the error before retrying. It does not automatically delete accounts or
undo pre-existing state.

Require successful final verification, then check again:

```bash
"$helper" check "${connection[@]}"
```

Required readiness result:

```text
Result: READY FOR ANSIBLE TRANSPORT
```

This establishes the helper's local checks, not end-to-end connectivity or
authorization to run workload playbooks.

Prepare any approved system CA trust separately with
[`rocky-ca-trust-prepare`](rocky-ca-trust.md) before workload source preflight.
The access helper does not install CA certificates, and its transport-ready
result does not establish HTTPS trust.

### Non-TTY Sudo and Existing Prepared Hosts

The root-owned, mode-`0440` policy at
`/etc/sudoers.d/90-platform-ansible-rocky` is:

```sudoers
Defaults:rocky !requiretty
rocky ALL=(ALL) NOPASSWD: ALL
```

`NOPASSWD` alone does not override `requiretty`. The first line permits only
`rocky` to use sudo without an interactive terminal; global `requiretty`,
`use_pty`, and other users' policy are not changed. The helper runs its command
checks in a new session with no controlling terminal, including
`runuser -u rocky -- sudo -n true`. Redirecting stdin alone is insufficient when
the helper is launched from a console.

For an already prepared host, transfer the reviewed updated helper and compare
its digest as in step 2. Reuse the same reviewed connection arguments and per-VM
public key, then run step 3's `check`, approved `apply`, and final `check`.
The old one-line policy is reported not ready by `check`; `check` never rewrites
it. `apply` can atomically upgrade only the exact previous policy
(`rocky ALL=(ALL) NOPASSWD: ALL` with one final newline), preserving the account
and key. The existing file must be root-owned, group root, mode `0440`, a
single-link regular file, and below root-controlled directories. Candidate
syntax is validated with `visudo` before publication and legacy content is
rechecked before replacement. Custom or unsafe policies are refused for review.

The helper lock serializes its own apply runs. Do not edit or converge sudoers
concurrently through another root process. An error after publication still
requires review; readiness is reported only after the full final checks pass.
If the detached sudo check still fails, review the effective host policy rather
than adding a forced SSH terminal or disabling Ansible pipelining.

## 4. Authenticate The VM Host Key

`check` and successful `apply` print the host-key fingerprint and a three-field
`known_hosts` line, using the reviewed server address:

```text
192.0.2.21 ssh-ed25519 <actual-host-key-base64>
```

The key can also be read manually from the authenticated VM console:

```bash
sudo ssh-keygen -E sha256 -lf /etc/ssh/ssh_host_ed25519_key.pub
sudo cat /etc/ssh/ssh_host_ed25519_key.pub
```

Preserve the authenticated record outside Git. A manual `.pub` file may include
a comment: use only `ssh-ed25519 <base64>` for the bundle's `host_key` field.
Use the full address-bound line for `known_hosts`. The automation `.pub` from
Step 1 is not the VM host key.

`ssh-keyscan` can collect a candidate, but cannot authenticate it. Never enroll
its result without independent verification. For nonstandard ports the helper
prints `[address]:port`; the current bundle generator supports only port `22`.

## 5. Define Inventory And Bundle Input

Add reviewed host values to the real private inventory. A minimal illustrative
entry is:

```yaml
all:
  children:
    ci_scope_bootstrap:
      hosts:
        node-01:
          ansible_host: 192.0.2.21
          ansible_port: 22
          ansible_user: rocky
          users_manage_ansible_user: false
```

Retain the environment's required role groups and existing variables; this is
not a replacement inventory. Review the rendered scope before running jobs.

Create the bundle input as an owner-only file outside Git, for example
`$HOME/.config/platform-infrastructure/dev-ssh-ci-input.json`:

```json
{
  "environment": "dev",
  "hosts": {
    "node-01": {
      "private_key": "/home/operator/.ssh/platform-config-dev-node-01-ansible_ed25519",
      "target": "192.0.2.21",
      "host_key": "ssh-ed25519 REPLACE_WITH_AUTHENTICATED_VM_HOST_KEY"
    }
  }
}
```

Replace `/home/operator` with the actual operator home and replace the host-key
placeholder with the authenticated two-field value. JSON does not expand `$HOME`
or `~`. Use exact inventory aliases and SSH targets. Every selected host needs
its own reviewed mapping; unknown host keys or addresses must block bundling.
Do not insert the three-field `known_hosts` line into `host_key`.

## 6. Generate And Verify The Bundle

On the operator workstation, keep a dedicated Bash session open through upload
and verification. The following creates a fresh owner-only temporary directory;
its cleanup traps remove generated private-key payloads on exit:

```bash
set -eu
work_dir=$(mktemp -d /dev/shm/platform-ssh-ci-bundle.XXXXXXXX)
trap 'rm -rf -- "${work_dir:?}"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

platform-ssh-ci-bundle create \
  --input "$HOME/.config/platform-infrastructure/dev-ssh-ci-input.json" \
  --output-directory "$work_dir/dev-ssh-ci"
```

The tool prints a non-secret summary. Check its environment and host count
against the approved inventory scope. It creates `key-bundle.json` and
`known_hosts` with mode `0600` in a mode-`0700` directory. Existing output
directories are rejected, as are payloads exceeding GitLab's 10,000-byte limit.
Never print the private bundle or attach it to logs, artifacts, or commits.

The generator does not upload to GitLab, contact VMs, authenticate host keys, or
generate new identities. See its authoritative
[input and output contract](https://codeberg.org/rch/platform-tools/src/branch/main/docs/ssh-ci-bundle.md).

## 7. Verify Controller Access And Configure GitLab

If the operator workstation is an approved SSH source, test from it using the
existing key and generated trust file in the same session:

```bash
key="$HOME/.ssh/platform-config-dev-node-01-ansible_ed25519"
ssh -F /dev/null \
  -o BatchMode=yes \
  -o IdentitiesOnly=yes \
  -o IdentityAgent=none \
  -o PreferredAuthentications=publickey \
  -o StrictHostKeyChecking=yes \
  -o GlobalKnownHostsFile=/dev/null \
  -o UserKnownHostsFile="$work_dir/dev-ssh-ci/known_hosts" \
  -i "$key" -p 22 rocky@192.0.2.21 \
  'python3 --version && sudo -n true'
```

Otherwise use an approved controller-side credential staging workflow. Do not
broaden network access or copy private keys to targets for this test. A test
from the operator workstation does not prove access from a containerized Runner;
repeat verification through the actual intended controller path.

Create these GitLab CI/CD variables using the generated file contents, not the
operator workstation's file paths:

| Generated File | Variable | Type | Protected | Environment Scope | Expansion |
| --- | --- | --- | --- | --- | --- |
| `key-bundle.json` | `PLATFORM_CI_SSH_KEY_BUNDLE` | File | Yes | `dev` | Disabled |
| `known_hosts` | `PLATFORM_CI_SSH_KNOWN_HOSTS` | File | Yes | `dev` | Disabled |

The current `platform-ci` inventory-ping contract requires Visible variables,
not masked ones, because their contents do not satisfy masking constraints.
Restrict variable access, protect the ref/environment, disable debug tracing,
and use reviewed immutable component and image pins. Follow
`docs/ansible-inventory-ping.md` in the separate `platform-ci` repository for the
static scope binding; do not replace an environment's staged rollout gates.

Run the approved protected inventory-ping job. It selects the appropriate key
for each host and verifies SSH plus Python-backed Ansible module execution.
It does not use become and does not qualify sudo or authorize configuration
playbooks. Keep workload rollout separately reviewed.

After verifying both GitLab variables, remove local generated payloads:

```bash
rm -rf -- "${work_dir:?}"
trap - EXIT HUP INT TERM
test ! -e "$work_dir"
```

Keep the original per-VM private keys in the approved outside-Git secret store.
Remove staged helper/public-key copies from `/root` after acceptance, leaving
the installed `authorized_keys` intact. Key rotation is a separate procedure:
the helper intentionally rejects a different installed key rather than silently
rotating or introducing overlapping authorization.
