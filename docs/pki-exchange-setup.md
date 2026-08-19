# PKI Exchange Setup

Prepare one online transfer station, one private GitLab Generic Package project,
and one restricted target SSH endpoint before running the
[Host-Local Registry PKI Workflow](registry-host-local-pki-workflow.md). This
guide prepares transport only. It authorizes no live request, publication,
signing, activation, decision, cleanup, or target mutation.

## Ownership Boundary

Store each input according to its authority:

| Location | Contents |
| --- | --- |
| `platform-config` | Public helpers, Ansible roles, sanitized setup procedures, and examples |
| `platform-private` | Real inventory, project and target references, public-key authorization policy, and non-secret environment configuration |
| `~/.config/platform-infrastructure/` | Real project records, CA trust, SSH identities, package tokens, and exchange workspaces |
| Offline signer storage | Approval, CA, and response-signing private keys plus controlled-media workspaces |

Never commit a real token, private key, inventory, endpoint record, or access
policy to this repository. The target leaf key remains target-local and never
enters any exchange directory.

## Connection Topology

The target never connects to GitLab:

```text
target VM
    ^
    | pinned SSH initiated by the transfer station
    v
online transfer station
    ^
    | authenticated HTTPS
    v
GitLab Generic Package Registry
```

The transfer station pulls request and evidence packages from the target. It
downloads response and outcome packages from GitLab and pushes their exact
payloads to the target. Ansible connections are separately authenticated and
never receive GitLab credentials.

## GitLab Project

Create one dedicated private project, for example
`platform/pki-exchange`. Enable Generic Packages. The repository may remain
empty unless it contains a narrow protected CI configuration.

Require these controls independently of the helper:

- Self-managed GitLab CE `18.11.3-ce.0`.
- Generic duplicate publication disabled at the owning group with no matching
  exception for `pki-exchange-*`.
- `pki-exchange-*` package push and deletion thresholds explicitly reviewed.
  Every identity at or above the push role can publish; a Developer threshold
  therefore also permits the documented Developer reader credential to push.
- Package deletion restricted to a role the publisher does not hold.
- Package cleanup disabled.
- Protected CI configuration, refs, environments, runners, and variables.
- Publication serialized by exact project, stage, service, and package version.
- No unrelated members, tokens, schedules, integrations, artifacts, or packages.

An SSH clone URL such as
`ssh://git@gitlab.example.test:2222/platform/pki-exchange.git` is not a Package
Registry origin. Record the HTTPS origin without a project path, query, or
fragment:

```text
schema=1
kind=pki-exchange-project
origin=https://gitlab.example.test
project_id=123
project_path=platform/pki-exchange
gitlab_version=18.11.3-ce.0
```

Obtain `project_id` from the project overview. The helper authenticates the live
project ID, full namespace path, and web URL against this record before package
access. The record pins the expected GitLab version; confirming the live version
remains a separate exact-version runtime qualification step.

## GitLab Credentials

Use separate publication and retrieval identities:

| Execution model | Publisher | Reader |
| --- | --- | --- |
| Protected GitLab CI | Dedicated project access token with `api` and the minimum package-push role | Dedicated project access token with `api` and Developer role |
| Operator-run transfer station | Dedicated project access token with `api` and the minimum package-push role | Dedicated project access token with `api` and Developer role |

Do not select repository, runner-management, Kubernetes, AI, or self-rotation
scopes. Do not use a personal administrator token. Package protection must deny
deletion even when a publisher token has the broad GitLab `api` scope required
by the package endpoints. GitLab 18.11's Generic Packages documentation also
requires that broad scope for its documented project-token download flow. A
reader with `api` and Developer role is not inherently read-only. The helper
permits only GET requests during reader operations, but the credential remains
write-capable outside the helper. Role-based package protection cannot deny
publication to a Developer reader while allowing a Developer publisher; it may
still set a higher deletion threshold. This unresolved capability is a runtime
qualification blocker, not a least-privilege reader design.

GitLab separately describes `read_api` as including package-registry reads, but
does not document that scope for the complete Generic Package project-token
flow. Treat a narrower `read_api` reader as unqualified until exact-version
runtime tests cover project authentication, package listing, package-file
listing, and file download. The helper's mandatory Projects API request is also
not in the documented job-token endpoint allowlist, so automatic `CI_JOB_TOKEN`
publication is unqualified for the current helper.

Although the helper accepts a `deploy` token header for Generic Package
operations, every operation first authenticates the exact private project
through `GET /api/v4/projects/:id`. A deploy token with only
`read_package_registry` cannot authorize that Projects API call. Do not select
`--token-type deploy` unless the helper stops requiring that endpoint and exact
GitLab runtime qualification proves the complete flow. Use `--token-type
private` with the dedicated reader project access token by default.

The helper reads each token from an owner-only file. It never accepts token bytes
in argv, a URL, a package, or output.

Configure the dedicated publisher as a protected masked file variable so token
bytes never need to be materialized by the job shell. Pass only the temporary
file path and never cache or publish that file:

```bash
test -f "$PKI_EXCHANGE_PUBLISH_TOKEN_FILE"
scripts/platform-pki-gitlab-package publish \
  ... \
  --token-type private \
  --token-file "$PKI_EXCHANGE_PUBLISH_TOKEN_FILE"
```

## Transfer-Station Layout

Use one owner-only namespace. Existing canonical PKI state and exchange history
must not be moved merely to adopt this layout.

```text
~/.config/platform-infrastructure/
├── config/pki-exchange/
│   ├── gitlab/
│   │   ├── project-record
│   │   └── ca.pem
│   └── endpoints/
│       └── registry-example.json
├── infra/pki-exchange/
│   ├── gitlab/
│   │   ├── publisher.token
│   │   └── reader.token
│   └── ssh/registry-example/
│       ├── identity
│       ├── identity.pub
│       └── known_hosts
└── pki-exchange/
    ├── intake/
    ├── gitlab-downloads/
    │   ├── request/
    │   ├── approval/
    │   ├── response/
    │   ├── evidence/
    │   └── outcome/
    ├── locks/
    └── registry-example/<request-id>/
        ├── trust/
        ├── request/
        ├── approval/
        ├── response/
        ├── evidence/
        └── outcome/
```

Set a restrictive umask and create every intermediate protected directory
explicitly. Creating only a deep leaf can leave an intermediate parent at the
process default mode.

```bash
umask 077
PI="$HOME/.config/platform-infrastructure"
SERVICE=registry-example
install -d -m 0700 -- \
  "$PI" \
  "$PI/config" \
  "$PI/config/pki-exchange" \
  "$PI/config/pki-exchange/gitlab" \
  "$PI/config/pki-exchange/endpoints" \
  "$PI/infra" \
  "$PI/infra/pki-exchange" \
  "$PI/infra/pki-exchange/gitlab" \
  "$PI/infra/pki-exchange/ssh" \
  "$PI/infra/pki-exchange/ssh/$SERVICE" \
  "$PI/pki-exchange" \
  "$PI/pki-exchange/intake" \
  "$PI/pki-exchange/gitlab-downloads" \
  "$PI/pki-exchange/gitlab-downloads/request" \
  "$PI/pki-exchange/gitlab-downloads/approval" \
  "$PI/pki-exchange/gitlab-downloads/response" \
  "$PI/pki-exchange/gitlab-downloads/evidence" \
  "$PI/pki-exchange/gitlab-downloads/outcome" \
  "$PI/pki-exchange/locks"
```

Directories are current-user-owned mode `0700`. Protected files are singly
linked regular files with mode `0400` or `0600`, except a reviewed CA bundle may
also be mode `0644`. Download destinations include `stage-manifest`; copy only
the exact payload allowlist into a separate `intake` directory before a direct
push.

Map the abstract workflow paths to this namespace consistently:

| Workflow purpose | Transfer-station path |
| --- | --- |
| Exchange root | `$PI/pki-exchange` |
| Raw direct request pull | `$PI/pki-exchange/intake/request-<request-id>` |
| Authenticated request source | `$PI/pki-exchange/<service>/<request-id>/request` |
| Frozen request trust | `$PI/pki-exchange/<service>/<request-id>/trust` |
| GitLab package download | `$PI/pki-exchange/gitlab-downloads/<stage>/<full-version>` |
| Payload-only response push | `$PI/pki-exchange/intake/response-<request-id>` |
| Raw direct evidence pull | `$PI/pki-exchange/intake/evidence-<deployment-sha256>` |
| Authenticated evidence source | `$PI/pki-exchange/<service>/<request-id>/evidence/<deployment-sha256>` |
| Payload-only outcome push | `$PI/pki-exchange/intake/outcome-<outcome-sha256>` |
| External publication lock | `$PI/pki-exchange/locks/<reviewed-coordinate>` |

In containerized Ansible commands, mount the host exchange root as
`/platform-pki-exchange`; values such as `REQUEST_DIR` and `EVIDENCE_DIR` use
that container path. `/outside-git` and `/secure` in the lifecycle examples are
generic protected-host paths, not additional required top-level directories.

## GitLab CA

Use the public CA certificate that authenticates the GitLab HTTPS certificate.
Do not generate a new CA for the helper. For an internal PKI, copy or directly
reference its reviewed public root CA:

```bash
test ! -e "$PI/config/pki-exchange/gitlab/ca.pem"
install -m 0600 -- /reviewed/trust/root-ca.crt \
  "$PI/config/pki-exchange/gitlab/ca.pem"
```

The GitLab server receives its leaf private key and leaf-plus-intermediate
fullchain. The transfer station and protected runner receive only the public root
CA trust anchor. A root CA private key never enters GitLab, a runner, or a target.

## Purpose-Specific SSH Identity

Do not reuse an Ansible administrator, cloud-init, Git, or personal SSH identity.
Generate a dedicated noninteractive Ed25519 identity directly at its final path
with `platform-tools`:

```bash
platform-ssh-init \
  --key-path "$PI/infra/pki-exchange/ssh/$SERVICE/identity" \
  --comment "platform PKI exchange $SERVICE" \
  --empty-passphrase \
  --print-public-key
```

The empty passphrase is intentional because the direct client is noninteractive.
The protected mode-`0600` file, restricted target account, exact host pin,
two-layer dispatcher, fixed facade, and target policy form the runtime boundary.

## Target Host Pin

Obtain the target's Ed25519 host-key fingerprint through a trusted console or
another independently authenticated channel. Do not trust `ssh-keyscan` output
by itself. The dedicated `known_hosts` file contains exactly one unhashed
record. For port 22, its host token exactly matches the endpoint host:

```text
192.0.2.61 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEPUBLICHOSTKEY
```

Write the reviewed record with mode `0600`, then confirm its fingerprint:

```bash
ssh-keygen -E sha256 -lf \
  "$PI/infra/pki-exchange/ssh/$SERVICE/known_hosts"
```

## Endpoint Record

Create one canonical JSON line with an absolute identity path, absolute
`known_hosts` path, reviewed OpenSSH fingerprint, exact network endpoint, fixed
remote helper, and restricted account:

```json
{"expected_host_key_sha256":"SHA256:REVIEWED_OPENSSH_FINGERPRINT","host":"192.0.2.61","identity_path":"/home/operator/.config/platform-infrastructure/infra/pki-exchange/ssh/registry-example/identity","known_hosts_path":"/home/operator/.config/platform-infrastructure/infra/pki-exchange/ssh/registry-example/known_hosts","port":22,"remote_helper_path":"/usr/local/libexec/platform-pki-host-local-exchange","schema":1,"user":"exchange-operator"}
```

Store it as
`config/pki-exchange/endpoints/<service>.json` with mode `0600`. The endpoint
host and the `known_hosts` token must refer to the same exact endpoint. Port 22
uses the bare host token. A non-default port uses `[host]:port`; IPv6 addresses
are also bracketed. Do not mix an IP address in one with a DNS name in the other.

## Target Access Policy

Before testing direct exchange, provision the target with the public
`pki_host_local_exchange_access` role and reviewed private configuration. The
role:

- Creates a dedicated locked `exchange-operator` system account.
- Refuses to adopt a pre-existing unmarked account or group, reserves both names
  before creation, and converts that reservation to an exact UID/GID ownership
  record immediately after creating and validating the identity.
- Installs one root-controlled `identity.pub` key with OpenSSH `restrict` and an
  account-wide `Match User` policy that both force the same dispatcher.
- Selects only the fixed authorized-key file, disables authorized-key commands,
  and denies interactive shell, PTY, forwarding, SCP, SFTP, and arbitrary
  commands for the entire account. Any other globally configured public-key
  authentication path is still constrained by the account-wide forced command.
- Permits passwordless sudo only for a root broker. The broker independently
  revalidates the operation and coordinates, pins the protected root-owned
  facade by descriptor, and never authorizes `cleanup-outcome`.
- Uses the reservation marker to recover a run interrupted during account or
  group creation; later failures retain the exact managed UID/GID record.
- Removes sudo authority first and removes the account only when that safe
  root-owned marker still matches every recorded identity attribute.

Enable it in private inventory with a reference to the outside-Git public key:

```yaml
pki_host_local_exchange_access_state: present
pki_host_local_exchange_access_authorized_key: >-
  {{
    lookup(
      'ansible.builtin.file',
      (
        lookup('ansible.builtin.env', 'PLATFORM_INFRASTRUCTURE_CONFIG_DIR')
        | dirname
      )
      ~ '/infra/pki-exchange/ssh/registry-example/identity.pub'
    )
  }}
```

The role defaults to `absent` and is part of normal registry convergence so
revocation and policy drift remain managed. Disabled access is revoked before
service roles; enabled access converges afterward.

The access role intentionally does not own the lifecycle facade. The focused
playbook and normal enabled registry convergence first call the certificate
role's fixed lifecycle-helper and exchange-endpoint task files through the
administrative Ansible identity. This installs or updates only the helper,
facade, fixed config, and target spool; it does not create a request or change
certificate state. The access role then rejects a missing, symlinked, writable,
or incorrectly owned facade or ancestor during apply.

Use the focused entry point for initial setup or upgrades. Check mode predicts a
missing endpoint and account hierarchy without enabling access; apply installs
them, and a second check verifies idempotency:

```bash
make syntax ENV=dev PLAYBOOK=playbooks/registry-pki-exchange-access.yml
make registry-pki-exchange-access ENV=dev LIMIT=registry-example
make check ENV=dev PLAYBOOK=playbooks/registry-pki-exchange-access.yml \
  LIMIT=registry-example
```

The normal Ansible administrative identity remains separate. The public
host-local certificate role owns installation of the facade, fixed
configuration, and target spool during lifecycle or access-endpoint preparation;
the access role never receives the private exchange identity. Do not substitute
a broad Ansible administrator key for the restricted exchange identity.

## Offline Layout

Keep offline command inputs separate from online receipts, manifests, package
metadata, tokens, and endpoint records:

```text
~/.config/platform-pki-offline/<service>/
├── offline-approver
├── offline-approver.pub
├── offline-response
├── offline-response.pub
├── transactions/
├── media-in/
│   ├── request/
│   ├── signer-input/
│   └── evidence/
├── work/approved/
└── media-out/
    ├── approval/
    ├── response/
    └── outcome/
```

The offline root and every staging directory are mode `0700`; private keys and
payload files are mode `0600`. Preserve existing keys, replay state, and
transactions. Direct mode no longer writes new packages to a legacy
controller-local outcome ingress, but historical ingress must remain until an
explicit retention decision authorizes removal.

If signer state and transfer credentials reside on the same networked host, the
directories provide logical separation only. A genuinely offline signer keeps
canonical `platform-pki` state, approval keys, response keys, and media workspaces
on a disconnected host or encrypted removable storage.

## Optional GitLab Runner

A GitLab job executes on a runner, not on the GitLab server. A CI publisher uses
a dedicated protected runner locked to the exchange project. It receives exact
payloads through a reviewed ingress, receives the dedicated publisher project
token only as a protected masked file variable, and serializes each coordinate
with a `resource_group`. It receives no Ansible inventory, target SSH identity,
signer key, CA private key, or target network access.

Do not use ordinary CI artifacts as an undocumented second package transport. A
remote runner needs a separately reviewed ingress and egress. A dedicated runner
on the protected transfer station avoids that extra boundary.

## Verification Order

Before a production exchange:

1. Verify every protected directory and file owner, mode, type, and link count.
2. Compare the dedicated host-key fingerprint through the trusted target console.
3. Confirm the project record against GitLab project metadata and exact version.
4. Confirm project protection, duplicate, deletion, cleanup, token, and runner
   settings through the GitLab administrative interface.
5. Provision and review the fixed exchange endpoint, restricted target account,
   SSH policy, broker, and sudo policy.
6. Test SSH authentication with a nonexistent request ID; reaching the facade and
   receiving `request not found` demonstrates authentication without target
   mutation.
7. Qualify all five package families in a disposable GitLab coordinate.
8. Run the normal lifecycle only under separate request, signing, activation,
   decision, import, and cleanup authorization.

Do not disable TLS verification, accept a host key interactively, select a
newest package, repair a conflicting package, or delete retained evidence to make
qualification pass.
