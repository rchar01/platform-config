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
| `~/.config/platform-infrastructure/pki/` | Authoritative `platform-pki` signer state |
| `~/.config/platform-infrastructure/pki-exchange/` | Raw transport and authenticated controller exchange history |
| `~/.config/platform-pki-offline/<exact-service>/` | Initializer-managed reviewed request, approval, signer-input, response, evidence, outcome, and temporary approved work |
| `~/.config/platform-pki-keys/<stable-trust-domain>/` | Explicit approval and response private-key custody |

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

Before each publication, the publisher must hold an external lock with exact
coordinate `<project-id>:<stage>:<service>:<full-package-version>`. An
operator-run publisher follows the reviewed protected-lock procedure and stops
on an ambiguous or stale holder; there is no implicit helper lock and this guide
does not invent a lock command. Protected CI uses the same coordinate:

```yaml
resource_group: "${CI_PROJECT_ID}:${PKI_STAGE}:${PKI_SERVICE}:${PKI_PACKAGE_VERSION}"
```

The four variables must equal the project and exact arguments passed to
`gitlab-package publish`. One global protected exchange lock is also safe.

Configure the dedicated publisher as a protected masked file variable so token
bytes never need to be materialized by the job shell. Pass only the temporary
file path and never cache or publish that file. This is an argument template,
not a complete executable lifecycle step:

```bash
test -f "$PKI_EXCHANGE_PUBLISH_TOKEN_FILE"
platform-pki gitlab-package publish \
  ... \
  --token-type private \
  --token-file "$PKI_EXCHANGE_PUBLISH_TOKEN_FILE"
```

## Transfer-Station Layout

Use the canonical [Same-Workstation PKI Layout](pki-local-layout.md). Existing
canonical PKI state and exchange history must not be moved merely to adopt this
layout. `pki-exchange/` is the controller/transport workspace. The disjoint
exact-service offline workspace holds reviewed payload-only command stages,
including the response source consumed by controller response check.

```text
~/.config/platform-infrastructure/
├── config/pki-exchange/
│   ├── gitlab/
│   │   ├── project-record
│   │   └── ca.pem
│   └── endpoints/
│       └── registry-dev-01.json
├── infra/pki-exchange/
│   ├── gitlab/
│   │   ├── publisher.token
│   │   └── reader.token
│   └── ssh/registry-dev-01/
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
    └── registry-dev-01/<request-id>/
        ├── trust/
        ├── request/
        ├── approval/
        ├── response/
        ├── evidence/
        └── outcome/
```

The same workstation separately keeps authoritative state at
`~/.config/platform-infrastructure/pki/`, reviewed command work at
`~/.config/platform-pki-offline/<exact-service>/`, and approval/response keys at
`~/.config/platform-pki-keys/<stable-trust-domain>/`. On a transfer-only host,
do not copy or create signer state or keys merely to match the map.

Set a restrictive umask and create every intermediate protected directory
explicitly. Creating only a deep leaf can leave an intermediate parent at the
process default mode.

**Actor:** Transfer-station administrator. **Run on:** Online transfer station.
**Prerequisite:** Reviewed current user, service, and canonical XDG namespace.
**Output/provenance:** Exact owner-only online directory skeleton. **Idempotent
retry/result:** `install -d` preserves exact directories and modes them `0700`;
stop on a conflicting non-directory or ownership. **Next actor:** GitLab/SSH
setup administrator.

```bash
umask 077
PI="${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure"
SERVICE=registry-dev-01
TARGET=dev-registry-01
EXCHANGE_IDENTITY=registry-dev-01
OFFLINE_ROOT="${XDG_CONFIG_HOME:-$HOME/.config}/platform-pki-offline"
OFFLINE_WORKSPACE="$OFFLINE_ROOT/$SERVICE"
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
  "$PI/infra/pki-exchange/ssh/$EXCHANGE_IDENTITY" \
  "$PI/pki-exchange" \
  "$PI/pki-exchange/intake" \
  "$PI/pki-exchange/gitlab-downloads" \
  "$PI/pki-exchange/gitlab-downloads/request" \
  "$PI/pki-exchange/gitlab-downloads/approval" \
  "$PI/pki-exchange/gitlab-downloads/response" \
  "$PI/pki-exchange/gitlab-downloads/evidence" \
  "$PI/pki-exchange/gitlab-downloads/outcome" \
  "$PI/pki-exchange/locks"
platform-pki offline-workspace init "$SERVICE" --root "$OFFLINE_ROOT"
```

Directories are current-user-owned mode `0700`. Protected files are singly
linked regular files with mode `0400` or `0600`, except a reviewed CA bundle may
also be mode `0644`. Download destinations include `stage-manifest`; materialize
only the exact payload allowlist into the separate exact-service offline
workspace with the canonical
[No-Clobber Materialization](registry-host-local-pki-workflow.md#canonical-no-clobber-materialization)
procedure. Do not use an overwrite-capable copy or `install` loop. Raw target
request/evidence pulls remain in `pki-exchange/intake` because their controller
intake commands authenticate and publish them from there.

Map the abstract workflow paths to this namespace consistently:

| Workflow purpose | Transfer-station path |
| --- | --- |
| Exchange root | `$PI/pki-exchange` |
| Raw direct request pull | `$PI/pki-exchange/intake/request-<request-id>` |
| Authenticated request source | `$PI/pki-exchange/<service>/<request-id>/request` |
| Frozen request trust | `$PI/pki-exchange/<service>/<request-id>/trust` |
| GitLab package download | `$PI/pki-exchange/gitlab-downloads/<stage>/<full-version>` |
| Approver request staging | `$OFFLINE_WORKSPACE/media-in/request/<request-id>` |
| Approval attempt staging | `$OFFLINE_WORKSPACE/media-out/approval/<request-id>-<approval-sha256>` |
| Signer input staging | `$OFFLINE_WORKSPACE/media-in/signer-input/<request-id>-<approval-sha256>` |
| Response-check and response-push source | `$OFFLINE_WORKSPACE/media-out/response/<request-id>` |
| Raw direct evidence pull | `$PI/pki-exchange/intake/evidence-<deployment-sha256>` |
| Authenticated evidence source | `$PI/pki-exchange/<service>/<request-id>/evidence/<deployment-sha256>` |
| Reviewed evidence custody | `$OFFLINE_WORKSPACE/media-in/evidence/<deployment-sha256>` |
| Payload-only outcome push | `$OFFLINE_WORKSPACE/media-out/outcome/<request-id>-<outcome-sha256>` |
| External publication lock | `$PI/pki-exchange/locks/<reviewed-coordinate>` |

In containerized Ansible commands, mount the host exchange root as
`/platform-pki-exchange`; values such as `REQUEST_DIR` and `EVIDENCE_DIR` use
that container path. Response check also requires its host offline root to be
mounted read-only and an explicit container-visible `RESPONSE_DIR`; the canonical
workflow shows the current wrapper invocation. The response source must be an
exact six-file protected directory that neither contains nor is contained by the
controller exchange root. A transport download may remain under the exchange
root, but it is never the response-check or direct push source.

## GitLab CA

Use the public CA certificate that authenticates the GitLab HTTPS certificate.
Do not generate a new CA for the helper. For an internal PKI, copy or directly
reference its reviewed public root CA:

**Actor:** GitLab transport administrator. **Run on:** Online transfer station.
**Prerequisite:** Independently reviewed public GitLab trust anchor and absent
destination. **Output/provenance:** Exact CA bytes copied from the reviewed trust
source. **Idempotent retry/result:** The explicit absence check refuses overwrite;
reauthenticate an existing file instead of replacing it. **Next actor:** SSH
endpoint administrator.

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

**Actor:** SSH endpoint administrator. **Run on:** Online transfer station.
**Prerequisite:** Protected final parent and approved noninteractive custody.
**Output/provenance:** Dedicated keypair and printed public key from
`platform-ssh-init`; private key stays at the named path. **Idempotent
retry/result:** Follow helper conflict handling; never replace an enrolled key as
a retry. **Next actor:** Trusted host-key reviewer.

```bash
platform-ssh-init \
  --key-path "$PI/infra/pki-exchange/ssh/$EXCHANGE_IDENTITY/identity" \
  --comment "platform PKI exchange $EXCHANGE_IDENTITY" \
  --empty-passphrase \
  --print-public-key
```

The empty passphrase is intentional because the direct client is noninteractive.
The protected mode-`0600` file, restricted target account, exact host pin,
two-layer dispatcher, fixed facade, and target policy form the runtime boundary.

## Target Host Pin

Obtain the target's complete two-field Ed25519 host public key through a trusted
console or another independently authenticated channel. Do not trust
`ssh-keyscan` output by itself. Preserve the reviewed key as one shell argument;
do not add a comment or source it through command substitution.

Create both local trust files with `platform-pki`. The protected endpoint and
SSH parent directories and the dedicated mode-`0600` identity from the previous
step must already exist:

**Actor:** Trusted host-key reviewer. **Run on:** Online transfer station after
independent console/channel comparison. **Prerequisite:** Exact reviewed
two-field Ed25519 public key, protected identity, and owner-only parents.
**Output/provenance:** Owner-only one-record `known_hosts`, canonical endpoint
record, OpenSSH `SHA256:<base64>` display fingerprint, and lowercase hexadecimal
binary-key-blob SHA-256 from the same reviewed key. **Idempotent retry/result:**
An exact rerun reports `status` `existing`; byte-different or unsafe existing
state blocks setup without replacement. **Next actor:** Private inventory
administrator.

```bash
REVIEWED_HOST_PUBLIC_KEY='ssh-ed25519 <reviewed-base64-key>'
platform-pki direct-exchange endpoint-init \
  "$PI/config/pki-exchange/endpoints/$SERVICE.json" \
  --host 192.0.2.61 \
  --host-public-key "$REVIEWED_HOST_PUBLIC_KEY" \
  --identity-path "$PI/infra/pki-exchange/ssh/$EXCHANGE_IDENTITY/identity" \
  --known-hosts-path "$PI/infra/pki-exchange/ssh/$EXCHANGE_IDENTITY/known_hosts" \
  --user exchange-operator
```

The initializer performs no host discovery, network access, SSH identity
generation, or target mutation. It writes the exact `known_hosts` record first
and the endpoint activation record last, then reloads both through the normal
direct-exchange validation path. Record its JSON fields
`expected_host_key_sha256` and `transport_host_key_sha256`. The latter is the
provisional inventory enrollment value required before `request-pull`; never
convert the display fingerprint or recompute this value manually. The first
direct `request-pull` reports the authenticated protocol value as
`transport_host_key_sha256`; require equality with the enrollment value and
carry the reported value forward for intake and package coordinates.

## CSR Trust Source Preparation

After endpoint enrollment and independent host-key review, prepare the matching
requester, deployer, and host-vars source change before installing signer or
target trust. This workflow requires platform-tools v3.2.0 or later. Run the
maintained source editor without `--write` first:

**Actor:** Private inventory administrator. **Run on:** Reviewed configuration
workstation. **Prerequisite:** Exact reviewed two-field Ed25519 public key,
current-user-owned private repository without group- or world-writable source
paths, and selected relative host-vars path. The metadata policy covers both
signer sources and the complete inventory YAML consumer scan. Use a separate
owner-controlled checkout when shared group-write access is intentional.
**Output/provenance:** Deterministic three-file source diff with locally derived
transport and complete signer-file digests. **Idempotent retry/result:** Dry-run
changes nothing; an exact applied state prints no diff. **Next actor:**
Repository reviewer.

```bash
PRIVATE_REPO=/absolute/path/to/platform-private
HOST_VARS=config/inventories/dev/host_vars/registry.example.yml
HOST_PRINCIPAL=registry.example
platform-pki csr-trust-source update-host "$HOST_PRINCIPAL" \
  --private-repo "$PRIVATE_REPO" \
  --host-vars "$HOST_VARS" \
  --host-public-key "$REVIEWED_HOST_PUBLIC_KEY"
```

Review that only the selected principal in
`pki/csr-trust/requesters.allowed_signers` and
`pki/csr-trust/deployers.allowed_signers`, the transport digest, and the two
matching host-vars trust digests change. Apply the same source edit only after
that review:

```bash
platform-pki csr-trust-source update-host "$HOST_PRINCIPAL" \
  --private-repo "$PRIVATE_REPO" \
  --host-vars "$HOST_VARS" \
  --host-public-key "$REVIEWED_HOST_PUBLIC_KEY" \
  --write
git -C "$PRIVATE_REPO" status --short
git -C "$PRIVATE_REPO" diff HEAD --check
git -C "$PRIVATE_REPO" diff HEAD -- \
  pki/csr-trust/requesters.allowed_signers \
  pki/csr-trust/deployers.allowed_signers \
  "$HOST_VARS"
```

The command rejects another inventory consumer of either outgoing shared trust
digest rather than leaving it stale. It performs no network access, endpoint
change, trust installation, Ansible action, target mutation, or Git staging.
If it reports that inspection is required, stop before installation and resolve
the complete Git-visible source state. Signer-side `platform-pki
csr-trust-install` and target-side Ansible trust bootstrap are later, separately
authorized steps. The equivalent manual digest and review procedure is
documented with the exact source metadata requirements in
[CSR Trust Source Host Updates](https://codeberg.org/rch/platform-tools/src/branch/main/docs/pki-csr-trust-source.md).

## Endpoint Record

`endpoint-init` creates one canonical JSON line with an absolute identity path,
absolute `known_hosts` path, reviewed OpenSSH fingerprint, exact network
endpoint, fixed remote helper, and restricted account:

```json
{"expected_host_key_sha256":"SHA256:REVIEWED_OPENSSH_FINGERPRINT","host":"192.0.2.61","identity_path":"/home/operator/.config/platform-infrastructure/infra/pki-exchange/ssh/registry-dev-01/identity","known_hosts_path":"/home/operator/.config/platform-infrastructure/infra/pki-exchange/ssh/registry-dev-01/known_hosts","port":22,"remote_helper_path":"/usr/local/libexec/platform-pki-host-local-exchange","schema":1,"user":"exchange-operator"}
```

It stores the record as `config/pki-exchange/endpoints/<service>.json` with mode
`0600`. The endpoint
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
- Removes sudo, key, and SSH authority first; terminates processes owned by the
  exact recorded temporary UID; and removes the account only when that safe
  root-owned marker still matches every recorded identity attribute.

Configure the outside-Git public key reference in private inventory:

```yaml
pki_host_local_exchange_access_authorized_key: >-
  {{
    lookup(
      'ansible.builtin.file',
      (
        lookup('ansible.builtin.env', 'PLATFORM_INFRASTRUCTURE_CONFIG_DIR')
        | dirname
      )
      ~ '/infra/pki-exchange/ssh/registry-dev-01/identity.pub'
    )
  }}
```

The role has no inventory-selectable state. Its default task entry point is
structurally revoke-only, and normal registry convergence always revokes access
before service roles and never re-enables it. The wrapper first uses the fixed
lease-claim entry point; the focused access playbook then requires that owned
lease before selecting fixed access enablement.

The access role intentionally does not own the lifecycle facade. The focused
playbook first calls the certificate role's fixed lifecycle-helper and
exchange-endpoint task files through the
administrative Ansible identity. This installs or updates only the helper,
facade, fixed config, and target spool; it does not create a request or change
certificate state. The access role then rejects a missing, symlinked, writable,
or incorrectly owned facade or ancestor during apply.

Syntax-check the focused entry point during setup or upgrades. The canonical
workflow's fixed direct-exchange Make routes apply it only after atomically
claiming the target operation lease and before token-bound EXIT/signal
revocation. A concurrent claim fails without changing the active operation. Do
not leave the standalone enable target as an operator step:

**Actor:** Lifecycle/access administrator. **Run on:** Ansible controller.
**Prerequisite:** Reviewed private public-key reference. **Output/provenance:**
Syntax result. **Idempotent retry/result:** Repeated syntax checks are
non-mutating. **Next actor:** Canonical workflow Bootstrap stage.

```bash
make syntax ENV=dev PLAYBOOK=playbooks/registry-pki-exchange-access.yml
```

The normal Ansible administrative identity remains separate. The public
host-local certificate role owns installation of the facade, fixed
configuration, and target spool during lifecycle or access-endpoint preparation;
the access role never receives the private exchange identity. Do not substitute
a broad Ansible administrator key for the restricted exchange identity.

## Offline Layout

Keep reviewed command inputs separate from exchange receipts, manifests, package
metadata, tokens, endpoint records, authoritative signer state, and private
keys. Follow the `platform-tools`
[Offline PKI Workspace](https://codeberg.org/rch/platform-tools/src/branch/main/docs/pki-offline-workspace.md)
initializer contract; do not guess undocumented flags or create placeholder key
files.

```text
~/.config/platform-pki-offline/<exact-service>/
├── README.md
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

The offline root and every staging directory are mode `0700`; its fixed README
and payload files are mode `0600`. This workspace owns media custody and work
only. It creates and owns no private keys, public keys, or secret placeholders.
Approval and response key paths remain explicit operator inputs beneath the
separate `~/.config/platform-pki-keys/<stable-trust-domain>/` root. The
workspace must not claim signer transactions, replay state,
candidates, responses, outcomes, or accepted history. Preserve that
authoritative state under `~/.config/platform-infrastructure/pki/`.

For same-workstation operation, `pki-transfer` is retired and its former leaves
map to the initialized offline workspace as documented in
[Retired And Historical Paths](pki-local-layout.md#retired-and-historical-paths).
`pki-outcome-ingress` is also retired historical compatibility storage: direct
mode has no write or default there, and controller-local import uses only an
explicit operator-supplied `OUTCOME_DIR`. Preserve existing historical content
until an explicit classification and retention decision.

If signer state, transfer credentials, and approval/response keys reside on the
same networked host, the directories provide logical separation only. There is
no physical offline isolation and one host compromise has a larger blast radius;
the actor separation is only key and namespace separation unless distinct
people or systems are actually used. Cryptographic authentication, exact digest
binding, replay protection, no-clobber publication, and target-local leaf-key
custody still apply. A genuinely offline signer keeps
canonical `~/.config/platform-infrastructure/pki/` state, explicit external
approval/response keys, and the separate offline media/work workspace on a
disconnected host or encrypted removable storage. The workspace never becomes a
second signer namespace.

## Optional GitLab Runner

A GitLab job executes on a runner, not on the GitLab server. A CI publisher uses
a dedicated protected runner locked to the exchange project. It receives exact
payloads through a reviewed ingress, receives the dedicated publisher project
token only as a protected masked file variable, and serializes each coordinate
with the exact-coordinate `resource_group` defined above. It receives no Ansible
inventory, target SSH identity, signer key, CA private key, or target network
access.

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
