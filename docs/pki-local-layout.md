# Same-Workstation PKI Layout

This page is the canonical integrated operator map for the approved
same-workstation PKI model. It assigns one purpose to each outside-Git root and
keeps signer authority, transport history, reviewed command work, and long-lived
approval/response keys distinct even when one workstation holds all four.

The same-workstation model is an operating mode, not a claim that the signer is
physically offline. The command paths remain explicit. No `platform-config` or
`platform-tools` command gets a path default from this page.

## Canonical Roots

```bash
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
PKI_NAMESPACE="$CONFIG_HOME/platform-infrastructure"
PKI_ROOT="$PKI_NAMESPACE/pki"
EXCHANGE_ROOT="$PKI_NAMESPACE/pki-exchange"
OFFLINE_ROOT="$CONFIG_HOME/platform-pki-offline"
OFFLINE_WORKSPACE="$OFFLINE_ROOT/$SERVICE"
KEY_ROOT="$CONFIG_HOME/platform-pki-keys"
KEY_DOMAIN="$KEY_ROOT/$STABLE_TRUST_DOMAIN"
APPROVAL_KEY="$KEY_DOMAIN/offline-approver"
RESPONSE_KEY="$KEY_DOMAIN/offline-response"
```

`PKI_NAMESPACE` is the namespace root, not the `pki/` leaf. Pass
`--namespace "$PKI_NAMESPACE"`; `platform-pki` derives
`$PKI_NAMESPACE/pki`. Use `--pki-dir "$PKI_ROOT"` only when intentionally
selecting that separate explicit interface.

| Root | Producer | Consumer | Authority | Backup inclusion | Retention |
| --- | --- | --- | --- | --- | --- |
| `~/.config/platform-infrastructure/pki/` | `platform-pki` signer, inventory, trust, rollover, export, and recovery commands | Signer and verification commands | Authoritative signer state, including replay, transactions, candidates, responses, decisions, outcomes, accepted history, and `pki/legacy` migration provenance | Required in encrypted signer backups; test restore without replacing live state | Retain pending, recovery, historical, and migration-provenance state. Remove nothing merely because a request completed or a rollback hold expired. |
| `~/.config/platform-infrastructure/pki-exchange/` | Direct/GitLab transport and `platform-config` controller intake/check actions | Controller authentication, package publication/retrieval, and direct push/pull commands | Raw transport history plus authenticated controller history; not signer or target authority | Include authenticated controller history when required by the evidence backup policy. Raw downloads are not a signer-backup substitute. | Preserve lifecycle attempts, conflicts, manifests, frozen trust, and authenticated history until an explicit evidence-retention decision. |
| `~/.config/platform-pki-offline/<exact-service>/` | Offline workspace initializer and explicit no-clobber materialization/approval/export steps | Approver, signer, publisher, response check, and direct push commands | Reviewed operator custody and command workspace only; never signer replay, transaction, candidate, response, outcome, or recovery authority | Excluded from authoritative signer backups. Back up only when a separate custody/evidence policy requires it. | Preserve in-flight, conflicting, failed, and unattributed material. After terminal verification, disposal still requires an exact-path retention decision. |
| `~/.config/platform-pki-keys/<stable-trust-domain>/` | Reviewed key-generation or key-import procedure | `offline-csr approve`, `offline-csr sign`, and outcome publication through explicit key paths | Private approval and response key custody; public trust remains separately installed in signer/target trust | Required under the approved encrypted key-recovery policy, separately from routine workspace copies and passphrases | Retain while any installed trust or retained history depends on the key. Rotate by trust policy or compromise response, not by deleting a service-generation workspace. |

`platform-pki backup` covers its authoritative PKI tree; it does not make the
exchange, offline-workspace, or key roots authoritative and does not implicitly
back up those siblings. Backup and disposal procedures must classify each root
separately.

### Backup And Isolated Restore

An isolated restore must preserve the authoritative tree's canonical absolute
path. Terminal migration and recovery records can bind that path and filesystem
identities; extracting the tree at an arbitrary alternate path is expected to
fail closed rather than silently rewrite those records. Never edit a retained
journal to make an alternate-path test pass.

Use this minimum restore-validation contract:

1. Verify the encrypted archive against its owner-only receipt and recorded
   digest before decryption.
2. Extract under an owner-only temporary root with a restrictive umask. Preserve
   archived ownership and modes, or map the original operator UID exactly inside
   the sandbox.
3. Use a network-disabled VM, container, or private mount namespace. Hide the
   live PKI tree and present only the restored tree at the original canonical
   absolute path; do not give the verifier writable access to live state.
4. Run non-mutating custody and exact terminal-record verification. A custody
   report may return reviewed findings, but it must traverse the restored tree
   without a path, ownership, mode, journal, or recovery error. Reauthenticate
   each required digest-qualified retained outcome as its recorded terminal
   state.
5. Remove the temporary restored copy under the approved secret-disposal policy.
   Ordinary unlinking is cleanup, not proof of physical secure erasure.

## Filesystem Modes

- Keep each active root and every protected workspace/staging directory
  current-user-owned mode `0700` with no symlink components.
- Keep PKI state at the exact per-object modes enforced by `platform-pki`; do not
  recursively chmod the authoritative tree. Private state and control files are
  owner-only, while tool-produced public exports may have their documented
  public modes.
- Keep approval and response private keys current-user-owned, singly linked
  regular files at mode `0600`. Do not loosen their containing domain directory
  beyond `0700`.
- Keep offline payload files current-user-owned, singly linked regular files at
  mode `0600`. The workspace initializer's `README.md` is also mode `0600`.
- Keep exchange project records, endpoint records, SSH identities, and tokens at
  their documented `0400` or `0600` modes. A reviewed public CA bundle may be
  `0644` where the consuming command permits it.
- Treat a mode, owner, type, link-count, or ancestor mismatch as a stop
  condition. Do not repair an unattributed tree merely to make a command pass.

## Exact Service And Stable Key Domain

The offline workspace is keyed by the exact lifecycle service. The approval and
response key directory is keyed by the stable trust domain.

For example, the first registry target uses exact service `registry-dev-01`
while the reviewed trust keys remain those of the stable `registry-dev` domain:

```bash
SERVICE=registry-dev-01
STABLE_TRUST_DOMAIN=registry-dev
OFFLINE_ROOT="${XDG_CONFIG_HOME:-$HOME/.config}/platform-pki-offline"
OFFLINE_WORKSPACE="$OFFLINE_ROOT/$SERVICE"
KEY_DOMAIN="${XDG_CONFIG_HOME:-$HOME/.config}/platform-pki-keys/$STABLE_TRUST_DOMAIN"
APPROVAL_KEY="$KEY_DOMAIN/offline-approver"
RESPONSE_KEY="$KEY_DOMAIN/offline-response"
```

Do not rename the `registry-dev-01` workspace to `registry-dev`, and do not add
`-01` to the key domain merely because the target service is node-specific. Reusing
the stable domain is valid only while installed policy identifies the same
reviewed approval/response public keys. A key rotation is a trust change and has
its own overlap and retention procedure.

## Operator Key Loss And Replacement

The approval and response private keys remain only in reviewed operator custody.
They are never installed on a target. The target receives their public key
material as part of the complete immutable schema-2 trust snapshot under
`<state-root>/trust/<trust-id>/`; the signer receives reviewed public trust under
`PKI_ROOT/inventory/csr-trust/`. Public trust and a public `.pub` file cannot
reconstruct a lost private key.

Include the complete stable key-domain directory in the separate encrypted
operator-key backup procedure. `platform-pki backup` does not include it. Take a
new operator-key backup after initial creation and every rotation, keep its
recovery credential separately, and test an owner-only restore by comparing the
restored public-key fingerprints with reviewed trust.

Classify a loss before changing anything:

- If only `.pub` is missing, derive it from the existing private key and verify
  its fingerprint. This is not rotation and requires no target trust change.
- If the private key is available in a recovery backup, restore the same key at
  mode `0600`, derive or restore `.pub`, and verify the fingerprint against
  installed trust. This is not rotation.
- If the private key has no recovery copy, create a replacement at a fresh
  explicit path and perform a complete trust rotation. Never overwrite a
  surviving public key or manually replace target trust files.

Before irreversible replacement, stop new lifecycle operations. Resolve
pre-candidate dependencies first: a previously signed approval remains
verifiable after loss of the approval private key, but an absent approval cannot
be recreated with the replacement identity. Complete a request with its frozen
trust when the remaining required key is available, or exactly cancel an
unconsumed request before rotating a key that it still depends on.

If the response key is lost before signer candidate/response state exists, exact
cancellation of the unconsumed request can clear the external pending state
before rotation. Once a candidate depends on that response identity, completion
requires either the original private key or an already authenticated signed
outcome. A replacement key is rejected by the retained response trust. If
neither recovery source exists, normal finalization, abandonment, and trust
rotation remain blocked: preserve all state, make no manual target change, and
escalate to a separately designed disaster-recovery or new-PKI-epoch decision.

Only after every dependent request is terminal or exactly cancelled may the
rotation gate prove that signer, controller, transport, and target contain no
pending request, candidate, or recovery state. A replacement key is never valid
for a request whose trust was already frozen. This gate requires an explicit
inventory of every known request coordinate and its exact cancellation evidence
or authenticated terminal outcome; there is no global newest-request discovery
command. If that inventory cannot be established, rotation remains blocked.
The signer trust installer supplies the final signer-side retained-candidate
gate before it publishes replacement trust.

For an irrecoverable key, retain old public trust and signed history, record the
replacement public key in the reviewed durable private trust source, publish the
fixed five-file tree with `platform-pki csr-trust-source publish` to
`$PLATFORM_INFRASTRUCTURE_CONFIG_DIR/pki-source`, atomically install signer trust
from that protected publication, and install a new immutable target trust ID
through the owning Ansible playbook. Update controller digests and start only new
requests with that trust ID. The exact registry procedure is in
[Operator Key Loss And Replacement](registry-host-local-pki-workflow.md#operator-key-loss-and-replacement).

## Offline Workspace Leaves

Initialize the exact-service skeleton with the maintained command rather than
creating placeholder keys or undocumented directories:

```bash
platform-pki offline-workspace init "$SERVICE" --root "$OFFLINE_ROOT"
```

The active leaf roles are:

| Role | Canonical same-workstation path |
| --- | --- |
| Request input for approval | `$OFFLINE_WORKSPACE/media-in/request/<request-id>` |
| Protected approved five-file work | `$OFFLINE_WORKSPACE/work/approved/<request-id>` |
| Approval publication/output | `$OFFLINE_WORKSPACE/media-out/approval/<request-id>-<approval-sha256>` |
| Signer input | `$OFFLINE_WORKSPACE/media-in/signer-input/<request-id>-<approval-sha256>` |
| Response publication, response check, and direct push source | `$OFFLINE_WORKSPACE/media-out/response/<request-id>` |
| Reviewed evidence custody | `$OFFLINE_WORKSPACE/media-in/evidence/<deployment-sha256>` |
| Outcome publication and direct push source | `$OFFLINE_WORKSPACE/media-out/outcome/<request-id>-<outcome-sha256>` |

These paths identify purpose; they do not grant authority. Commands still
authenticate exact allowlists, records, signatures, trust, and digest
coordinates. Use the canonical no-clobber materialization procedure from the
[host-local workflow](registry-host-local-pki-workflow.md#canonical-no-clobber-materialization)
when moving payloads between roots.

## Separation And Overlap Rules

- Keep the four active roots component-wise disjoint. None may equal, contain,
  or be contained by another.
- Do not connect roots with symlinks, bind-mount aliases used as durable layout,
  hard links, or shared mutable leaf directories.
- A GitLab download may remain under `pki-exchange`, but response check and
  direct response/outcome push consume an explicitly named payload-only offline
  workspace leaf. Response check rejects source/exchange containment overlap.
- The offline workspace never becomes a second signer namespace. Signer
  transactions and recovery remain under `PKI_ROOT` even when approval and
  signing input is under `OFFLINE_WORKSPACE`.
- Approval and response private keys never enter the offline workspace,
  exchange history, GitLab package, target spool, or public repository.
- Do not overlap trust/key rotation with a pending request. Preserve old keys,
  public trust, signer history, packages, and workspaces until every dependent
  request is terminal and the separate retention decision is complete.
- Preserve every ambiguous or retained stage at its exact reported path. Never
  use wildcard cleanup to make a retry pass.

## Operating Modes

### Same Workstation

The current examples use all four roots on one workstation. No controlled-media
copy is needed between an exchange download and the exact-service offline
workspace, but no-clobber materialization and every cryptographic check still
apply. Actor labels identify responsibilities and key use, not independent
machines or people.

This mode has no physical offline isolation. Compromise of the workstation has a
larger blast radius because signer state, transport credentials/history,
reviewed work, and approval/response keys may all be reachable from one host.
Role separation is only key and namespace separation unless different people or
machines are actually used. Request, approval, response, target, deployment,
validation-result, and outcome signature checks; exact digest binding; replay
protection; frozen trust; target-local leaf-key custody; and no-clobber checks
still remain.

### Separate Or Disconnected Stations

The same root purposes and exact-service/stable-domain distinction apply when
transport, approval, and signing use separate stations. Move only documented
payload allowlists through reviewed controlled media and preserve explicit input
and output paths. Physical separation can reduce online compromise exposure, but
it does not replace protocol authentication or retention rules.

### Direct And Controller-Local Exchange

`direct` is the current host-local exchange mode. Direct commands name exact
request/evidence destinations and response/outcome sources; Ansible does not
transport package bytes.

`controller-local` is explicit compatibility behavior for the documented
request, evidence, and outcome targets. It has no implicit path. In particular,
controller-local outcome import requires an explicit protected `OUTCOME_DIR`.
Do not mix modes within one request without an approved recovery procedure that
accounts for both byte paths.

## Retired And Historical Paths

### `pki-transfer`

`~/.config/platform-infrastructure/pki-transfer/` is retired for
same-workstation operation. There is no current write or default to this path,
and current examples do not create it. Its former roles map as follows:

| Retired role | Canonical replacement |
| --- | --- |
| `pki-transfer/request/<request-id>` | `$OFFLINE_WORKSPACE/media-in/request/<request-id>` |
| `pki-transfer/approval/<request-id>-<approval-sha256>` | `$OFFLINE_WORKSPACE/media-out/approval/<request-id>-<approval-sha256>` |
| `pki-transfer/signer-input/<request-id>-<approval-sha256>` | `$OFFLINE_WORKSPACE/media-in/signer-input/<request-id>-<approval-sha256>` |
| `pki-transfer/response/<request-id>` | `$OFFLINE_WORKSPACE/media-out/response/<request-id>` |
| `pki-transfer/outcome/<request-id>-<outcome-sha256>` | `$OFFLINE_WORKSPACE/media-out/outcome/<request-id>-<outcome-sha256>` |

Existing content is historical input to a classification and retention review;
retirement does not authorize deletion. Materialize a required exact payload at
its canonical replacement, authenticate it through the normal command, and keep
the old path until its retention decision is recorded.

### `pki-outcome-ingress`

`~/.config/platform-infrastructure/pki-outcome-ingress/` is retired historical
compatibility storage. Direct mode does not write or read it, and no current
command defaults to it. The only current compatibility route is an explicitly
authorized controller-local import whose `OUTCOME_DIR` names one exact protected
six-file source. Historical ingress content remains preserved until classified;
do not present package presence there as current target or signer authority.

### Two Different `legacy` Trees

`~/.config/platform-infrastructure/legacy/` is an outer quarantine for retired
configuration or secret material, such as migrated passphrase files. It is not
authoritative PKI state. Keep it until replacement-secret operations, recovery,
backup review, and the approved secret-disposal gate have all completed.

`~/.config/platform-infrastructure/pki/legacy/` is different: it is
authoritative CA-migration provenance inside the signer tree. It records the
journaled singleton-to-generation migration without copying private keys and
must remain with authoritative signer history and backups. Do not dispose of it
as though it were the outer quarantine.

Any `.pki-post-*` snapshot found in or beside these roots is unclassified
historical material. Its name does not establish authority, backup status, safe
content, or disposability. Before any disposition, record its exact path,
ownership, mode, links, origin, contents classification, relationship to
canonical state, whether it is the only recovery copy, and which backups contain
it. Require successful canonical-state verification, required restore evidence,
closed lifecycle/recovery state, and an approved retention or secret-disposal
decision. Until all gates pass, preserve the snapshot; this documentation does
not claim that any such snapshot has been deleted.
