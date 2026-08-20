# Host-Local Registry PKI Workflow

Complete [PKI Exchange Setup](pki-exchange-setup.md) before this workflow. It
prepares protected online and offline storage, the GitLab project and
credentials, the pinned target endpoint, and the restricted SSH identity.

This runbook moves one Zot registry from a managed certificate to a certificate
whose leaf private key never leaves the registry host. The examples are
sanitized. Real inventory, trust policy, hostnames, CA files, and non-secret
environment configuration belong in `../platform-private`; passphrases, private
keys, tokens, and other secrets remain outside Git.

The lifecycle is deliberately staged:

```text
Bootstrap -> Request -> Gate 1 -> Activate/Evidence -> Gate 2 -> Complete
                  |                                  |
                  | offline approval and signing     | offline finalization
                  |                                  | and outcome signing
                  `------------ external ------------'

Fixed Cleanup: revoke direct exchange access after every online stage,
including failed or interrupted stages.
```

Gate 1 prevents response admission or activation until an offline approver has
approved the exact request and the offline signer has produced the exact signed
response. Gate 2 prevents terminal import until fresh target evidence has passed
the runner preflight and the offline signer has accepted that exact evidence.
Neither gate is a GitLab approval, an Ansible prompt, or package presence.
Ansible performs lifecycle orchestration but no direct SSH, GitLab, or
controlled-media transport.

## Security Invariants

- Select exactly one registry target and one distinct validation runner.
- Never individually fetch, copy, inspect, hash, stat, or log the target's
  `tls.key`. An approved encrypted whole-VM backup may contain it, but the key is
  never extracted or handled as an individual artifact.
- Never place approval, response-signing, CA, or target private keys in Git,
  `/tmp`, shell arguments, environment variables, tickets, or chat.
- Carry exact request, approval, artifact, deployment, and outcome coordinates
  from authenticated command output. Never select `latest`, `current`, newest,
  or a neighboring digest-suffixed attempt.
- Treat transport as untrusted. Canonical records, detached signatures, frozen
  trust, exact digest pins, target state, and signer state establish authority.
- Stop on an unexpected file, owner, mode, link count, digest, principal,
  namespace, lifecycle state, or recovery journal.
- Preserve ambiguous stages and journals as evidence. Never use wildcard
  cleanup.
- Keep the managed predecessor, signer history, target history, exchange
  packages, and backups until a separate retention decision is approved.

## Responsibilities And Actors

Actor labels identify responsibility and key custody, not necessarily different
people. One person may perform multiple compatible roles, but must use the
credential and execution host named for the role.

| Actor | Responsibility |
| --- | --- |
| Lifecycle operator | Runs exact `platform-config` lifecycle commands from the Ansible controller and records their public coordinates. |
| Target producer | Target helper creates the request, retains the leaf key, activates the response, and signs deployment evidence. This is a delegated machine role, not a shell login. |
| Validation runner | Distinct reviewed host performs strict read-only Zot validation and signs the validation result. |
| Transport operator | Runs pinned direct SSH movement and maintains controlled-media custody; does not approve, sign, publish, or infer authority. |
| GitLab publisher | Uses the dedicated publisher credential to publish one exact package coordinate while holding its external lock. |
| GitLab retriever | Uses the dedicated retrieval credential to download and validate one operator-supplied exact coordinate. |
| Offline approver | Reviews and signs one exact request while disconnected. |
| Offline signer | Holds CA/response keys, signs the approved CSR, records candidate decisions, and exports response/outcome payloads while disconnected. |

`platform-config` owns target request generation, controller intake, response
authentication, transactional activation and rollback, runner validation,
evidence intake, outcome import, lifecycle status, and normal Zot convergence.
`platform-tools` owns direct and GitLab transport, offline approval and signing,
certificate/outcome export, candidate decisions, signer recovery, and signer
backup. Protocol details are in
[OpenSSL PKI Helpers](https://codeberg.org/rch/platform-tools/src/branch/main/docs/pki-openssl.md)
and [Host-Local PKI CSR Handoff](https://codeberg.org/rch/platform-tools/src/branch/main/docs/handoffs/pki-host-local-csr-handoff.md).

## Package Identity And Custody

Every package name remains exactly `pki-exchange-<stage>-<service>`. Actor names
must not be added. A username, job name, actor label, or publisher credential is
not package authority: stage schemas, canonical payload bytes, detached
signatures, frozen trust, and exact lifecycle coordinates are authoritative.

| Stage | Exact version | Payload producer or signer | GitLab publisher |
| --- | --- | --- | --- |
| `request` | `<request-id>` | Target produces three request files; controller intake produces `collection-receipt` | GitLab publisher |
| `approval` | `<request-id>-<approval-sha256>` | Offline approver signs `approval` | GitLab publisher |
| `response` | `<request-id>` | Offline signer signs the response and publishes the local certificate export | GitLab publisher |
| `evidence` | `<request-id>-<deployment-sha256>` | Target signs `deployment`; validation runner signs `validation-result` | GitLab publisher |
| `outcome` | `<request-id>-<outcome-sha256>` | Offline signer accepts evidence and signs `outcome` | GitLab publisher |

The publisher may be protected CI or an operator-run transfer station. The
retriever is a separate responsibility even if the same reviewed workstation is
used. Neither role becomes the payload producer or signer by moving bytes.

## Service Identity During A Clean Reset

Keep `SERVICE` stable during ordinary renewal or key rotation; request ID,
certificate serial, and digests identify each generation. If target-local key
and lifecycle state are intentionally destroyed while finalized signer history
is retained and same-service replacement is unavailable, use an exceptional
internal generation such as `registry-dev-g2`. Preserve the old service and
signer history, never reuse a suffix, and choose the next number from reviewed
retained inventory. The exact generation value is used consistently by signer
inventory, controller paths, and all five actor-neutral package names.

In a genuinely fresh PKI namespace with no signer state for the service, use the
unsuffixed `registry-dev`. That is a new PKI epoch; rebuild CA hierarchy and
trust explicitly rather than adding `-g2` only because the VM is new.

## Protected Paths

Use `~/.config/platform-infrastructure` as the canonical online namespace. Its
`pki/` tree remains authoritative PKI and signer state. Use the separate
`~/.config/platform-pki-offline/<service>/` workspace only for controlled-media
ingress/egress and temporary approved work. Approval and response keys remain
explicit protected inputs outside the initializer-managed tree. Together those
keys and the media/work workspace form the offline custody boundary; neither
owns or replaces signer transactions, replay state, candidates, responses,
outcomes, or accepted history. Those remain under the authoritative PKI
namespace.

Follow the `platform-tools`
[Offline PKI Workspace](https://codeberg.org/rch/platform-tools/src/branch/main/docs/pki-offline-workspace.md)
documentation for its initializer contract; do not guess flags not documented
there. The initializer creates no keys or secret placeholders. Existing safe
keys and authoritative state must be preserved.

The examples use these reviewed paths. **Actor:** Lifecycle operator for online
values and offline signer for the disconnected copy. **Run on:** Each actor's
own reviewed shell. **Prerequisite:** Completed setup and protected canonical
directories. **Output and provenance:** Shell variables map already reviewed
inventory and paths; they produce no authority or digest. **Retry/result:**
Reassignment is non-mutating; stop if an existing path maps to a different
purpose. **Next actor:** Bootstrap actors.

```bash
ENVIRONMENT=dev
SERVICE=registry-dev
TARGET=registry-example
RUNNER=registry-validator-example
PI="${XDG_CONFIG_HOME:-$HOME/.config}/platform-infrastructure"
PKI_NAMESPACE="$PI/pki"
EXCHANGE_ROOT="$PI/pki-exchange"
TRANSFER_ROOT="$PI/pki-transfer"
CONTAINER_TRANSFER_ROOT=/tmp/platform-home/.config/platform-infrastructure/pki-transfer
OFFLINE_ROOT="${XDG_CONFIG_HOME:-$HOME/.config}/platform-pki-offline/$SERVICE"
APPROVAL_KEY=/secure/offline-approval
RESPONSE_KEY=/secure/offline-response
SIGNER_EVIDENCE_ROOT=/secure/evidence
CONTROLLED_MEDIA_IN=/media/platform-pki-in
ENDPOINT_RECORD="$PI/config/pki-exchange/endpoints/registry-example.json"
PROJECT_RECORD="$PI/config/pki-exchange/gitlab/project-record"
GITLAB_CA="$PI/config/pki-exchange/gitlab/ca.pem"
PUBLISH_TOKEN=/run/secrets/gitlab-package-publisher-token
READ_TOKEN=/run/secrets/gitlab-package-reader-token
```

`CONTROLLED_MEDIA_IN` is the reviewed read-only mount of incoming controlled
media on whichever online or offline station is performing the next explicit
materialization. It is never a publication destination.

`EXCHANGE_ROOT` contains controller exchange history and transport downloads.
`TRANSFER_ROOT` is its protected sibling for reviewed payload-only media stages.
For response check, the exact six-file source must be under `TRANSFER_ROOT` and
must neither be inside nor contain `EXCHANGE_ROOT`. In the development
container, the same source is read-only beneath `CONTAINER_TRANSFER_ROOT` while
the separately mounted controller exchange is `/platform-pki-exchange`.

Do not turn this page into one unattended script. Review and authorize one stage
at a time.

## Canonical No-Clobber Materialization

Every payload-only materialization below uses this reviewed procedure. Define it
in the current protected Bash session before running a materialization step. It
uses only explicit literal destination names and explicit source paths; never
populate its arguments by enumerating an untrusted directory.

The procedure requires Linux `renameat2(RENAME_NOREPLACE)` and Python 3. It
accepts an exact safe existing destination only when its complete allowlist,
bytes, ownership, modes, link counts, and stable identities match. Otherwise it
builds a mode-`0700` same-parent stage, copies each mode-`0600` singly linked
regular file through pinned descriptors, rechecks source bytes and identities,
fsyncs the stage, and atomically renames without replacement. Conflicting or
race-created destinations are never replaced. Failures preserve the original
content and report any exact temporary stage path for review; do not remove that
path with a wildcard.

There is no overwrite-capable rename fallback. If `renameat2` is unavailable or
unsupported by libc, the kernel, or the destination filesystem, the procedure
fails closed and preserves the reported stage for review. Do not patch libc or
substitute `mv`, `os.rename`, or another check-then-rename sequence.

Extra or missing names, differing bytes, unsafe directory or file modes,
symlinks, hard-linked files, and source/destination identity or metadata changes
during the operation all fail closed and remain preserved.

```bash
materialize_exact_tree() {
  python3 - "$@" <<'PY'
import ctypes
import errno
import hashlib
import os
import secrets
import stat
import sys

uid = os.getuid()
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
stage_path = None
open_fds = []


def snapshot(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def require_directory(value, label):
    if not stat.S_ISDIR(value.st_mode):
        raise RuntimeError(f"{label} is not a directory")
    if value.st_uid != uid:
        raise RuntimeError(f"{label} is not owned by the current user")
    if stat.S_IMODE(value.st_mode) != 0o700:
        raise RuntimeError(f"{label} mode is not 0700")


def require_file(value, label):
    if not stat.S_ISREG(value.st_mode):
        raise RuntimeError(f"{label} is not a regular file")
    if value.st_uid != uid:
        raise RuntimeError(f"{label} is not owned by the current user")
    if stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1:
        raise RuntimeError(f"{label} mode/link count is unsafe")


def canonical_absolute(path, label):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise RuntimeError(f"{label} is not an absolute canonical path")
    return path


def open_directory(path, label):
    canonical_absolute(path, label)
    if os.path.realpath(path) != path:
        raise RuntimeError(f"{label} contains a symlink component")
    descriptor = os.open(path, directory_flags)
    open_fds.append(descriptor)
    metadata = os.fstat(descriptor)
    require_directory(metadata, label)
    return descriptor, snapshot(metadata), tuple(sorted(os.listdir(descriptor)))


def digest(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    value = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return value.digest()
        value.update(chunk)


def require_stable_directory(record, label):
    descriptor, original, entries = record
    if snapshot(os.fstat(descriptor)) != original:
        raise RuntimeError(f"{label} identity or metadata changed")
    if tuple(sorted(os.listdir(descriptor))) != entries:
        raise RuntimeError(f"{label} entries changed")


def require_same_directory_identity(record, label):
    descriptor, original, _ = record
    current = snapshot(os.fstat(descriptor))
    for index in (0, 1, 2, 4, 5):
        if current[index] != original[index]:
            raise RuntimeError(f"{label} identity, ownership, or mode changed")


try:
    arguments = sys.argv[1:]
    if len(arguments) < 3 or len(arguments) % 2 == 0:
        raise RuntimeError("usage: DEST NAME SOURCE [NAME SOURCE ...]")

    destination = canonical_absolute(arguments[0], "destination")
    pairs = list(zip(arguments[1::2], arguments[2::2], strict=True))
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise RuntimeError("destination names are duplicated")
    for name in names:
        if not name or name in {".", ".."} or "/" in name:
            raise RuntimeError("destination name is not one literal basename")

    parent_path = os.path.dirname(destination)
    destination_name = os.path.basename(destination)
    parent = open_directory(parent_path, "destination parent")
    parent_fd = parent[0]

    source_directories = {}
    sources = {}
    for name, source_path in pairs:
        canonical_absolute(source_path, f"source {name}")
        if os.path.basename(source_path) != name:
            raise RuntimeError(f"source basename for {name} differs")
        source_parent_path = os.path.dirname(source_path)
        if source_parent_path == parent_path:
            raise RuntimeError("source and destination parent must differ")
        if source_parent_path not in source_directories:
            source_directories[source_parent_path] = open_directory(
                source_parent_path, f"source parent for {name}"
            )
        source_parent_fd = source_directories[source_parent_path][0]
        source_fd = os.open(name, file_flags, dir_fd=source_parent_fd)
        open_fds.append(source_fd)
        source_metadata = os.fstat(source_fd)
        require_file(source_metadata, f"source {name}")
        sources[name] = (source_fd, snapshot(source_metadata))

    try:
        destination_fd = os.open(destination_name, directory_flags, dir_fd=parent_fd)
    except FileNotFoundError:
        destination_fd = None
    if destination_fd is not None:
        open_fds.append(destination_fd)
        destination_metadata = os.fstat(destination_fd)
        require_directory(destination_metadata, "existing destination")
        destination_snapshot = snapshot(destination_metadata)
        if set(os.listdir(destination_fd)) != set(names) or len(os.listdir(destination_fd)) != len(names):
            raise RuntimeError("existing destination allowlist differs")
        existing_files = {}
        for name in names:
            existing_fd = os.open(name, file_flags, dir_fd=destination_fd)
            open_fds.append(existing_fd)
            existing_metadata = os.fstat(existing_fd)
            require_file(existing_metadata, f"existing destination {name}")
            existing_snapshot = snapshot(existing_metadata)
            existing_files[name] = (existing_fd, existing_snapshot)
            source_fd, source_snapshot = sources[name]
            if digest(source_fd) != digest(existing_fd):
                raise RuntimeError(f"existing destination {name} bytes differ")
        for name in names:
            source_fd, source_snapshot = sources[name]
            existing_fd, existing_snapshot = existing_files[name]
            if snapshot(os.fstat(source_fd)) != source_snapshot:
                raise RuntimeError(f"source {name} changed during comparison")
            if snapshot(os.fstat(existing_fd)) != existing_snapshot:
                raise RuntimeError(f"existing destination {name} changed during comparison")
        if snapshot(os.fstat(destination_fd)) != destination_snapshot:
            raise RuntimeError("existing destination changed during comparison")
        if set(os.listdir(destination_fd)) != set(names) or len(os.listdir(destination_fd)) != len(names):
            raise RuntimeError("existing destination entries changed during comparison")
        for path, record in source_directories.items():
            require_stable_directory(record, f"source directory {path}")
        require_stable_directory(parent, "destination parent")
        print(f"status=existing destination={destination}")
        raise SystemExit(0)

    for _ in range(128):
        stage_name = f".pki-materialize.{secrets.token_hex(16)}"
        try:
            os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
            break
        except FileExistsError:
            continue
    else:
        raise RuntimeError("cannot reserve a unique materialization stage")
    stage_path = os.path.join(parent_path, stage_name)
    stage_fd = os.open(stage_name, directory_flags, dir_fd=parent_fd)
    open_fds.append(stage_fd)
    require_directory(os.fstat(stage_fd), "materialization stage")

    staged_files = {}
    for name in names:
        source_fd, source_snapshot = sources[name]
        output_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=stage_fd,
        )
        open_fds.append(output_fd)
        os.lseek(source_fd, 0, os.SEEK_SET)
        copied = hashlib.sha256()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            copied.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output_fd, view)
                view = view[written:]
        os.fsync(output_fd)
        require_file(os.fstat(output_fd), f"staged {name}")
        staged_files[name] = (output_fd, snapshot(os.fstat(output_fd)))
        if copied.digest() != digest(source_fd):
            raise RuntimeError(f"source {name} bytes changed during copy")
        if snapshot(os.fstat(source_fd)) != source_snapshot:
            raise RuntimeError(f"source {name} identity or metadata changed during copy")

    if set(os.listdir(stage_fd)) != set(names) or len(os.listdir(stage_fd)) != len(names):
        raise RuntimeError("materialization stage allowlist differs")
    for name in names:
        source_fd, source_snapshot = sources[name]
        output_fd, output_snapshot = staged_files[name]
        if snapshot(os.fstat(source_fd)) != source_snapshot:
            raise RuntimeError(f"source {name} changed after copy")
        if snapshot(os.fstat(output_fd)) != output_snapshot:
            raise RuntimeError(f"staged {name} changed after copy")
    for path, record in source_directories.items():
        require_stable_directory(record, f"source directory {path}")
    require_same_directory_identity(parent, "destination parent")
    parent_entries = os.listdir(parent_fd)
    expected_parent_entries = set(parent[2]) | {stage_name}
    if set(parent_entries) != expected_parent_entries or len(parent_entries) != len(expected_parent_entries):
        raise RuntimeError("destination parent entries changed during staging")
    os.fsync(stage_fd)

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(parent_fd, os.fsencode(stage_name), parent_fd, os.fsencode(destination_name), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise RuntimeError("destination appeared during no-clobber publication")
        raise OSError(error, os.strerror(error))
    stage_path = None
    os.fsync(parent_fd)
    print(f"status=created destination={destination}")
except SystemExit:
    raise
except Exception as error:
    suffix = f"; preserved_stage={stage_path}" if stage_path else ""
    print(f"materialization failed: {error}{suffix}", file=sys.stderr)
    raise SystemExit(1)
finally:
    for descriptor in reversed(open_fds):
        try:
            os.close(descriptor)
        except OSError:
            pass
PY
}
```

An exact retry reports `status=existing`. Any failure is a stop condition: keep
the destination and any reported stage unchanged for attribution. This procedure
does not authorize removal of old immutable coordinates.

## Argument Provenance

Fill an outside-Git operator record only from authenticated output. Do not
manually recompute or infer a digest when the producing command reports it.

| Coordinate | Exact provenance and meaning |
| --- | --- |
| `REQUEST_ID` | Request creation output; exact 32-lowercase-hex lifecycle ID. |
| `REQUEST_SHA256` | Request creation output; SHA-256 of exact canonical `request` bytes. |
| `CSR_SHA256` | Request creation output; SHA-256 of exact `tls.csr` bytes. |
| `CSR_SPKI_SHA256` | Request creation output; digest of the CSR public-key SPKI. |
| `TRANSPORT_HOST_KEY_SHA256` | Direct `request-pull` JSON field; 64-lowercase-hex SHA-256 of the binary SSH host public-key blob signed into `collection-receipt`. |
| Endpoint `expected_host_key_sha256` | Independently reviewed OpenSSH display fingerprint in `SHA256:<base64>` form. It identifies the same host-key blob but is not the raw hexadecimal transport digest. |
| `APPROVAL_SHA256` | `offline-csr approve` JSON field `approval_sha256`; SHA-256 of exact canonical `approval` bytes and the approval-version suffix. Do not hash the signature or derive it manually. |
| `ARTIFACT_SHA256` | `certificate-export publish` JSON field `manifest_sha256`; SHA-256 of exact canonical `artifact` bytes, used as the artifact pin. It is not the GitLab `stage-manifest` digest. |
| `DEPLOYMENT_SHA256` | Successful activation output; SHA-256 of exact target-signed canonical `deployment` bytes and the evidence-version suffix. |
| `OUTCOME_SHA256` | `csr-outcome publish` JSON field `manifest_sha256`; SHA-256 of exact canonical `outcome` bytes and the outcome-version suffix. It is not the GitLab `stage-manifest` digest. |
| Direct destination paths | `request-pull` and `evidence-pull` JSON field `destination_dir`; exact no-clobber local publication path. |
| Certificate/outcome paths | Exact `certificate-export resolve --format path` or `csr-outcome resolve --format path` output after digest-pinned reauthentication. |
| Package versions | Request/response: `REQUEST_ID`; approval: `REQUEST_ID-APPROVAL_SHA256`; evidence: `REQUEST_ID-DEPLOYMENT_SHA256`; outcome: `REQUEST_ID-OUTCOME_SHA256`. |

## Publication Lock

GitLab multi-file publication is not atomic. Before every `gitlab-package
publish`, the GitLab publisher must acquire an external lock keyed by this exact
tuple:

```text
<project-id>:<stage>:<service>:<full-package-version>
```

For an operator-run publication, use the approved lock procedure to inspect the
protected lock namespace, acquire exclusive custody of that exact tuple, record
the non-secret holder and start time, retain the lock through the helper's final
coordinate reinspection, and release it only after an unambiguous result. On an
ambiguous or stale lock, stop for review; do not delete it or run a second
publisher. This runbook does not invent a lock helper command.

Protected GitLab CI must serialize the identical coordinate with this exact
shape:

```yaml
resource_group: "${CI_PROJECT_ID}:${PKI_STAGE}:${PKI_SERVICE}:${PKI_PACKAGE_VERSION}"
```

The variables must already contain the exact project ID, stage, service, and
full package version supplied to the publish command. A single global protected
exchange lock is stricter and also acceptable. The helper does not acquire the
external lock.

## Bootstrap Stage

Review private signer inventory, schema-2 five-file trust, target and runner
validation material, managed predecessor state, rollback hold, unresolved
recovery state, GitLab controls, endpoint pin, and backup/restore procedures.
Trust rotation is forbidden while a request is pending.

### B1. Install And Verify Signer State

**Actor:** Offline signer. **Run on:** Disconnected signer host. **Prerequisite:**
Reviewed private inventory/trust and short-lived passphrase files. **Output and
provenance:** Installed inventory/trust, rollover status, successful passphrase
verification, and encrypted backup path from `platform-pki`. **Retry/result:**
Exact installs and verification are idempotent; stop on recovery state or a
conflict. **Next actor:** Lifecycle operator.

```bash
platform-pki inventory-install \
  --namespace "$PKI_NAMESPACE" \
  --private-repo /absolute/path/to/platform-private
platform-pki csr-trust-install \
  --namespace "$PKI_NAMESPACE" \
  --private-repo /absolute/path/to/platform-private
platform-pki ca-rollover status \
  --namespace "$PKI_NAMESPACE" --format json
platform-pki ca-passphrase-verify \
  --namespace "$PKI_NAMESPACE" \
  --root-pass-file /run/secrets/platform-pki-root-pass \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
platform-pki backup \
  --namespace "$PKI_NAMESPACE" \
  --age-recipient '<reviewed-age-recipient>'
```

### B2. Provision Validation Material And Bootstrap Trust

**Actor:** Lifecycle operator. **Run on:** Ansible controller; delegated to the
exact target and distinct runner. **Prerequisite:** Reviewed outside-Git CA,
validation boundary, five-file trust, and exact inventory selection. **Output
and provenance:** Ansible success for installed validation inputs and target
trust. **Retry/result:** Exact reinstallation is an authenticated no-op; no trust
rotation occurs. **Next actor:** Lifecycle operator.

```bash
make registry-pki-validation-material \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER"
make apply ENV="$ENVIRONMENT" \
  PLAYBOOK=playbooks/registry-pki-trust.yml LIMIT="$TARGET"
```

On an initialized target, status may report `managed-migration-needed` with
`required_action=create-migration-request`. Status is not a fresh-install
bootstrap command; the mutable request stage installs the lifecycle helper and
independently proves the managed predecessor.

### B3. Verify Bootstrap Readiness Without Creating A Request

**Actor:** Lifecycle operator. **Run on:** Ansible controller in check mode,
delegated to the exact target and distinct runner. **Prerequisite:** B1/B2 and
reviewed private lifecycle inputs. **Output and provenance:** Fixed readiness
preflight validates topology, request helper, lifecycle/runner helpers, and exact
target validation-material metadata/digests without transport or request state.
**Retry/result:** Read-only and repeatable; any failure blocks Request. **Next
actor:** Lifecycle operator.

```bash
make registry-pki-bootstrap-readiness \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER"
```

Run [Fixed Cleanup](#fixed-cleanup) after Bootstrap. Request then re-enables the
restricted endpoint only for its authorized transport window.

## Request Stage

### R0. Prepare Wrapper-Managed Direct Access

**Actor:** Lifecycle operator. **Run on:** Ansible controller and exact target.
**Prerequisite:** Private inventory supplies the exact reviewed public key and
Bootstrap authorization is complete. **Output and provenance:** No access is
enabled at this step. The fixed request-pull wrapper in R2 atomically claims the
target operation lease, enables and validates the restricted endpoint, runs one
route, then revokes before releasing its lease on exit or a handled signal.
**Retry/result:** A concurrent lease claim fails without mutating the active
operation; unsafe or unmanaged identity state fails closed. **Next actor:**
Lifecycle operator.

### R1. Create The Target-Local Request

**Actor:** Lifecycle operator; payload producer is the target. **Run on:**
Ansible controller, delegated to the exact target. **Prerequisite:** Bootstrap
complete, normal Zot smoke healthy, no unresolved lifecycle state. **Output and
provenance:** Target helper reports `REQUEST_ID`, `REQUEST_SHA256`, `CSR_SHA256`,
and `CSR_SPKI_SHA256`; record those exact fields. **Retry/result:** Exact pending
state is revalidated; conflicts or expired state fail closed. **Next actor:**
Transport operator.

```bash
make registry-pki-request ENV="$ENVIRONMENT" LIMIT="$TARGET"
```

The default lifetime is one hour. If reviewed transport needs more time, replace
the preceding command with this explicit alternative, up to seven days:

```bash
make registry-pki-request ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_TTL_SECONDS=604800
```

### R2. Pull The Exact Request

**Actor:** Transport operator. **Run on:** Online transfer station. **Prerequisite:**
Exact request ID and reviewed endpoint record. **Output and provenance:** Direct
client JSON reports `status`, service, target, request ID,
`transport_host_key_sha256`, and `destination_dir`; record the digest as
`TRANSPORT_HOST_KEY_SHA256` and require the destination shown below. **Retry/result:**
Exact existing bytes return idempotent success; a conflict is preserved and
rejected. **Next actor:** Lifecycle operator.

```bash
make registry-pki-direct-request-pull \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  ENDPOINT_RECORD="$ENDPOINT_RECORD" REQUEST_ID="$REQUEST_ID" \
  TRANSFER_DIR="$EXCHANGE_ROOT/intake/request-$REQUEST_ID"
```

### R3. Authenticate Request Intake

**Actor:** Lifecycle operator. **Run on:** Ansible controller localhost only.
**Prerequisite:** Exact R1 digests, R2 host-key digest, and exact three-file pull
directory. **Output and provenance:** Authenticated controller publication at
`$EXCHANGE_ROOT/$SERVICE/$REQUEST_ID/request` plus frozen trust; no target
connection or Ansible file transfer occurs. **Retry/result:** Exact publication
is idempotent; any byte, trust, inventory, principal, SAN, or profile conflict
fails closed. **Next actor:** Lifecycle operator.

```bash
PLATFORM_CONFIG_PKI_EXCHANGE_ROOT="$EXCHANGE_ROOT" \
make registry-pki-request-intake \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" REQUEST_ID="$REQUEST_ID" \
  REQUEST_SHA256="$REQUEST_SHA256" CSR_SHA256="$CSR_SHA256" \
  CSR_SPKI_SHA256="$CSR_SPKI_SHA256" \
  TRANSPORT_HOST_KEY_SHA256="$TRANSPORT_HOST_KEY_SHA256" \
  REQUEST_DIR="/platform-pki-exchange/intake/request-$REQUEST_ID"
```

The publication contains exactly `tls.csr`, `request`, `request.sig`, and
`collection-receipt`; the sibling frozen trust directory contains exactly the
five reviewed trust files. The target `tls.key` remains target-local.

### R4. Confirm Pending State

**Actor:** Lifecycle operator. **Run on:** Ansible controller, delegated read-only
to the target. **Prerequisite:** Successful intake. **Output and provenance:**
Authenticated target status. **Retry/result:** Read-only and repeatable; require
`status=request-pending` and `required_action=collect-or-await-response`.
**Next actor:** GitLab publisher.

```bash
make registry-pki-status ENV="$ENVIRONMENT" LIMIT="$TARGET"
```

### R5. Publish The Request Package

**Actor:** GitLab publisher. **Run on:** Authorized online transfer station or
protected CI. **Prerequisite:** Exact request publication and frozen trust,
publisher token, project/CA records, and held external lock
`<project-id>:request:<service>:<request-id>`. **Output and provenance:** Complete
`pki-exchange-request-$SERVICE` version `$REQUEST_ID`; helper-generated
`stage-manifest` is transport completion evidence only. **Retry/result:** Matching
manifest-absent partial resumes; complete exact package is idempotent; ambiguous
or conflicting state is retained and rejected. **Next actor:** GitLab retriever.

```bash
platform-pki gitlab-package publish \
  --stage request --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" --package-version "$REQUEST_ID" \
  --source-dir "$EXCHANGE_ROOT/$SERVICE/$REQUEST_ID/request" \
  --project-record "$PROJECT_RECORD" \
  --token-type private --token-file "$PUBLISH_TOKEN" \
  --ca-file "$GITLAB_CA" \
  --inventory-record /outside-git/pki/request-inventory \
  --trust-dir "$EXCHANGE_ROOT/$SERVICE/$REQUEST_ID/trust" \
  --transport-host-key-sha256 "$TRANSPORT_HOST_KEY_SHA256"
```

The Request stage ends pending. Revoke direct access through
[Fixed Cleanup](#fixed-cleanup), then enter Gate 1.

## Gate 1: Offline Approval And Signing

Gate 1 starts from the exact published request coordinate and ends only when the
exact signed response package has been published. Offline actors never connect
to GitLab.

### G1.1. Download And Materialize Approver Input

**Actor:** GitLab retriever. **Run on:** Online retrieval station. **Prerequisite:**
Operator-supplied exact request coordinate, reader token, reviewed request
inventory/trust, and host-key digest. **Output and provenance:** Validated
transport package under `gitlab-downloads` and exact three-file approver input
under `TRANSFER_ROOT/request/$REQUEST_ID`. **Retry/result:** Exact destinations
are idempotent; conflicts fail without replacement. **Next actor:** Transport
operator, then offline approver.

```bash
platform-pki gitlab-package download \
  --stage request --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" --package-version "$REQUEST_ID" \
  --destination-dir "$EXCHANGE_ROOT/gitlab-downloads/request/$REQUEST_ID" \
  --project-record "$PROJECT_RECORD" \
  --token-type private --token-file "$READ_TOKEN" \
  --ca-file "$GITLAB_CA" \
  --inventory-record /outside-git/pki/request-inventory \
  --trust-dir "$EXCHANGE_ROOT/$SERVICE/$REQUEST_ID/trust" \
  --transport-host-key-sha256 "$TRANSPORT_HOST_KEY_SHA256"
materialize_exact_tree "$TRANSFER_ROOT/request/$REQUEST_ID" \
  tls.csr "$EXCHANGE_ROOT/gitlab-downloads/request/$REQUEST_ID/tls.csr" \
  request "$EXCHANGE_ROOT/gitlab-downloads/request/$REQUEST_ID/request" \
  request.sig "$EXCHANGE_ROOT/gitlab-downloads/request/$REQUEST_ID/request.sig"
```

Retain `collection-receipt` and `stage-manifest` as online transport evidence.
The transport operator moves only the exact three-file directory through
controlled media to `$OFFLINE_ROOT/media-in/request/$REQUEST_ID`.

### G1.2. Approve The Exact Request

**Actor:** Offline approver. **Run on:** Disconnected approver host. **Prerequisite:**
Exact three-file controlled-media input, independently installed policy/trust,
approval key, and live human review. **Output and provenance:** JSON field
`approval_sha256` and exact five-file approved directory; record that field as
`APPROVAL_SHA256`. **Retry/result:** Review the displayed request and type the
exact confirmation; do not use `--yes`. Preserve conflicts and expired attempts.
**Next actor:** Transport operator, then GitLab publisher.

```bash
platform-pki offline-csr approve "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --operation migrate \
  --request-id "$REQUEST_ID" \
  --input-dir "$OFFLINE_ROOT/media-in/request/$REQUEST_ID" \
  --approval-key "$APPROVAL_KEY" \
  --output-dir "$OFFLINE_ROOT/work/approved/$REQUEST_ID"
```

The approved directory contains exactly mode-`0600` `tls.csr`, `request`,
`request.sig`, `approval`, and `approval.sig`. After recording
`APPROVAL_SHA256`, materialize only `approval` and `approval.sig` at the exact
approval attempt coordinate
`$OFFLINE_ROOT/media-out/approval/$REQUEST_ID-$APPROVAL_SHA256`:

`--output-dir` above is a fresh absent command work stage because the approval
digest does not exist until `approve` returns. It is not a retained or transport
approval-attempt coordinate. Every materialized approval attempt begins with the
reported approval digest as shown below; never reuse the work stage for a new
attempt.

```bash
materialize_exact_tree \
  "$OFFLINE_ROOT/media-out/approval/$REQUEST_ID-$APPROVAL_SHA256" \
  approval "$OFFLINE_ROOT/work/approved/$REQUEST_ID/approval" \
  approval.sig "$OFFLINE_ROOT/work/approved/$REQUEST_ID/approval.sig"
```

Move that exact two-file directory through controlled media; G1.3 materializes
the received files into the matching online digest-qualified coordinate.

### G1.3. Materialize The Received Approval Attempt

**Actor:** Transport operator. **Run on:** Online transfer station with the
reviewed controlled medium mounted read-only at `CONTROLLED_MEDIA_IN`. **Prerequisite:**
Exact digest-qualified two-file media directory from G1.2. **Output and
provenance:** Exact online approval attempt at
`$TRANSFER_ROOT/approval/$REQUEST_ID-$APPROVAL_SHA256`. **Retry/result:** The
canonical no-clobber procedure reports `created` or exact `existing`; all other
results preserve both media input and destination and block publication. **Next
actor:** GitLab publisher.

```bash
materialize_exact_tree \
  "$TRANSFER_ROOT/approval/$REQUEST_ID-$APPROVAL_SHA256" \
  approval \
  "$CONTROLLED_MEDIA_IN/approval/$REQUEST_ID-$APPROVAL_SHA256/approval" \
  approval.sig \
  "$CONTROLLED_MEDIA_IN/approval/$REQUEST_ID-$APPROVAL_SHA256/approval.sig"
```

### G1.4. Publish The Approval Attempt

**Actor:** GitLab publisher. **Run on:** Authorized online transfer station or
protected CI. **Prerequisite:** Exact two-file approval source, authoritative
`APPROVAL_SHA256` from G1.2, and held lock
`<project-id>:approval:<service>:<request-id>-<approval-sha256>`. **Output and
provenance:** `pki-exchange-approval-$SERVICE` version
`$REQUEST_ID-$APPROVAL_SHA256`. **Retry/result:** Exact partial resume and
complete-package idempotency only; preserve conflicts. **Next actor:** GitLab
retriever.

```bash
platform-pki gitlab-package publish \
  --stage approval --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$APPROVAL_SHA256" \
  --source-dir "$TRANSFER_ROOT/approval/$REQUEST_ID-$APPROVAL_SHA256" \
  --project-record "$PROJECT_RECORD" \
  --token-type private --token-file "$PUBLISH_TOKEN" \
  --ca-file "$GITLAB_CA"
```

### G1.5. Retrieve Approval And Build Signer Input

**Actor:** GitLab retriever. **Run on:** Online retrieval station. **Prerequisite:**
Exact request and approval versions. **Output and provenance:** Validated approval
download and exact five signer command inputs assembled from the separately
validated request and approval packages. **Retry/result:** Exact existing
destinations are idempotent; no overwrite or inferred version. **Next actor:**
Transport operator, then offline signer.

```bash
platform-pki gitlab-package download \
  --stage approval --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$APPROVAL_SHA256" \
  --destination-dir "$EXCHANGE_ROOT/gitlab-downloads/approval/$REQUEST_ID-$APPROVAL_SHA256" \
  --project-record "$PROJECT_RECORD" \
  --token-type private --token-file "$READ_TOKEN" \
  --ca-file "$GITLAB_CA"
materialize_exact_tree \
  "$TRANSFER_ROOT/approval/$REQUEST_ID-$APPROVAL_SHA256" \
  approval \
  "$EXCHANGE_ROOT/gitlab-downloads/approval/$REQUEST_ID-$APPROVAL_SHA256/approval" \
  approval.sig \
  "$EXCHANGE_ROOT/gitlab-downloads/approval/$REQUEST_ID-$APPROVAL_SHA256/approval.sig"
materialize_exact_tree \
  "$TRANSFER_ROOT/signer-input/$REQUEST_ID-$APPROVAL_SHA256" \
  tls.csr "$TRANSFER_ROOT/request/$REQUEST_ID/tls.csr" \
  request "$TRANSFER_ROOT/request/$REQUEST_ID/request" \
  request.sig "$TRANSFER_ROOT/request/$REQUEST_ID/request.sig" \
  approval "$TRANSFER_ROOT/approval/$REQUEST_ID-$APPROVAL_SHA256/approval" \
  approval.sig \
  "$TRANSFER_ROOT/approval/$REQUEST_ID-$APPROVAL_SHA256/approval.sig"
```

Move only the exact digest-qualified five-file signer-input directory through
controlled media to
`$OFFLINE_ROOT/media-in/signer-input/$REQUEST_ID-$APPROVAL_SHA256`. Neither
`stage-manifest`, `collection-receipt`, package metadata, GitLab checksums, nor
transport credentials enter signer command input.

### G1.6. Sign And Publish The Local Certificate Export

**Actor:** Offline signer. **Run on:** Disconnected signer host. **Prerequisite:**
Exact five-file input, authoritative signer state, response key, and intermediate
passphrase file. **Output and provenance:** Sign creates immutable signer
candidate/response state; certificate export JSON reports `manifest_sha256`,
recorded as `ARTIFACT_SHA256`; resolve prints the exact authenticated six-file
path. **Retry/result:** Signing obeys replay and recovery journals; stop on
recovery-required. Export is exact-idempotent and resolve is read-only.
**Next actor:** Transport operator, then GitLab publisher.

```bash
platform-pki offline-csr sign "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --operation migrate \
  --request-id "$REQUEST_ID" \
  --input-dir "$OFFLINE_ROOT/media-in/signer-input/$REQUEST_ID-$APPROVAL_SHA256" \
  --response-key "$RESPONSE_KEY" \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
```

Publish the local export and record its returned `manifest_sha256` as
`ARTIFACT_SHA256`:

```bash
platform-pki certificate-export publish "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID"
```

Resolve with that exact digest, set `RESPONSE_EXPORT_DIR` to the literal path
printed by `resolve`, and materialize the six files:

```bash
platform-pki certificate-export resolve "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" \
  --manifest-sha256 "$ARTIFACT_SHA256" \
  --format path
RESPONSE_EXPORT_DIR=/absolute/path/reported-by-certificate-export-resolve
materialize_exact_tree \
  "$OFFLINE_ROOT/media-out/response/$REQUEST_ID" \
  artifact "$RESPONSE_EXPORT_DIR/artifact" \
  tls.crt "$RESPONSE_EXPORT_DIR/tls.crt" \
  ca-chain.crt "$RESPONSE_EXPORT_DIR/ca-chain.crt" \
  fullchain.crt "$RESPONSE_EXPORT_DIR/fullchain.crt" \
  response "$RESPONSE_EXPORT_DIR/response" \
  response.sig "$RESPONSE_EXPORT_DIR/response.sig"
```

The resolved directory contains exactly `artifact`, `tls.crt`, `ca-chain.crt`,
`fullchain.crt`, `response`, and `response.sig`. Stage those exact public files
under `$OFFLINE_ROOT/media-out/response/$REQUEST_ID`, then move them through
controlled media to `$CONTROLLED_MEDIA_IN/response/$REQUEST_ID` on the online
transfer station. Preserve mode `0700` on the directory, mode `0600` on each
singly linked file, and the resolved bytes.

### G1.7. Materialize The Received Response

**Actor:** Transport operator. **Run on:** Online transfer station with reviewed
controlled media mounted read-only. **Prerequisite:** Exact six-file response at immutable
request coordinate `$REQUEST_ID`. **Output and provenance:** Exact online
response source at `$TRANSFER_ROOT/response/$REQUEST_ID`, still outside
`EXCHANGE_ROOT`. **Retry/result:** Canonical no-clobber `created` or exact
`existing`; any other result preserves inputs and blocks publication. **Next
actor:** GitLab publisher.

```bash
materialize_exact_tree "$TRANSFER_ROOT/response/$REQUEST_ID" \
  artifact "$CONTROLLED_MEDIA_IN/response/$REQUEST_ID/artifact" \
  tls.crt "$CONTROLLED_MEDIA_IN/response/$REQUEST_ID/tls.crt" \
  ca-chain.crt "$CONTROLLED_MEDIA_IN/response/$REQUEST_ID/ca-chain.crt" \
  fullchain.crt "$CONTROLLED_MEDIA_IN/response/$REQUEST_ID/fullchain.crt" \
  response "$CONTROLLED_MEDIA_IN/response/$REQUEST_ID/response" \
  response.sig "$CONTROLLED_MEDIA_IN/response/$REQUEST_ID/response.sig"
```

### G1.8. Publish The Response

**Actor:** GitLab publisher. **Run on:** Authorized online transfer station or
protected CI. **Prerequisite:** Exact resolved six-file response and held lock
`<project-id>:response:<service>:<request-id>`. **Output and provenance:**
`pki-exchange-response-$SERVICE` version `$REQUEST_ID`. **Retry/result:** Exact
partial resume and complete-package idempotency only; preserve conflicts.
**Next actor:** GitLab retriever in Activate/Evidence.

```bash
platform-pki gitlab-package publish \
  --stage response --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" --package-version "$REQUEST_ID" \
  --source-dir "$TRANSFER_ROOT/response/$REQUEST_ID" \
  --project-record "$PROJECT_RECORD" \
  --token-type private --token-file "$PUBLISH_TOKEN" \
  --ca-file "$GITLAB_CA"
```

Gate 1 is satisfied only after exact package validation succeeds. GitLab
presence alone does not authorize activation.

## Activate/Evidence Stage

### A0. Prepare Wrapper-Managed Direct Access

**Actor:** Lifecycle operator. **Run on:** Ansible controller and exact target.
**Prerequisite:** Gate 1 is satisfied and private inventory supplies the
reviewed public key. **Output and provenance:** No access is enabled at this
step. The response-push wrapper in A3 owns the lease-bound access window.
**Retry/result:** Stale or unsafe identity state fails closed. **Next actor:**
GitLab retriever.

### A1. Download And Materialize The Response Outside Exchange

**Actor:** GitLab retriever. **Run on:** Online retrieval station. **Prerequisite:**
Exact response version and artifact digest from Gate 1. **Output and provenance:**
Transport download beneath `EXCHANGE_ROOT`, then a separate exact six-file
directory at `$TRANSFER_ROOT/response/$REQUEST_ID`. **Retry/result:** Download is
idempotent for exact bytes. Materialization must target an absent or already
exact reviewed directory; never merge conflicting content. **Next actor:**
Lifecycle operator.

```bash
platform-pki gitlab-package download \
  --stage response --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" --package-version "$REQUEST_ID" \
  --destination-dir "$EXCHANGE_ROOT/gitlab-downloads/response/$REQUEST_ID" \
  --project-record "$PROJECT_RECORD" \
  --token-type private --token-file "$READ_TOKEN" \
  --ca-file "$GITLAB_CA"
materialize_exact_tree "$TRANSFER_ROOT/response/$REQUEST_ID" \
  artifact "$EXCHANGE_ROOT/gitlab-downloads/response/$REQUEST_ID/artifact" \
  tls.crt "$EXCHANGE_ROOT/gitlab-downloads/response/$REQUEST_ID/tls.crt" \
  ca-chain.crt \
  "$EXCHANGE_ROOT/gitlab-downloads/response/$REQUEST_ID/ca-chain.crt" \
  fullchain.crt \
  "$EXCHANGE_ROOT/gitlab-downloads/response/$REQUEST_ID/fullchain.crt" \
  response "$EXCHANGE_ROOT/gitlab-downloads/response/$REQUEST_ID/response" \
  response.sig \
  "$EXCHANGE_ROOT/gitlab-downloads/response/$REQUEST_ID/response.sig"
```

`stage-manifest` remains in the transport download. The response-check source is
the payload-only directory outside `EXCHANGE_ROOT`, not the download directory
and not an `intake/` child.

### A2. Authenticate And Snapshot The Response

**Actor:** Lifecycle operator. **Run on:** Ansible controller localhost only.
**Prerequisite:** Exact external six-file source, artifact pin, frozen request
and trust. **Output and provenance:** Authenticated immutable controller snapshot
at `$EXCHANGE_ROOT/$SERVICE/$REQUEST_ID/response`, reported with `status=ready`.
**Retry/result:** Exact snapshot returns existing/idempotent; source/exchange
overlap or any conflict fails. No Zot or target mutation occurs. **Next actor:**
Transport operator.

```bash
PLATFORM_CONFIG_PKI_EXCHANGE_ROOT="$EXCHANGE_ROOT" \
make registry-pki-response-check \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  RESPONSE_DIR="$CONTAINER_TRANSFER_ROOT/response/$REQUEST_ID"
```

### A3. Push The Exact Response

**Actor:** Transport operator. **Run on:** Online transfer station. **Prerequisite:**
Successful A2 and the same exact external six-file source. **Output and
provenance:** Direct client reports exact request/artifact coordinates and
`status=staged` or `status=existing` from fixed target ingress. **Retry/result:**
Exact restaging is idempotent; a first conflicting candidate requires review.
**Next actor:** Lifecycle operator.

```bash
make registry-pki-direct-response-push \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  ENDPOINT_RECORD="$ENDPOINT_RECORD" REQUEST_ID="$REQUEST_ID" \
  ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  TRANSFER_DIR="$TRANSFER_ROOT/response/$REQUEST_ID"
```

### A4. Activate And Validate

**Actor:** Lifecycle operator; target producer and validation runner are delegated
actors. **Run on:** Ansible controller, exact target, and distinct runner.
**Prerequisite:** Authenticated directly staged response, exact request and
artifact digests, and one distinct reviewed runner. **Output and provenance:**
`status=activated-and-validated` and the exact target-signed `deployment` digest;
record it as `DEPLOYMENT_SHA256`. **Retry/result:** Activation runs automatically
after all preflights pass. Do not blindly rerun after failure or
recovery-required status; use
[Target Activation Recovery](#target-activation-recovery). **Next actor:**
Lifecycle operator.

```bash
make registry-pki-activate \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256"
```

All package authentication, target-local key matching, exact bindings, local Zot
validation, distinct-runner validation, and journal-bound rollback remain. The
single activation route appends direct mode and the exact request, artifact, and
runner coordinates after caller `EXTRA_ARGS`. There is no controller-local or
interactive activation route.

### A5. Export, Pull, And Intake Evidence

**Actor:** Lifecycle operator for export/intake; transport operator for pull;
payload producers are target and runner. **Run on:** Ansible controller and
online transfer station, with read-only target operations. **Prerequisite:**
Exact successful activation coordinates. **Output and provenance:** Export
reports exact direct coordinates; pull JSON reports `destination_dir`; intake
authenticates and publishes the five files at
`$EXCHANGE_ROOT/$SERVICE/$REQUEST_ID/evidence/$DEPLOYMENT_SHA256`.
**Retry/result:** Exact export is read-only and exact pull/intake are idempotent;
conflicts fail closed. **Next actor:** GitLab publisher.

```bash
make registry-pki-evidence-export \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256"
make registry-pki-direct-evidence-pull \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  ENDPOINT_RECORD="$ENDPOINT_RECORD" REQUEST_ID="$REQUEST_ID" \
  ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256" \
  TRANSFER_DIR="$EXCHANGE_ROOT/intake/evidence-$DEPLOYMENT_SHA256"
PLATFORM_CONFIG_PKI_EXCHANGE_ROOT="$EXCHANGE_ROOT" \
make registry-pki-evidence-intake \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" REQUEST_ID="$REQUEST_ID" \
  ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256" \
  EVIDENCE_DIR="/platform-pki-exchange/intake/evidence-$DEPLOYMENT_SHA256"
```

The exact evidence payload is `deployment`, `deployment.sig`,
`validation-boundary`, `validation-result`, and `validation-result.sig`.

### A6. Publish The Evidence Attempt

**Actor:** GitLab publisher. **Run on:** Authorized online transfer station or
protected CI. **Prerequisite:** Authenticated evidence source and held lock
`<project-id>:evidence:<service>:<request-id>-<deployment-sha256>`. **Output and
provenance:** `pki-exchange-evidence-$SERVICE` version
`$REQUEST_ID-$DEPLOYMENT_SHA256`. **Retry/result:** Exact partial resume and
complete-package idempotency only; preserve conflicts. **Next actor:** Lifecycle
operator, then GitLab retriever in Gate 2.

```bash
platform-pki gitlab-package publish \
  --stage evidence --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$DEPLOYMENT_SHA256" \
  --source-dir "$EXCHANGE_ROOT/$SERVICE/$REQUEST_ID/evidence/$DEPLOYMENT_SHA256" \
  --project-record "$PROJECT_RECORD" \
  --token-type private --token-file "$PUBLISH_TOKEN" \
  --ca-file "$GITLAB_CA"
```

### A7. Converge Custody And Run The Decision Preflight

**Actor:** Lifecycle operator; validation runner performs the final read-only
observation. **Run on:** Ansible controller, target, and distinct runner.
**Prerequisite:** Evidence intake and publication complete; `activate-finish`
has published authenticated active and rollback state. TLS custody is derived
from that target state, not selected in inventory. **Output and provenance:** Status must report
`evidence-exported`, `controller-exported`, and `await-signer-outcome`; second
registry apply is idempotent; smoke passes; decision preflight reports
`result=passed`. **Retry/result:** Status/preflight are read-only; convergence is
repeatable. The registry apply fails closed on helper drift or error, unresolved
journals, malformed or ambiguous lifecycle state, or configuration mismatch; it
never falls back to managed custody. A failed fresh preflight blocks Gate 2. **Next actor:** GitLab
retriever.

```bash
make registry-pki-status \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256"
make apply ENV="$ENVIRONMENT" PLAYBOOK=playbooks/registry.yml LIMIT="$TARGET"
make apply ENV="$ENVIRONMENT" PLAYBOOK=playbooks/registry.yml LIMIT="$TARGET"
make smoke-registry ENV="$ENVIRONMENT" LIMIT="$TARGET"
make registry-pki-decision-preflight \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256"
```

Revoke direct access through [Fixed Cleanup](#fixed-cleanup), then enter Gate 2.

## Gate 2: Offline Finalization And Outcome Signing

### G2.1. Download The Exact Evidence

**Actor:** GitLab retriever. **Run on:** Online retrieval station. **Prerequisite:**
Exact evidence version from A4/A6 and successful fresh decision preflight.
**Output and provenance:** Validated package under the exact digest-suffixed
download path. **Retry/result:** Exact existing destination is idempotent;
conflicts are preserved. **Next actor:** Transport operator, then offline signer.

```bash
platform-pki gitlab-package download \
  --stage evidence --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$DEPLOYMENT_SHA256" \
  --destination-dir "$EXCHANGE_ROOT/gitlab-downloads/evidence/$REQUEST_ID-$DEPLOYMENT_SHA256" \
  --project-record "$PROJECT_RECORD" \
  --token-type private --token-file "$READ_TOKEN" \
  --ca-file "$GITLAB_CA"
```

Move the exact five evidence payload files, not `stage-manifest`, through
controlled media to `$OFFLINE_ROOT/media-in/evidence/$DEPLOYMENT_SHA256`.
After offline review, materialize only exact `deployment` and `deployment.sig`
as signer command input under `$SIGNER_EVIDENCE_ROOT/$DEPLOYMENT_SHA256`; keep
the supplemental evidence and media-custody copy separate.

### G2.2. Verify And Finalize The Candidate

**Actor:** Offline signer. **Run on:** Disconnected signer host. **Prerequisite:**
Exact evidence package, authoritative signer history, and separate finalization
authorization based on the fresh target/runner preflight. **Output and
provenance:** Verify reports historical signer state with
`live_state_claimed=false`; finalize records authenticated deployment evidence.
**Retry/result:** Review and type the exact finalize confirmation. Finalization
is journaled; stop for signer recovery rather than changing evidence or action.
**Next actor:** Offline signer.

```bash
platform-pki csr-candidate verify "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" --format json
platform-pki csr-candidate finalize "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" \
  --artifact-manifest-sha256 "$ARTIFACT_SHA256" \
  --evidence-file "$SIGNER_EVIDENCE_ROOT/$DEPLOYMENT_SHA256/deployment" \
  --evidence-signature "$SIGNER_EVIDENCE_ROOT/$DEPLOYMENT_SHA256/deployment.sig"
```

### G2.3. Publish And Resolve The Local Outcome Export

**Actor:** Offline signer. **Run on:** Disconnected signer host. **Prerequisite:**
Finalized candidate and the same dedicated response key frozen into signer
trust. **Output and provenance:** Publish JSON field `manifest_sha256`, recorded
as `OUTCOME_SHA256`; resolve prints the exact authenticated six-file path.
**Retry/result:** Exact publication is idempotent; conflicts/recovery state fail.
Resolve is read-only and digest-pinned. **Next actor:** Transport operator, then
GitLab publisher.

```bash
platform-pki csr-outcome publish "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" \
  --outcome-key "$RESPONSE_KEY"
```

Record the returned `manifest_sha256` as `OUTCOME_SHA256`. Resolve with that
exact digest, set `OUTCOME_EXPORT_DIR` to the literal path printed by `resolve`,
and materialize the six files:

```bash
platform-pki csr-outcome resolve "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" \
  --manifest-sha256 "$OUTCOME_SHA256" \
  --format path
OUTCOME_EXPORT_DIR=/absolute/path/reported-by-csr-outcome-resolve
materialize_exact_tree \
  "$OFFLINE_ROOT/media-out/outcome/$REQUEST_ID-$OUTCOME_SHA256" \
  outcome "$OUTCOME_EXPORT_DIR/outcome" \
  outcome.sig "$OUTCOME_EXPORT_DIR/outcome.sig" \
  deployment "$OUTCOME_EXPORT_DIR/deployment" \
  deployment.sig "$OUTCOME_EXPORT_DIR/deployment.sig" \
  deployers.allowed_signers "$OUTCOME_EXPORT_DIR/deployers.allowed_signers" \
  decision "$OUTCOME_EXPORT_DIR/decision"
```

The exact outcome payload is `outcome`, `outcome.sig`, `deployment`,
`deployment.sig`, `deployers.allowed_signers`, and `decision`. Materialize those
six public files under the exact immutable coordinate
`$OFFLINE_ROOT/media-out/outcome/$REQUEST_ID-$OUTCOME_SHA256`, then move that
directory through controlled media. G2.5 materializes the received payload at
the matching online coordinate.

### G2.4. Back Up Finalized Signer State

**Actor:** Offline signer. **Run on:** Disconnected signer host. **Prerequisite:**
Successful finalization and outcome export. **Output and provenance:** New
encrypted backup path from authoritative `$PKI_NAMESPACE` state. **Retry/result:**
Each successful invocation creates reviewed backup material; retain prior
backups. **Next actor:** GitLab publisher.

```bash
platform-pki backup \
  --namespace "$PKI_NAMESPACE" \
  --age-recipient '<reviewed-age-recipient>'
```

### G2.5. Materialize The Received Outcome

**Actor:** Transport operator. **Run on:** Online transfer station with reviewed
controlled media mounted read-only. **Prerequisite:** Exact digest-qualified six-file
outcome from G2.3. **Output and provenance:** Exact online outcome source at
`$TRANSFER_ROOT/outcome/$REQUEST_ID-$OUTCOME_SHA256`. **Retry/result:** Canonical
no-clobber `created` or exact `existing`; any other result preserves inputs and
blocks publication. **Next actor:** GitLab publisher.

```bash
materialize_exact_tree \
  "$TRANSFER_ROOT/outcome/$REQUEST_ID-$OUTCOME_SHA256" \
  outcome \
  "$CONTROLLED_MEDIA_IN/outcome/$REQUEST_ID-$OUTCOME_SHA256/outcome" \
  outcome.sig \
  "$CONTROLLED_MEDIA_IN/outcome/$REQUEST_ID-$OUTCOME_SHA256/outcome.sig" \
  deployment \
  "$CONTROLLED_MEDIA_IN/outcome/$REQUEST_ID-$OUTCOME_SHA256/deployment" \
  deployment.sig \
  "$CONTROLLED_MEDIA_IN/outcome/$REQUEST_ID-$OUTCOME_SHA256/deployment.sig" \
  deployers.allowed_signers \
  "$CONTROLLED_MEDIA_IN/outcome/$REQUEST_ID-$OUTCOME_SHA256/deployers.allowed_signers" \
  decision \
  "$CONTROLLED_MEDIA_IN/outcome/$REQUEST_ID-$OUTCOME_SHA256/decision"
```

### G2.6. Publish The Outcome

**Actor:** GitLab publisher. **Run on:** Authorized online transfer station or
protected CI. **Prerequisite:** Exact six-file outcome source, authoritative
`OUTCOME_SHA256`, and held lock
`<project-id>:outcome:<service>:<request-id>-<outcome-sha256>`. **Output and
provenance:** `pki-exchange-outcome-$SERVICE` version
`$REQUEST_ID-$OUTCOME_SHA256`. **Retry/result:** Exact partial resume and
complete-package idempotency only; preserve conflicts. **Next actor:** GitLab
retriever in Complete.

```bash
platform-pki gitlab-package publish \
  --stage outcome --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$OUTCOME_SHA256" \
  --source-dir "$TRANSFER_ROOT/outcome/$REQUEST_ID-$OUTCOME_SHA256" \
  --project-record "$PROJECT_RECORD" \
  --token-type private --token-file "$PUBLISH_TOKEN" \
  --ca-file "$GITLAB_CA"
```

Gate 2 is satisfied only after exact package validation succeeds. The outcome is
authenticated historical signer evidence, not a claim about current target
state.

## Complete Stage

### C0. Prepare Wrapper-Managed Direct Access

**Actor:** Lifecycle operator. **Run on:** Ansible controller and exact target.
**Prerequisite:** Gate 2 is satisfied and private inventory supplies the
reviewed public key. **Output and provenance:** No access is enabled at this
step. The outcome-push wrapper in C2 owns the lease-bound access window.
**Retry/result:** Stale or unsafe identity state fails closed. **Next actor:**
GitLab retriever.

### C1. Download And Materialize The Outcome

**Actor:** GitLab retriever. **Run on:** Online retrieval station. **Prerequisite:**
Exact outcome version and all prior lifecycle pins. **Output and provenance:**
Validated transport package and separate exact six-file payload directory at
`$TRANSFER_ROOT/outcome/$REQUEST_ID-$OUTCOME_SHA256`. **Retry/result:** Exact destinations
are idempotent; never merge or replace a conflict. **Next actor:** Transport
operator.

```bash
platform-pki gitlab-package download \
  --stage outcome --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$OUTCOME_SHA256" \
  --destination-dir "$EXCHANGE_ROOT/gitlab-downloads/outcome/$REQUEST_ID-$OUTCOME_SHA256" \
  --project-record "$PROJECT_RECORD" \
  --token-type private --token-file "$READ_TOKEN" \
  --ca-file "$GITLAB_CA"
materialize_exact_tree \
  "$TRANSFER_ROOT/outcome/$REQUEST_ID-$OUTCOME_SHA256" \
  outcome \
  "$EXCHANGE_ROOT/gitlab-downloads/outcome/$REQUEST_ID-$OUTCOME_SHA256/outcome" \
  outcome.sig \
  "$EXCHANGE_ROOT/gitlab-downloads/outcome/$REQUEST_ID-$OUTCOME_SHA256/outcome.sig" \
  deployment \
  "$EXCHANGE_ROOT/gitlab-downloads/outcome/$REQUEST_ID-$OUTCOME_SHA256/deployment" \
  deployment.sig \
  "$EXCHANGE_ROOT/gitlab-downloads/outcome/$REQUEST_ID-$OUTCOME_SHA256/deployment.sig" \
  deployers.allowed_signers \
  "$EXCHANGE_ROOT/gitlab-downloads/outcome/$REQUEST_ID-$OUTCOME_SHA256/deployers.allowed_signers" \
  decision \
  "$EXCHANGE_ROOT/gitlab-downloads/outcome/$REQUEST_ID-$OUTCOME_SHA256/decision"
```

### C2. Push The Exact Outcome

**Actor:** Transport operator. **Run on:** Online transfer station. **Prerequisite:**
Exact six-file outcome payload and direct endpoint authorization. **Output and
provenance:** Direct client reports exact coordinates and `status=staged` or
`status=existing`. **Retry/result:** Exact restaging is idempotent. An incorrect
first candidate requires administrator review; restricted SSH cannot clean it.
**Next actor:** Lifecycle operator.

```bash
make registry-pki-direct-outcome-push \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  ENDPOINT_RECORD="$ENDPOINT_RECORD" REQUEST_ID="$REQUEST_ID" \
  ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256" OUTCOME_SHA256="$OUTCOME_SHA256" \
  TRANSFER_DIR="$TRANSFER_ROOT/outcome/$REQUEST_ID-$OUTCOME_SHA256"
```

### C3. Preflight And Import The Outcome

**Actor:** Lifecycle operator. **Run on:** Ansible controller, delegated to the
exact target. **Prerequisite:** Exact package already in fixed target spool.
**Output and provenance:** Check mode authenticates target spool and must report
`status=would-import`; apply publishes immutable history and must report
`status=imported` or authenticated `existing`. **Retry/result:** After import,
the facade removes only the exact stage. To prove an exact rerun, repeat C2 then
C3; never bypass spool authentication. **Next actor:** Lifecycle operator.

```bash
make registry-pki-outcome-import \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256" \
  OUTCOME_SHA256="$OUTCOME_SHA256" \
  EXTRA_ARGS=--check
make registry-pki-outcome-import \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256" \
  OUTCOME_SHA256="$OUTCOME_SHA256"
```

### C4. Verify Terminal State

**Actor:** Lifecycle operator; validation runner performs a fresh read-only
observation. **Run on:** Ansible controller, target, and distinct runner.
**Prerequisite:** Successful outcome import. **Output and provenance:** Fixed
terminal verifier authenticates all five exact coordinates, requires
`status=complete`, `signer_outcome_state=finalized`,
`evidence_state=controller-exported`, `required_action=none`, and
`recovery_required=false`, and runs a fresh distinct-runner preflight; registry
smoke proves service behavior. **Retry/result:** Verification is read-only and
repeatable; any drift fails terminal acceptance. **Next actor:** Backup operator,
then Fixed Cleanup.

```bash
make registry-pki-terminal-verification \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER" \
  SERVICE="$SERVICE" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256" OUTCOME_SHA256="$OUTCOME_SHA256"
make smoke-registry ENV="$ENVIRONMENT" LIMIT="$TARGET"
```

`renewal_eligible=false` is expected; authenticated host-local renewal completion
is not implemented. Take the approved post-migration target/VM backup and test
restore only in an isolated network-disabled instance. VM lifecycle and backup
tooling remain in their owning repositories.

## Fixed Cleanup

Direct access is a temporary transport capability, not lifecycle authority.
Bootstrap, Request, Activate/Evidence, and Complete must invoke this target with
`always` semantics in the operator procedure or protected CI pipeline. Bootstrap
uses it to prove setup access is absent before Request; the three transport
stages use it after success, failure, or interruption and before an external-gate
wait or terminal acceptance.

**Actor:** Lifecycle operator or protected CI cleanup job. **Run on:** Ansible
controller and the same exact target. **Prerequisite:** Stage success, failure,
or interruption; cleanup does not depend on PKI package state. **Output and
provenance:** Structurally fixed playbook selects only revocation, removes sudo
authority first, validates exact managed identity ownership, and removes a safe
empty operation lease with `rmdir` only after access is absent. Caller extra
arguments cannot select enablement. **Retry/result:** Exact absence is
idempotent; an unsafe, nonempty, or tampered lease, marker, or identity conflict
is retained and fails closed.
**Next actor:** External gate owner or terminal operator.

This standalone tokenless cleanup is an administrative revocation boundary. Do
not overlap it, or normal registry convergence, with a healthy in-flight wrapper
unless intentionally terminating that operation.

```bash
make registry-pki-exchange-access-revoke \
  ENV="$ENVIRONMENT" LIMIT="$TARGET"
```

For protected GitLab CI, use a dedicated project-locked runner whose
`pki-protected` tag is assigned only to a runner configured as protected and
which does not accept untagged jobs. Keep the sanitized environment and target
literal and reviewed; do not derive either from package input. This pattern
makes cleanup a required job after the online stage and makes the next gate job
depend on successful cleanup:

```yaml
stages:
  - pki-online
  - pki-cleanup
  - pki-gate

variables:
  PKI_ENVIRONMENT: "dev"
  PKI_TARGET: "registry-example"

.pki-protected-job:
  tags:
    - pki-protected
  rules:
    - if: '$CI_COMMIT_REF_PROTECTED == "true"'

pki-fixed-cleanup:
  extends: .pki-protected-job
  stage: pki-cleanup
  needs:
    - job: pki-online-stage
      artifacts: false
  when: always
  allow_failure: false
  retry:
    max: 2
    when:
      - runner_system_failure
      - stuck_or_timeout_failure
      - script_failure
  script:
    - make registry-pki-exchange-access-revoke ENV="$PKI_ENVIRONMENT" LIMIT="$PKI_TARGET"

pki-next-gate:
  extends: .pki-protected-job
  stage: pki-gate
  needs:
    - job: pki-fixed-cleanup
      artifacts: false
  when: on_success
  allow_failure: false
  script:
    - make registry-pki-exchange-access-revoke ENV="$PKI_ENVIRONMENT" LIMIT="$PKI_TARGET"
```

In this excerpt, `pki-online-stage` is the existing protected job containing the
exact commands from the applicable Request, Activate/Evidence, or Complete stage
above; the commands are not replaced by a generic dispatcher script. The cleanup
target runs the structurally fixed `tasks_from: revoke` boundary and
then verifies the fixed paths, account, and group are absent. The next gate job
independently reruns that idempotent revocation and absence verification before
the external gate owner permits an offline wait or terminal acceptance. Any CI
terminal-acceptance job must likewise `need` `pki-fixed-cleanup`, run only on
success, and begin by rerunning the same fixed target; it must not rely only on
an earlier job's status.

`when: always` and bounded retry improve ordinary success/failure coverage, but
GitLab cannot guarantee that in-pipeline cleanup executes after pipeline
cancellation, runner loss, or infrastructure failure. After any such event, the
next gate or job must independently run fixed revocation and verify absence
before proceeding. If no protected runner can execute, an administrator must
perform the same exact out-of-band revocation and absence verification before
the lifecycle resumes.

Do not invent another cleanup helper or substitute wildcard target cleanup. A
failed revocation blocks the external wait or terminal acceptance and requires
exact identity recovery.

## Expected Status Transitions

| Status | Required action | Meaning |
| --- | --- | --- |
| `managed-migration-needed` | `create-migration-request` | Managed Zot certificate is ready for migration. |
| `request-pending` | `collect-or-await-response` | Target key/request exists; no active response. |
| `request-expired` | `abandon-expired-request` | Pending request expired before response acceptance. |
| `response-ready` | `activate-response` | Exact response is installed and ready. |
| `activated-and-validated` | `export-evidence` | Candidate is active and runner validation passed. |
| `evidence-exported` | `await-signer-outcome` | Exact deployment evidence reached the controller. |
| `complete` | `none` | Finalized signer outcome matches current active state. |
| `signer-outcome-abandoned` | `none` | Authenticated abandonment is terminal; candidate is not active authority. |
| `activation-recovery-required` | `recover-activation` | Run only journal-bound target recovery. |
| `abandonment-evidence-required` | `publish-rolled-back-evidence` | Publish exact restored-predecessor evidence before signer abandonment. |
| `abandonment-evidence-required` | `publish-not-activated-evidence` | Stop; no public Ansible entry point currently publishes this evidence. |
| `conflict` | `resolve-conflict` | Stop and investigate; do not overwrite state. |

## Controller-Local Compatibility Mode

The explicit compatibility targets are:

```text
registry-pki-request-controller-local
registry-pki-evidence-export-controller-local
registry-pki-outcome-import-controller-local
```

These request, evidence, and outcome compatibility targets set
`pki_host_local_certificate_exchange_mode=controller-local`; their normal
counterparts set `direct`. Do not mix modes within a request unless an approved
recovery procedure accounts for both byte paths. Activation has no compatibility
target: `registry-pki-activate` is direct-only and automatic after its exact
preflights pass.

## Target Activation Recovery

If status reports `activation-recovery-required`, do not retry activation.

### Recovery And Rolled-Back Evidence

**Actor:** Lifecycle operator; target and runner perform journal-bound recovery
and validation. **Run on:** Ansible controller, target, and distinct runner.
**Prerequisite:** Exact recovery status and original request/artifact pins.
**Output and provenance:** Recovery status; if required, newly signed rolled-back
deployment evidence and its exact digest. **Retry/result:** Only helper-journaled
recovery is permitted. Record the returned deployment digest; stop if recovery
fails. **Next actor:** Transport operator and offline signer through the same
evidence package path.

```bash
make registry-pki-recover \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256"
make registry-pki-publish-rolled-back-evidence \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256"
make registry-pki-evidence-export \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256"
```

After exact evidence transport and signer review, abandon with the digest-pinned
evidence.

**Actor:** Offline signer. **Run on:** Disconnected signer host. **Prerequisite:**
Authenticated rolled-back evidence and exact artifact pin. **Output and
provenance:** Terminal decision `action=abandon`, `result=rolled-back`,
`state=abandoned`. **Retry/result:** Interactive, journaled, and exact; never
change the action or evidence to bypass recovery. **Next actor:** Follow the same
outcome publish, transport, import, and terminal verification sequence.

```bash
platform-pki csr-candidate abandon "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" \
  --artifact-manifest-sha256 "$ARTIFACT_SHA256" \
  --evidence-file "$SIGNER_EVIDENCE_ROOT/$DEPLOYMENT_SHA256/deployment" \
  --evidence-signature "$SIGNER_EVIDENCE_ROOT/$DEPLOYMENT_SHA256/deployment.sig"
```

If status requires `publish-not-activated-evidence`, stop. This repository has
no public Ansible entry point that can publish that signed target evidence. Do
not construct it manually. Managed-migration rollback is supported;
host-local-predecessor abandonment remains fail-closed.

## Signer Recovery

### Recover An Interrupted Signing Transaction

**Actor:** Offline signer. **Run on:** Disconnected signer host. **Prerequisite:**
Exact signer recovery journal and request ID. **Output and provenance:** Recovered
journaled transaction or explicit retained recovery state. **Retry/result:**
Resume only the journaled operation; omit `--response-key` only when its response
signature already exists. Never delete a journal. **Next actor:** Resume Gate 1
at certificate export.

```bash
platform-pki csr-recover \
  --namespace "$PKI_NAMESPACE" \
  --transaction "csr-$REQUEST_ID" \
  --response-key "$RESPONSE_KEY"
```

### Recover An Interrupted Finalization

**Actor:** Offline signer. **Run on:** Disconnected signer host. **Prerequisite:**
Finalization recovery journal. **Output and provenance:** Resume-only completion
of exact journaled finalization. **Retry/result:** Repeat only this recovery; it
does not invert the decision. **Next actor:** Resume Gate 2 at outcome export.

```bash
platform-pki csr-recover --namespace "$PKI_NAMESPACE"
```

## Expired Or Cancelled Requests

### Remove An Unconsumed Pending Request

**Actor:** Lifecycle operator. **Run on:** Ansible controller and exact target.
**Prerequisite:** For abandonment, authenticated expired state; for cancellation,
exact unexpired request ID and request digest with no consumer state. **Output
and provenance:** Target helper confirms exact request/key removal without
changing active Zot TLS. **Retry/result:** Absent exact state is idempotent;
response/version/evidence/journal state blocks removal. **Next actor:** Fixed
Cleanup, then a separately authorized fresh request if needed.

```bash
make registry-pki-abandon-expired-request \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" REQUEST_ID="$REQUEST_ID"
```

Use this separate alternative only for exact cancellation:

```bash
make registry-pki-cancel-request \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" REQUEST_SHA256="$REQUEST_SHA256"
```

## Retained Stages, Retention, And Backup

If outcome import reports a retained `/var/tmp/.platform-pki-outcome-*` stage or
target `.accepted-outcome-stage-*`, stop. Preserve the reported canonical path,
confirm no import remains active, attribute that exact stage through the
approved recovery process, and remove only that exact identity after review.
Never use a glob or broad temporary-directory cleanup.

If immutable outcome history exists without `accepted-outcome`, status fails
closed. Restage the same exact package and rerun import with the same four exact
coordinates so the no-clobber importer can authenticate history and complete
pointer publication.

Retain signer replay, transactions, candidates, responses, exports, trust,
decisions, outcomes, and accepted history under `$PKI_NAMESPACE`; controller
request/trust/response/evidence/outcome history under `EXCHANGE_ROOT`; all
GitLab package attempts and manifests; target pending/version/active/rollback/
evidence/outcome state and journals; the managed predecessor; encrypted signer
backups; and target/VM backups with restore evidence. Expiry of a rollback hold
permits review, not cleanup.

## Local Repository Verification

### Verify Platform-Tools Changes

**Actor:** Repository developer. **Run on:** `platform-tools` checkout through
its test container. **Prerequisite:** A change to signer, publication, parser, or
transport behavior used by this workflow. **Output and provenance:** Focused
signer/publication/parser results, full repository verification, and whitespace
validation from that checkout. **Retry/result:** Diagnose failures against the
changed repository; passing fake-HTTPS tests do not qualify live GitLab.
**Next actor:** Platform-config verifier.

```bash
./scripts/in-test-container make test-pki-csr-outcome
./scripts/in-test-container make test-platform-pki-publication
./scripts/in-test-container python3 -m pytest tests/test_platform_pki_parser.py
./scripts/in-test-container make verify
git diff --check
```

### Verify Platform-Config Changes

**Actor:** Repository developer. **Run on:** Development workstation through the
project container. **Prerequisite:** Documentation or implementation change
ready for review. **Output and provenance:** Focused pytest and lint results plus
Git whitespace validation. **Retry/result:** Fix the diagnosed change; do not
weaken tests or hide an environmental failure. **Next actor:** Reviewer.

```bash
PLATFORM_CONFIG_CONTAINER_PROFILE=test ./scripts/in-container \
  python -m pytest -n 0 \
  tests/python/test_pki_host_local_exchange.py \
  tests/python/test_pki_host_local_lifecycle_helper.py \
  tests/python/test_registry_pki_boundary.py
PLATFORM_CONFIG_CONTAINER_PROFILE=test ./scripts/in-container \
  ansible-lint playbooks/registry-pki-outcome-import.yml \
  roles/pki_host_local_certificate
git diff --check
```

`platform-tools` has focused package validation coverage under
`make test-pki-gitlab-package`, but neither repository claims live GitLab
runtime qualification from local fake-HTTPS tests. Live acceptance additionally
requires exact check-mode import, idempotent import, terminal status, post-import
decision preflight, registry smoke, fixed access cleanup, and isolated backup
restore validation.
