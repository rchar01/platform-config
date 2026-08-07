#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
HELPER="${ROOT_DIR}/roles/pki_host_local_certificate/files/platform-pki-host-local-trust"
REQUEST_HELPER="${ROOT_DIR}/roles/pki_host_local_certificate/files/platform-pki-host-local-request"

if [[ $(id -u) -ne 0 && ${PLATFORM_PKI_TEST_USERNS:-0} != 1 ]]; then
  exec env PLATFORM_PKI_TEST_USERNS=1 unshare -Ur -- "$0" "$@"
fi
[[ $(id -u) -eq 0 && $(id -g) -eq 0 ]] || {
  printf '%s\n' 'test requires uid/gid 0 or an unprivileged user namespace' >&2
  exit 1
}
[[ -x $HELPER && -x $REQUEST_HELPER ]] || {
  printf '%s\n' 'host-local PKI helpers must be executable' >&2
  exit 1
}

umask 077
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pki-host-local-trust-test.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
SOURCE="${WORK}/reviewed-source"
KEY="${WORK}/request-key"
mkdir -m 700 -- "$SOURCE"
ssh-keygen -q -t ed25519 -N '' -f "$KEY"
chmod 600 "$KEY"
read -r KEY_ALGORITHM KEY_PAYLOAD _ <"${KEY}.pub"
[[ $KEY_ALGORITHM == ssh-ed25519 ]]

write_canonical_source() {
  local root=$1
  mkdir -p -- "$root"
  chmod 0700 "$root"
  printf '%s %s %s\n' test-target "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${root}/requesters.allowed_signers"
  printf '%s %s %s\n' test-approver "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${root}/approvers.allowed_signers"
  printf '%s %s %s\n' test-response "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${root}/responses.allowed_signers"
  printf '%s %s %s\n' test-target "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${root}/deployers.allowed_signers"
  printf '%s\n' \
    'schema=2' \
    'request_namespace=platform-pki-csr-request-v1' \
    'approval_namespace=platform-pki-csr-approval-v1' \
    'response_namespace=platform-pki-csr-response-v1' \
    'deployment_namespace=platform-pki-csr-deployment-v1' \
    'request_max_age_seconds=604800' \
    'sole_operator_min_delay_seconds=86400' \
    'approval_max_age_seconds=86400' \
    'deployment_max_age_seconds=86400' \
    'clock_skew_seconds=300' \
    'approver_principal=test-approver' \
    'response_principal=test-response' >"${root}/policy"
  chmod 600 "${root}"/*
}
write_canonical_source "$SOURCE"

digest() {
  local result
  result="$(sha256sum -- "$1")"
  printf '%s\n' "${result%% *}"
}

set_digests() {
  local root=$1
  POLICY_DIGEST="$(digest "${root}/policy")"
  REQUESTERS_DIGEST="$(digest "${root}/requesters.allowed_signers")"
  APPROVERS_DIGEST="$(digest "${root}/approvers.allowed_signers")"
  RESPONSES_DIGEST="$(digest "${root}/responses.allowed_signers")"
  DEPLOYERS_DIGEST="$(digest "${root}/deployers.allowed_signers")"
}
set_digests "$SOURCE"

run_install() {
  local state=$1
  shift
  local target="${state}/trust/reviewed-v1"
  "$HELPER" install "$@" \
    --state-root "$state" \
    --trust-id reviewed-v1 \
    --requester-principal test-target \
    --response-principal test-response \
    --trust-binding policy "${target}/policy" "$POLICY_DIGEST" \
    --trust-binding requesters.allowed_signers "${target}/requesters.allowed_signers" "$REQUESTERS_DIGEST" \
    --trust-binding approvers.allowed_signers "${target}/approvers.allowed_signers" "$APPROVERS_DIGEST" \
    --trust-binding responses.allowed_signers "${target}/responses.allowed_signers" "$RESPONSES_DIGEST" \
    --trust-binding deployers.allowed_signers "${target}/deployers.allowed_signers" "$DEPLOYERS_DIGEST"
}

prepare_ingress() {
  local state=$1
  "$HELPER" prepare --state-root "$state" --trust-id reviewed-v1 >/dev/null
  install -m 0600 -- "$SOURCE"/* "${state}/trust/.ingress-reviewed-v1/"
}

wait_for_stage() {
  local state=$1 candidate
  for _ in $(seq 1 100); do
    candidate="$(compgen -G "${state}/trust/.stage-*" || true)"
    if [[ -n $candidate ]]; then
      printf '%s\n' "$candidate"
      return
    fi
    sleep 0.02
  done
  printf 'timed out waiting for trust stage: %s\n' "$state" >&2
  return 1
}

tree_snapshot() {
  python3 - "$1" <<'PY'
import hashlib
import json
import os
import stat
import sys

root = sys.argv[1]
result = []
if os.path.lexists(root):
    for current, directories, files in os.walk(root):
        directories.sort()
        files.sort()
        for name in directories + files:
            path = os.path.join(current, name)
            metadata = os.lstat(path)
            record = [
                os.path.relpath(path, root), stat.S_IFMT(metadata.st_mode),
                stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid,
                metadata.st_nlink, metadata.st_size, metadata.st_ino,
            ]
            if stat.S_ISREG(metadata.st_mode):
                record.append(hashlib.sha256(open(path, "rb").read()).hexdigest())
            result.append(record)
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
PY
}

expect_failure() {
  local label=$1
  shift
  if "$@" >"${WORK}/failure.stdout" 2>"${WORK}/failure.stderr"; then
    printf 'expected failure was accepted: %s\n' "$label" >&2
    exit 1
  fi
  [[ ! -s ${WORK}/failure.stdout ]] || {
    printf 'failed helper emitted stdout: %s\n' "$label" >&2
    exit 1
  }
}

ABSENT_STATE="${WORK}/absent-state"
before_absent="$(tree_snapshot "$ABSENT_STATE")"
expect_failure 'absent check prerequisites' run_install "$ABSENT_STATE" --check
[[ $(tree_snapshot "$ABSENT_STATE") == "$before_absent" ]]
[[ ! -e $ABSENT_STATE && ! -L $ABSENT_STATE ]]

STATE="${WORK}/state"
"$HELPER" prepare --state-root "$STATE" --trust-id reviewed-v1 >/dev/null
before_ingress_check="$(tree_snapshot "$STATE")"
expect_failure 'check without complete ingress' run_install "$STATE" --check
[[ $(tree_snapshot "$STATE") == "$before_ingress_check" ]]
install -m 0600 -- "$SOURCE"/* "${STATE}/trust/.ingress-reviewed-v1/"
before_ready_check="$(tree_snapshot "$STATE")"
check_output="$(run_install "$STATE" --check)"
[[ $(tree_snapshot "$STATE") == "$before_ready_check" ]]
python3 - "$check_output" <<'PY'
import json
import sys

if json.loads(sys.argv[1])["status"] != "would-install":
    raise SystemExit("complete ingress check did not report would-install")
PY

REQUEST_STATE="$STATE" REQUEST_PENDING="${WORK}/request-before-bootstrap" \
  expect_failure 'request before trust bootstrap' \
  "$REQUEST_HELPER" request \
    --service registry-test --target test-target --requester-principal test-target \
    --operation issue --profile server-p384-sha384-v1 \
    --inventory-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --current-cert-sha256 none --common-name registry.test.example \
    --dns-san registry.test.example --response-principal test-response \
    --request-ttl-seconds 3600 --request-signing-key "$KEY" \
    --request-namespace platform-pki-csr-request-v1 \
    --state-root "$STATE" --pending-root "${WORK}/request-before-bootstrap" \
    --trust-binding policy "${STATE}/trust/reviewed-v1/policy" "$POLICY_DIGEST" \
    --trust-binding requesters.allowed_signers "${STATE}/trust/reviewed-v1/requesters.allowed_signers" "$REQUESTERS_DIGEST" \
    --trust-binding approvers.allowed_signers "${STATE}/trust/reviewed-v1/approvers.allowed_signers" "$APPROVERS_DIGEST" \
    --trust-binding responses.allowed_signers "${STATE}/trust/reviewed-v1/responses.allowed_signers" "$RESPONSES_DIGEST" \
    --trust-binding deployers.allowed_signers "${STATE}/trust/reviewed-v1/deployers.allowed_signers" "$DEPLOYERS_DIGEST"

install_output="$(run_install "$STATE")"
python3 - "$install_output" <<'PY'
import json
import sys

if json.loads(sys.argv[1])["status"] != "installed":
    raise SystemExit("trust bootstrap did not report installed")
PY
TARGET="${STATE}/trust/reviewed-v1"
target_inode="$(stat -c '%i' "$TARGET")"
python3 - "$STATE" <<'PY'
import os
import stat
import sys

state = sys.argv[1]
if set(os.listdir(state)) != {"lock", "trust"}:
    raise SystemExit("state root contains unexpected post-install entries")
for path in (state, os.path.join(state, "trust"), os.path.join(state, "trust", "reviewed-v1")):
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != 0 or metadata.st_gid != 0:
        raise SystemExit(f"unsafe trust directory metadata: {path}")
for name in ("lock", "trust/reviewed-v1/policy", "trust/reviewed-v1/requesters.allowed_signers", "trust/reviewed-v1/approvers.allowed_signers", "trust/reviewed-v1/responses.allowed_signers", "trust/reviewed-v1/deployers.allowed_signers"):
    metadata = os.lstat(os.path.join(state, name))
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != 0 or metadata.st_gid != 0 or metadata.st_nlink != 1:
        raise SystemExit(f"unsafe trust file metadata: {name}")
PY
noop_output="$(run_install "$STATE" --check)"
[[ $(stat -c '%i' "$TARGET") == "$target_inode" ]]
[[ $(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["status"])' "$noop_output") == existing ]]

request_output="$($REQUEST_HELPER request \
  --service registry-test --target test-target --requester-principal test-target \
  --operation issue --profile server-p384-sha384-v1 \
  --inventory-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --current-cert-sha256 none --common-name registry.test.example \
  --dns-san registry.test.example --response-principal test-response \
  --request-ttl-seconds 3600 --request-signing-key "$KEY" \
  --request-namespace platform-pki-csr-request-v1 \
  --state-root "$STATE" --pending-root "${WORK}/request-after-bootstrap" \
  --trust-binding policy "${TARGET}/policy" "$POLICY_DIGEST" \
  --trust-binding requesters.allowed_signers "${TARGET}/requesters.allowed_signers" "$REQUESTERS_DIGEST" \
  --trust-binding approvers.allowed_signers "${TARGET}/approvers.allowed_signers" "$APPROVERS_DIGEST" \
  --trust-binding responses.allowed_signers "${TARGET}/responses.allowed_signers" "$RESPONSES_DIGEST" \
  --trust-binding deployers.allowed_signers "${TARGET}/deployers.allowed_signers" "$DEPLOYERS_DIGEST")"
[[ $(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["status"])' "$request_output") == created ]]

python3 - "${STATE}/lock" <<'PY' &
import fcntl
import sys
import time

with open(sys.argv[1], "rb") as stream:
    fcntl.flock(stream, fcntl.LOCK_EX)
    time.sleep(30)
PY
lock_pid=$!
for _ in $(seq 1 50); do
  if ! flock -n "${STATE}/lock" true 2>/dev/null; then break; fi
  sleep 0.02
done
expect_failure 'lock contention' run_install "$STATE" --check
kill "$lock_pid"
wait "$lock_pid" 2>/dev/null || true

mv -- "${TARGET}/policy" "${WORK}/policy.saved"
ln -s "${WORK}/policy.saved" "${TARGET}/policy"
expect_failure 'destination symlink' run_install "$STATE" --check
rm -- "${TARGET}/policy"
mv -- "${WORK}/policy.saved" "${TARGET}/policy"
mv -- "${TARGET}/requesters.allowed_signers" "${WORK}/requesters.saved"
ln -- "${WORK}/requesters.saved" "${TARGET}/requesters.allowed_signers"
expect_failure 'destination hardlink' run_install "$STATE" --check
rm -- "${TARGET}/requesters.allowed_signers"
mv -- "${WORK}/requesters.saved" "${TARGET}/requesters.allowed_signers"
printf '%s\n' unexpected >"${TARGET}/extra"
expect_failure 'destination extra' run_install "$STATE" --check
rm -- "${TARGET}/extra"
chmod 0644 "${TARGET}/responses.allowed_signers"
expect_failure 'destination unsafe metadata' run_install "$STATE" --check
chmod 0600 "${TARGET}/responses.allowed_signers"
printf '%s\n' unexpected >"${STATE}/unexpected"
expect_failure 'unexpected target state' run_install "$STATE" --check
rm -- "${STATE}/unexpected"

old_policy_digest=$POLICY_DIGEST
POLICY_DIGEST=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
expect_failure 'attempted trust rotation' run_install "$STATE" --check
POLICY_DIGEST=$old_policy_digest
expect_failure 'other trust ID' "$HELPER" install --check \
  --state-root "$STATE" --trust-id reviewed-v2 \
  --requester-principal test-target --response-principal test-response \
  --trust-binding policy "${STATE}/trust/reviewed-v2/policy" "$POLICY_DIGEST" \
  --trust-binding requesters.allowed_signers "${STATE}/trust/reviewed-v2/requesters.allowed_signers" "$REQUESTERS_DIGEST" \
  --trust-binding approvers.allowed_signers "${STATE}/trust/reviewed-v2/approvers.allowed_signers" "$APPROVERS_DIGEST" \
  --trust-binding responses.allowed_signers "${STATE}/trust/reviewed-v2/responses.allowed_signers" "$RESPONSES_DIGEST" \
  --trust-binding deployers.allowed_signers "${STATE}/trust/reviewed-v2/deployers.allowed_signers" "$DEPLOYERS_DIGEST"

printf '%s\n' active >"${STATE}/active"
printf '%s\n' rollback >"${STATE}/rollback"
printf '%s\n' boundary >"${STATE}/validation-boundary"
install -d -m 0700 -- \
  "${STATE}/evidence/0123456789abcdef0123456789abcdef/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
chmod 0700 -- "${STATE}/evidence" "${STATE}/evidence/0123456789abcdef0123456789abcdef"
for evidence_name in deployment deployment.sig validation-boundary validation-result validation-result.sig; do
  printf '%s\n' "$evidence_name" \
    >"${STATE}/evidence/0123456789abcdef0123456789abcdef/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/${evidence_name}"
done
chmod 0600 -- "${STATE}/active" "${STATE}/rollback" "${STATE}/validation-boundary" \
  "${STATE}/evidence/0123456789abcdef0123456789abcdef/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"*
lifecycle_snapshot="$(tree_snapshot "$STATE")"
lifecycle_output="$(run_install "$STATE" --check)"
[[ $(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["status"])' "$lifecycle_output") == existing ]]
[[ $(tree_snapshot "$STATE") == "$lifecycle_snapshot" ]]

run_invalid_case() {
  local name=$1 mutation=$2
  local state="${WORK}/invalid-${name}"
  prepare_ingress "$state"
  local ingress="${state}/trust/.ingress-reviewed-v1"
  case "$mutation" in
    schema) python3 - "$ingress/policy" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1]); path.write_text(path.read_text().replace("schema=2", "schema=1"))
PY
      ;;
    principal) printf '%s %s %s\n' Test-target "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${ingress}/requesters.allowed_signers" ;;
    key) printf '%s\n' 'test-target ssh-ed25519 AAAA' >"${ingress}/requesters.allowed_signers" ;;
    requester) printf '%s %s %s\n' other-target "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${ingress}/requesters.allowed_signers" ;;
    approver) printf '%s %s %s\n' other "$KEY_ALGORITHM" "$KEY_PAYLOAD" >>"${ingress}/approvers.allowed_signers" ;;
    response) printf '%s %s %s\n' other "$KEY_ALGORITHM" "$KEY_PAYLOAD" >>"${ingress}/responses.allowed_signers" ;;
    deployer) printf '%s %s %s\n' other-target "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${ingress}/deployers.allowed_signers" ;;
    digest) printf '%s\n' extra >>"${ingress}/deployers.allowed_signers" ;;
    symlink) mv -- "${ingress}/policy" "${WORK}/${name}.saved"; ln -s "${WORK}/${name}.saved" "${ingress}/policy" ;;
    hardlink) ln -- "${ingress}/policy" "${WORK}/${name}.link" ;;
    mode) chmod 0644 "${ingress}/policy" ;;
    extra) printf '%s\n' unexpected >"${ingress}/extra" ;;
  esac
  if [[ $mutation != digest && $mutation != symlink && $mutation != hardlink && $mutation != mode && $mutation != extra ]]; then
    set_digests "$ingress"
  else
    set_digests "$SOURCE"
  fi
  expect_failure "$name" run_install "$state"
  set_digests "$SOURCE"
}

for invalid in schema principal key requester approver response deployer digest symlink hardlink mode extra; do
  run_invalid_case "$invalid" "$invalid"
done

CRASH_STATE="${WORK}/crash-state"
prepare_ingress "$CRASH_STATE"
crash_after_journal() {
  PLATFORM_PKI_TRUST_CRASH_AT=after-journal run_install "$CRASH_STATE"
}
expect_failure 'crash after journal' crash_after_journal
[[ -f ${CRASH_STATE}/trust-install.journal ]]
before_crash_check="$(tree_snapshot "$CRASH_STATE")"
expect_failure 'check does not recover journal' run_install "$CRASH_STATE" --check
[[ $(tree_snapshot "$CRASH_STATE") == "$before_crash_check" ]]
[[ $(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["status"])' "$(run_install "$CRASH_STATE")") == installed ]]

PUBLISHED_STATE="${WORK}/published-state"
prepare_ingress "$PUBLISHED_STATE"
crash_after_publication() {
  PLATFORM_PKI_TRUST_CRASH_AT=after-publication run_install "$PUBLISHED_STATE"
}
expect_failure 'crash after publication' crash_after_publication
[[ -d ${PUBLISHED_STATE}/trust/reviewed-v1 && -f ${PUBLISHED_STATE}/trust-install.journal ]]
[[ $(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["status"])' "$(run_install "$PUBLISHED_STATE")") == existing ]]
[[ $(find "$PUBLISHED_STATE" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort) == $'lock\ntrust' ]]

for cleanup_point in after-ingress-cleanup-file after-ingress-cleanup; do
  cleanup_state="${WORK}/${cleanup_point}-state"
  prepare_ingress "$cleanup_state"
  crash_during_ingress_cleanup() {
    PLATFORM_PKI_TRUST_CRASH_AT="$cleanup_point" run_install "$cleanup_state"
  }
  expect_failure "crash at ${cleanup_point}" crash_during_ingress_cleanup
  [[ -d ${cleanup_state}/trust/reviewed-v1 && -f ${cleanup_state}/trust-install.journal ]]
  [[ $(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["status"])' "$(run_install "$cleanup_state")") == existing ]]
  [[ $(find "$cleanup_state" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort) == $'lock\ntrust' ]]
done

ORPHAN_STATE="${WORK}/orphan-state"
prepare_ingress "$ORPHAN_STATE"
crash_before_journal() {
  PLATFORM_PKI_TRUST_CRASH_AT=after-stage-create-before-journal run_install "$ORPHAN_STATE"
}
expect_failure 'crash after stage creation before journal' crash_before_journal
[[ ! -e ${ORPHAN_STATE}/trust-install.journal && ! -L ${ORPHAN_STATE}/trust-install.journal ]]
[[ $(find "${ORPHAN_STATE}/trust" -mindepth 1 -maxdepth 1 -type d -name '.stage-*' | wc -l) -eq 1 ]]
[[ $(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["status"])' "$(run_install "$ORPHAN_STATE")") == installed ]]

NONEMPTY_ORPHAN_STATE="${WORK}/nonempty-orphan-state"
prepare_ingress "$NONEMPTY_ORPHAN_STATE"
crash_with_foreign_orphan() {
  PLATFORM_PKI_TRUST_CRASH_AT=after-stage-create-before-journal run_install "$NONEMPTY_ORPHAN_STATE"
}
expect_failure 'foreign orphan setup crash' crash_with_foreign_orphan
nonempty_orphan="$(find "${NONEMPTY_ORPHAN_STATE}/trust" -mindepth 1 -maxdepth 1 -type d -name '.stage-*')"
printf '%s\n' foreign >"${nonempty_orphan}/foreign"
chmod 0600 "${nonempty_orphan}/foreign"
nonempty_orphan_inode="$(stat -c '%i' "$nonempty_orphan")"
expect_failure 'nonempty unjournaled stage' run_install "$NONEMPTY_ORPHAN_STATE"
[[ $(stat -c '%i' "$nonempty_orphan") == "$nonempty_orphan_inode" && $(<"${nonempty_orphan}/foreign") == foreign ]]

AMBIGUOUS_ORPHAN_STATE="${WORK}/ambiguous-orphan-state"
prepare_ingress "$AMBIGUOUS_ORPHAN_STATE"
crash_with_ambiguous_orphan() {
  PLATFORM_PKI_TRUST_CRASH_AT=after-stage-create-before-journal run_install "$AMBIGUOUS_ORPHAN_STATE"
}
expect_failure 'ambiguous orphan setup crash' crash_with_ambiguous_orphan
ambiguous_orphan="$(find "${AMBIGUOUS_ORPHAN_STATE}/trust" -mindepth 1 -maxdepth 1 -type d -name '.stage-*')"
mkdir -m 0700 -- "${AMBIGUOUS_ORPHAN_STATE}/trust/unexpected"
ambiguous_orphan_inode="$(stat -c '%i' "$ambiguous_orphan")"
ambiguous_foreign_inode="$(stat -c '%i' "${AMBIGUOUS_ORPHAN_STATE}/trust/unexpected")"
expect_failure 'ambiguous unjournaled stage' run_install "$AMBIGUOUS_ORPHAN_STATE"
[[ $(stat -c '%i' "$ambiguous_orphan") == "$ambiguous_orphan_inode" ]]
[[ $(stat -c '%i' "${AMBIGUOUS_ORPHAN_STATE}/trust/unexpected") == "$ambiguous_foreign_inode" ]]

RACE_STATE="${WORK}/race-state"
prepare_ingress "$RACE_STATE"
PLATFORM_PKI_TRUST_PAUSE_AT=before-publication run_install "$RACE_STATE" >"${WORK}/race.stdout" 2>"${WORK}/race.stderr" &
race_pid=$!
for _ in $(seq 1 100); do
  if compgen -G "${RACE_STATE}/trust/.stage-*" >/dev/null; then break; fi
  sleep 0.02
done
compgen -G "${RACE_STATE}/trust/.stage-*" >/dev/null
printf '%s\n' changed >>"${RACE_STATE}/trust/.ingress-reviewed-v1/requesters.allowed_signers"
if wait "$race_pid"; then
  printf '%s\n' 'ingress replacement race was accepted' >&2
  exit 1
fi
[[ ! -e ${RACE_STATE}/trust/reviewed-v1 && ! -L ${RACE_STATE}/trust/reviewed-v1 ]]

CONFLICT_STATE="${WORK}/conflict-state"
prepare_ingress "$CONFLICT_STATE"
PLATFORM_PKI_TRUST_PAUSE_AT=before-publication run_install "$CONFLICT_STATE" >"${WORK}/conflict.stdout" 2>"${WORK}/conflict.stderr" &
conflict_pid=$!
for _ in $(seq 1 100); do
  if compgen -G "${CONFLICT_STATE}/trust/.stage-*" >/dev/null; then break; fi
  sleep 0.02
done
mkdir -m 700 -- "${CONFLICT_STATE}/trust/reviewed-v1"
printf '%s\n' foreign >"${CONFLICT_STATE}/trust/reviewed-v1/foreign"
if wait "$conflict_pid"; then
  printf '%s\n' 'destination conflict race was overwritten' >&2
  exit 1
fi
[[ $(<"${CONFLICT_STATE}/trust/reviewed-v1/foreign") == foreign ]]

LOCK_RACE_STATE="${WORK}/lock-race-state"
prepare_ingress "$LOCK_RACE_STATE"
PLATFORM_PKI_TRUST_PAUSE_AT=before-publication run_install "$LOCK_RACE_STATE" >"${WORK}/lock-race.stdout" 2>"${WORK}/lock-race.stderr" &
lock_race_pid=$!
for _ in $(seq 1 100); do
  if compgen -G "${LOCK_RACE_STATE}/trust/.stage-*" >/dev/null; then break; fi
  sleep 0.02
done
mv -- "${LOCK_RACE_STATE}/lock" "${LOCK_RACE_STATE}/lock.validated"
touch -- "${LOCK_RACE_STATE}/lock"
chmod 0600 "${LOCK_RACE_STATE}/lock"
if wait "$lock_race_pid"; then
  printf '%s\n' 'canonical lock replacement race was accepted' >&2
  exit 1
fi
[[ ! -e ${LOCK_RACE_STATE}/trust/reviewed-v1 && ! -L ${LOCK_RACE_STATE}/trust/reviewed-v1 ]]

run_target_replacement_race() {
  local kind=$1
  local state="${WORK}/${kind}-replacement-state" stage pid
  prepare_ingress "$state"
  PLATFORM_PKI_TRUST_PAUSE_AT=before-publication run_install "$state" \
    >"${WORK}/${kind}-replacement.stdout" 2>"${WORK}/${kind}-replacement.stderr" &
  pid=$!
  stage="$(wait_for_stage "$state")"
  [[ -f ${state}/trust-install.journal ]]
  case "$kind" in
    state)
      mv -- "$state" "${state}.validated"
      mkdir -m 0700 -- "$state"
      ;;
    trust)
      mv -- "${state}/trust" "${state}/trust.validated"
      mkdir -m 0700 -- "${state}/trust"
      ;;
    ingress)
      mv -- "${state}/trust/.ingress-reviewed-v1" "${state}/trust/.ingress-reviewed-v1.validated"
      mkdir -m 0700 -- "${state}/trust/.ingress-reviewed-v1"
      ;;
    stage)
      mv -- "$stage" "${stage}.validated"
      mkdir -m 0700 -- "$stage"
      ;;
    journal)
      mv -- "${state}/trust-install.journal" "${state}/trust-install.journal.validated"
      install -m 0600 -- "${state}/trust-install.journal.validated" "${state}/trust-install.journal"
      ;;
  esac
  if wait "$pid"; then
    printf 'target %s replacement race was accepted\n' "$kind" >&2
    exit 1
  fi
  [[ ! -s ${WORK}/${kind}-replacement.stdout ]]
  if [[ $kind == state ]]; then
    [[ ! -e ${state}.validated/trust/reviewed-v1 && ! -L ${state}.validated/trust/reviewed-v1 ]]
  elif [[ $kind == trust ]]; then
    [[ ! -e ${state}/trust.validated/reviewed-v1 && ! -L ${state}/trust.validated/reviewed-v1 ]]
  else
    [[ ! -e ${state}/trust/reviewed-v1 && ! -L ${state}/trust/reviewed-v1 ]]
  fi
}

for replacement in state trust ingress stage journal; do
  run_target_replacement_race "$replacement"
done

STAGE_MISMATCH_STATE="${WORK}/stage-mismatch-state"
prepare_ingress "$STAGE_MISMATCH_STATE"
stage_mismatch_crash() {
  PLATFORM_PKI_TRUST_CRASH_AT=after-journal run_install "$STAGE_MISMATCH_STATE"
}
expect_failure 'stage identity setup crash' stage_mismatch_crash
STAGE_MISMATCH_PATH="$(wait_for_stage "$STAGE_MISMATCH_STATE")"
mv -- "$STAGE_MISMATCH_PATH" "${STAGE_MISMATCH_PATH}.journaled"
mkdir -m 0700 -- "$STAGE_MISMATCH_PATH"
stage_mismatch_inode="$(stat -c '%i' "$STAGE_MISMATCH_PATH")"
expect_failure 'journaled stage identity mismatch' run_install "$STAGE_MISMATCH_STATE"
[[ $(stat -c '%i' "$STAGE_MISMATCH_PATH") == "$stage_mismatch_inode" ]]
[[ -f ${STAGE_MISMATCH_STATE}/trust-install.journal ]]

if [[ $ROOT_DIR == /workspace ]]; then
  ROLE_STATE="${WORK}/role-state"
  ROLE_HELPER="${WORK}/bin/platform-pki-host-local-trust"
  ROLE_VARS="${WORK}/role-vars.json"
  ROLE_PLAYBOOK="${ROOT_DIR}/tests/fixtures/pki-host-local-trust-role/integration.yml"
  python3 - "$ROLE_VARS" "$SOURCE" "$ROLE_STATE" "$ROLE_HELPER" \
    "$POLICY_DIGEST" "$REQUESTERS_DIGEST" "$APPROVERS_DIGEST" "$RESPONSES_DIGEST" "$DEPLOYERS_DIGEST" <<'PY'
import json
import sys

output, source, state, helper, policy, requesters, approvers, responses, deployers = sys.argv[1:]
names = ("policy", "requesters.allowed_signers", "approvers.allowed_signers", "responses.allowed_signers", "deployers.allowed_signers")
digests = dict(zip(names, (policy, requesters, approvers, responses, deployers), strict=True))
variables = {
    "ansible_remote_tmp": f"{state}-ansible-tmp",
    "pki_host_local_certificate_target": "localhost",
    "pki_host_local_certificate_requester_principal": "localhost",
    "pki_host_local_certificate_response_principal": "test-response",
    "pki_host_local_certificate_trust_id": "reviewed-v1",
    "pki_host_local_certificate_state_root": state,
    "pki_host_local_certificate_trust_helper_path": helper,
    "pki_host_local_certificate_trust_sources": {name: f"{source}/{name}" for name in names},
    "pki_host_local_certificate_trust_paths": {name: f"{state}/trust/reviewed-v1/{name}" for name in names},
    "pki_host_local_certificate_trust_sha256": digests,
}
with open(output, "w", encoding="utf-8") as stream:
    json.dump(variables, stream, sort_keys=True)
PY
  printf '%s %s %s\n' localhost "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${SOURCE}/requesters.allowed_signers"
  printf '%s %s %s\n' localhost "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${SOURCE}/deployers.allowed_signers"
  chmod 600 "${SOURCE}/requesters.allowed_signers"
  chmod 600 "${SOURCE}/deployers.allowed_signers"
  REQUESTERS_DIGEST="$(digest "${SOURCE}/requesters.allowed_signers")"
  DEPLOYERS_DIGEST="$(digest "${SOURCE}/deployers.allowed_signers")"
  python3 - "$ROLE_VARS" "$REQUESTERS_DIGEST" "$DEPLOYERS_DIGEST" <<'PY'
import json, sys
path, requester_digest, deployer_digest = sys.argv[1:]
with open(path, encoding="utf-8") as stream: variables = json.load(stream)
variables["pki_host_local_certificate_trust_sha256"]["requesters.allowed_signers"] = requester_digest
variables["pki_host_local_certificate_trust_sha256"]["deployers.allowed_signers"] = deployer_digest
with open(path, "w", encoding="utf-8") as stream: json.dump(variables, stream, sort_keys=True)
PY

  python3 - "$ROOT_DIR/plugins/action/platform_pki_trust_ingress.py" "$SOURCE" "$WORK" <<'PY'
import hashlib
import importlib.util
import os
import shutil
import sys

plugin_path, source, work = sys.argv[1:]
spec = importlib.util.spec_from_file_location("platform_pki_trust_ingress_test", plugin_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

def pin(path):
    with open(path, "rb") as stream:
        digest = hashlib.sha256(stream.read()).hexdigest()
    return module.pin_source(path, digest)

def require_recheck_failure(pinned, label):
    try:
        pinned.recheck()
    except module.AnsibleActionFail:
        return
    finally:
        pinned.close()
    raise SystemExit(f"controller {label} replacement was accepted")

file_root = os.path.join(work, "controller-file-source")
shutil.copytree(source, file_root)
file_path = os.path.join(file_root, "requesters.allowed_signers")
pinned = pin(file_path)
os.rename(file_path, f"{file_path}.validated")
shutil.copy2(f"{file_path}.validated", file_path)
os.chmod(file_path, 0o600)
require_recheck_failure(pinned, "file")

ancestor_root = os.path.join(work, "controller-ancestor-source")
shutil.copytree(source, ancestor_root)
pinned = pin(os.path.join(ancestor_root, "policy"))
os.rename(ancestor_root, f"{ancestor_root}.validated")
os.mkdir(ancestor_root, 0o700)
shutil.copy2(f"{ancestor_root}.validated/policy", os.path.join(ancestor_root, "policy"))
os.chmod(os.path.join(ancestor_root, "policy"), 0o600)
require_recheck_failure(pinned, "ancestor")

try:
    module.pin_source(plugin_path, "0" * 64)
except module.AnsibleActionFail as exc:
    if "outside the public repository" not in str(exc):
        raise
else:
    raise SystemExit("controller source inside the public repository was accepted")
PY

  before_role_state_check="$(tree_snapshot "$ROLE_STATE")"
  if ansible-playbook --check -i localhost, -e "@${ROLE_VARS}" "$ROLE_PLAYBOOK" >/dev/null 2>&1; then
    printf '%s\n' 'role check accepted absent helper/state prerequisites' >&2
    exit 1
  fi
  [[ $(tree_snapshot "$ROLE_STATE") == "$before_role_state_check" ]]
  [[ ! -e $ROLE_HELPER && ! -L $ROLE_HELPER ]]
  ansible-playbook -i localhost, -e "@${ROLE_VARS}" "$ROLE_PLAYBOOK" >/dev/null
  role_inode="$(stat -c '%i' "${ROLE_STATE}/trust/reviewed-v1")"
  ansible-playbook --check -i localhost, -e "@${ROLE_VARS}" "$ROLE_PLAYBOOK" >/dev/null
  role_output="$(ansible-playbook -i localhost, -e "@${ROLE_VARS}" "$ROLE_PLAYBOOK")"
  [[ $(stat -c '%i' "${ROLE_STATE}/trust/reviewed-v1") == "$role_inode" ]]
  grep -qE 'changed=0.*failed=0' <<<"$role_output" || {
    printf '%s\n' "$role_output" >&2
    printf '%s\n' 'Second trust role run was not an exact no-op' >&2
    exit 1
  }
fi

printf '%s\n' 'Host-local PKI trust helper checks passed.'
