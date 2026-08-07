#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
HELPER="${ROOT_DIR}/roles/pki_host_local_certificate/files/platform-pki-host-local-request"

if [[ $(id -u) -ne 0 && ${PLATFORM_PKI_TEST_USERNS:-0} != 1 ]]; then
  exec env PLATFORM_PKI_TEST_USERNS=1 unshare -Ur -- "$0" "$@"
fi
[[ $(id -u) -eq 0 ]] || { printf '%s\n' 'test requires uid 0 or an unprivileged user namespace' >&2; exit 1; }
[[ -x $HELPER ]] || { printf 'helper is not executable: %s\n' "$HELPER" >&2; exit 1; }

umask 077
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pki-host-local-request-test.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

TRUST="${WORK}/trust/reviewed-v1"
STATE="${WORK}/state"
PENDING="${WORK}/pending"
SIGNING_KEY="${WORK}/request-key"
CURRENT_CERT="${WORK}/current.crt"
mkdir -m 700 -- "${WORK}/trust" "$TRUST"

ssh-keygen -q -t ed25519 -N '' -f "$SIGNING_KEY"
chmod 600 "$SIGNING_KEY"
read -r KEY_ALGORITHM KEY_PAYLOAD _ <"${SIGNING_KEY}.pub"
[[ $KEY_ALGORITHM == ssh-ed25519 ]]

printf '%s %s %s\n' test-target "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${TRUST}/requesters.allowed_signers"
printf '%s %s %s\n' test-approver "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${TRUST}/approvers.allowed_signers"
printf '%s %s %s\n' test-response "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${TRUST}/responses.allowed_signers"
printf '%s %s %s\n' test-target "$KEY_ALGORITHM" "$KEY_PAYLOAD" >"${TRUST}/deployers.allowed_signers"
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
  'response_principal=test-response' >"${TRUST}/policy"
chmod 600 "${TRUST}"/*

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj /CN=old.test.example -keyout "${WORK}/current.key" -out "$CURRENT_CERT" \
  >/dev/null 2>&1
chmod 600 "$CURRENT_CERT"

digest() {
  local result
  result="$(sha256sum -- "$1")"
  printf '%s\n' "${result%% *}"
}

CURRENT_DIGEST="$(digest "$CURRENT_CERT")"
POLICY_DIGEST="$(digest "${TRUST}/policy")"
REQUESTERS_DIGEST="$(digest "${TRUST}/requesters.allowed_signers")"
APPROVERS_DIGEST="$(digest "${TRUST}/approvers.allowed_signers")"
RESPONSES_DIGEST="$(digest "${TRUST}/responses.allowed_signers")"
DEPLOYERS_DIGEST="$(digest "${TRUST}/deployers.allowed_signers")"

run_helper() {
  "$HELPER" request "$@" \
    --service registry-test \
    --target test-target \
    --requester-principal test-target \
    --operation migrate \
    --profile server-p384-sha384-v1 \
    --inventory-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --current-cert-sha256 "$CURRENT_DIGEST" \
    --current-cert-path "$CURRENT_CERT" \
    --common-name registry.test.example \
    --dns-san registry.test.example \
    --dns-san test-target \
    --ip-san 192.0.2.61 \
    --response-principal test-response \
    --request-ttl-seconds "${REQUEST_TTL:-3600}" \
    --request-signing-key "$SIGNING_KEY" \
    --request-namespace platform-pki-csr-request-v1 \
    --trust-binding policy "${TRUST}/policy" "$POLICY_DIGEST" \
    --trust-binding requesters.allowed_signers "${TRUST}/requesters.allowed_signers" "$REQUESTERS_DIGEST" \
    --trust-binding approvers.allowed_signers "${TRUST}/approvers.allowed_signers" "$APPROVERS_DIGEST" \
    --trust-binding responses.allowed_signers "${TRUST}/responses.allowed_signers" "$RESPONSES_DIGEST" \
    --trust-binding deployers.allowed_signers "${TRUST}/deployers.allowed_signers" "$DEPLOYERS_DIGEST" \
    --state-root "${REQUEST_STATE:-$STATE}" \
    --pending-root "${REQUEST_PENDING:-$PENDING}"
}

tree_snapshot() {
  python3 - "$WORK" <<'PY'
import hashlib
import json
import os
import stat
import sys

root = sys.argv[1]
result = []
for current, directories, files in os.walk(root):
    directories.sort()
    files.sort()
    for name in directories + files:
        path = os.path.join(current, name)
        metadata = os.lstat(path)
        record = [
            os.path.relpath(path, root),
            stat.S_IFMT(metadata.st_mode),
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_nlink,
            metadata.st_size,
        ]
        if stat.S_ISREG(metadata.st_mode):
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOATIME", 0))
            try:
                data = b""
                while True:
                    chunk = os.read(descriptor, 65536)
                    if not chunk:
                        break
                    data += chunk
            finally:
                os.close(descriptor)
            record.extend((metadata.st_atime_ns, hashlib.sha256(data).hexdigest()))
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

wait_for_helper_pause() {
  local parent_pid=$1
  local helper_pid=
  for _ in $(seq 1 100); do
    if [[ -r /proc/${parent_pid}/task/${parent_pid}/children ]]; then
      read -r helper_pid _ <"/proc/${parent_pid}/task/${parent_pid}/children" || true
    fi
    if [[ -n $helper_pid && -r /proc/${helper_pid}/wchan ]] \
      && [[ $(<"/proc/${helper_pid}/wchan") == hrtimer_nanosleep ]]; then
      return
    fi
    sleep 0.02
  done
  printf '%s\n' 'helper did not reach the injected pause' >&2
  return 1
}

before_absent_check="$(tree_snapshot)"
if run_helper --check >/dev/null 2>/dev/null; then
  printf '%s\n' 'check mode accepted an absent state root and lock' >&2
  exit 1
fi
after_absent_check="$(tree_snapshot)"
[[ $before_absent_check == "$after_absent_check" ]]
[[ ! -e $STATE && ! -L $STATE && ! -e $PENDING && ! -L $PENDING ]]

mkdir -m 700 -- "$STATE"
touch -- "${STATE}/lock"
chmod 600 "${STATE}/lock"
before_check="$(tree_snapshot)"
check_output="$(run_helper --check)"
after_check="$(tree_snapshot)"
[[ $before_check == "$after_check" ]]
[[ ! -e $PENDING && ! -L $PENDING ]]
python3 - "$check_output" "$PENDING" <<'PY'
import json
import sys

record = json.loads(sys.argv[1])
if record != {"status": "would-create", "pending_dir": sys.argv[2]}:
    raise SystemExit(f"unexpected check result: {record}")
PY

created_output="$(run_helper)"
read -r REQUEST_ID PENDING_DIR < <(
  python3 - "$created_output" <<'PY'
import json
import re
import sys

record = json.loads(sys.argv[1])
expected_keys = {
    "status", "request_id", "request_sha256", "csr_sha256",
    "csr_spki_sha256", "pending_dir",
}
if set(record) != expected_keys or record["status"] != "created":
    raise SystemExit(f"unexpected creation result: {record}")
if not re.fullmatch(r"[0-9a-f]{32}", record["request_id"]):
    raise SystemExit("request ID is not canonical")
print(record["request_id"], record["pending_dir"])
PY
)
[[ $PENDING_DIR == "${PENDING}/${REQUEST_ID}" ]]

python3 - "$PENDING_DIR" <<'PY'
import os
import stat
import sys

root = sys.argv[1]
metadata = os.lstat(root)
if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != 0:
    raise SystemExit("pending request directory metadata is unsafe")
expected = {"tls.key", "tls.csr", "request", "request.sig"}
if set(os.listdir(root)) != expected:
    raise SystemExit("pending request does not contain exactly four files")
for name in expected:
    metadata = os.lstat(os.path.join(root, name))
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
    ):
        raise SystemExit(f"unsafe protocol file metadata: {name}")
PY

python3 - "$PENDING_DIR" "$REQUEST_ID" "$CURRENT_DIGEST" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
fields = (
    "schema", "request_id", "nonce", "created_epoch", "expires_epoch",
    "operation", "service", "target", "requester_principal",
    "inventory_sha256", "csr_sha256", "csr_spki_sha256",
    "current_cert_sha256", "profile", "response_principal",
)
data = (root / "request").read_bytes()
if not data.endswith(b"\n") or b"\r" in data:
    raise SystemExit("request is not canonically newline-terminated")
lines = data.decode("ascii").splitlines()
record = {}
for expected, line in zip(fields, lines, strict=True):
    key, value = line.split("=", 1)
    if key != expected:
        raise SystemExit("request field order is not canonical")
    record[key] = value
if len(lines) != 15:
    raise SystemExit("request field count is not 15")
expected = {
    "schema": "1",
    "request_id": sys.argv[2],
    "operation": "migrate",
    "service": "registry-test",
    "target": "test-target",
    "requester_principal": "test-target",
    "inventory_sha256": "a" * 64,
    "current_cert_sha256": sys.argv[3],
    "profile": "server-p384-sha384-v1",
    "response_principal": "test-response",
}
if any(record[key] != value for key, value in expected.items()):
    raise SystemExit("request values do not match supplied bindings")
if int(record["expires_epoch"]) - int(record["created_epoch"]) != 3600:
    raise SystemExit("request TTL is not exact")
if record["csr_sha256"] != hashlib.sha256((root / "tls.csr").read_bytes()).hexdigest():
    raise SystemExit("CSR digest binding is invalid")
PY

ssh-keygen -Y verify \
  -f "${TRUST}/requesters.allowed_signers" \
  -I test-target \
  -n platform-pki-csr-request-v1 \
  -s "${PENDING_DIR}/request.sig" <"${PENDING_DIR}/request" >/dev/null
openssl req -in "${PENDING_DIR}/tls.csr" -verify -noout >/dev/null 2>&1
openssl pkey -in "${PENDING_DIR}/tls.key" -pubout -outform DER -out "${WORK}/key-spki.der"
openssl req -in "${PENDING_DIR}/tls.csr" -pubkey -noout -out "${WORK}/csr-public.pem"
openssl pkey -pubin -in "${WORK}/csr-public.pem" -outform DER -out "${WORK}/csr-spki.der"
cmp -s "${WORK}/key-spki.der" "${WORK}/csr-spki.der"

existing_output="$(run_helper)"
python3 - "$existing_output" "$REQUEST_ID" <<'PY'
import json
import sys

record = json.loads(sys.argv[1])
if record["status"] != "existing" or record["request_id"] != sys.argv[2]:
    raise SystemExit(f"idempotent rerun did not select the validated request: {record}")
PY

printf '%s\n' active >"${STATE}/active"
printf '%s\n' rollback >"${STATE}/rollback"
printf '%s\n' boundary >"${STATE}/validation-boundary"
evidence_root="${STATE}/evidence/0123456789abcdef0123456789abcdef/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
mkdir -p -- "$evidence_root"
chmod 0700 -- "${STATE}/evidence" "${STATE}/evidence/0123456789abcdef0123456789abcdef"
for evidence_name in deployment deployment.sig validation-boundary validation-result validation-result.sig; do
  printf '%s\n' "$evidence_name" >"${evidence_root}/${evidence_name}"
done
chmod 0600 -- "${STATE}/active" "${STATE}/rollback" "${STATE}/validation-boundary" "${evidence_root}"/*
lifecycle_output="$(run_helper)"
[[ $(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["status"])' "$lifecycle_output") == existing ]]
printf '%s\n' unresolved >"${STATE}/activation-journal"
chmod 0600 "${STATE}/activation-journal"
expect_failure 'unresolved activation journal' run_helper
rm -- "${STATE}/activation-journal"

flock "${STATE}/lock" sleep 30 &
lock_pid=$!
for _ in $(seq 1 50); do
  if ! flock -n "${STATE}/lock" true 2>/dev/null; then
    break
  fi
  sleep 0.02
done
expect_failure 'lock contention' run_helper
kill "$lock_pid"
wait "$lock_pid" 2>/dev/null || true

run_changed_ttl() { REQUEST_TTL=7200 run_helper; }
expect_failure 'changed request TTL' run_changed_ttl

mv -- "${PENDING_DIR}/request.sig" "${WORK}/request.sig.saved"
ln -s "${WORK}/request.sig.saved" "${PENDING_DIR}/request.sig"
expect_failure 'symlinked protocol file' run_helper
rm -- "${PENDING_DIR}/request.sig"
mv -- "${WORK}/request.sig.saved" "${PENDING_DIR}/request.sig"

mv -- "${PENDING_DIR}/tls.csr" "${WORK}/tls.csr.saved"
ln -- "${WORK}/tls.csr.saved" "${PENDING_DIR}/tls.csr"
expect_failure 'hard-linked protocol file' run_helper
rm -- "${PENDING_DIR}/tls.csr"
mv -- "${WORK}/tls.csr.saved" "${PENDING_DIR}/tls.csr"

printf '%s\n' unexpected >"${PENDING_DIR}/unexpected"
expect_failure 'unexpected protocol entry' run_helper
rm -- "${PENDING_DIR}/unexpected"

mv -- "${PENDING_DIR}/request" "${WORK}/request.saved"
printf '%s\n' malformed >"${PENDING_DIR}/request"
expect_failure 'malformed pending request' run_helper
rm -- "${PENDING_DIR}/request"
mv -- "${WORK}/request.saved" "${PENDING_DIR}/request"

cp -a -- "$PENDING_DIR" "${PENDING}/00000000000000000000000000000000"
expect_failure 'multiple pending requests' run_helper
rm -rf -- "${PENDING}/00000000000000000000000000000000"

ln -s "$STATE" "${WORK}/state-link"
run_symlinked_root() { REQUEST_STATE="${WORK}/state-link" run_helper; }
expect_failure 'symlinked state root' run_symlinked_root
rm -- "${WORK}/state-link"

expired_state="${WORK}/expired-state"
expired_pending="${WORK}/expired-pending"
create_short_request() {
  REQUEST_STATE="$expired_state" REQUEST_PENDING="$expired_pending" REQUEST_TTL=1 run_helper
}
expired_output="$(create_short_request)"
sleep 2
expect_failure 'expired pending request' create_short_request

crash_state="${WORK}/crash-state"
crash_pending="${WORK}/crash-pending"
crash_after_key() {
  REQUEST_STATE="$crash_state" REQUEST_PENDING="$crash_pending" \
    PLATFORM_PKI_REQUEST_CRASH_AT=after-key run_helper
}
expect_failure 'crash after private-key generation' crash_after_key
[[ -f ${crash_state}/request.journal ]]
compgen -G "${crash_pending}/.stage-*" >/dev/null
before_crash_check="$(tree_snapshot)"
if REQUEST_STATE="$crash_state" REQUEST_PENDING="$crash_pending" run_helper --check >/dev/null 2>/dev/null; then
  printf '%s\n' 'check mode accepted interrupted pre-publication state' >&2
  exit 1
fi
after_crash_check="$(tree_snapshot)"
[[ $before_crash_check == "$after_crash_check" ]]
recovered_output="$(REQUEST_STATE="$crash_state" REQUEST_PENDING="$crash_pending" run_helper)"
[[ ! -e ${crash_state}/request.journal && ! -L ${crash_state}/request.journal ]]
[[ $(find "$crash_pending" -mindepth 1 -maxdepth 1 -type d -name '[0-9a-f]*' | wc -l) -eq 1 ]]

published_state="${WORK}/published-state"
published_pending="${WORK}/published-pending"
crash_after_publication() {
  REQUEST_STATE="$published_state" REQUEST_PENDING="$published_pending" \
    PLATFORM_PKI_REQUEST_CRASH_AT=after-publication run_helper
}
expect_failure 'crash after request publication' crash_after_publication
[[ -f ${published_state}/request.journal ]]
before_published_check="$(tree_snapshot)"
if REQUEST_STATE="$published_state" REQUEST_PENDING="$published_pending" run_helper --check >/dev/null 2>/dev/null; then
  printf '%s\n' 'check mode accepted interrupted post-publication state' >&2
  exit 1
fi
after_published_check="$(tree_snapshot)"
[[ $before_published_check == "$after_published_check" ]]
pause_published_recovery() {
  REQUEST_STATE="$published_state" REQUEST_PENDING="$published_pending" \
    PLATFORM_PKI_REQUEST_PAUSE_AT=before-recovery-journal-removal run_helper
}
pause_published_recovery >"${WORK}/published-root-race.stdout" 2>"${WORK}/published-root-race.stderr" &
published_root_race_pid=$!
wait_for_helper_pause "$published_root_race_pid"
mv -- "$published_pending" "${published_pending}.validated"
cp -a -- "${published_pending}.validated" "$published_pending"
if wait "$published_root_race_pid"; then
  printf '%s\n' 'recovery accepted a replaced pending root' >&2
  exit 1
fi
[[ -f ${published_state}/request.journal ]]
rm -rf -- "$published_pending"
mv -- "${published_pending}.validated" "$published_pending"

pause_published_recovery >"${WORK}/published-race.stdout" 2>"${WORK}/published-race.stderr" &
published_race_pid=$!
wait_for_helper_pause "$published_race_pid"
mv -- "${published_state}/request.journal" "${published_state}/request.journal.validated"
cp -- "${published_state}/request.journal.validated" "${published_state}/request.journal"
chmod 600 "${published_state}/request.journal"
if wait "$published_race_pid"; then
  printf '%s\n' 'replaced recovery journal was unlinked' >&2
  exit 1
fi
[[ -f ${published_state}/request.journal ]]
rm -- "${published_state}/request.journal"
mv -- "${published_state}/request.journal.validated" "${published_state}/request.journal"
published_recovery_output="$(REQUEST_STATE="$published_state" REQUEST_PENDING="$published_pending" run_helper)"
[[ ! -e ${published_state}/request.journal && ! -L ${published_state}/request.journal ]]
python3 - "$published_recovery_output" <<'PY'
import json
import sys

if json.loads(sys.argv[1])["status"] != "existing":
    raise SystemExit("published request recovery did not retain the validated request")
PY

race_pending="${WORK}/race-pending"
race_one() { REQUEST_STATE="${WORK}/race-state-one" REQUEST_PENDING="$race_pending" run_helper; }
race_two() { REQUEST_STATE="${WORK}/race-state-two" REQUEST_PENDING="$race_pending" run_helper; }
race_one >"${WORK}/race-one.stdout" 2>"${WORK}/race-one.stderr" &
race_one_pid=$!
race_two >"${WORK}/race-two.stdout" 2>"${WORK}/race-two.stderr" &
race_two_pid=$!
race_successes=0
if wait "$race_one_pid"; then race_successes=$((race_successes + 1)); fi
if wait "$race_two_pid"; then race_successes=$((race_successes + 1)); fi
[[ $race_successes -ge 1 ]]
[[ $(find "$race_pending" -mindepth 1 -maxdepth 1 -type d -name '[0-9a-f]*' | wc -l) -eq 1 ]]
python3 - "${WORK}/race-one.stdout" "${WORK}/race-two.stdout" <<'PY'
import json
import pathlib
import sys

statuses = []
for name in sys.argv[1:]:
    content = pathlib.Path(name).read_text(encoding="utf-8").strip()
    if content:
        statuses.append(json.loads(content)["status"])
if statuses.count("created") != 1 or any(value not in {"created", "existing"} for value in statuses):
    raise SystemExit(f"concurrent pending-root outcomes are invalid: {statuses}")
PY

binding_state="${WORK}/binding-state"
binding_pending="${WORK}/binding-pending"
replace_state_lock() {
  REQUEST_STATE="$binding_state" REQUEST_PENDING="$binding_pending" \
    PLATFORM_PKI_REQUEST_PAUSE_AT=before-publication run_helper
}
replace_state_lock >"${WORK}/binding.stdout" 2>"${WORK}/binding.stderr" &
binding_pid=$!
for _ in $(seq 1 100); do
  if compgen -G "${binding_pending}/.stage-*/request.sig" >/dev/null; then break; fi
  sleep 0.02
done
compgen -G "${binding_pending}/.stage-*/request.sig" >/dev/null
mv -- "${binding_state}/lock" "${binding_state}/lock.validated"
touch -- "${binding_state}/lock"
chmod 600 "${binding_state}/lock"
if wait "$binding_pid"; then
  printf '%s\n' 'state-lock path replacement race was accepted' >&2
  exit 1
fi
rm -- "${binding_state}/lock"
mv -- "${binding_state}/lock.validated" "${binding_state}/lock"
REQUEST_STATE="$binding_state" REQUEST_PENDING="$binding_pending" run_helper >/dev/null

pending_binding_state="${WORK}/pending-binding-state"
pending_binding_root="${WORK}/pending-binding-root"
replace_pending_root() {
  REQUEST_STATE="$pending_binding_state" REQUEST_PENDING="$pending_binding_root" \
    PLATFORM_PKI_REQUEST_PAUSE_AT=before-publication run_helper
}
replace_pending_root >"${WORK}/pending-binding.stdout" 2>"${WORK}/pending-binding.stderr" &
pending_binding_pid=$!
for _ in $(seq 1 100); do
  if compgen -G "${pending_binding_root}/.stage-*/request.sig" >/dev/null; then break; fi
  sleep 0.02
done
compgen -G "${pending_binding_root}/.stage-*/request.sig" >/dev/null
mv -- "$pending_binding_root" "${pending_binding_root}.validated"
mkdir -m 700 -- "$pending_binding_root"
if wait "$pending_binding_pid"; then
  printf '%s\n' 'pending-root replacement race was accepted' >&2
  exit 1
fi
rm -rf -- "$pending_binding_root"
mv -- "${pending_binding_root}.validated" "$pending_binding_root"
REQUEST_STATE="$pending_binding_state" REQUEST_PENDING="$pending_binding_root" run_helper >/dev/null

publication_journal_state="${WORK}/publication-journal-state"
publication_journal_pending="${WORK}/publication-journal-pending"
replace_publication_journal() {
  REQUEST_STATE="$publication_journal_state" REQUEST_PENDING="$publication_journal_pending" \
    PLATFORM_PKI_REQUEST_PAUSE_AT=before-publication-journal-removal run_helper
}
replace_publication_journal >"${WORK}/publication-journal.stdout" 2>"${WORK}/publication-journal.stderr" &
publication_journal_pid=$!
wait_for_helper_pause "$publication_journal_pid"
mv -- "${publication_journal_state}/request.journal" \
  "${publication_journal_state}/request.journal.validated"
cp -- "${publication_journal_state}/request.journal.validated" \
  "${publication_journal_state}/request.journal"
chmod 600 "${publication_journal_state}/request.journal"
if wait "$publication_journal_pid"; then
  printf '%s\n' 'normal publication unlinked a replaced journal' >&2
  exit 1
fi
[[ -f ${publication_journal_state}/request.journal ]]
rm -- "${publication_journal_state}/request.journal"
mv -- "${publication_journal_state}/request.journal.validated" \
  "${publication_journal_state}/request.journal"
REQUEST_STATE="$publication_journal_state" REQUEST_PENDING="$publication_journal_pending" run_helper >/dev/null

replacement_state="${WORK}/replacement-state"
replacement_pending="${WORK}/replacement-pending"
replace_during_signing() {
  REQUEST_STATE="$replacement_state" REQUEST_PENDING="$replacement_pending" \
    PLATFORM_PKI_REQUEST_PAUSE_AT=before-signing run_helper
}
replace_during_signing >"${WORK}/replacement.stdout" 2>"${WORK}/replacement.stderr" &
replacement_pid=$!
for _ in $(seq 1 100); do
  if compgen -G "${replacement_pending}/.stage-*/request" >/dev/null; then break; fi
  sleep 0.02
done
compgen -G "${replacement_pending}/.stage-*/request" >/dev/null
mv -- "$SIGNING_KEY" "${SIGNING_KEY}.validated"
ssh-keygen -q -t ed25519 -N '' -f "$SIGNING_KEY"
chmod 600 "$SIGNING_KEY"
if wait "$replacement_pid"; then
  printf '%s\n' 'signing-key replacement race was accepted' >&2
  exit 1
fi
rm -- "$SIGNING_KEY" "${SIGNING_KEY}.pub"
mv -- "${SIGNING_KEY}.validated" "$SIGNING_KEY"
REQUEST_STATE="$replacement_state" REQUEST_PENDING="$replacement_pending" run_helper >/dev/null

python3 - "$SIGNING_KEY" "$check_output" "$created_output" "$existing_output" "$expired_output" "$recovered_output" "$published_recovery_output" <<'PY'
import json
import pathlib
import sys

key_lines = [line for line in pathlib.Path(sys.argv[1]).read_bytes().splitlines() if line]
for output in sys.argv[2:]:
    encoded = output.encode("utf-8")
    json.loads(output)
    if b"PRIVATE KEY" in encoded or any(len(line) >= 16 and line in encoded for line in key_lines):
        raise SystemExit("helper stdout exposed private key bytes")
PY

if [[ $ROOT_DIR == /workspace ]]; then
  ROLE_STATE="${WORK}/role-state"
  ROLE_PENDING="${WORK}/role-pending"
  ROLE_VERSIONS="${WORK}/role-versions"
  ROLE_HELPER="${WORK}/bin/platform-pki-host-local-request"
  ROLE_PLAYBOOK="${ROOT_DIR}/tests/fixtures/pki-host-local-request-role/integration.yml"
  [[ ! -e $ROLE_STATE && ! -L $ROLE_STATE ]] || {
    printf '%s\n' 'role integration state already exists in the disposable container' >&2
    exit 1
  }
  [[ ! -e $ROLE_PENDING && ! -L $ROLE_PENDING ]] || {
    printf '%s\n' 'role integration pending root already exists in the disposable container' >&2
    exit 1
  }
  [[ ! -e $ROLE_HELPER && ! -L $ROLE_HELPER ]] || {
    printf '%s\n' 'role integration helper already exists in the disposable container' >&2
    exit 1
  }
  read -r role_algorithm role_payload _ < <(ssh-keygen -y -f "$SIGNING_KEY")
  printf '%s %s %s\n' localhost "$role_algorithm" "$role_payload" >"${TRUST}/requesters.allowed_signers"
  printf '%s %s %s\n' localhost "$role_algorithm" "$role_payload" >"${TRUST}/deployers.allowed_signers"
  REQUESTERS_DIGEST="$(digest "${TRUST}/requesters.allowed_signers")"
  DEPLOYERS_DIGEST="$(digest "${TRUST}/deployers.allowed_signers")"
  ROLE_VARS="${WORK}/role-vars.json"
  python3 - \
    "$ROLE_VARS" "$TRUST" "$CURRENT_CERT" "$CURRENT_DIGEST" \
    "$SIGNING_KEY" "$ROLE_STATE" "$ROLE_PENDING" "$ROLE_VERSIONS" "$ROLE_HELPER" \
    "$POLICY_DIGEST" "$REQUESTERS_DIGEST" "$APPROVERS_DIGEST" \
    "$RESPONSES_DIGEST" "$DEPLOYERS_DIGEST" <<'PY'
import json
import sys

(
    output,
    trust,
    current_cert,
    current_digest,
    signing_key,
    target_root,
    pending_root,
    versions_root,
    helper_path,
    policy_digest,
    requesters_digest,
    approvers_digest,
    responses_digest,
    deployers_digest,
) = sys.argv[1:]
trust_root = f"{target_root}/trust/reviewed-v1"
names = (
    "policy",
    "requesters.allowed_signers",
    "approvers.allowed_signers",
    "responses.allowed_signers",
    "deployers.allowed_signers",
)
digests = dict(
    zip(
        names,
        (
            policy_digest,
            requesters_digest,
            approvers_digest,
            responses_digest,
            deployers_digest,
        ),
        strict=True,
    )
)
variables = {
    "ansible_remote_tmp": f"{target_root}-ansible-tmp",
    "pki_host_local_certificate_service": "registry-test",
    "pki_host_local_certificate_target": "localhost",
    "pki_host_local_certificate_operation": "migrate",
    "pki_host_local_certificate_inventory_sha256": "a" * 64,
    "pki_host_local_certificate_current_cert_sha256": current_digest,
    "pki_host_local_certificate_current_cert_path": current_cert,
    "pki_host_local_certificate_requester_principal": "localhost",
    "pki_host_local_certificate_response_principal": "test-response",
    "pki_host_local_certificate_common_name": "registry.test.example",
    "pki_host_local_certificate_dns_sans": ["registry.test.example", "localhost"],
    "pki_host_local_certificate_ip_sans": ["192.0.2.61"],
    "pki_host_local_certificate_validity_days": 397,
    "pki_host_local_certificate_request_ttl_seconds": 3600,
    "pki_host_local_certificate_request_signing_key_path": signing_key,
    "pki_host_local_certificate_trust_id": "reviewed-v1",
    "pki_host_local_certificate_state_root": target_root,
    "pki_host_local_certificate_pending_root": pending_root,
    "pki_host_local_certificate_versions_root": versions_root,
    "pki_host_local_certificate_request_helper_path": helper_path,
    "pki_host_local_certificate_controller_exchange_root": "/tmp/platform-pki-exchange",
    "pki_host_local_certificate_transport": "sftp",
    "pki_host_local_certificate_transport_host_key_sha256": "b" * 64,
    "pki_host_local_certificate_trust_paths": {
        name: f"{trust_root}/{name}" for name in names
    },
    "pki_host_local_certificate_trust_sha256": digests,
}
with open(output, "w", encoding="utf-8") as stream:
    json.dump(variables, stream, sort_keys=True)
PY

  mkdir -m 700 -- "$ROLE_STATE" "${ROLE_STATE}/trust" "${ROLE_STATE}/trust/reviewed-v1"
  install -m 0600 -- "${TRUST}"/* "${ROLE_STATE}/trust/reviewed-v1/"
  : >"${ROLE_STATE}/lock"
  chmod 600 "${ROLE_STATE}/lock"
  mkdir -m 755 -- "$(dirname -- "$ROLE_HELPER")"
  install -m 0755 -- "$HELPER" "$ROLE_HELPER"
  role_helper_digest="$(digest "$ROLE_HELPER")"

  ansible-playbook --check -i localhost, -e "@${ROLE_VARS}" "$ROLE_PLAYBOOK" >/dev/null
  [[ ! -e $ROLE_PENDING && ! -L $ROLE_PENDING ]]
  [[ $(digest "$ROLE_HELPER") == "$role_helper_digest" ]]
  [[ $(find "$ROLE_STATE" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort) == $'lock\ntrust' ]]

  if ! role_output="$(ansible-playbook -i localhost, -e "@${ROLE_VARS}" "$ROLE_PLAYBOOK" 2>&1)"; then
    printf '%s\n' "$role_output" >&2
    printf '%s\n' 'Host-local request role integration failed' >&2
    exit 1
  fi
  [[ $role_output != *'PRIVATE KEY'* ]]
  [[ -x $ROLE_HELPER ]]
  mapfile -t role_requests < <(find "$ROLE_PENDING" -mindepth 1 -maxdepth 1 -type d -printf '%f\n')
  [[ ${#role_requests[@]} -eq 1 && ${role_requests[0]} =~ ^[0-9a-f]{32}$ ]]
  [[ -f ${ROLE_PENDING}/${role_requests[0]}/tls.key ]]
  [[ ! -e ${WORK}/tls.key && ! -L ${WORK}/tls.key ]]

  if ! idempotent_role_output="$(ansible-playbook -i localhost, -e "@${ROLE_VARS}" "$ROLE_PLAYBOOK" 2>&1)"; then
    printf '%s\n' "$idempotent_role_output" >&2
    printf '%s\n' 'Second host-local request role run failed' >&2
    exit 1
  fi
  grep -qE 'changed=0.*failed=0' <<<"$idempotent_role_output" || {
    printf '%s\n' "$idempotent_role_output" >&2
    printf '%s\n' 'Second host-local request role run was not idempotent' >&2
    exit 1
  }
fi

printf '%s\n' 'Host-local PKI request helper checks passed.'
