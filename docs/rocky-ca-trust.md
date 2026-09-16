# Rocky CA Trust Preparation

`scripts/rocky-ca-trust-prepare` is a standalone, target-local companion to
`rocky-ansible-host-prepare`. It installs a reviewed root and, optionally, one
explicitly approved intermediate as separate system-wide CA anchors before
workload bootstrap. It does not download certificates, alter SSH access, run
Ansible, contact endpoints or skip TLS validation.

## Inputs And Scope

Run as root on Rocky Linux 10, with Python 3.12+, SELinux enforcing, and existing
`openssl`, `hostnamectl`, `getenforce`, `restorecon`, `matchpathcon` and
`update-ca-trust` commands. The helper installs no packages.

Transfer the reviewed helper through authenticated provisioning access, record
and compare its `sha256sum`, and stage it root-owned with mode `0755`. Supply
offline certificate files through absolute paths under root-controlled,
non-symlink directories, for example `/root/platform-ca/`. Inputs must be
root:root, singly linked regular files, not writable by group/others, at most
16 KiB each. Use mode `0600` or `0644`.

Each input must contain exactly one canonical PEM CA certificate (CRLF and
trailing newline differences are accepted). The required fingerprints are
SHA-256 hashes of **DER certificate bytes**, not hashes of PEM files. Compare
these with the authoritative PKI source:

```bash
openssl x509 -in /root/platform-ca/root.crt -noout -fingerprint -sha256
```

CLI fingerprints use 64 lowercase hex characters without colons. Real CA files,
fingerprints, names and host scope belong in the private environment procedure.
An intermediate is optional; supplying its file and fingerprint authorizes it
as a **system-wide trust anchor**, not merely a cached issuer or trust limited
to a repository hostname. This is an explicit environment policy choice.

| Argument | Meaning |
| --- | --- |
| `check` / `apply` | Read-only observation / confirmed installation and refresh |
| `--expected-hostname` | Reviewed literal static hostname, checked with `hostnamectl --static` |
| `--root-file`, `--root-fingerprint` | Required local root certificate and DER fingerprint |
| `--root-name` | Anchor basename; default `platform-root-ca.crt` |
| `--intermediate-file`, `--intermediate-fingerprint` | Optional pair for a CA signed by the supplied root |
| `--intermediate-name` | Anchor basename; default `platform-intermediate-ca.crt`; requires the intermediate pair |
| `--confirm` | Apply only, exactly `<expected-hostname>:ca-trust` |

Names must be distinct `.crt` basenames. Both destinations are fixed below
`/etc/pki/ca-trust/source/anchors/`; arbitrary destination directories are not
accepted. Select previously installed manual anchor names explicitly to reuse
them. Matching certificate content and root:root `0644` metadata are retained;
different content, symlinks, hardlinks or unsafe metadata stop for review.
Omitting an intermediate does not remove an existing one. There is no deletion,
rotation or automatic migration operation.

## Check, Apply, Check

Example for a root-only environment. Replace the hostname and fingerprint with
reviewed private values; do not derive the expected hostname from the target
merely to satisfy the identity check. Run these commands in the same Bash session:

```bash
helper=/root/rocky-ca-trust-prepare
expected_hostname=node-01.example.test
inputs=(
  --expected-hostname "$expected_hostname"
  --root-file /root/platform-ca/root.crt
  --root-fingerprint '<reviewed-lowercase-64-hex-DER-fingerprint>'
)
sudo /usr/bin/python3.12 "$helper" check "${inputs[@]}"
```

`check` returns 0 only when the selected anchors, their expected SELinux labels
and their presence in the extracted TLS PEM bundle are verified. Missing anchors
or stale extraction return 1, as do validation errors; inspect the diagnostic
before approving apply. Argument errors return 2. Check never creates a lock,
stages files on disk, installs certificates or refreshes trust.

If an intermediate is explicitly approved, add its file, fingerprint and optional
name to `inputs` for **all three commands**. Root/intermediate CA constraints,
signing usage, validity and the chain back to the root are checked before either
anchor is written. The root self-signature is verified. Source bytes are read
once and fingerprint-verified; chain verification uses a RAM-only root snapshot.

After reviewing the intended host, issuers, missing files and any failures:

```bash
sudo /usr/bin/python3.12 "$helper" apply "${inputs[@]}" \
  --confirm "${expected_hostname}:ca-trust"
```

Require exit zero, then run:

```bash
sudo /usr/bin/python3.12 "$helper" check "${inputs[@]}"
```

Expected successful result:

```text
Result: SELECTED CA ANCHORS AND TLS BUNDLE READY
```

Apply preflights every selected destination, publishes only missing anchors
atomically without overwriting, restores their SELinux labels, and always runs
`update-ca-trust extract` before final verification. Matching anchors are not
rewritten on repeated apply. The generated store is refreshed even when no
anchor changed, so an approved rerun can finish an interrupted refresh without
a separate marker protocol.

## Failure And Qualification Boundaries

The root-owned `0600` lock `/run/platform-ca-trust-prepare.lock` coordinates only
this helper's applies. It does not coordinate other root processes, package
transactions, Ansible or direct trust-store edits. Prohibit those concurrent
mutations and do not run check concurrently with apply.

An interrupted/failed apply can leave one or both anchors installed or a refresh
incomplete. It returns failure and performs no rollback or retry. Review the
state, then explicitly approve another apply if appropriate. Different existing
certificates or unsafe files require operator review rather than forced repair.
An abrupt interruption during atomic publication may leave a temporary file or
extra hardlink; do not bypass the link-count guard to continue.

Check observes selected anchors and the current contents/label of
`/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`. It is not a receipt proving a
previous failed refresh completed every output format, nor an audit of every
system CA or consuming process. Do not edit generated bundles manually.

After local readiness, separately verify strict hostname-aware HTTPS in the
actual consuming context on every target. For RKE2, require the unchanged
[bootstrap source preflight](rke2-operations.md#bootstrap-source-preflight) in a
fresh pipeline before any RKE2 mutation. Host trust does not qualify pod/Helm-job
trust, image pulls or Runner checkout.

## Focused Offline Tests

```bash
PLATFORM_CONFIG_CONTAINER_PROFILE='test' ./scripts/in-container \
  python -m pytest -n 0 -q tests/python/test_rocky_ca_trust_prepare.py
```

These use generated certificates, real OpenSSL verification and sandboxed file
operations. They do not install CA trust on managed hosts or qualify live TLS.
