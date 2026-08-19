# Host-Local Registry PKI Workflow

This runbook covers the complete implemented workflow for moving one Zot
registry from a managed certificate to a certificate whose leaf private key
never leaves the registry host. It joins the target/controller operations in
`platform-config` with the approval, signing, decision, and export operations in
`platform-tools`.

The examples are sanitized. Real inventory, trust policy, hostnames, CA files,
and non-secret environment configuration belong in `../platform-private`.
Passphrases, private keys, and other secrets remain outside Git.

This workflow automates neither transport nor renewal. Direct host-key-pinned
SSH moves exact packages across the target boundary. GitLab Generic Packages
provide the normal durable online exchange, while protected local custody is the
fallback. Ansible never runs GitLab or package-movement network commands. Every
transfer remains an explicit movement of one exact allowlisted public package.

## Security Invariants

- Select exactly one registry target and one distinct validation runner.
- Never individually fetch, copy, inspect, hash, stat, or log the target's
  `tls.key`. Approved encrypted whole-VM backups may contain it, but the key is
  never extracted or handled as an individual backup artifact.
- Never place approval, response-signing, CA, or target private keys in Git,
  `/tmp`, shell arguments, environment variables, tickets, or chat.
- Carry exact request, artifact, deployment, and outcome coordinates forward.
  Never select `latest`, `current`, or the newest directory.
- Treat transport as untrusted. Canonical records, detached signatures, frozen
  trust, and exact digest pins establish authority.
- Stop on an unexpected file, owner, mode, link count, digest, principal,
  namespace, lifecycle state, or recovery journal.
- Preserve ambiguous stages and journals as evidence. Never use wildcard
  cleanup.
- Keep the managed predecessor, signer history, target history, exchange
  packages, and backups until a separate retention decision is approved.

## Repository Responsibilities

`platform-config` owns target request generation, public request collection,
response intake, transactional activation and rollback, runner validation,
deployment evidence, signer-outcome import, lifecycle status, and normal Zot
convergence.

`platform-tools` owns signer inventory and trust, offline approval and signing,
certificate-only response export, candidate decisions, terminal outcome export,
signer recovery, and encrypted signer-state backup.

The protocol and signer command details are documented in
[OpenSSL PKI Helpers](https://codeberg.org/rch/platform-tools/src/branch/main/docs/pki-openssl.md).
The lower-level package and signature contract is documented in
[Host-Local PKI CSR Handoff](https://codeberg.org/rch/platform-tools/src/branch/main/docs/handoffs/pki-host-local-csr-handoff.md).

## Coordinate Worksheet

Create an outside-Git operator record before starting. Fill each value only from
authenticated command output and do not change it later.

| Name | Source |
|---|---|
| `ENVIRONMENT` | Reviewed private Ansible environment, such as `dev` |
| `SERVICE` | Exact signer and lifecycle service, such as `registry-dev` |
| `TARGET` | Exact one-host registry inventory limit |
| `RUNNER` | Exact distinct read-only validation runner |
| `PKI_NAMESPACE` | Absolute signer namespace outside Git |
| `EXCHANGE_ROOT` | Protected controller exchange root outside Git |
| `REQUEST_ID` | Request creation output; 32 lowercase hexadecimal characters |
| `REQUEST_SHA256` | Request creation output |
| `CSR_SHA256` | Request creation output |
| `CSR_SPKI_SHA256` | Request creation output |
| `TRANSPORT_HOST_KEY_SHA256` | Direct `request-pull` output; lowercase hexadecimal SSH key-blob digest |
| `APPROVAL_SHA256` | SHA-256 of the exact canonical `approval` file |
| `ARTIFACT_SHA256` | `certificate-export publish` `manifest_sha256` |
| `DEPLOYMENT_SHA256` | Successful activation output |
| `OUTCOME_SHA256` | `csr-outcome publish` `manifest_sha256` |
| `RESPONSE_DIR` | Exact resolved six-file certificate export |
| `EVIDENCE_DIR` | Exact digest-keyed controller evidence directory |
| `OUTCOME_DIR` | Exact resolved six-file terminal outcome export |
| `ENDPOINT_RECORD` | Protected direct SSH endpoint record outside Git |

The examples below use shell variables only to make coordinate reuse visible:

```bash
ENVIRONMENT=dev
SERVICE=registry-dev
TARGET=registry-example
RUNNER=registry-validator-example
PKI_NAMESPACE=/outside-git/pki-namespace
EXCHANGE_ROOT=/outside-git/pki-exchange
ENDPOINT_RECORD=/outside-git/pki-endpoints/registry-example.json
```

Do not turn this page into an unattended script. Review and run one phase at a
time.

## Direct Endpoint Record

Create one current-user-owned mode-`0600` canonical JSON-line endpoint record.
It has exactly this schema, with keys serialized in sorted order:

```json
{"expected_host_key_sha256":"SHA256:REVIEWED_OPENSSH_FINGERPRINT","host":"registry-example","identity_path":"/outside-git/ssh/registry-exchange","known_hosts_path":"/outside-git/ssh/registry-exchange.known_hosts","port":22,"remote_helper_path":"/usr/local/libexec/platform-pki-host-local-exchange","schema":1,"user":"exchange-operator"}
```

The identity and endpoint files must be mode `0600`. The known-hosts file must
be mode `0600` and contain exactly one unhashed record for the endpoint token.
The endpoint account must have only reviewed noninteractive sudo access to the
fixed facade. The helper enforces `StrictHostKeyChecking=yes`, no agent, X11,
proxy, or shell, and the reviewed OpenSSH `SHA256:` host-key fingerprint.

`request-pull` also emits `transport_host_key_sha256`, the lowercase hexadecimal
SHA-256 of the same SSH key blob. Carry that exact value into request intake; it
is the format signed into the collection receipt.

## GitLab Transport

GitLab is the normal durable online transport between authenticated local
intakes. It is not protocol authority: signed records, frozen trust, and exact
digests remain authoritative. An authorized online transfer station runs these
commands with an exact protected project record, CA file, token file, and
package coordinate. The offline approver and signer never connect to GitLab, and
no Ansible playbook invokes these commands.

Before every publication, acquire a protected external lock keyed by exact
project, stage, service, and full package version. A protected CI
`resource_group` or an equivalent reviewed operator lock is acceptable. The
helper does not acquire this lock; every publication example below assumes the
lock is already held and must not be run concurrently at the same coordinate.

After direct request intake, publish the canonical request publication:

```bash
scripts/platform-pki-gitlab-package publish \
  --stage request --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" --package-version "$REQUEST_ID" \
  --source-dir "$EXCHANGE_ROOT/$SERVICE/$REQUEST_ID/request" \
  --project-record /outside-git/gitlab/project-record \
  --token-type private --token-file /run/secrets/gitlab-package-token \
  --ca-file /outside-git/gitlab/ca.pem \
  --inventory-record /outside-git/pki/request-inventory \
  --trust-dir "$EXCHANGE_ROOT/$SERVICE/$REQUEST_ID/trust" \
  --transport-host-key-sha256 "$TRANSPORT_HOST_KEY_SHA256"
```

The online transfer station downloads that exact request version with the same
reviewed request inventory, trust, and host-key coordinate:

```bash
scripts/platform-pki-gitlab-package download \
  --stage request --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" --package-version "$REQUEST_ID" \
  --destination-dir /secure/gitlab-request/"$REQUEST_ID" \
  --project-record /outside-git/gitlab/project-record \
  --token-type deploy --token-file /run/secrets/gitlab-package-token \
  --ca-file /outside-git/gitlab/ca.pem \
  --inventory-record /outside-git/pki/request-inventory \
  --trust-dir /outside-git/pki/reviewed-trust \
  --transport-host-key-sha256 "$TRANSPORT_HOST_KEY_SHA256"
install -d -m 0700 /secure/reviewed-request/"$REQUEST_ID"
for name in tls.csr request request.sig; do
  install -m 0600 -- \
    /secure/gitlab-request/"$REQUEST_ID"/"$name" \
    /secure/reviewed-request/"$REQUEST_ID"/"$name"
done
```

Retain `collection-receipt` and `stage-manifest` as transport evidence outside
the offline command-input directory. Move only the exact three files in
`/secure/reviewed-request/$REQUEST_ID` across the controlled-media boundary to
the offline approver.

After offline approval, move only `approval` and `approval.sig` back to the
online transfer station. Record the exact `approval` file digest as
`APPROVAL_SHA256` and publish that digest-keyed attempt:

```bash
scripts/platform-pki-gitlab-package publish \
  --stage approval --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$APPROVAL_SHA256" \
  --source-dir /outside-git/approval/"$APPROVAL_SHA256" \
  --project-record /outside-git/gitlab/project-record \
  --token-type private --token-file /run/secrets/gitlab-package-token \
  --ca-file /outside-git/gitlab/ca.pem
```

An online transfer station retrieves that exact approval coordinate and
materializes the five signer command inputs from the separately validated
request and approval packages:

```bash
scripts/platform-pki-gitlab-package download \
  --stage approval --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$APPROVAL_SHA256" \
  --destination-dir /secure/gitlab-approval/"$APPROVAL_SHA256" \
  --project-record /outside-git/gitlab/project-record \
  --token-type deploy --token-file /run/secrets/gitlab-package-token \
  --ca-file /outside-git/gitlab/ca.pem
for name in approval approval.sig; do
  install -m 0600 -- \
    /secure/gitlab-approval/"$APPROVAL_SHA256"/"$name" \
    /secure/reviewed-request/"$REQUEST_ID"/"$name"
done
```

Move only that exact five-file command-input directory across controlled media
to the offline signer. Neither `stage-manifest`, `collection-receipt`, package
metadata, nor transport credentials enter the signer input.

After offline signing, move the exact six-file response through controlled media
to the online transfer station. The station publishes package version
`REQUEST_ID`:

```bash
scripts/platform-pki-gitlab-package publish \
  --stage response --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" --package-version "$REQUEST_ID" \
  --source-dir /secure/response/"$REQUEST_ID" \
  --project-record /outside-git/gitlab/project-record \
  --token-type private --token-file /run/secrets/gitlab-package-token \
  --ca-file /outside-git/gitlab/ca.pem
```

Download the exact response package. GitLab downloads contain the six payload
files plus `stage-manifest`; materialize a separate exact-six directory before
deep response validation or direct push:

```bash
scripts/platform-pki-gitlab-package download \
  --stage response --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" --package-version "$REQUEST_ID" \
  --destination-dir /outside-git/gitlab-response/"$REQUEST_ID" \
  --project-record /outside-git/gitlab/project-record \
  --token-type deploy --token-file /run/secrets/gitlab-package-token \
  --ca-file /outside-git/gitlab/ca.pem
install -d -m 0700 "$EXCHANGE_ROOT/intake/response-$REQUEST_ID"
for name in artifact tls.crt ca-chain.crt fullchain.crt response response.sig; do
  install -m 0600 -- \
    /outside-git/gitlab-response/"$REQUEST_ID"/"$name" \
    "$EXCHANGE_ROOT/intake/response-$REQUEST_ID/$name"
done
```

After direct evidence pull and local intake, publish the exact evidence package:

```bash
scripts/platform-pki-gitlab-package publish \
  --stage evidence --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$DEPLOYMENT_SHA256" \
  --source-dir "$EXCHANGE_ROOT/$SERVICE/$REQUEST_ID/evidence/$DEPLOYMENT_SHA256" \
  --project-record /outside-git/gitlab/project-record \
  --token-type private --token-file /run/secrets/gitlab-package-token \
  --ca-file /outside-git/gitlab/ca.pem
```

The online transfer station downloads that exact digest-keyed evidence version,
then moves the reviewed signer inputs through controlled media to the offline
signer:

```bash
scripts/platform-pki-gitlab-package download \
  --stage evidence --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$DEPLOYMENT_SHA256" \
  --destination-dir /secure/gitlab-evidence/"$DEPLOYMENT_SHA256" \
  --project-record /outside-git/gitlab/project-record \
  --token-type deploy --token-file /run/secrets/gitlab-package-token \
  --ca-file /outside-git/gitlab/ca.pem
```

After the terminal offline signer decision, move the six-file outcome through
controlled media to the online transfer station. The station publishes it at
its exact digest-keyed version:

```bash
scripts/platform-pki-gitlab-package publish \
  --stage outcome --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$OUTCOME_SHA256" \
  --source-dir /secure/outcome/"$REQUEST_ID" \
  --project-record /outside-git/gitlab/project-record \
  --token-type private --token-file /run/secrets/gitlab-package-token \
  --ca-file /outside-git/gitlab/ca.pem
```

Download the exact terminal outcome and materialize its six payload files before
`outcome-push`:

```bash
scripts/platform-pki-gitlab-package download \
  --stage outcome --service "$SERVICE" --target "$TARGET" \
  --request-id "$REQUEST_ID" \
  --package-version "$REQUEST_ID-$OUTCOME_SHA256" \
  --destination-dir /outside-git/gitlab-outcome/"$REQUEST_ID" \
  --project-record /outside-git/gitlab/project-record \
  --token-type deploy --token-file /run/secrets/gitlab-package-token \
  --ca-file /outside-git/gitlab/ca.pem
install -d -m 0700 /outside-git/protected-outcome/"$REQUEST_ID"
for name in outcome outcome.sig deployment deployment.sig deployers.allowed_signers decision; do
  install -m 0600 -- \
    /outside-git/gitlab-outcome/"$REQUEST_ID"/"$name" \
    /outside-git/protected-outcome/"$REQUEST_ID"/"$name"
done
```

The repository has unit coverage for package validation and coordinate rules,
but this runbook does not claim live GitLab runtime qualification.

## Phase 1: Establish Prerequisites

Before a live request:

1. Review the private signer service inventory. A migration entry uses
   `key_custody: host-local`, the exact target, validation-boundary digest, SANs,
   certificate profile, and rollback hold.
2. Review one schema-2 trust tree containing exactly `policy`,
   `requesters.allowed_signers`, `approvers.allowed_signers`,
   `responses.allowed_signers`, and `deployers.allowed_signers`.
3. Confirm the signer, controller, and target use the same reviewed trust.
4. Review the CA bundle and validation boundary installed on the target and
   runner. The CA bundle is the profiled intermediate followed by its root.
5. Confirm the target currently serves the managed predecessor expected by a
   migration request and that normal Zot smoke checks pass.
6. Confirm there is no unresolved signer or target recovery state.
7. Create an encrypted signer backup and an approved target/VM backup. A backup
   is not accepted until its restore procedure is known and testable.

Install and verify signer inventory and public trust from the private repository:

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

Provision the reviewed validation material on the one target and runner, then
bootstrap target trust once:

```bash
make registry-pki-validation-material \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER"
make apply ENV="$ENVIRONMENT" \
  PLAYBOOK=playbooks/registry-pki-trust.yml LIMIT="$TARGET"
```

An exact trust reinstall is an authenticated no-op. Trust rotation is not part
of this workflow and must not occur while any request is pending.

On an already initialized lifecycle target, status may report
`managed-migration-needed` with `required_action=create-migration-request`.
Do not use status as a fresh-install bootstrap gate: it is read-only and requires
the lifecycle helper to exist already. The mutable request phase installs that
helper and independently proves the managed predecessor before creating state.

## Phase 2: Create And Intake The Target Request

Create one target-local P-384 key and signed request. The normal target is direct
and does not collect bytes through Ansible:

```bash
make registry-pki-request ENV="$ENVIRONMENT" LIMIT="$TARGET"
```

The default request lifetime is one hour. Use an explicit longer lifetime only
when the reviewed transport requires it, up to seven days:

```bash
make registry-pki-request ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_TTL_SECONDS=604800
```

Record `REQUEST_ID`, `REQUEST_SHA256`, `CSR_SHA256`, and `CSR_SPKI_SHA256`. Pull
the exact three public files through pinned SSH into a protected mode-`0700`
directory under the mounted exchange root:

```bash
scripts/platform-pki-direct-exchange request-pull \
  "$ENDPOINT_RECORD" "$REQUEST_ID" \
  "$EXCHANGE_ROOT/intake/request-$REQUEST_ID"
```

Record `transport_host_key_sha256` as `TRANSPORT_HOST_KEY_SHA256`, then perform
the controller-only authenticated intake. `/platform-pki-exchange` is the
container view of `PLATFORM_CONFIG_PKI_EXCHANGE_ROOT`:

```bash
PLATFORM_CONFIG_PKI_EXCHANGE_ROOT="$EXCHANGE_ROOT" \
make registry-pki-request-intake \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" REQUEST_ID="$REQUEST_ID" \
  REQUEST_SHA256="$REQUEST_SHA256" CSR_SHA256="$CSR_SHA256" \
  CSR_SPKI_SHA256="$CSR_SPKI_SHA256" \
  TRANSPORT_HOST_KEY_SHA256="$TRANSPORT_HOST_KEY_SHA256" \
  REQUEST_DIR="/platform-pki-exchange/intake/request-$REQUEST_ID"
```

This playbook gathers no facts, delegates only to localhost, and uses no Ansible
file transfer or target connection. It authenticates request signature, CSR,
SPKI, inventory, host-key, principal, SAN, profile, and frozen trust bindings
before atomically publishing:

```text
<exchange-root>/<service>/<request-id>/request/
|-- tls.csr
|-- request
|-- request.sig
`-- collection-receipt
```

The target `tls.key` remains root-owned on the target and is not present in the
direct package or controller exchange.

Re-read status and require `status=request-pending` with
`required_action=collect-or-await-response`:

```bash
make registry-pki-status ENV="$ENVIRONMENT" LIMIT="$TARGET"
```

## Phase 3: Approve, Sign, And Export The Response

Move exactly `tls.csr`, `request`, and `request.sig` to the reviewed approver
input through the approved controlled-media process. The approver input
directory must contain no other entry.

Create the protected five-file approved signer input:

```bash
platform-pki offline-csr approve "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --operation migrate \
  --request-id "$REQUEST_ID" \
  --input-dir /media/reviewed-request \
  --approval-key /secure/offline-approval \
  --output-dir /secure/approved/"$REQUEST_ID"
```

Review the displayed request and type the exact interactive confirmation. Do
not use `--yes` for a live run.

The approval destination is current-user-owned mode `0700` and contains exactly
mode-`0600` `tls.csr`, `request`, `request.sig`, `approval`, and
`approval.sig`.

Sign the approved request with the active intermediate and the dedicated
response-signing key:

```bash
platform-pki offline-csr sign "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --operation migrate \
  --request-id "$REQUEST_ID" \
  --input-dir /secure/approved/"$REQUEST_ID" \
  --response-key /secure/offline-response \
  --intermediate-pass-file /run/secrets/platform-pki-intermediate-pass
```

If signing reports recovery-required state, stop and use the exact signer
recovery procedure in [Signer Recovery](#signer-recovery).

Publish the immutable six-file certificate-only export:

```bash
platform-pki certificate-export publish "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID"
```

Record the returned `manifest_sha256` as `ARTIFACT_SHA256`, then resolve that
exact export:

```bash
platform-pki certificate-export resolve "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" \
  --manifest-sha256 "$ARTIFACT_SHA256" \
  --format path
```

The resolved response directory contains exactly:

```text
artifact
tls.crt
ca-chain.crt
fullchain.crt
response
response.sig
```

Move those exact six public files back to one protected current-user-owned
mode-`0700` controller directory. Each file must be singly linked, mode `0600`,
and unchanged from the resolved signer export.

## Phase 4: Authenticate, Push, And Activate The Response

Authenticate and snapshot the returned response entirely on the controller:

```bash
PLATFORM_CONFIG_PKI_EXCHANGE_ROOT="$EXCHANGE_ROOT" \
make registry-pki-response-check \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  RESPONSE_DIR="/platform-pki-exchange/intake/response-$REQUEST_ID"
```

Require `status=ready`. This phase does not contact Zot or mutate the target.

Push the same exact six-file reviewed response to the fixed target ingress:

```bash
scripts/platform-pki-direct-exchange response-push \
  "$ENDPOINT_RECORD" "$REQUEST_ID" "$ARTIFACT_SHA256" \
  "$EXCHANGE_ROOT/intake/response-$REQUEST_ID"
```

Require `status=staged` or `status=existing`. Activation accepts only an already
existing/staged ingress or an already installed version. It rejects a fresh
`prepared`/`would-prepare` result, unexpected files, and incomplete ingress.

Activate the exact response and validate it from the distinct reviewed runner:

```bash
make registry-pki-activate \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256"
```

Type exactly the confirmation shown by the command:

```text
activate SERVICE REQUEST_ID ARTIFACT_SHA256
```

There is no noninteractive live override. Successful activation reports
`status=activated-and-validated` and an exact `deployment` digest. Record that
digest as `DEPLOYMENT_SHA256`.

If activation fails or status reports recovery required, do not rerun activation
blindly. Follow [Target Activation Recovery](#target-activation-recovery).

## Phase 5: Retrieve And Intake Evidence, Then Converge Zot Custody

Report the exact direct evidence coordinates, retrieve the five-file attempt
through pinned SSH, and authenticate it locally:

```bash
make registry-pki-evidence-export \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256"
scripts/platform-pki-direct-exchange evidence-pull \
  "$ENDPOINT_RECORD" "$REQUEST_ID" "$ARTIFACT_SHA256" \
  "$DEPLOYMENT_SHA256" \
  "$EXCHANGE_ROOT/intake/evidence-$DEPLOYMENT_SHA256"
PLATFORM_CONFIG_PKI_EXCHANGE_ROOT="$EXCHANGE_ROOT" \
make registry-pki-evidence-intake \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" REQUEST_ID="$REQUEST_ID" \
  ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256" \
  EVIDENCE_DIR="/platform-pki-exchange/intake/evidence-$DEPLOYMENT_SHA256"
```

The digest-keyed evidence directory contains exactly:

```text
deployment
deployment.sig
validation-boundary
validation-result
validation-result.sig
```

Read status with the exact deployment coordinate:

```bash
make registry-pki-status \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256"
```

Require `status=evidence-exported`,
`evidence_state=controller-exported`, and
`required_action=await-signer-outcome`.

Set the target's private Zot inventory only after successful authenticated
activation:

```yaml
zot_registry_tls_custody: host-local
zot_registry_tls_host_local_target: registry-example
```

Run normal registry convergence twice and require the second run to be
idempotent, then run smoke validation:

```bash
make apply ENV="$ENVIRONMENT" PLAYBOOK=playbooks/registry.yml LIMIT="$TARGET"
make apply ENV="$ENVIRONMENT" PLAYBOOK=playbooks/registry.yml LIMIT="$TARGET"
make smoke-registry ENV="$ENVIRONMENT" LIMIT="$TARGET"
```

Normal convergence resolves immutable certificate and key paths through the
target lifecycle helper. Inventory cannot select a private-key path.

Immediately before the signer decision, perform a fresh exact runner preflight:

```bash
make registry-pki-decision-preflight \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256"
```

Require `result=passed`.

## Phase 6: Finalize And Export The Signer Outcome

Move the exact evidence directory through controlled media to a protected signer
location. Keep the directory current-user-owned mode `0700` and each file
singly linked at mode `0600`. Verify signer history before deciding:

```bash
platform-pki csr-candidate verify "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" --format json
```

The signer reports historical state and always sets `live_state_claimed` to
false. Current live authority comes from the target status and runner preflight,
not this command.

Finalize the candidate with the exact exported deployment evidence:

```bash
platform-pki csr-candidate finalize "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" \
  --artifact-manifest-sha256 "$ARTIFACT_SHA256" \
  --evidence-file /secure/evidence/"$DEPLOYMENT_SHA256"/deployment \
  --evidence-signature /secure/evidence/"$DEPLOYMENT_SHA256"/deployment.sig
```

Review and type the exact interactive confirmation. Finalization records
authenticated historical evidence; it does not contact or mutate the target.

Publish the immutable terminal outcome using the same dedicated response key
whose public key is frozen in the signing transaction trust:

```bash
platform-pki csr-outcome publish "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" \
  --outcome-key /secure/offline-response
```

Record `manifest_sha256` as `OUTCOME_SHA256`, then resolve that exact package:

```bash
platform-pki csr-outcome resolve "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" \
  --manifest-sha256 "$OUTCOME_SHA256" \
  --format path
```

The outcome directory contains exactly:

```text
outcome
outcome.sig
deployment
deployment.sig
deployers.allowed_signers
decision
```

Move those six public files back to one protected current-user-owned mode-`0700`
controller directory. Each file must remain singly linked and mode `0600`.

Create another encrypted signer backup after finalization:

```bash
platform-pki backup \
  --namespace "$PKI_NAMESPACE" \
  --age-recipient '<reviewed-age-recipient>'
```

## Phase 7: Import The Outcome And Prove Terminal State

Push the exact outcome into the fixed target spool:

```bash
scripts/platform-pki-direct-exchange outcome-push \
  "$ENDPOINT_RECORD" "$REQUEST_ID" "$ARTIFACT_SHA256" \
  "$DEPLOYMENT_SHA256" "$OUTCOME_SHA256" \
  /outside-git/protected-outcome/"$REQUEST_ID"
```

Require `status=staged` or `status=existing`. Run the complete non-mutating
target-spool importer check first:

```bash
make registry-pki-outcome-import \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256" \
  OUTCOME_SHA256="$OUTCOME_SHA256" \
  EXTRA_ARGS=--check
```

Check mode authenticates the complete package already at
`EXCHANGE_SPOOL_ROOT/outcomes/REQUEST_ID/OUTCOME_SHA256` and target public state
without package transfer or lifecycle mutation. Require `status=would-import`.

Import the exact outcome:

```bash
make registry-pki-outcome-import \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256" \
  OUTCOME_SHA256="$OUTCOME_SHA256"
```

Require `status=imported`. The role proves immutable accepted history, then asks
the facade to remove only the exact staged outcome. A second import therefore
requires repeating `outcome-push`; it returns `existing` and cleans the restaged
duplicate. The target stores immutable history under
`STATE_ROOT/outcomes/REQUEST_ID/OUTCOME_SHA256/` and atomically publishes
`STATE_ROOT/accepted-outcome`.

Read final status:

```bash
make registry-pki-status \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256"
```

For a finalized active candidate, require all of:

```text
status=complete
signer_outcome_state=finalized
evidence_state=controller-exported
required_action=none
recovery_required=false
```

`renewal_eligible=false` is expected. Authenticated renewal completion for a
host-local predecessor is not implemented.

Re-run the strict runner decision preflight and registry smoke test after outcome
import:

```bash
make registry-pki-decision-preflight \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256"
make smoke-registry ENV="$ENVIRONMENT" LIMIT="$TARGET"
```

Take the approved post-migration target/VM backup. Restore it into an isolated,
network-disabled test instance, verify the expected disks, mounts, Zot service,
registry data, and guest freeze/thaw behavior, then remove only that isolated
restore. Keep backup tooling and VM lifecycle code in their owning repositories,
not `platform-config`.

## Controller-Local Compatibility Mode

The original Ansible byte-transfer implementation remains available only by
explicit selection:

```text
registry-pki-request-controller-local
registry-pki-activate-controller-local
registry-pki-evidence-export-controller-local
registry-pki-outcome-import-controller-local
```

These targets set `pki_host_local_certificate_exchange_mode=controller-local`.
The normal target names set `direct`. Do not mix modes within one request unless
an approved recovery procedure explicitly accounts for both byte paths.

## Expected Status Transitions

| Status | Required Action | Meaning |
|---|---|---|
| `managed-migration-needed` | `create-migration-request` | Managed Zot certificate is ready for migration |
| `request-pending` | `collect-or-await-response` | Target key/request exists; no active response |
| `request-expired` | `abandon-expired-request` | Pending request expired before response acceptance |
| `response-ready` | `activate-response` | Exact response is installed and ready |
| `activated-and-validated` | `export-evidence` | Candidate is active and runner validation passed |
| `evidence-exported` | `await-signer-outcome` | Exact deployment evidence reached the controller |
| `complete` | `none` | Finalized signer outcome matches current active state |
| `signer-outcome-abandoned` | `none` | Authenticated abandonment is terminal; candidate is not active authority |
| `activation-recovery-required` | `recover-activation` | Run only journal-bound target recovery |
| `abandonment-evidence-required` | `publish-rolled-back-evidence` | Publish exact restored-predecessor evidence before signer abandonment |
| `abandonment-evidence-required` | `publish-not-activated-evidence` | Stop: no public Ansible entry point currently publishes this evidence |
| `conflict` | `resolve-conflict` | Stop and investigate; do not overwrite state |

## Target Activation Recovery

If status reports `activation-recovery-required`, invoke only exact
journal-bound recovery:

```bash
make registry-pki-recover \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256"
```

If recovery restores the predecessor and requests rolled-back evidence, validate
that predecessor locally and from the reviewed runner:

```bash
make registry-pki-publish-rolled-back-evidence \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" RUNNER_LIMIT="$RUNNER" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256"
```

Record the returned deployment digest as `DEPLOYMENT_SHA256` and export that
exact evidence:

```bash
make registry-pki-evidence-export \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" ARTIFACT_SHA256="$ARTIFACT_SHA256" \
  DEPLOYMENT_SHA256="$DEPLOYMENT_SHA256"
```

Move the resulting exact evidence directory through controlled media to the
signer, then use the digest-pinned signer abandonment command:

```bash
platform-pki csr-candidate abandon "$SERVICE" \
  --namespace "$PKI_NAMESPACE" \
  --request-id "$REQUEST_ID" \
  --artifact-manifest-sha256 "$ARTIFACT_SHA256" \
  --evidence-file /secure/evidence/"$DEPLOYMENT_SHA256"/deployment \
  --evidence-signature /secure/evidence/"$DEPLOYMENT_SHA256"/deployment.sig
```

Review and type the exact interactive confirmation. Require an authenticated
terminal decision with `action=abandon`, `result=rolled-back`, and
`state=abandoned`. Then publish, transfer, and import the terminal signer outcome
through the same digest-pinned steps. Managed-migration rollback is supported;
host-local predecessor abandonment remains fail-closed.

If status instead requires `publish-not-activated-evidence`, stop. The lifecycle
schema and outcome importer recognize that state, but this repository currently
has no public Ansible entry point that can create and publish the required signed
target evidence. Do not construct it manually or finalize signer abandonment
without that implemented boundary.

## Signer Recovery

For interrupted signing, recover the exact journaled transaction:

```bash
platform-pki csr-recover \
  --namespace "$PKI_NAMESPACE" \
  --transaction "csr-$REQUEST_ID" \
  --response-key /secure/offline-response
```

Omit `--response-key` only when the journaled response signature already exists.
For interrupted candidate finalization, use resume-only recovery:

```bash
platform-pki csr-recover --namespace "$PKI_NAMESPACE"
```

Never delete a signer journal to make another command run.

## Expired Or Cancelled Requests

Abandon one exact expired request only when no response or consumer state exists:

```bash
make registry-pki-abandon-expired-request \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" REQUEST_ID="$REQUEST_ID"
```

Cancel an unexpired pending request only with both exact coordinates:

```bash
make registry-pki-cancel-request \
  ENV="$ENVIRONMENT" LIMIT="$TARGET" \
  REQUEST_ID="$REQUEST_ID" REQUEST_SHA256="$REQUEST_SHA256"
```

Neither operation changes Zot's active TLS paths.

## Retained Stage Recovery

If outcome import reports a retained `/var/tmp/.platform-pki-outcome-*` stage or
target `.accepted-outcome-stage-*`, stop. Preserve the reported canonical path,
confirm no import process remains active, and attribute the exact stage through
the approved recovery process. Remove only that exact identity after review.
Never use a glob or broad temporary-directory cleanup.

If immutable outcome history exists without `accepted-outcome`, status fails
closed. Rerun the importer with the same package and all four exact coordinates;
the no-clobber importer authenticates existing history and completes pointer
publication.

## Retention And Backup

Retain at least:

- Signer replay, transaction, candidate, response, export, retained trust,
  decision, outcome, and accepted history.
- Controller request, frozen trust, response, evidence, and outcome packages.
- Target pending/version, active, rollback, evidence, outcome, accepted pointer,
  and any recovery journal state.
- The managed predecessor and its rollback material for the approved hold.
- Encrypted signer backups and approved target/VM backups with restore evidence.

Expiry of a rollback hold permits a separate review; it does not authorize
cleanup.

## Local Repository Verification

These repositories do not currently rely on CI for this workflow. Before
publishing changes to these boundaries, run the repository-supported local
checks.

For `platform-tools` signer-outcome changes:

```bash
./scripts/in-test-container make test-pki-csr-outcome
./scripts/in-test-container make test-platform-pki-publication
./scripts/in-test-container python3 -m pytest tests/test_platform_pki_parser.py
./scripts/in-test-container make verify
git diff --check
```

For `platform-config` host-local PKI changes:

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

Live acceptance additionally requires exact check-mode outcome preflight,
idempotent outcome import, terminal status, post-import decision preflight,
registry smoke, and isolated backup restore validation.
