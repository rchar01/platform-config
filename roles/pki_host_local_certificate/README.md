# pki_host_local_certificate

Defines the fail-closed, operator-only target/controller/runner orchestration for
one host-local Zot certificate lifecycle. Normal convergence does not import
this role or any `registry-pki-*.yml` playbook.

## Entry Points

Use only these structural playbooks:

- `registry-pki-validation-material.yml` invokes the separate
  `pki_host_local_validation_material` role to provision the reviewed CA and
  validation boundary on one exact target and one distinct runner. The
  certificate lifecycle role does not import that prerequisite role.
- `registry-pki-trust.yml` bootstraps the exact reviewed five-file target trust.
- `registry-pki-request.yml` creates or validates a target-local request and,
  outside check mode, collects only `tls.csr`, `request`, and `request.sig` into
  the protected controller exchange.
- `registry-pki-abandon-expired-request.yml` removes only one exact authenticated
  expired pending request. It refuses unexpired requests and any response,
  version, active, evidence, or unresolved journal state for that request.
- `registry-pki-cancel-request.yml` removes one exact authenticated pending
  request only when both its request ID and request SHA-256 match. It has the
  same response, version, active, evidence, and journal refusal boundaries.
- `registry-pki-status.yml` reads and strictly validates lifecycle status.
- `registry-pki-response-check.yml` authenticates one exact external signer
  response entirely on the controller and publishes its immutable controller
  snapshot. It does not contact Zot or mutate the target.
- `registry-pki-activate.yml` prepares and installs the response, shows the
  exact activation candidate, requires an exact interactive confirmation,
  activates locally, validates Zot from one distinct reviewed runner, and
  publishes signed target evidence.
- `registry-pki-recover.yml` explicitly performs only the recovery encoded by
  the lifecycle journal and then reads status.
- `registry-pki-evidence-export.yml` collects one exact authenticated target
  evidence attempt into the controller exchange.
- `registry-pki-decision-preflight.yml` binds controller-exported evidence to
  current target status and a fresh read-only runner observation.
- `registry-pki-outcome-import.yml` authenticates one exact six-file terminal
  signer package on the controller and target, then publishes immutable target
  history and its accepted pointer.

Trust, request, expired-request abandonment, activation, and recovery remain
explicit operator actions. Request lifetime defaults to 3600 seconds and may be
overridden for one invocation with `REQUEST_TTL_SECONDS`, up to the schema-2
policy maximum of 604800 seconds.

Migration requests bind the canonical first leaf certificate from the current
Zot certificate file. Zot may serve a concatenated fullchain, but the digest in
`current_cert_sha256` remains the signer-managed leaf certificate digest used
by CSR history and candidate finalization.
Renewal, archive cleanup, and live inventory enablement remain outside this role.

## Fixed Helpers

The target lifecycle helper is installed only as
`/usr/local/libexec/platform-pki-host-local-lifecycle`. The read-only runner
validator is installed only as
`/usr/local/libexec/platform-pki-zot-read-only-validate`. Check mode never
installs either helper and requires reviewed root-owned mode-`0755` copies to
already exist.

Mutable lifecycle phases install the distribution `python3-cryptography`
package required by the lifecycle helper. Read-only and check-mode phases do
not install packages; run a mutable request or activation phase first.

The request and trust phases retain their dedicated existing helpers. Private
keys remain on the target. Do not add `fetch`, `slurp`, facts, debug output, or
controller-side copy operations that handle `tls.key`.

## Frozen Inputs

All operational values default to inert empty strings, empty mappings, zeroes,
or `false`, except fixed helper and namespace paths. An operator must supply the
exact request, artifact, response-file digest mapping, validation boundary,
reviewed CA, endpoint, runner, lifetime, rollback, and phase bindings required
by the selected entry point.

For `service: registry-dev`, the only accepted target roots are:

```yaml
pki_host_local_certificate_state_root: /var/lib/platform-config/pki/host-local/registry-dev
pki_host_local_certificate_pending_root: /etc/zot/tls-pending
pki_host_local_certificate_versions_root: /etc/zot/tls-versions
```

Other service names retain canonical disjoint-root flexibility for synthetic
tests. Lifecycle paths reject `latest` and `current` components. The fixed Zot
configuration path is `/etc/zot/config.json`.

Request collection additionally requires the exact five reviewed controller
trust sources. Each source basename must equal its trust mapping key:

```yaml
pki_host_local_certificate_trust_sources:
  policy: /outside-git/reviewed-trust/policy
  requesters.allowed_signers: /outside-git/reviewed-trust/requesters.allowed_signers
  approvers.allowed_signers: /outside-git/reviewed-trust/approvers.allowed_signers
  responses.allowed_signers: /outside-git/reviewed-trust/responses.allowed_signers
  deployers.allowed_signers: /outside-git/reviewed-trust/deployers.allowed_signers
```

Response ingress accepts only the reviewed artifact SHA-256 pin. The fixed
action derives and returns the exact six-key digest map for `artifact`,
`tls.crt`, `ca-chain.crt`, `fullchain.crt`, `response`, and `response.sig`; the
role validates every derived digest and requires the artifact entry to equal
`pki_host_local_certificate_artifact_manifest_sha256`.

Status, evidence export, and decision preflight never create or update helper
files. They require exact existing mode-`0755` lifecycle or validator helpers,
including in check mode. When status receives a deployment digest, it first
authenticates that exact controller evidence publication with
`platform_pki_evidence_status`; only verified final/activated evidence permits
the controller-exported flag to reach target status. Status does not contact
controller evidence when the deployment digest is empty.

Outcome import reuses the installed lifecycle helper, response principal,
controller-frozen response/deployer trust, and target-frozen trust. It accepts no
key or new trust input. The source is one absolute mode-`0700` current-user
directory containing exactly the six upstream files at mode `0600` with one link
each. In normal mode the action transfers only those bytes through a randomized
root-owned mode-`0700` stage, marks the byte-bearing task `no_log`, and requires
exact cleanup before returning. Check mode completes controller authentication
and rechecks first, then invokes only the read-only scalar target preflight
through Ansible's safely quoted, become-aware low-level connection path. It does
not execute an Ansible module and creates no AnsiballZ payload, stage, or Ansible
temporary transfer path.

The importer never stats, opens, reads, hashes, stages, or transfers a candidate,
version, or restored managed private-key file. Managed rollback validation parses
the restored Zot config's canonical TLS path object but accesses only its selected
public certificate chain. Scalar preflight authenticates active state through
named public version files, retained signed request material when available,
the signed response, artifact and certificate chain, and matching signed target
evidence. It never enumerates the version directory or accesses its private key.
Other target binding comes from signed public outcome/deployment records and
authenticated rollback records.

The target stores immutable packages under
`STATE_ROOT/outcomes/REQUEST_ID/OUTCOME_SHA256/` and publishes
`STATE_ROOT/accepted-outcome` only after target reauthentication. Exact reruns
are no-ops and conflicts fail. Status remains `evidence-exported` while the
pointer is absent, becomes `complete` only for a finalized outcome matching the
current active identity, and reports `signer-outcome-abandoned` for authenticated
abandonment with no predecessor, or authenticated managed-migration rollback,
without claiming that candidate active.
Finalized managed predecessors are bound exactly to rollback certificate/SPKI
records and require all unavailable managed history fields to be `none`.
Host-local predecessor outcomes fail closed because rollback records do not yet
carry authenticated predecessor intermediate, response, deployment, and decision
digests. Managed-migration rollback is the supported exception: signed rollback
evidence and the restored Zot-selected public certificate chain prove its managed
predecessor. Other abandonment with a non-empty predecessor fails closed because
its candidate rollback record is no longer present after terminal abandonment.
Historical outcomes never
replace target active state as live authority. `renewal_eligible` remains
`false`; authenticated renewal completion is not implemented by this workflow.
An interruption may leave validated history without the pointer; status then
fails closed and an exact rerun with the same coordinates completes no-clobber
pointer publication. A protected remote stage is removed before the action
returns. If identity or cleanup verification prevents safe removal, the action
fails, reports the retained canonical stage, and leaves it as evidence for
explicit operator inspection rather than deleting an unattributable path. A
retained `.accepted-outcome-stage-*` blocks further imports as ambiguous state
until exact-path operator recovery.

## Activation Boundary

Activation requires exactly one registry play target and one distinct inventory
host named by `pki_host_local_certificate_remote_validator`. The reviewed CA and
validation boundary must already exist at their exact target and runner paths;
this lifecycle role never distributes them. Provision those public prerequisites
separately with `make registry-pki-validation-material ENV=... LIMIT=...`
`RUNNER_LIMIT=...` after reviewing and pinning both controller sources. The CA
source is exactly the profiled intermediate followed by its self-signed root;
extra, reversed, unrelated, or incorrectly profiled certificates are rejected.

Before mutation, `activate-start --check` must return the exact candidate. The
operator must then type exactly:

```text
activate SERVICE REQUEST_ID ARTIFACT_SHA256
```

There is no noninteractive override. After local activation, the runner emits
one canonical public observation. Only those bytes are copied under the
root-owned mode-`0700` `/run/platform-pki-host-local/` directory as
`REQUEST_ID.observation` with mode `0600`; the file is removed in `always`. Any
ordinary failure after `activate-start` dispatches
the helper's exact `recover` action, and recovery failure is not ignored.

In Ansible check mode activation runs helper `--check` preflights only. It does
not transfer a response, prompt, restart Zot, invoke the network validator, copy
an observation, or clean up target state.

Zot must reference the immutable version files under
`/etc/zot/tls-versions/REQUEST_ID/`. Its certificate path is
`fullchain.crt`, not the leaf-only `tls.crt`.

## Decision Boundary

Decision preflight supplies the exact exported deployment digest to status, so
the lifecycle helper must authenticate matching target evidence and report
`evidence-exported`. The delegated runner then validates the exact active leaf,
expected served intermediate, reviewed boundary, reviewed CA digest, and HTTPS
`/v2/` endpoint. The canonical observation must be no more than 300 seconds
from the controller observation time. No observation file is copied and no Zot
state is changed. A successful run emits only a safe assertion summary binding
service, target, request, artifact, deployment, observed epoch, the exact
observed-plus-300 expiry epoch, and `result=passed`.

Status, response check, activation finish, recovery, and evidence export also
emit safe `ansible.builtin.assert` success summaries after their existing exact
metadata validation passes. Status exposes the helper's compact public JSON;
the other summaries contain only public lifecycle coordinates, certificate
digests, approved response/evidence directories, action/result labels, and
authenticated lifecycle status. They never expose key paths or bytes, trust
contents, or certificate and signature contents.
