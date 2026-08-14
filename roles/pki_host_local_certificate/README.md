# pki_host_local_certificate

Defines the fail-closed, operator-only target/controller/runner orchestration for
one host-local Zot certificate lifecycle. Normal convergence does not import
this role or any `registry-pki-*.yml` playbook.

## Entry Points

Use only these structural playbooks:

- `registry-pki-trust.yml` bootstraps the exact reviewed five-file target trust.
- `registry-pki-request.yml` creates or validates a target-local request and,
  outside check mode, collects only `tls.csr`, `request`, and `request.sig` into
  the protected controller exchange.
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

Trust, request, activation, and recovery remain explicit operator actions.
Signer outcome import, completion, renewal, archive handling, and live inventory
enablement are intentionally outside this role.

## Fixed Helpers

The target lifecycle helper is installed only as
`/usr/local/libexec/platform-pki-host-local-lifecycle`. The read-only runner
validator is installed only as
`/usr/local/libexec/platform-pki-zot-read-only-validate`. Check mode never
installs either helper and requires reviewed root-owned mode-`0755` copies to
already exist.

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

## Activation Boundary

Activation requires exactly one registry play target and one distinct inventory
host named by `pki_host_local_certificate_remote_validator`. The reviewed CA and
validation boundary must already exist at their exact target and runner paths;
the role never distributes them.

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
