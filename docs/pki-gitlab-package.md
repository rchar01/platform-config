# GitLab PKI Package Exchange

`platform-pki gitlab-package` from `platform-tools` publishes and downloads exact host-local
PKI Generic Packages. It implements transport only. It does not collect from a
target, approve or sign a request, activate a certificate, decide a candidate,
or treat GitLab as PKI authority.

The canonical package contract is the
[`platform-tools` GitLab package exchange guide](https://codeberg.org/rch/platform-tools/src/branch/main/docs/pki-gitlab-package-exchange.md).
Stop if that contract and this integration guide disagree.

Complete [PKI Exchange Setup](pki-exchange-setup.md) before using this helper.
That guide owns transfer-station paths, project controls, credential separation,
target SSH preparation, offline storage, and optional runner setup.
The [Same-Workstation PKI Layout](pki-local-layout.md) is authoritative for the
active roots, exact-service workspaces, stable key domains, and retired paths.

## Package Families

Every package name is `pki-exchange-<stage>-<service>`. The caller supplies the
exact full version; the helper never scans for newest or a neighboring attempt.
Actor or job names must not be added to package names. They describe custody,
not authority: consumers authenticate the canonical payload, exact stage,
detached signatures, frozen trust, and lifecycle coordinates.

| Stage | Exact version | Producer or signer | Publisher | Payload order before `stage-manifest` |
| --- | --- | --- | --- | --- |
| `request` | `<request-id>` | Target produces request; controller produces receipt | Dedicated GitLab publisher | `tls.csr`, `request`, `request.sig`, `collection-receipt` |
| `approval` | `<request-id>-<sha256(approval)>` | Offline approver | Dedicated GitLab publisher | `approval`, `approval.sig` |
| `response` | `<request-id>` | Offline signer | Dedicated GitLab publisher | `artifact`, `tls.crt`, `ca-chain.crt`, `fullchain.crt`, `response`, `response.sig` |
| `evidence` | `<request-id>-<sha256(deployment)>` | Target derives evidence from the runner's unsigned observation and signs both records | Dedicated GitLab publisher | `deployment`, `deployment.sig`, `validation-boundary`, `validation-result`, `validation-result.sig` |
| `outcome` | `<request-id>-<sha256(outcome)>` | Offline signer | Dedicated GitLab publisher | `outcome`, `outcome.sig`, `deployment`, `deployment.sig`, `deployers.allowed_signers`, `decision` |

The approval suffix comes from `offline-csr approve` JSON field
`approval_sha256`; the evidence suffix is the successful activation's exact
deployment-file digest; and the outcome suffix comes from `csr-outcome publish`
JSON field `manifest_sha256`, which is the exact canonical `outcome` digest.
Certificate export's `manifest_sha256` is the exact canonical `artifact` digest,
not a GitLab `stage-manifest` digest. Do not manually infer these values when the
producer reports them.

Publish source directories contain payload only. The helper validates the exact
allowlist, builds the canonical `stage-manifest`, and uploads it last. Download
destinations contain payload plus the downloaded and validated manifest.

Source directories, existing destination directories, and destination parents
must be canonical absolute outside-Git paths owned by the invoking user with
mode `0700`. Files must be current-user-owned, singly linked regular files with
mode `0600`. Unsafe metadata, links, hidden files, alternate names, nested
paths, private-key extras, and size-limit violations fail closed.

## Validation

All stages require canonical ordered records, the exact service, target,
request ID, package version, payload order, and payload digests. The helper also
checks these stage-specific bindings:

- Approval lifetime, operation, profile, identities, digest fields, and SSH
  signature container.
- Response and artifact fields, exact response/signature/certificate/chain
  digests, certificate SPKI, exact `fullchain.crt` construction, states,
  issuer generations, and SSH signature container.
- Evidence deployment, validation-boundary, and validation-result coordinates
  and cross-bindings, digest-suffixed version, and both target-host SSH signature
  containers. The runner observation consumed by the target is unsigned and is
  not a package payload.
- Outcome, deployment, and decision coordinates and cross-bindings, exact
  deployment/signature/deployer-trust/decision digests, canonical deployer
  trust, terminal state, digest-suffixed version, and SSH signature containers.

Request transport retains the stronger existing validation. In addition to the
payload directory, it requires a protected reviewed inventory record, exact
five-file frozen trust directory, and enrolled transport host-key digest. It
validates the request, receipt, schema-2 policy, CSR profile and SPKI, inventory
CN/SANs, lifetimes, trust digests, and detached request signature
cryptographically. These inputs are rechecked during HTTP operations.

Non-request signature containers and record cross-bindings are structural
transport admission checks. Canonical offline/target/signer commands remain
responsible for authoritative signature, trust, freshness, replay, certificate,
deployment, and lifecycle decisions.

## Protected Configuration

The project record is current-user-owned, singly linked, mode `0400` or `0600`,
outside Git, and has this exact schema:

```text
schema=1
kind=pki-exchange-project
origin=https://gitlab.example.test
project_id=123
project_path=platform/pki-exchange
gitlab_version=18.11.3-ce.0
```

The helper binds the live project `id`, `path_with_namespace`, and `web_url` to
that record before package access. It supports `job`, `private`, and `deploy`
token header types for generic operations; the compatibility publisher supports
`job` and `private`. Token bytes come only from a protected mode-`0400` or
mode-`0600` file and never enter argv, URLs, payloads, or output. The reviewed CA
bundle is also descriptor-pinned.

Every operation first authenticates `GET /api/v4/projects/:id`. GitLab 18.11's
Generic Packages documentation explicitly supports a project access token with
`api` scope and Developer role. Use that documented configuration for the
default external reader (`--token-type private`) unless the complete helper has
qualified a narrower token against the exact target version. This credential is
not inherently read-only. The helper itself permits only GET requests in reader
operations, but the credential can be used outside the helper to call broader
APIs. Role-based package protection cannot deny publication to this Developer
reader while allowing a Developer publisher; it may still impose a higher
deletion threshold. Treat this as a qualification blocker unless the narrower
`read_api` scope passes complete exact-version runtime tests or the credential
design changes. A deploy token with only `read_package_registry` cannot
authenticate the Projects API.

The helper does not inspect or configure package protection, duplicate policy,
cleanup, membership, token scopes, or project settings. Independently require
self-managed GitLab CE `18.11.3-ce.0`, one private exchange project, disabled
Generic duplicate publication and cleanup, protected `pki-exchange-*` packages,
and credentials without package deletion or settings authority.

## Publish

Before invoking a publisher, hold an external lock keyed exactly as
`<project-id>:<stage>:<service>:<full-package-version>`. The operator lock
procedure must retain exclusive custody through final coordinate reinspection
and stop on stale or ambiguous ownership; the helper provides no lock command.
Protected GitLab CI uses:

```yaml
resource_group: "${CI_PROJECT_ID}:${PKI_STAGE}:${PKI_SERVICE}:${PKI_PACKAGE_VERSION}"
```

This template publishes one exact approval attempt:

**Actor:** GitLab publisher. **Run on:** Authorized online transfer station or
protected CI. **Prerequisite:** Exact payload-only source, publisher credential,
project/CA records, and held exact-coordinate external lock. **Output/provenance:**
Exact package plus helper-generated `stage-manifest`. **Idempotent retry/result:**
Matching manifest-absent partial resumes and complete exact package succeeds;
conflicts are retained. **Next actor:** GitLab retriever named by the canonical
lifecycle stage.

```bash
platform-pki gitlab-package publish \
  --stage approval \
  --service registry-dev-01 \
  --target dev-registry-01 \
  --request-id 0123456789abcdef0123456789abcdef \
  --package-version 0123456789abcdef0123456789abcdef-<approval-sha256> \
  --source-dir /outside-git/pki-exchange/approval-attempt \
  --project-record /outside-git/config/pki-exchange-project \
  --token-type private \
  --token-file /outside-git/secrets/pki-exchange-publisher.token \
  --ca-file /outside-git/trust/gitlab-ca.crt
```

For `--stage request`, also supply:

```text
--inventory-record /outside-git/config/registry-dev-request-inventory
--trust-dir /outside-git/pki-exchange/frozen-trust
--transport-host-key-sha256 <64-lowercase-hex>
```

The helper enumerates every page for all six GitLab 18.11 package statuses and
accepts only an absent coordinate or exactly one `default` package. A matching
manifest-absent partial resumes in canonical order. A complete matching package
is idempotent. Manifest-present partials, blocked/ambiguous statuses, extra or
duplicate files, and digest conflicts are retained and rejected without
deletion or repair.

`publish-request` remains as a compatibility command for the original
`<exchange-root>/<service>/<request-id>/{request,trust}` workspace. It requires
the existing request directory to include a prebuilt canonical manifest and
applies the same full request validation. New integrations should use generic
`publish` with a payload-only `--source-dir`.

## Download

This template downloads one exact response coordinate:

**Actor:** GitLab retriever. **Run on:** Authorized online retrieval station.
**Prerequisite:** Operator-supplied exact coordinate, reader credential, and
project/CA records. **Output/provenance:** Validated payload plus
`stage-manifest` at the exact destination. **Idempotent retry/result:** Exact
existing destination succeeds; conflicts remain untouched and fail. **Next
actor:** Lifecycle actor named by the canonical workflow.

```bash
platform-pki gitlab-package download \
  --stage response \
  --service registry-dev-01 \
  --target dev-registry-01 \
  --request-id 0123456789abcdef0123456789abcdef \
  --package-version 0123456789abcdef0123456789abcdef \
  --destination-dir /outside-git/pki-exchange/downloaded-response \
  --project-record /outside-git/config/pki-exchange-project \
  --token-type private \
  --token-file /outside-git/secrets/pki-exchange-read.token \
  --ca-file /outside-git/trust/gitlab-ca.crt
```

The destination parent must already exist with mode `0700`. The helper requires
one complete exact package, downloads every file through bounded GETs, compares
locally computed SHA-256 with package-file API metadata, validates the manifest
and stage, then reinspects the exact coordinate. It publishes a same-parent
mode-`0700` transport directory with mode-`0600` files using Linux atomic
no-clobber rename. An exact existing destination is idempotent; any conflict is
left untouched and fails.

Redirects, changed origins, malformed pagination, uncertain HTTP results,
coordinate mutation, and over-limit responses fail closed. No operation uses
`DELETE` or fuzzy/newest selection.

Transport downloads may live under the controller exchange root. Before
response check, `response-push`, or `outcome-push`, materialize only the exact
payload allowlist into the protected exact-service offline workspace using the
single canonical
[No-Clobber Materialization](registry-host-local-pki-workflow.md#canonical-no-clobber-materialization)
procedure. [PKI Exchange Setup](pki-exchange-setup.md#transfer-station-layout)
defines the immutable request, approval, signer-input, response, evidence, and
outcome destinations beneath `OFFLINE_WORKSPACE`. `pki-transfer` is retired for
same-workstation operation. Do not use an overwrite-capable copy or `install`
loop. Response check rejects a source that contains or is contained by its
controller exchange root.

## Remaining Gates

The `platform-tools` `make test-pki-gitlab-package` fake HTTPS tests cover every
family in both directions, manifest-last upload, partial resume, exact
idempotency, conflicts, extras, malformed manifests, download mutation,
redirects, and token redaction. They do not qualify live GitLab behavior.
Before production use, still require:

- protected CI `resource_group` serialization using the exact coordinate shape
  above, or the equivalent reviewed operator lock;
- disposable runtime qualification against exact GitLab `18.11.3-ce.0`;
- reviewed private inventory, trust, credentials, project controls, and token
  scopes;
- controlled-media custody procedures and canonical offline protocol checks;
- separate authorization for publication, retrieval, signing, activation,
  decision, outcome handling, and every live mutation.

The command examples are inert templates, not authorization to contact a live
GitLab instance or operate a real PKI lifecycle.
