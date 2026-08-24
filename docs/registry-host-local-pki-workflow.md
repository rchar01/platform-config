# Host-Local Registry PKI Workflow

This is the canonical operator workflow for one Zot registry target. Complete
[PKI Exchange Setup](pki-exchange-setup.md) first. Real inventory, trust policy,
project records, CA files, and secrets remain outside public Git.

## Invariants

- `LIMIT` selects exactly one registry host.
- The target leaf private key never leaves that host.
- Only `issue` and `renew` are supported.
- Request, approval, response, transport-manifest, and host-local lifecycle
  records use schema 2.
- Target trust uses schema 3 and exactly four files:
  `approvers.allowed_signers`, `policy`, `requesters.allowed_signers`, and
  `responses.allowed_signers`.
- The target exchanges package bytes directly with one private GitLab Generic
  Package project. Ansible never carries package bytes.
- Ansible activation does not accept request IDs, digests, package versions, or
  exchange directories. The request route returns one authenticated request ID
  for the separately authorized offline stages.
- GitLab CE `18.11.3-ce.0` live token and package behavior must pass its explicit
  rollout gate before use.

## Request

Run the request route:

```bash
make registry-pki-request-publish ENV=dev LIMIT=<one-host> [REQUEST_TTL_SECONDS=1..604800]
```

Square brackets denote the optional TTL assignment and are not literal shell
syntax. The default request lifetime is 3600 seconds. The route validates and
installs the schema-3 trust snapshot, creates or revalidates the target-local key
and schema-2 request, and has the target publish the package directly to GitLab.
The request payload is exactly `tls.csr`, `request`, and `request.sig`;
`stage-manifest` is transport metadata.

On success, the route reports only the authenticated 32-hex `request_id` outside
the protected publication task. Record that exact value for the offline handoff;
do not derive or substitute a package coordinate.

For `issue`, a fresh registry starts with empty controller TLS sources and Zot
in derived dormant custody. For `renew`, the route derives the predecessor from
authenticated active target state.

## Offline Gate

After request publication, stop the Ansible workflow. Separately authorize the
offline approval/signing process. That process authenticates the request, uses
`platform-pki gitlab-package` to publish the signed approval stage, issues the
certificate, and publishes the response stage to the same private GitLab
project. Carry the exact request ID returned by the request route through those
offline stages. Their remaining commands and private-key custody are outside
these Ansible routes and are not defined here.

The approval payload is exactly `approval` and `approval.sig`. The response
payload must be exactly `artifact`, `tls.crt`, `ca-chain.crt`, `fullchain.crt`,
`response`, and `response.sig`. Each stage adds a schema-2 `stage-manifest` as
transport metadata. The schema-2 response `artifact` has no candidate or
deployment state fields.

## Activate

After the separately authorized response publication:

```bash
make registry-pki-response-activate ENV=dev LIMIT=<one-host>
```

The route derives the request and response coordinates from authenticated target
state. If target status requires recovery, it recovers the activation journal
before attempting GitLab transport. It then downloads the response directly on
the target, authenticates it before mutation, activates and validates Zot
locally, and rolls back on failure. A successful route requires final
`status=complete` and `required_action=none`.

Run the external registry smoke check separately when required:

```bash
make smoke-registry ENV=dev
```

The smoke check does not participate in activation validation or rollback.

## Rejected State

There is no public migrate, reset, cancellation, status, direct/controller-local,
SSH exchange/access, controller intake/check/transfer, runner, evidence,
deployment, validation-result, or outcome route. Helper-hash predecessor
migration is also unsupported.

Old or ambiguous lifecycle state is rejected. Preserve it for review; reset or
recreate the target only under separate authorization before beginning this
workflow.

An expired pending request is preserved and reported as `status=request-expired`,
`request_id=none`, and `required_action=reset-required`. No route exposes its
coordinates or removes it.
