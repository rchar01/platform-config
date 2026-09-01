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
- Inventory selects direct target-to-GitLab package transport or issue-only
  target-local filesystem exchange. Ansible never carries package bytes.
- Ansible activation does not accept request IDs, digests, package versions, or
  exchange directories. The request route returns one authenticated request ID
  for the separately authorized offline stages.
- GitLab CE `18.11.3-ce.0` live token and package behavior must pass its explicit
  rollout gate before GitLab transport is used.

## Request

Run the request route:

```bash
make registry-pki-request-publish ENV=dev LIMIT=<one-host> [REQUEST_TTL_SECONDS=1..604800]
```

Square brackets denote the optional TTL assignment and are not literal shell
syntax. The default request lifetime is 3600 seconds. The route validates and
installs the schema-3 trust snapshot, creates or revalidates the target-local key
and schema-2 request. GitLab mode publishes directly from the target; filesystem
mode exports to the fixed request directory owned by the pre-provisioned transfer
UID. The request payload is exactly `tls.csr`, `request`, and `request.sig`.
Only GitLab adds `stage-manifest` transport metadata.

On success, the route reports only the authenticated 32-hex `request_id` outside
the protected publication task. Record that exact value for the offline handoff;
do not derive or substitute a package coordinate.

For `issue`, a fresh registry starts with empty controller TLS sources and Zot
in derived dormant custody. For `renew`, the route derives the predecessor from
authenticated active target state.

## Offline Gate

After request publication, stop the Ansible workflow and separately authorize
offline approval and signing. GitLab mode uses `platform-pki gitlab-package` for
the request, approval, and response stages. In filesystem mode, retrieve exactly
`tls.csr`, `request`, and `request.sig`; authenticate and sign them using the
separately controlled offline process; then upload exactly the six response files
below as mode `0600` to the pre-created response directory. Carry the exact
request ID returned by the request route through either handoff. Signer private
key custody remains outside these Ansible routes.

The approval payload is exactly `approval` and `approval.sig`. The response
payload must be exactly `artifact`, `tls.crt`, `ca-chain.crt`, `fullchain.crt`,
`response`, and `response.sig`. Each stage adds a schema-2 `stage-manifest` as
transport metadata in GitLab mode only. Filesystem mode has no stage manifest.
The schema-2 response `artifact` has no candidate or deployment state fields.

## Activate

After GitLab response publication or completion of the filesystem upload:

```bash
make registry-pki-response-activate ENV=dev LIMIT=<one-host>
```

The route derives the request and response coordinates from authenticated target
state. If target status requires recovery, it recovers the activation journal
before transport. It then downloads the response directly from GitLab or imports
the exact filesystem response into protected target-local ingress, authenticates
it before mutation, activates and validates Zot locally, and rolls back on
failure. A successful route requires final
`status=complete` and `required_action=none`.

Run the external registry smoke check separately when required:

```bash
make smoke-registry ENV=dev
```

The smoke check does not participate in activation validation or rollback.

## Rejected State

There is no public migrate, reset, cancellation, status, direct/controller-local,
Ansible-provisioned SSH/SFTP access, controller intake/check/transfer, runner, evidence,
deployment, validation-result, or outcome route. Helper-hash predecessor
migration is also unsupported.

Old or ambiguous lifecycle state is rejected. Preserve it for review; reset or
recreate the target only under separate authorization before beginning this
workflow.

An expired pending request is preserved and reported as `status=request-expired`,
`request_id=none`, and `required_action=reset-required`. No route exposes its
coordinates or removes it.
