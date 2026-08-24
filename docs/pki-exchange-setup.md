# PKI Exchange Setup

Prepare one registry target and one private GitLab Generic Package project for
the [Host-Local Registry PKI Workflow](registry-host-local-pki-workflow.md).
This setup authorizes no request, signing operation, activation, reset, or live
rollout.

## Architecture

The target connects directly to GitLab over authenticated HTTPS:

```text
registry target <---- authenticated HTTPS ----> private GitLab project
       ^
       |
       `---- Ansible installs public configuration and invokes fixed routes
```

Request and response package bytes never pass through Ansible or a controller
workspace. There is no direct/controller-local mode, SSH exchange endpoint,
transfer station, controller intake/check/transfer route, runner, or separate
evidence/outcome package flow.

Offline approval and signing remain outside these Ansible routes. The external
process consumes the published request package, publishes the signed approval
package, and publishes the authenticated response package to the same private
project through the `platform-pki gitlab-package` route. Use its separately
reviewed procedure; this repository does not establish an exact signer command.

## GitLab Project

Create and review exactly one private Generic Package project for this exchange.
Private configuration must reference its reviewed project record and the CA
bundle that authenticates its HTTPS certificate. Keep both outside public Git.
Disable unreviewed membership, package deletion, cleanup, duplicate publication,
and unrelated automation according to the approved project policy.

The target routes derive package names, versions, request IDs, and digests from
authenticated target state. Target-local Ansible routes do not accept package
coordinates or download directories. Successful request publication reports one
authenticated request ID, which the operator carries through the separately
authorized offline request, approval, signing, and response stages.

Self-managed GitLab CE `18.11.3-ce.0` live behavior is not qualified by local
tests or documentation. Exact-version token authentication, project access,
Generic Package publication/download, duplicate handling, partial publication,
and deletion/cleanup controls remain an explicit, unqualified rollout gate.
Do not use a live PKI route until that gate is approved.

## Target Token

Provision the GitLab token directly on the target through the approved secret
deployment process. The configured token path defaults to:

```text
/etc/platform-config/pki-gitlab-token
```

The file must be:

- owned by `root:root`;
- a regular file, not a symlink;
- singly linked (`nlink=1`);
- mode `0600`;
- from 1 through 4096 bytes.

Do not put token bytes in inventory, vars, facts, templates, Git, shell argv,
environment variables, logs, or command output. Ansible uses `stat` under
`no_log` to validate metadata only. It does not copy or read token content. The
target helper opens the pre-provisioned file directly when contacting GitLab.

## Public Inputs

Private inventory references reviewed outside-Git sources for:

- the GitLab project record;
- the GitLab HTTPS CA bundle;
- the target-installed `platform-pki` transport client and its reviewed SHA-256;
- the schema-3 trust files and their SHA-256 digests;
- the reviewed CA used for strict local Zot validation.

Target trust contains exactly:

```text
approvers.allowed_signers
policy
requesters.allowed_signers
responses.allowed_signers
```

Each trust source basename must match its mapping key. The trust `policy` uses
schema 3. Request and response records use schema 2.

Example variable shape, using sanitized paths only:

```yaml
pki_host_local_certificate_gitlab_project_record_source: /outside-git/pki/gitlab-project
pki_host_local_certificate_gitlab_ca_source: /outside-git/pki/gitlab-ca.crt
pki_host_local_certificate_platform_pki_source: /outside-git/bin/platform-pki
pki_host_local_certificate_platform_pki_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
pki_host_local_certificate_gitlab_token_path: /etc/platform-config/pki-gitlab-token

pki_host_local_certificate_trust_sources:
  approvers.allowed_signers: /outside-git/pki/trust/approvers.allowed_signers
  policy: /outside-git/pki/trust/policy
  requesters.allowed_signers: /outside-git/pki/trust/requesters.allowed_signers
  responses.allowed_signers: /outside-git/pki/trust/responses.allowed_signers
```

The transport-client source must be outside the public repository, owned by the
controller user, mode `0600`, singly linked, and no larger than 8 MiB. The role
pins its descriptor and reviewed digest throughout transfer, copies the project
record, CA bundle, and reviewed public trust, and never copies the token or target
leaf private key.

## Package Contract

The request package payload is exactly:

```text
tls.csr
request
request.sig
```

The approval package payload is exactly:

```text
approval
approval.sig
```

The response package payload is exactly:

```text
artifact
tls.crt
ca-chain.crt
fullchain.crt
response
response.sig
```

Each package has a schema-2 `stage-manifest` generated and validated as transport
metadata. It is not a signed PKI payload and does not replace request, approval,
or response authentication. The response `artifact` is schema 2 and contains no
candidate or deployment state fields.

## State Gate

Only `issue` and `renew` are supported. Do not reuse lifecycle state from the
retired SSH, controller-local, migration, runner/evidence/outcome, five-file
trust, or helper-hash predecessor workflows. The new routes reject old or
ambiguous state. Preserve such state for review and use only a separately
authorized reset or target recreation.
