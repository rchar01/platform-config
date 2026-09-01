# PKI Exchange Setup

Prepare target-local GitLab or filesystem transport for a host-local certificate
lifecycle. This setup authorizes no request, signing operation, activation,
reset, or live rollout.

## Architecture

GitLab mode connects the target directly to GitLab over authenticated HTTPS:

```text
registry target <---- authenticated HTTPS ----> private GitLab project
       ^
       |
       `---- Ansible installs public configuration and invokes fixed routes
```

Filesystem mode uses a fixed target-local exchange tree:

```text
operator -- approved SFTP path --> target filesystem exchange
                                      ^
                                      |
               Ansible creates fixed directories and invokes lifecycle helpers
```

Request and response bytes never pass through Ansible or a controller workspace.
The role does not provision SSH/SFTP access, a bastion, transfer account, or
credentials. There is no controller intake/check/transfer route, runner, or
separate evidence/outcome package flow.

Offline approval and signing remain outside these Ansible routes. GitLab mode
uses `platform-pki gitlab-package`; filesystem mode moves only the exact request
and response payloads and uses existing `platform-pki offline-csr approve|sign`
operations. Transport success never replaces signed-record authentication.

## Filesystem Exchange

Select the transport only through private inventory:

```yaml
pki_host_local_certificate_transport: filesystem
pki_host_local_certificate_filesystem_exchange_root: /srv/platform-pki-exchange
pki_host_local_certificate_filesystem_owner_uid: 1000
```

The root must be canonical, have no symlinked ancestor, and remain disjoint from
state, pending, versions, and trust roots. Every ancestor of the exchange root
must already exist as a root-owned directory without group or other write
permission. The role creates root-owned mode-`0755` exchange parents and
pre-creates request-specific mode-`0700` request and response directories owned
by the configured non-root UID.

After request publication, retrieve exactly:

```text
tls.csr
request
request.sig
```

After authorized approval and signing, upload exactly these mode-`0600` files to
the pre-created response directory:

```text
artifact
tls.crt
ca-chain.crt
fullchain.crt
response
response.sig
```

Complete the upload before invoking response activation. A partial, linked,
misowned, or extra-file response fails closed. The transfer UID can cause denial
of service by changing transport files, but signatures and target-local state
prevent it from authorizing a certificate. Files are retained; cleanup requires
a separate retention decision.

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

## GitLab Target Token

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

Both modes reference reviewed outside-Git trust and validation CA sources.
GitLab mode additionally references:

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
pki_host_local_certificate_reviewed_ca_source: /outside-git/pki/zot-validation-ca.crt
pki_host_local_certificate_reviewed_ca_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
pki_host_local_certificate_reviewed_ca_target_path: /etc/platform-config/zot-validation-ca.crt
pki_host_local_certificate_reviewed_ca_mode: "0644"

pki_host_local_certificate_trust_sources:
  approvers.allowed_signers: /outside-git/pki/trust/approvers.allowed_signers
  policy: /outside-git/pki/trust/policy
  requesters.allowed_signers: /outside-git/pki/trust/requesters.allowed_signers
  responses.allowed_signers: /outside-git/pki/trust/responses.allowed_signers
```

The transport-client source must be outside the public repository, owned by the
controller user, mode `0600`, singly linked, and no larger than 8 MiB. The role
pins its descriptor and reviewed digest throughout transfer, copies the project
record, GitLab CA bundle, and reviewed public trust, and never copies the token
or target leaf private key. The reviewed Zot CA source has the same metadata
policy with a 1 MiB limit; activation digest-pins and installs it as `root:root`
with only mode `0600` or `0644` before strict local validation.

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

GitLab packages have a schema-2 `stage-manifest` generated and validated as
transport metadata. Filesystem mode has no stage manifest. Neither transport
replaces request, approval, or response authentication. The response `artifact`
is schema 2 and contains no candidate or deployment state fields.

## State Gate

GitLab supports `issue` and `renew`; filesystem transport initially supports
`issue` only. Do not reuse lifecycle state from the
retired SSH, controller-local, migration, runner/evidence/outcome, five-file
trust, or helper-hash predecessor workflows. The new routes reject old or
ambiguous state. Preserve such state for review and use only a separately
authorized reset or target recreation.
