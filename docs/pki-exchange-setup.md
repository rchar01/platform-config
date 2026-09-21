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

One exchange, two certificate profiles, service-specific activation. The signer
supports the exact server profile and the generic client profile through the
same three public request and six public response files, schema-2 records and
v2 signature namespaces. Commands, trust and replay rules stay the same; no new
exchange framework is needed, and leaf keys never leave their consuming hosts.

## Monitoring PKI Direction

Monitoring will reuse the target-local key custody and signed exchange model
used for OpenBao. The current
[`pki_host_local_certificate` role](../roles/pki_host_local_certificate/README.md)
preserves fixed Zot/pristine OpenBao server adapters and adds issue-only
`client-stage-v1` request/import/staging entry points. It does not yet provide
an Alloy renewal adapter or live monitoring operation route. The Alloy role now
has a separate [guarded initial start](../roles/grafana_alloy/README.md#guarded-initial-start)
that consumes staged direct paths and an exact protected inventory snapshot.
`server-p384-sha384-v1` remains the CN-only subject/`serverAuth` profile;
client staging accepts only `client-p384-sha384-v1`.
Pristine OpenBao and filesystem exchange are currently issue-only; their
existence does not establish monitoring renewal support.

The host-native monitoring lifecycle will retain these boundaries:

1. Generate the leaf key on its consuming host; keep it out of request/response
   packages, Ansible variables and controller workspaces.
2. Publish an authenticated CSR/request through inventory-selected
   `platform-pki gitlab-package` transport or the fixed filesystem exchange.
3. Review and sign offline through `platform-tools`, binding the approved
   identity/profile to the request. Transport remains untrusted for authorization.
4. Verify the signed response against local request/key state, install a
   protected immutable version, and use a fixed service-specific activation
   adapter with validation and rollback.

Monitoring uses separate leaf keys/certificates, not OpenBao's identities. Alloy
will use `client-p384-sha384-v1`, whose exact controlled RFC2253 subject DN
matches HAProxy's `CN=...,OU=...,O=...,C=...` allowlist. A collector sending both
logs and metrics needs separate Loki-writer and Mimir-writer certificate/key
pairs, mapped to `alloy_loki_writer` and `alloy_mimir_writer` respectively.
These mappings are service-specific authorization, not a writer field or
Loki/Mimir enum in tools inventory or review. The client profile keeps
P-384/SHA-384, a full structured DN, no SAN or CSR attributes, exactly five
clientAuth-only leaf extensions and fresh-key renewal. The exact server profile
is unchanged.

Alloy verifies the HAProxy server certificate and hostname; HAProxy verifies the
collector certificate, CRL and exact role mapping. HAProxy-to-backend TLS uses
separate identities and trust. Runtime CA trust and the public keys authenticating
exchange records are separate trust selections. No running OpenBao service is
needed for this offline signing model.

`platform-tools` now supports `client-p384-sha384-v1` inventory,
signing/fresh-key renewal, certificate export and schema-2 package validation.
The unreleased predecessor profile has no compatibility alias. Client inventory
requires explicit numeric `days` from 1 through 365000 and a canonical positive
rollback-hold declaration. Issued and historical client validity must match the
exact signed inventory duration; historical/current selected-service equality
remains required. Request and approval have no issuer field; the response binds
the actual issuer.

Target client request/import and immutable staging now reuse the existing helpers
and transport. Staging never selects a current certificate or changes service
state. Initial Alloy process activation can authenticate that snapshot against
the signed requests and start the preconfigured service with failure recovery;
it does not create PKI active/predecessor records. Rotation, overlapping renewal
and CA-side CRL generation/distribution remain unimplemented. The monitoring design calls for a dedicated client CA hierarchy and
397-day leaves. Begin renewal preparation approximately 45 days before expiry;
activate the replacement at least 30 days before predecessor expiry and preserve
at least 30 days of valid, trusted, unrevoked overlap and rollback availability
after successful activation. Keep the predecessor key until that hold and
delivery verification pass. Emergency revocation overrides normal overlap and
removes the identity from every HAProxy role map before deploying the updated
CRL; never restore a revoked predecessor for rollback. This is the agreed
monitoring policy, not implemented renewal behavior or a change to OpenBao's
current adapter. Monitoring's 397-day choice and at least 30-day overlap/rollback
must be enforced by its target adapters; tools enforce the signed inventory
duration and positive rollback declaration without a generic 30-day minimum.
CA lifetimes remain separate. Current HAProxy/etcd roles
still copy controller PKI sources; they have not migrated to target-local custody.
Alloy now consumes separate Mimir and Loki TLS file references. Loki consumption
has local input/file and native-client synthetic delivery coverage; signed
certificate lifecycle integration and authenticated version selectors remain
unimplemented. See [Alloy TLS inputs](../roles/grafana_alloy/README.md#loki-tls-inputs).
Main acceptance testing of the simplified client support remains pending; this
documentation does not establish live qualification.

Kubernetes Alloy requires a separate key-custody and Secret delivery/rotation
contract. Do not export a host's private key or reuse its identity to populate
cluster workloads. No monitoring-specific command or variable is introduced by
this design documentation.

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
