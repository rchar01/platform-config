# pki_host_local_certificate

Provides operator-only, target-local certificate lifecycles for the fixed
`zot-v1` and `openbao-pristine-v1` service adapters. Normal convergence does not
invoke this role. Its default task entry point fails closed; the two public
routes per fixed adapter select the request or activation task file.

## Operator Routes

The complete public operator surface is:

```bash
make registry-pki-request-publish ENV=dev LIMIT=<one-host> [REQUEST_TTL_SECONDS=1..604800]
make registry-pki-response-activate ENV=dev LIMIT=<one-host>
make openbao-pki-request-publish ENV=dev LIMIT=<one-openbao-host> [REQUEST_TTL_SECONDS=1..604800]
make openbao-pki-response-activate ENV=dev LIMIT=<one-openbao-host>
```

Square brackets denote the optional TTL assignment and are not literal shell
syntax. Each `LIMIT` must literally name exactly one canonical host in the
adapter's inventory group. It cannot be omitted, name a pattern, or also resolve
to an unrelated host. The request lifetime defaults to 3600 seconds. Zot accepts
`issue` and `renew`; pristine OpenBao accepts `issue` only.

The request route installs and validates the schema-3 trust snapshot, creates or
revalidates the target-local private key and schema-2 request, and has the target
publish the request package directly to its configured private GitLab Generic
Package project. The activation route derives the request and package coordinates
from authenticated target state; recovers an interrupted activation journal
before transport when required; downloads and authenticates the schema-2
response on the target; activates and validates the selected fixed service
adapter locally; and rolls back on failure. Success requires final
`status=complete` and `required_action=none`.

After successful request publication, the request route reports only the
authenticated 32-hex `request_id` outside its protected `no_log` task. Carry that
exact ID into the separately authorized offline request, approval, signing, and
response-publication process. The activation Ansible route does not accept it as
input.

Offline approval and signing are separate, authorized processes outside these
Ansible routes. They continue to use only the reviewed request, approval, and
response boundary provided by `platform-pki gitlab-package`; there is no
OpenBao-specific `platform-tools` command.

The OpenBao request and activation routes are per-node PKI operations. Repeat
them separately for each canonical OpenBao host. They do not replace the
full-cluster limit required by OpenBao staging or bootstrap playbooks and are
never imported by `site.yml`.

OpenBao activation requires the selected `openbao.service` to be inactive and
masked. The playbook temporarily unmasks it only while the fixed response route
runs, then independently attempts to stop and restore the mask in an `always`
block. Success requires a final inactive, masked unit. It never enables the
service; initialization and cluster bootstrap remain separate full-cluster
operations.

## Trust And Packages

The immutable schema-3 target trust directory contains exactly:

```text
approvers.allowed_signers
policy
requesters.allowed_signers
responses.allowed_signers
```

Each controller source is an absolute outside-Git path whose basename matches
its mapping key. The role pins and validates each reviewed digest before
installing the public trust snapshot.

The schema-2 request package payload is exactly:

```text
tls.csr
request
request.sig
```

The schema-2 response package payload is exactly:

```text
artifact
tls.crt
ca-chain.crt
fullchain.crt
response
response.sig
```

`stage-manifest` is transport metadata, not PKI authority or an additional
payload. The target exchanges these package bytes directly with one configured
private GitLab project. Ansible never carries package bytes.

## Token Boundary

The GitLab token must be provisioned on the target before either route runs. It
must be a `root:root` regular, non-symlink file with link count 1, mode `0600`,
and size from 1 through 4096 bytes. Ansible checks only this metadata under
`no_log`; it does not read token bytes into variables, facts, output, argv, or
environment variables. The target facade opens the token file directly.

The reviewed GitLab project record and CA bundle are public inputs copied from
outside Git. `pki_host_local_certificate_platform_pki_source` supplies the
reviewed transport client installed on the target. The transport-client source
must be an outside-repository, controller-user-owned, singly linked regular file
with mode `0600`; `pki_host_local_certificate_platform_pki_sha256` pins its exact
reviewed bytes before descriptor-bound transfer.

`pki_host_local_certificate_reviewed_ca_source` supplies the public CA bundle
used for strict local service validation. It follows the same outside-repository,
controller-user-owned, singly linked, mode-`0600` source policy and is limited to
1 MiB. Activation descriptor-pins
`pki_host_local_certificate_reviewed_ca_sha256` and installs the exact bytes as
`root:root` at `pki_host_local_certificate_reviewed_ca_target_path` with the
selected `0600` or `0644` mode before invoking local validation.
For `openbao-pristine-v1`, the target is fixed at
`/etc/platform-config/openbao-validation-ca.crt`; the runtime trust file
`/etc/openbao/tls/ca.crt` remains exclusively owned by the OpenBao role.

## Required Inputs

Private inventory supplies the service and target identity, the fixed adapter,
`issue` or `renew`,
certificate profile and SANs, inventory digest, requester and response
principals, schema-3 trust ID/path/source/digest mappings, lifecycle roots,
reviewed GitLab project record and CA sources, installed target token path,
transport-client source and SHA-256, reviewed service CA source, target path,
digest and mode, minimum remaining lifetime, and rollback interval. Zot also
requires its fixed `/v2/` endpoint. OpenBao derives its local health endpoint and
therefore requires the endpoint variable to be empty.

The fixed target defaults include:

```yaml
pki_host_local_certificate_request_signing_key_path: /etc/ssh/ssh_host_ed25519_key
pki_host_local_certificate_request_namespace: platform-pki-csr-request-v2
pki_host_local_certificate_gitlab_token_path: /etc/platform-config/pki-gitlab-token
pki_host_local_certificate_service_adapter: zot-v1
pki_host_local_certificate_service_unit: zot.service
pki_host_local_certificate_service_config_path: /etc/zot/config.json
pki_host_local_certificate_zot_config_path: /etc/zot/config.json
```

The only OpenBao contract is `openbao-pristine-v1`. It is issue-only, requires a
node-scoped service identifier beginning with `openbao-`, and fixes the unit to
`openbao.service`, the listener config to `/etc/openbao/listener.hcl`, direct
ports to `18200` and `8201`, the container-visible versions root to
`/openbao/config/tls-versions`, the base config directory to `/openbao/config`,
the Raft data directory to `/var/lib/openbao`, and the bootstrap marker to
`/var/lib/platform-config/openbao-bootstrap.json`. Private inventory supplies a
canonical node DNS name and IPv4 address that must also appear in the certificate
SANs. Arbitrary adapters, service commands, validators, endpoints, renewal, and
operator-supplied request or package coordinates are rejected.

Private keys remain target-local. Do not add `fetch`, `slurp`, debug output,
facts, or controller-side copies that expose `tls.key` or GitLab token bytes.

## State Compatibility

This breaking workflow does not migrate predecessor helper hashes or lifecycle
state. State from retired migration, direct/controller-local, SSH exchange,
runner/evidence/outcome, or schema-2 trust workflows is rejected. Preserve it
until a separately reviewed retention decision; use only a separately authorized
reset or target recreation before starting the new workflow.

Current Ansible runs render facade configuration schema 3 with the explicit
adapter contract. The target facade continues to accept the exact persisted
schema-2 Zot configuration and preserves its prior lifecycle command arguments.

GitLab CE `18.11.3-ce.0` live token and Generic Package behavior remains an
explicit, unqualified rollout gate. Local helper tests do not qualify a live
deployment.
