# GitLab PKI Package Exchange

The host-local Zot workflow uses one private GitLab Generic Package project as
untrusted transport. The registry target publishes request bytes and downloads
response bytes directly. Ansible invokes the fixed target route but never
carries package bytes.

## Package Contract

Request, approval, and response records use schema 2. The request payload is exactly:

```text
tls.csr
request
request.sig
```

The approval payload is exactly:

```text
approval
approval.sig
```

The response payload is exactly:

```text
artifact
tls.crt
ca-chain.crt
fullchain.crt
response
response.sig
```

Each package uses a schema-2 `stage-manifest` as transport metadata generated and
checked by the package client. It is not PKI authority. Consumers authenticate
the signed request, approval, or response and local state rather than package
presence. The schema-2 response `artifact` omits candidate and deployment state.

The target derives activation package coordinates from authenticated lifecycle
state. No target-local Ansible route accepts a request ID, digest, package
version, source directory, or destination directory. Successful request
publication reports one authenticated request ID for the separately authorized
offline stages.

## Credential Boundary

One pre-provisioned target-local token is used for the configured private
project. It must be a `root:root`, mode-`0600`, singly linked regular non-symlink
from 1 through 4096 bytes. Ansible validates only metadata under `no_log` and
never reads token bytes into variables, facts, output, argv, or environment
variables. See [PKI Exchange Setup](pki-exchange-setup.md).

Offline approval/signing is outside these Ansible routes. It is responsible for
authenticating the request and using `platform-pki gitlab-package` to publish the
signed approval stage and authenticated response stage to the same project under
separate authorization. Carry the exact request ID reported by the request route
through those offline stages; this guide does not invent their remaining command
line.

## Rollout Gate

GitLab CE `18.11.3-ce.0` live token and Generic Package behavior remains
explicitly unqualified. Before rollout, qualify token authentication and
authorization, request publication, response retrieval, duplicate and partial
package handling, and deletion/cleanup protections against that exact live
version. Local tests and a syntactically valid project record do not satisfy the
gate.

Evidence, deployment, validation-result, and outcome package families are not
part of this transport. Direct/controller-local and SSH package exchange are not
supported.
