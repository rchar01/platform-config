# pki_host_local_certificate

Defines the fail-closed target/controller contract for host-local PKI trust,
request, and activation runs. The operator-only `trust` action performs only an
initial schema-2 five-file target trust bootstrap or an exact protected no-op.
It validates an explicit five-key controller source mapping, pins every source
file and ancestor by descriptor, and transfers only the digest-validated bytes
from those descriptors to protected target ingress. A standard-library Python
helper pins the target state hierarchy, uses the canonical state lock, and
atomically publishes the complete tree. Existing different bytes, another trust
ID, unsafe metadata, path replacement, unexpected state, and all rotation
attempts fail closed.

The requester/target principal must appear independently in both
`requesters.allowed_signers` and `deployers.allowed_signers`; policy must pin
exactly one approver and response principal.

The request entry point only consumes separately installed frozen target trust;
it never copies or installs trust. It installs its request helper, then generates
or validates one target-local P-384 key, CSR, canonical request, and SSH
signature. The private key remains in the protected pending directory. Request
collection, certificate activation, service restart, rollback, and deployment
evidence are not implemented yet.

Use only the explicit `playbooks/registry-pki-trust.yml`,
`playbooks/registry-pki-request.yml`, and
`playbooks/registry-pki-activate.yml` entry points. None is imported by normal
convergence. The activation entry point intentionally fails after contract
validation until the remaining phases are implemented and tested.

Trust bootstrap requires these exact mappings, with source files outside Git
and all digests pinned to the reviewed bytes:

```yaml
pki_host_local_certificate_trust_sources:
  policy: /outside-git/reviewed-trust/policy
  requesters.allowed_signers: /outside-git/reviewed-trust/requesters.allowed_signers
  approvers.allowed_signers: /outside-git/reviewed-trust/approvers.allowed_signers
  responses.allowed_signers: /outside-git/reviewed-trust/responses.allowed_signers
  deployers.allowed_signers: /outside-git/reviewed-trust/deployers.allowed_signers
pki_host_local_certificate_trust_sha256:
  policy: 64-lowercase-hex
  requesters.allowed_signers: 64-lowercase-hex
  approvers.allowed_signers: 64-lowercase-hex
  responses.allowed_signers: 64-lowercase-hex
  deployers.allowed_signers: 64-lowercase-hex
```

Each controller source must be outside this public repository and be a
mode-`0600`, singly linked regular file owned by the controller process user;
its basename must match its mapping key. Every source ancestor must be owned by
root or that user and must not be unsafely writable. The action rechecks pinned
source identities before, during, and after transfer and does not return trust
bytes in its result. Check mode never creates the helper, state root, lock,
ingress, journal, or trust tree. An absent install can report
`would-install` only when the reviewed helper, protected state and lock, and a
complete protected ingress already exist; otherwise it fails with the missing
prerequisite. An interrupted transaction is never recovered in check mode.

The target helper journals the stage device and inode before populating it and
uses descriptor-relative mutation for stage publication, recovery, ingress
cleanup, and journal removal. Exact installed no-op validation also accepts the
canonical shared lifecycle siblings `active`, `rollback`,
`validation-boundary`, and `evidence`, while rejecting unresolved journals and
unknown state.

Private keys must remain on the destination host. Do not add `fetch`, `slurp`,
controller lookups, registered output, facts, debug output, or controller-side
copy operations that handle a leaf private key.
