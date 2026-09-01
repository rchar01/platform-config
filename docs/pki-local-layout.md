# Target-Local PKI Layout

The current host-local Zot and pristine OpenBao workflows do not use a controller
exchange or controller workspace. Transport and lifecycle state are target-local;
offline signer custody remains outside these Ansible routes.

## Target-Owned State

Each registry or OpenBao target owns:

- the leaf private key and pending request state;
- immutable certificate versions and authenticated active state;
- the schema-3 trust snapshot;
- in GitLab mode, the target-local facade configuration, protected spool,
  pre-provisioned token, reviewed project record, and HTTPS CA bundle;
- in filesystem mode, a fixed exchange tree containing only public requests and
  signed responses.

The token must be `root:root`, mode `0600`, a regular non-symlink with link count
1, and 1 through 4096 bytes. Ansible validates metadata only under `no_log` and
does not read token bytes.

Target trust contains exactly:

```text
approvers.allowed_signers
policy
requesters.allowed_signers
responses.allowed_signers
```

The request package contains `tls.csr`, `request`, and `request.sig`. The offline
approval package contains `approval` and `approval.sig`. The response package
contains `artifact`, `tls.crt`, `ca-chain.crt`, `fullchain.crt`, `response`, and
`response.sig`. Each `stage-manifest` uses schema 2 and is transport metadata.
GitLab mode exchanges request and response bytes directly with one private
Generic Package project. Filesystem mode exports the three request files and
imports the six response files through request-specific target-local directories.
Ansible never carries those bytes, and the target private key never enters either
transport.

Both fixed adapters reuse the same request, approval, and response records.
GitLab transport uses `platform-pki gitlab-package`; filesystem transport uses
the existing offline custody commands and no package coordinates. OpenBao has no
separate operator command or coordinate input. Its Ansible routes operate on one
canonical node at a time. Response activation temporarily unmasks the staged unit
for fixed local validation, then stops it and restores the mask without enabling
it.

Filesystem exchange roots have only pre-existing root-owned, non-writable
ancestors. The role owns exchange parents as `root:root` mode `0755` and creates
request-specific request and response directories as mode `0700` for the
pre-provisioned transfer UID. Files are mode `0600`; request directories contain
only `tls.csr`, `request`, and `request.sig`, while response directories contain
only `artifact`, `tls.crt`, `ca-chain.crt`, `fullchain.crt`, `response`, and
`response.sig`.

## Outside-Git Inputs

Keep real inventory and non-secret policy under `../platform-private/config/`.
Keep tokens, private keys, and other secrets outside Git. Reviewed public trust,
the GitLab project record and CA, the target transport client source, and the
reviewed local-validation CA are outside-Git inputs referenced by private vars.

Offline approval/signing has its own authoritative state, key custody, backup,
and retention policy outside these Ansible routes. This repository does not
define a canonical signer workspace or exact signer command.

## Retired Layouts

Controller exchange roots, arbitrary same-workstation transfer directories,
Ansible-provisioned SSH exchange identities, direct/controller-local spools,
controller intake/check/transfer
trees, runner observations, and evidence/outcome workspaces are not supported by
the current workflow. Their presence does not establish current authority.

Do not move, rewrite, or delete old state merely to make the new routes pass.
Preserve it until reviewed, then use a separately authorized reset or target
recreation. There is no helper-hash predecessor migration.
