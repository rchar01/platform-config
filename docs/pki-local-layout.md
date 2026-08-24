# Target-Local PKI Layout

The current host-local Zot workflow does not use a controller exchange or
same-workstation transport layout. Package transport and lifecycle state are
target-local; offline signer custody remains outside these Ansible routes.

## Target-Owned State

The registry target owns:

- the leaf private key and pending request state;
- immutable certificate versions and authenticated active state;
- the schema-3 trust snapshot;
- the target-local GitLab facade configuration and protected spool;
- the pre-provisioned GitLab token;
- the reviewed GitLab project record and HTTPS CA bundle.

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
The target exchanges request and response bytes directly with one private GitLab
Generic Package project; Ansible never carries them.

## Outside-Git Inputs

Keep real inventory and non-secret policy under `../platform-private/config/`.
Keep tokens, private keys, and other secrets outside Git. Reviewed public trust,
the GitLab project record and CA, the target transport client source, and the
reviewed local-validation CA are outside-Git inputs referenced by private vars.

Offline approval/signing has its own authoritative state, key custody, backup,
and retention policy outside these Ansible routes. This repository does not
define a canonical signer workspace or exact signer command.

## Retired Layouts

Controller exchange roots, same-workstation transfer directories, SSH exchange
identities, direct/controller-local spools, controller intake/check/transfer
trees, runner observations, and evidence/outcome workspaces are not supported by
the current workflow. Their presence does not establish current authority.

Do not move, rewrite, or delete old state merely to make the new routes pass.
Preserve it until reviewed, then use a separately authorized reset or target
recreation. There is no helper-hash predecessor migration.
