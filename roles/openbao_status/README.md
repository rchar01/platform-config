# openbao_status

Performs a strict, read-only status check of the approved three-node OpenBao
`2.6.1` Integrated Storage cluster. The role runs from one selected OpenBao
inventory host but delegates every API and source-file operation to the Ansible
controller.

The role:

- verifies each direct node through certificate-validated TLS;
- requires one initialized, unsealed active node and two initialized, unsealed
  standbys in the same cluster;
- reads a dedicated status token only from an outside-Git controller file; the
  documented operational lifecycle installs it with `0600` permissions;
- sends that token only as `X-Vault-Token` to the active node, never follows
  redirects, and suppresses token-bearing task output;
- requires exactly the expected three unique Raft voters, expected cluster
  addresses, one leader, and agreement between the API active node and Raft
  leader;
- requires exactly the two approved durable file audit devices; and
- repeats the strict Raft observation to reject changing membership, leadership,
  or configuration index.

The token needs only this policy:

```hcl
path "sys/storage/raft/configuration" {
  capabilities = ["read"]
}

path "sys/audit" {
  capabilities = ["read", "sudo"]
}
```

Set `openbao_status_token_src` in private inventory to an absolute controller
path. Never store the token in this repository or copy it to an OpenBao node.
This role does not initialize, unseal, restart, reconfigure, or write OpenBao.

The dev runbook uses a manually rotated, non-renewable orphan service token and
stores it at
`~/.config/platform-infrastructure/config/openbao/dev/status.token`. Token
expiry does not affect OpenBao availability; it blocks this status gate until
an administrator issues and installs a replacement. This role consumes the
token but does not issue, renew, rotate, or revoke it.
