# Host-Local PKI Exchange Access Role

This role manages the persistent, restricted SSH principal used by
`platform-pki direct-exchange` from `platform-tools`. It is separate from Ansible administrator
access and from certificate issuance lifecycle actions.

The present state requires the lifecycle-owned exchange facade to exist with
safe root ownership, refuses unmanaged account or group collisions, reserves
the fixed names before creation, and converts that reservation to an exact
UID/GID ownership record immediately after validating the new system identity.
A root-controlled
authorized-key file and account-wide `sshd` `Match User` policy both force the
unprivileged dispatcher and deny interactive shells, PTYs, forwarding, SCP,
SFTP, alternate authorized-key files and commands, and arbitrary commands. Any
other globally configured public-key authentication path is still constrained
by the same account-wide forced command.

The unprivileged dispatcher accepts only the four public exchange operations.
Sudo grants only a separate root broker, never the facade directly. The broker
independently revalidates sudo provenance and command coordinates, opens the
facade through a pinned descriptor after checking its protected ancestor chain,
and executes it with a fixed environment. `cleanup-outcome` remains unavailable
to the SSH identity.

The fixed revoke entry point can safely unwind an interrupted reservation or act
on a fully managed identity only when the root-owned marker is canonical and
every present account or group attribute matches. A managed record must also
match its exact UID and GID. It
removes sudo authority first, then the key, account-wide SSH policy, account,
home, group, dispatchers, and marker. It never adopts or removes an unmarked
same-name identity. There is no external state selector: the role's default
entry point is revoke-only. The lease-claim playbook selects the fixed `enable`
claim entry point, and the focused access playbook requires that owned lease
before selecting `enable_access`. The outside-Git public key reference belongs
in private inventory.

```yaml
pki_host_local_exchange_access_authorized_key: >-
  {{ lookup('ansible.builtin.file', '/outside-git/identity.pub') }}
```

The private identity never enters Ansible inventory or a managed-host payload.
The target facade itself remains owned by `pki_host_local_certificate`. The
focused access playbook calls that role's fixed lifecycle-helper and
exchange-endpoint task files before enabling access; it does not create a
request or change certificate state. Normal registry convergence only revokes
access before service convergence and never re-enables it. Direct use of this
access role is revoke-only.

Direct access is temporary transport capability, not PKI or lifecycle authority.
The canonical workflow uses the config-owned direct-exchange Make routes to
atomically claim one target-scoped operation lease, enable, run exactly one
supported `platform-pki direct-exchange` operation, and revoke before releasing
the lease on exit or a handled signal. The lease is a fixed empty root-owned
mode-`0700` directory with the wrapper's random operation token in metadata.
Concurrent wrappers fail their claim without revoking or changing the active
operation. Token-bound cleanup refuses a missing, replaced, nonempty, or
tampered lease before changing access. The fixed cleanup
target remains `make registry-pki-exchange-access-revoke ENV=<environment>
LIMIT=<target>`; it selects the structurally fixed revoke task entry point and
exact absence is idempotent. This tokenless target and normal registry
convergence are administrative revocation boundaries: do not run them over a
healthy in-flight wrapper unless intentionally terminating that operation. Do
not invoke the enable target as an unbounded operator step. See
[Host-Local Registry PKI Workflow](../../docs/registry-host-local-pki-workflow.md#fixed-cleanup).
