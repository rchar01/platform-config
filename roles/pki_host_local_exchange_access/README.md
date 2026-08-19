# Host-Local PKI Exchange Access Role

This role manages the persistent, restricted SSH principal used by
`scripts/platform-pki-direct-exchange`. It is separate from Ansible administrator
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

The absent state can safely unwind an interrupted reservation or act on a fully
managed identity only when the root-owned marker is canonical and every present
account or group attribute matches. A managed record must also match its exact
UID and GID. It
removes sudo authority first, then the key, account-wide SSH policy, account,
home, group, dispatchers, and marker. It never adopts or removes an unmarked
same-name identity. The role defaults to absent. Real enablement and the
outside-Git public key reference belong in private inventory.

```yaml
pki_host_local_exchange_access_state: present
pki_host_local_exchange_access_authorized_key: >-
  {{ lookup('ansible.builtin.file', '/outside-git/identity.pub') }}
```

The private identity never enters Ansible inventory or a managed-host payload.
The target facade itself remains owned by `pki_host_local_certificate`. The
focused access playbook and normal enabled registry convergence call that role's
fixed lifecycle-helper and exchange-endpoint task files before enabling access;
they do not create a request or change certificate state. Direct use of this
access role still fails closed when the facade is absent or unsafe.
