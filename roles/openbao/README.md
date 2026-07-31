# openbao

This is the retired standalone OpenBao implementation. It remains in the tree
only while its three-node HA replacement is developed; no active playbook calls
it. Do not apply it to the `openbao` group.

The legacy role owns one local OpenBao configuration, TLS deployment from
private source paths, persistent Raft storage under `/var/lib/openbao/data`, the
`openbao.container` Quadlet unit, service lifecycle, and source-scoped permanent
firewalld rich rules for `8200/tcp`. It does not expose cluster traffic or form a
three-voter cluster.

The official OpenBao image runs the server as UID `100` and GID `1000`, so the role pins the Quadlet user and grants that identity access to data and TLS key files through `openbao_container_uid` and `openbao_container_gid`. The generated systemd service sets `MemorySwapMax=0` as container-level hardening.

When `openbao_firewalld_manage` is true, the role manages permanent
source-scoped rich rules with offline-capable module operations. Rules are also
applied immediately when inventory explicitly configures firewalld to run.

This role intentionally does not initialize or unseal OpenBao. Initialization
and unseal operations require explicit operator action and must not be imported
from `playbooks/site.yml`.

Certificate private keys, unseal keys, root tokens, recovery keys, and any real CA material must stay outside public Git.

The supported public interface will be documented here only after the HA role
passes render, convergence, TLS, quorum, VIP, backup, and restore acceptance.
