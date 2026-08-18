# Monitoring etcd

Disabled-by-default configuration contract for the dedicated three-member etcd
cluster used only by Patroni.

This slice locks the official etcd `3.6.14` image by immutable index digest,
requires an explicit UID/GID `10001` runtime override because the upstream image
declares root, and renders a host-network Quadlet with a read-only root,
no-new-privileges, and no Linux capabilities. The etcd configuration requires
mutual TLS for both client and peer traffic, exactly three canonical members,
one exact local identity, and direct node DNS advertisements.

The role is validation-only in this slice. `monitoring_etcd_service_enabled`
must remain `false` and `monitoring_etcd_service_state` must remain `stopped`.
It does not inspect or initialize `/srv/monitoring/etcd`, copy PKI, pull images,
open firewall ports, install a Quadlet, or touch a service. Stateful convergence
and initialization remain separate later gates.

Real member addresses, DNS names, the cluster token, and TLS source paths belong
in private inventory or an outside-Git secret store. Normal convergence must
never reset an existing data directory or silently form a replacement cluster.
