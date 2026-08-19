# Monitoring Etcd Status Role

Strictly validates the three-node monitoring etcd bootstrap markers, current
content-addressed bundles, persistent Quadlet enablement, services, containers,
membership, direct endpoints, and stable mTLS health. It does not start, stop,
enable, render, repair, or mutate etcd state.

Invoke it only through
`playbooks/maintenance/monitoring-etcd-status.yml`, which requires all three
canonical monitoring hosts and compares their observations before querying the
cluster from one deterministic member.
