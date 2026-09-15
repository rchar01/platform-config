# rke2_kube_vip

Installs kube-vip as an RKE2-managed HelmChart for Kubernetes API high availability. This role is a cluster infrastructure add-on: it runs after the base `rke2` role and writes a HelmChart manifest on the RKE2 bootstrap server only.

The role is disabled by default. Set `rke2_kube_vip_enabled: true` in private inventory for environments that should own an API VIP.

The role is API-only by default. It enables control-plane VIP handling and disables service LoadBalancer handling so workload ingress and load balancing can be designed separately.

Real VIPs, interfaces, and environment-specific chart policy belong in private inventory. Public examples should use documentation-safe addresses and hostnames.

Example private variables:

```yaml
rke2_kube_vip_api_vip: 192.0.2.72
rke2_kube_vip_enabled: true
rke2_kube_vip_interface: eth0
rke2_kube_vip_chart_version: 0.9.9
rke2_kube_vip_image_tag: v1.2.1
rke2_kube_vip_env:
  cp_enable: "true"
  svc_enable: "false"
  vip_arp: "true"
  vip_subnet: "32"
  vip_leaderelection: "true"
  vip_leaseduration: "15"
  vip_renewdeadline: "10"
  vip_retryperiod: "2"
  lb_enable: "true"
  lb_port: "6443"
  vip_interface: "{{ rke2_kube_vip_interface }}"
```

Pin the application image separately from the chart version. Chart `0.9.9`
defaults to kube-vip `v1.0.4`, so `rke2_kube_vip_image_tag` is required to run
kube-vip `v1.2.1`.

`rke2_kube_vip_chart_repo` defaults to `https://kube-vip.github.io/helm-charts`.
For a repository requiring a private CA, explicitly select both
`rke2_kube_vip_chart_repo_ca_src` and `rke2_kube_vip_chart_repo_ca_sha256` in
private inventory. Both are strings and default to empty, which omits
`spec.repoCA`. The source is a controller-local canonical absolute path using
only letters, digits, `_`, `-`, `.`, and `/`, with no empty, `.` or `..`
components. Select a reviewed PEM CA file, not a private key; its contents are
published in the HelmChart. The checksum is exactly 64 hex digits (either case).
Keep the real file and pin in private configuration.

Before mutation, including in check mode, controller-side stat and slurp require
a nonempty regular non-symlink file of at most 1 MiB, check its SHA-256, and hash
the exact decoded slurp content again. JSON quoting preserves line endings and
final newlines in `spec.repoCA`. This uses the `repoCA` support in helm-controller
0.17.1 shipped with the approved RKE2 v1.35.5+rke2r2 baseline. It does not change
node or registry trust or disable TLS verification.

`playbooks/rke2-kube-vip-smoke.yml` compares the live Helm repository and exact CA
SHA-256, or requires `repoCA` absence when unconfigured. Qualify the repository's
`index.yaml`, selected chart archive, and Helm job separately; field agreement
does not establish download success or a chart-content checksum.

The leader-election values explicitly preserve kube-vip and Kubernetes
client-go's `15/10/2`-second defaults. `vip_leaseduration` controls how long
followers wait without a lease renewal before attempting takeover,
`vip_renewdeadline` controls how long the leader retries renewal before
stepping down, and `vip_retryperiod` controls the interval between attempts.
These values tolerate transient API or etcd latency better than the former
`5/3/1` defaults, at the cost of slower takeover after an abrupt leader failure.

Preflight checks confirm the API VIP is included in `rke2_tls_sans` and that every RKE2 server routes the VIP through the configured interface.
