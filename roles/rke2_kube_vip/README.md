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
rke2_kube_vip_env:
  cp_enable: "true"
  svc_enable: "false"
  vip_arp: "true"
  vip_subnet: "32"
  vip_leaderelection: "true"
  lb_enable: "true"
  lb_port: "6443"
  vip_interface: "{{ rke2_kube_vip_interface }}"
```

Preflight checks confirm the API VIP is included in `rke2_tls_sans` and that every RKE2 server routes the VIP through the configured interface.
