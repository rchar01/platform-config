# haproxy_workload_lb

Installs native HAProxy from OS packages and configures it as an external workload load balancer for Kubernetes ingress NodePorts.

This role is intentionally separate from RKE2 and in-cluster ingress roles. It models an external appliance-style load balancer: dev can use HAProxy on a VM, while production can use F5 with the same worker-node and NodePort target pattern.

The role is disabled by default. Set `haproxy_workload_lb_enabled: true` in private inventory for environments that should own this HAProxy VM.

Example private variables:

```yaml
haproxy_workload_lb_enabled: true
haproxy_workload_lb_http_backend_port: 30080
haproxy_workload_lb_https_backend_port: 30443
haproxy_workload_lb_backends:
  - name: k8s-worker-01
    address: 192.0.2.69
  - name: k8s-worker-02
    address: 192.0.2.70
  - name: k8s-worker-03
    address: 192.0.2.71
```

By default HAProxy listens on `80/tcp` and `443/tcp` and forwards raw TCP to worker NodePorts. TLS terminates in the in-cluster ingress controller, not on HAProxy.

When SELinux is enforcing, the role labels the configured backend NodePorts as `http_port_t` by default so the confined HAProxy process can connect to them without broad `haproxy_connect_any` access.
