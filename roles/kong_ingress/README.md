# kong_ingress

Installs Kong Gateway and Kong Ingress Controller as an RKE2-managed HelmChart.

This role owns the platform ingress controller, not application ingress definitions. It is intentionally separate from the base `rke2` role, kube-vip API HA, and the external HAProxy workload load balancer.

The first supported mode is classic Kubernetes `Ingress` only. Gateway API CRDs and `Gateway`/`HTTPRoute` resources are intentionally deferred to a later platform phase.

The role is disabled by default. Private inventories must opt in and pin the chart and image versions:

```yaml
kong_ingress_enabled: true
kong_ingress_chart_version: 0.24.0
kong_ingress_gateway_image_tag: 3.9.1
kong_ingress_controller_image_tag: 3.5.7
kong_ingress_proxy_http_node_port: 30080
kong_ingress_proxy_https_node_port: 30443
```

Kong's proxy service is exposed as fixed NodePorts so an external load balancer, such as dev HAProxy or production F5, can forward to worker node IPs without relying on in-cluster `LoadBalancer` services.

Only the proxy service should be exposed as `NodePort` in this phase. Manager and portal services are disabled.

The role validates fixed proxy NodePorts against the configured Kubernetes NodePort range, defaulting to `30000-32767`.
