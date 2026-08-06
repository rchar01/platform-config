# kong_ingress

Installs Kong Gateway and Kong Ingress Controller as an RKE2-managed HelmChart.

This role owns the optional Kong platform ingress controller, not application ingress definitions. It is intentionally separate from the base `rke2` role, kube-vip API HA, and the external HAProxy workload load balancer.

The first supported mode is classic Kubernetes `Ingress` only. Gateway API CRDs and `Gateway`/`HTTPRoute` resources are intentionally deferred to a later platform phase.

Bundled RKE2 Traefik is selected by default. Private inventories can select Kong instead and must pin its chart and image versions:

```yaml
platform_ingress_controller: kong
kong_ingress_chart_version: 0.24.0
kong_ingress_gateway_image_tag: 3.9.1
kong_ingress_controller_image_tag: 3.5.7
kong_ingress_proxy_http_node_port: 30080
kong_ingress_proxy_https_node_port: 30443
```

Selecting Kong configures RKE2 with `ingress-controller: none`, so the packaged Traefik and ingress-nginx controllers are not installed. `traefik` and `kong` are alternatives rather than coexisting platform controllers.

Apply and verify the RKE2 selection before installing Kong:

```bash
make apply ENV=dev PLAYBOOK=playbooks/rke2.yml
make smoke-rke2 ENV=dev
make apply ENV=dev PLAYBOOK=playbooks/kong-ingress.yml
make smoke-kong-ingress ENV=dev
```

The Kong role refuses to write its manifest while packaged Traefik resources remain. The retired `kong_ingress_enabled` variable is rejected so an old inventory cannot silently enable both controllers; replace it with `platform_ingress_controller: kong`.

Kong's proxy service is exposed as fixed NodePorts so an external load balancer, such as dev HAProxy or production F5, can forward to worker node IPs without relying on in-cluster `LoadBalancer` services.

Only the proxy service should be exposed as `NodePort` in this phase. Manager and portal services are disabled.

The role validates fixed proxy NodePorts against the configured Kubernetes NodePort range, defaulting to `30000-32767`.

Changing the selector on an existing cluster requires a planned ingress-class and controller migration. Removing an RKE2 manifest file alone does not uninstall resources that were previously applied from it.
