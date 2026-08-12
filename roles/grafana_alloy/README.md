# grafana_alloy

Owns the one host-native Grafana Alloy process used by Linux VM collection and
shared external probe features. The role pins the official Alloy `1.18.1`
`linux/amd64` RPM by SHA-256 and exact installed NEVRA, validates the complete
candidate configuration with that binary before replacement, and is disabled and
stopped by default.

Feature roles do not install, start, reload, or independently configure Alloy.
They contribute validated configuration through `grafana_alloy_feature_config`;
this role remains the sole owner of `/etc/alloy/config.alloy` and
`alloy.service`.

Multi-host orchestration can include `tasks_from: preflight.yml` on every host
before process-owner convergence. The normal role entry point runs the same
non-host-mutating validation before inspecting or changing the service owner.

At least one output is required when the role is enabled. Loki journal forwarding
uses `grafana_alloy_loki_url`. Prometheus features use the stable
`prometheus.remote_write.platform_metrics.receiver` component configured by
`grafana_alloy_prometheus_remote_write_*`. Authentication values are referenced
through restricted outside-Git files and are never rendered inline.

The current systemd override retains root execution for access to the existing
system journal collection contract. Reducing privileges requires separate target
qualification of journal access and all enabled collectors.
