# podman_registry_remaps

Manages optional rootful Podman logical-prefix registry remaps without changing
Podman packages, storage, sockets, kernel policy, or container services. The
role writes `/etc/containers/registries.conf.d/90-platform-config-remaps.conf`
when `podman_host_registry_remaps` is nonempty and removes only that owned file
when the mapping is empty.

```yaml
podman_host_registry_remaps:
  ghcr.io/example/service: registry.example.test/example/service
```

Each entry becomes one direct containers/image `prefix` to `location` rewrite.
When the entry is the effective match, the physical location replaces the
logical prefix without upstream fallback. Locations are credential-free
canonical lowercase registry paths with valid host labels, repository
components, and optional ports; system trust and Podman authentication remain
prerequisites.

`podman_host` depends on this role so normal host setup applies remaps before
package changes. Active service hosts may invoke this role independently through
a guarded service-specific maintenance playbook.
