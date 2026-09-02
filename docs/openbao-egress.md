# OpenBao Artifact and Egress Matrix

This matrix covers the OpenBao HA deployment, PKI, status, maintenance, and
smoke workflows, plus the optional observer services hosted on OpenBao nodes. It
applies to OpenBao `2.6.1` on EL10 AMD64 with Podman Quadlet, native HAProxy, and
Keepalived. A full `site.yml` run includes unrelated platform components and
therefore has additional egress.

Private inventory selects environment-specific repositories, registry routes,
service endpoints, and package identities. This public document uses safe
placeholders and contains no private hosts, credentials, addresses, or trust-file
locations. An inventory selection proves desired configuration, not deployment,
reachability, effective routing, or completed qualification.

Requalify this matrix whenever an image digest, package identity, registry route,
base OS repository, PKI transport, observer target, or deployment component
changes.

## Fetch Locations

| Origin | Direct requests | Dynamic or transitive requests |
| --- | --- | --- |
| OpenBao host DNF | Requested Podman, versionlock, kernel, firewalld, HAProxy, Keepalived, and conditional SELinux packages. | Repository metadata and signatures, signing keys, dependency-selected RPMs, package payloads, and mirror-selected hosts. |
| OpenBao host Podman | Exact digest-pinned OpenBao image manifest. | Registry authentication, manifest or index resolution, image config, layers, and registry-selected blob delivery. |
| Target-local PKI client | Optional authenticated GitLab package publication and download. | Package discovery and repeated inspection requests implemented by the pinned external client. |
| Controller | SSH orchestration and direct OpenBao or HAProxy status and smoke requests. | DNS resolution and conditional development-container build inputs. |
| Running OpenBao stack | No public artifact service is required. | Peer, Raft, client, HAProxy, metrics, DNS, and VRRP flows intended to remain environment-internal. |
| Optional OpenBao observers | Exact Grafana Alloy RPM download and inventory-selected monitoring targets. | Release redirects, local-RPM dependencies, probes, remote write, log delivery, PostgreSQL, S3, and DNS traffic. |
| Qualification runner | Pinned OpenBao image and disposable test-container inputs. | Registry, DNF, pip, and Galaxy dependency traffic used only by qualification tooling. |

The role does not download an OpenBao RPM, plugin, Helm chart, sidecar, or source
archive.

## Host Packages

The top-level OpenBao staging order is `firewalld`, `podman_host`, `openbao`,
`openbao_haproxy`, and `keepalived_vip`. Package-consuming roles also invoke the
read-only `rocky_repository_policy` dependency, while `podman_host` invokes
`container_runtime_kernel`.

Package selectors fall into three categories:

- `podman_host_package_nevra`, `openbao_haproxy_package_nevra`, and
  `keepalived_vip_package_nevra` are inventory-selected exact package identities;
- `python3-dnf-plugin-versionlock` is fixed and asserted by `podman_host`; and
- `container_runtime_kernel_packages`, `firewalld_package`, and
  `firewalld_python_package` are configurable package inputs whose defaults are
  `kmod`, `firewalld`, and `python3-firewall`.

When `openbao_haproxy_selinux_manage` is enabled and SELinux is active, HAProxy
also requests `openbao_haproxy_selinux_package`, which defaults to
`policycoreutils-python-utils`.

DNF resolves repository metadata, metadata signatures, signing keys, transitive
dependencies, and payload locations at transaction time. A mirrorlist or
metalink may select additional hosts dynamically. A finite destination set
therefore requires fixed approved base URLs or an internal repository snapshot.

The optional `rocky_repository_policy` gate can validate the effective release,
enabled repository IDs, URL mechanisms, and signature settings. It does not
fetch metadata or prove repository reachability, freshness, or immutable
contents.

## OpenBao Image

The approved defaults and current dev selection use this repository-qualified
identity:

| Property | Selected value |
| --- | --- |
| Logical image | `ghcr.io/openbao/openbao` |
| Version | `2.6.1` |
| Manifest digest | `sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0` |
| Platform | `linux/amd64` |
| Configured user | `openbao` |
| Qualified numeric identity | UID `100`, GID `1000` |

The role composes and uses:

```text
ghcr.io/openbao/openbao@sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0
```

Role convergence verifies digest, architecture, configured user name, and the
`v2.6.1` OCI version label. Repository image qualification separately verifies
that `openbao` resolves to UID `100` and GID `1000` in this exact artifact.

GHCR requests normally begin at
`https://ghcr.io/v2/openbao/openbao/manifests/<digest>` and may require token,
manifest or index, config, layer, and package-delivery requests selected by the
registry. Native candidate validation uses the local image with `--network none`
and `--pull never`, so configuration validation itself has no registry egress.

The generated service Quadlet does not set `Pull=never`. The role normally pulls
and verifies the image before service management, but a later service start can
attempt a registry pull if the local image disappears. Do not remove a running
host's only qualified local image to test routing.

## Optional Registry Remapping

`podman_host_registry_remaps` preserves a reviewed logical reference while
routing the physical request through an environment-selected registry:

```yaml
podman_host_registry_remaps:
  ghcr.io/openbao/openbao: registry.example.test/openbao/openbao
```

The `podman_registry_remaps` role writes
`/etc/containers/registries.conf.d/90-platform-config-remaps.conf` with:

```toml
[[registry]]
prefix = "ghcr.io/openbao/openbao"
location = "registry.example.test/openbao/openbao"
```

This is a containers/image direct `location` rewrite, not a mirror list. When
this entry is the effective match, Podman does not fall back to public GHCR if
the physical location is unavailable or lacks the image. The mapping is empty
by default, and an empty mapping removes only the role-owned drop-in.

The role does not remove or interpret other Podman registry configuration.
Root-specific configuration, later drop-ins, or a longer matching prefix can
override this entry. Qualification must inspect all rootful Podman registry
configuration and observe the route used for the exact logical reference.

For a dedicated Docker connector or registry-group hostname, use
`<registry-host>/<image-path>`. Nexus Repository `3.83.0+` optionally supports
the vendor's path-based routing form
`<nexus-host>/<repository-name>/<image-path>`, which must answer requests under
`/v2/<repository-name>/...`. The version is a vendor capability prerequisite,
not a version selected or managed by this repository.

A repository-content URL such as
`https://nexus.example.test/repository/docker-ghcr/v2` is not a Podman image
location because Podman places `/v2/` immediately after the registry authority.
Use a Docker connector, registry group, reverse-proxy route, or enabled Nexus
path-based route.

Locations cannot contain schemes or credentials. The role does not install
registry trust or Podman authentication. The endpoint must validate with system
trust, and required credentials must be provisioned separately in an approved
Podman authentication store.

## PKI Transport

Ansible transfers reviewed controller-side public CA and trust inputs over its
normal SSH transport. It does not copy the OpenBao leaf private key, which
remains target-local.

The selected target-local PKI transport has different egress behavior:

- `filesystem` publishes and imports signed packages through fixed target-local
  directories and implements no network transport;
- `gitlab` invokes the pinned `platform-pki gitlab-package` client on the target
  for authenticated HTTPS publication, discovery, inspection, and download; and
- the GitLab token is pre-provisioned on the target rather than copied by
  Ansible.

The filesystem route relies on separately provisioned movement across its fixed
exchange boundary. The GitLab implementation and exact package API calls belong
to the externally supplied pinned client. Certificate activation performs local
TLS and health validation against the OpenBao service, not public artifact
fetches.

## Operational And Runtime Flows

These flows are not public artifact acquisition, but they belong in environment
network policy and egress observation:

| Source | Destination | Purpose |
| --- | --- | --- |
| Controller | Managed hosts over SSH | Ansible orchestration and file transfer. |
| Controller | Node backend HTTPS listener | Health, Raft membership, and audit status. |
| Controller | Each node's HAProxy client listener | Direct-node smoke and HAProxy activation checks. |
| OpenBao node | Its own backend listener | Lifecycle and readiness checks. |
| OpenBao node | Peer backend and cluster listeners | Retry join and Raft communication. |
| Clients | HAProxy client listener | OpenBao API traffic. |
| HAProxy | Every OpenBao backend listener | TLS health checks and TCP forwarding. |
| Metrics collector | HAProxy metrics listener | Prometheus metrics collection. |
| Keepalived peers | Peer addresses using IP protocol `112` | Unicast VRRP. |
| Hosts and controller | Selected DNS resolvers | Resolution of configured service and node names. |

Backend, client, cluster, metrics, DNS, and PKI endpoints are inventory-selected.
They are intended to remain environment-internal, but public code cannot prove
their network placement. OpenBao smoke checks each HAProxy node address; they do
not prove VIP ownership or VIP-path health.

An internal pull-through registry may itself contact GHCR. That
registry-to-upstream flow is repository-service egress, not node egress.

## Optional Observer Egress

`playbooks/openbao-observers.yml` can install Grafana Alloy from:

```text
https://github.com/grafana/alloy/releases/download/v1.18.1/alloy-1.18.1-1.amd64.rpm
```

The selected payload checksum is
`sha256:7dbdc068feae7feaafbc48fefb9b41b6c91af24984c13277bf0a9d1a298a4126`,
and the required installed identity is `alloy-0:1.18.1-1.x86_64`. The URL is
inventory-overridable; the payload digest and identity provide the artifact
checks. Release redirects and local-RPM dependency resolution may add requests.

When activated, observer configuration can initiate inventory-selected HTTPS
blackbox probes, Prometheus remote write, Loki writes, TLS PostgreSQL primary
checks, Garage S3 `PUT`/`GET`/`DELETE` canaries, and DNS resolution. Observer
smoke can trigger configured probes and is therefore not necessarily network
local. These destinations are monitoring policy, not fixed OpenBao artifact
origins.

## Controller Toolchain

Supported `make` workflows run through `scripts/in-container`. If the local
development image is absent, the wrapper builds `Containerfile.dev`, beginning
with the digest-pinned
`docker.io/library/python:3.14.7-slim-trixie@sha256:83c1cebb322d099ac9e3a3a532ba74b0146d702838b25e4c75c02fa81ffeb910`
base image. That build also resolves APT, pip, and Ansible Galaxy artifacts and
their transitive dependencies. This is conditional controller preparation
egress, not managed OpenBao host egress.

Disposable integration and image tests may additionally pull Rocky test images
and install test dependencies. Qualification-only destinations must not be
copied into the managed-host allowlist.

## Active-Cluster Convergence

The normal `playbooks/openbao.yml` path stages pristine or disabled state and
must not be used to maintain an initialized active cluster. The explicit
maintenance playbook validates the complete active OpenBao group, then applies
only `podman_registry_remaps` without importing that path into `site.yml`. Its
preflight requires an exact explicit three-host limit, each host's observed
active lifecycle, and consistent cluster identity:

```bash
# Preview the registry drop-in change.
make check ENV=dev PLAYBOOK=playbooks/maintenance/openbao-registry-remaps.yml LIMIT=openbao

# Apply the registry drop-in to all three active voters.
make apply ENV=dev PLAYBOOK=playbooks/maintenance/openbao-registry-remaps.yml LIMIT=openbao

# Require a clean post-apply preview.
make check ENV=dev PLAYBOOK=playbooks/maintenance/openbao-registry-remaps.yml LIMIT=openbao
```

Review check-mode output before applying. This maintenance path changes no
Podman package, storage, socket, kernel, or OpenBao service state. Changing the
registry drop-in does not prove that an already-cached image used the new route.

## Qualification Procedure

For each image, package-source, or registry-route change:

1. Establish whether the cluster is pristine, pending bootstrap, active direct,
   active behind HAProxy, or in recovery. Select only the matching lifecycle
   workflow.
2. Validate the effective DNF repositories, signature policy, exact package
   identities, and dependency availability. Record immutable repository
   snapshots when the environment requires reproducibility.
3. Converge `podman_registry_remaps` on the exact intended hosts through a
   supported playbook. Inspect the role-owned drop-in and require a clean
   post-apply check.
4. Review `/etc/containers/registries.conf`, every system drop-in, and applicable
   root-specific configuration. Require that no competing entry wins for the
   exact logical reference.
5. Optionally diagnose the physical Docker endpoint with a manifest request. Its
   `/v2/...` path must include any path-based Nexus repository segment. A raw
   `curl` response does not prove Podman's effective route or complete layer
   availability.
6. Pull the unchanged logical reference through Podman:

   ```bash
   sudo podman --log-level=debug pull \
     ghcr.io/openbao/openbao@sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0
   sudo podman image inspect \
     ghcr.io/openbao/openbao@sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0
   sudo podman run --rm --network none --pull never --entrypoint /bin/sh \
     ghcr.io/openbao/openbao@sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0 \
     -c 'test "$(id -u openbao):$(id -g openbao)" = 100:1000'
   ```

7. Correlate Podman debug output, node network observations, and internal
   registry logs. Repeat with node access to public GHCR denied. This proves the
   node route, not the pull-through registry's own upstream policy.
8. For an active direct cluster, run
   `make status-openbao ENV=dev LIMIT=openbao`. Run
   `make smoke-openbao ENV=dev LIMIT=openbao` only after HAProxy is active. Any
   image or configuration change that requires voter restarts uses
   `make roll-openbao ENV=dev LIMIT=openbao` and its manual-unseal gates.
9. Store environment-specific evidence, dates, package identities, route logs,
   and denied-egress results outside this public repository. Publish only a
   sanitized durable summary when needed.

An ordinary OpenBao role apply is not route evidence when the exact image is
already present because the role skips its pull.

## Authoritative Sources

- [OpenBao release `v2.6.1`](https://github.com/openbao/openbao/releases/tag/v2.6.1)
- [OpenBao container package](https://github.com/openbao/openbao/pkgs/container/openbao)
- [Podman registry configuration](https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md)
- [Podman registry drop-ins](https://github.com/containers/image/blob/main/docs/containers-registries.conf.d.5.md)
- [Nexus Repository Docker path-based routing](https://help.sonatype.com/en/docker-registry.html#path-based-routing-162059)
