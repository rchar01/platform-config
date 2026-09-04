# RKE2 Artifact and Egress Matrix

This matrix documents the external artifacts used by the qualified native-RPM
RKE2 installation path. It applies to RKE2 `v1.35.5+rke2r2` on EL10 AMD64 with
Calico, Traefik, and kube-vip. Update and requalify it whenever any package,
chart, image, repository, base image, or build dependency changes.
Changing `rke2_cni`, `platform_ingress_controller`, artifact-affecting
`rke2_extra_config`, or deployed workloads requires regenerating and
requalifying the matrix because those inputs may introduce additional artifacts.

Private inventory may replace every environment-specific repository and
registry endpoint with an approved internal mirror. This public document names
upstream sources only; it does not contain private hosts, addresses, VIPs,
interfaces, credentials, or trust-file locations.

## Fetch Locations

| Origin | Direct requests | Dynamic or transitive requests |
| --- | --- | --- |
| RKE2 nodes | Rancher signing key and repository metadata; exact node and SELinux RPMs; requested firewalld, kernel-module, and kmod package payloads; OCI image manifests for workloads scheduled on that node. | Hashed DNF metadata, dependency-selected RPMs, and OS package closure; registry authentication plus image config, layer, and redirect destinations. |
| RKE2 Helm Controller job | kube-vip Helm index. The job may run on any eligible cluster node. | Chart URL selected from the index and its release-asset redirect. |
| CI Runner and operational job | Digest-pinned maintained operational image from GHCR and immutable GitLab repositories, then SSH and internal smoke endpoints. | GHCR authentication and image layers. The job does not proxy target-node RPM or OCI downloads. |

The pristine-node preflight, Ansible template rendering, guarded reboot,
second-apply idempotency checks, and smoke playbooks do not intentionally fetch
external artifacts. Runtime reconciliation may still pull a missing image while
smoke waits for a workload.

## Native RPM Sources

The role configures the two Rancher repositories disabled by default and enables
them only for the exact RKE2 transaction. Both package and repository GPG checks
are enabled. The signing key is independently pinned by SHA-256 and OpenPGP
fingerprint.

### Configuring RPM Sources

These variables are the public configuration interface for RKE2 RPM sources:

| Variable | Purpose |
| --- | --- |
| `rke2_rpm_common_repository_url` | HTTPS DNF base URL containing common packages such as `rke2-selinux`. |
| `rke2_rpm_version_repository_url` | HTTPS DNF base URL containing versioned `rke2-server`, `rke2-agent`, and `rke2-common` packages. |
| `rke2_rpm_gpg_key_url` | HTTPS source for the repository signing key. |
| `rke2_rpm_gpg_key_sha256` | Reviewed lowercase SHA-256 of the downloaded key. |
| `rke2_rpm_gpg_key_fingerprint` | Reviewed uppercase OpenPGP fingerprint. |

The repository values are base URLs, not individual RPM URLs or OCI registry
references. They must contain metadata and packages matching `rke2_version`,
`rke2_rpm_el_major`, `rke2_rpm_arch`, `rke2_rpm_package_release`, and
`rke2_rpm_selinux_package_nevra`. Role defaults are intentionally empty so each
inventory must select and review its sources.

Real environment values belong in private inventory. For example, an internal
immutable mirror that preserves Rancher's packages, metadata signatures, and
signing key could use this public placeholder configuration:

```yaml
rke2_version: v1.35.5+rke2r2
rke2_rpm_el_major: "10"
rke2_rpm_arch: x86_64
rke2_rpm_package_release: 0.el10
rke2_rpm_selinux_package_nevra: rke2-selinux-0.23-1.el10.noarch

rke2_rpm_common_repository_url: >-
  https://rpm-mirror.example.test/rke2/v1.35.5-rke2r2/common/centos/10/noarch
rke2_rpm_version_repository_url: >-
  https://rpm-mirror.example.test/rke2/v1.35.5-rke2r2/1.35/centos/10/x86_64
rke2_rpm_gpg_key_url: >-
  https://rpm-mirror.example.test/rke2/v1.35.5-rke2r2/public.key
rke2_rpm_gpg_key_sha256: >-
  7d2415f7fc532c365c8874bfad966566daaa0d04a9a5ba14d1db6080a9c12629
rke2_rpm_gpg_key_fingerprint: C8CFF216455126E9B9C918BE925EA29AE257814A # gitleaks:allow - Public signing-key fingerprint.
```

The existing checksum and fingerprint remain valid only when the mirror serves
the unchanged Rancher key and preserves both upstream signature sets. A mirror
that re-signs content must sign both RPM packages and repository metadata with
the one configured key, publish that reviewed key, and configure its SHA-256 and
fingerprint. Separate package-signing and metadata-signing keys require a role
enhancement. Do not embed credentials in repository URLs; authenticated
repositories require a separate secret-backed interface.

| Artifact | Exact upstream source |
| --- | --- |
| Rancher signing key | `https://rpm.rancher.io/public.key` |
| Signing-key SHA-256 | `7d2415f7fc532c365c8874bfad966566daaa0d04a9a5ba14d1db6080a9c12629` |
| Signing-key fingerprint | `C8CFF216455126E9B9C918BE925EA29AE257814A` |
| Common repository metadata | `https://rpm.rancher.io/rke2/stable/common/centos/10/noarch/repodata/repomd.xml` |
| Version repository metadata | `https://rpm.rancher.io/rke2/stable/1.35/centos/10/x86_64/repodata/repomd.xml` |
| `rke2-selinux-0.23-1.el10.noarch` | `https://rpm.rancher.io/rke2/stable/common/centos/10/noarch/rke2-selinux-0.23-1.el10.noarch.rpm` |
| Server package | `https://rpm.rancher.io/rke2/stable/1.35/centos/10/x86_64/rke2-server-1.35.5~rke2r2-0.el10.x86_64.rpm` |
| Agent package | `https://rpm.rancher.io/rke2/stable/1.35/centos/10/x86_64/rke2-agent-1.35.5~rke2r2-0.el10.x86_64.rpm` |

With repository GPG verification enabled, DNF also requests the detached
metadata signature, normally `repodata/repomd.xml.asc`. DNF then reads
`repomd.xml` and follows its hashed metadata filenames. Those filenames and
repository contents are mutable and cannot be represented by one permanent list
of object URLs. Use an immutable repository snapshot when that boundary is
unacceptable.

The role directly requests the exact SELinux package and one exact server or
agent package. Their RPM metadata selects the exact matching
`rke2-common-1.35.5~rke2r2-0.el10.x86_64` from the version repository. Its
qualified upstream object is:

```text
https://rpm.rancher.io/rke2/stable/1.35/centos/10/x86_64/rke2-common-1.35.5~rke2r2-0.el10.x86_64.rpm
```

The RKE2 path also directly requests these unversioned package names from the
enabled OS repositories:

- `firewalld`
- `python3-firewall`
- `kernel-modules-extra`
- `kmod`

The selected RKE2 and SELinux RPM metadata additionally names `iptables`,
`kernel-modules-extra`, `container-selinux`, `libselinux-utils`,
`policycoreutils`, and `selinux-policy-base`. Except for the exact matching
`rke2-common` constraint, DNF selects the OS NEVRAs and complete transitive
closure from repository metadata at transaction time.

The public role does not create Rocky repository definitions. Private inventory
or host image policy selects the OS origin, release, mirrorlist or base URLs, and
signature policy. The attended qualification selected the public Rocky 10.2
HTTPS mirrorlists below for BaseOS, AppStream, and Extras; other environments
must substitute and review their own effective sources. The package mirror hosts
are returned dynamically by the mirrorlist service.

```text
https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=BaseOS-10.2
https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=AppStream-10.2
https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=extras-10.2
```

Allowing only `mirrors.rockylinux.org` is insufficient: it serves mirror
metadata, not necessarily the selected RPM payloads. A finite firewall allowlist
requires fixed base URLs or an internal Rocky snapshot.

## RKE2 Runtime Images

The effective selectors are `rke2_cni: calico` and
`platform_ingress_controller: traefik`.

The public configuration does not map `docker.io` to the internal registry and
does not disable containerd's default registry endpoint. RKE2 system images
therefore use Docker Hub directly unless private inventory adds an explicit
mirror. The logical default endpoint is `https://index.docker.io/v2`; token,
manifest, blob, and CDN requests introduce dynamically selected endpoints.

RKE2 publishes release-associated image-list assets. The lists below are the
complete release bundles selected by this configuration and are discovery inputs
for a full offline mirror. They contain tags, not immutable image digests, and
are not proof that every optional image is scheduled or pulled by a particular
cluster. Qualification must resolve and record each required manifest or index
digest; that digest inventory, not a later re-resolution of these tags, is the
offline mirror contract.

### Core Bundle

Official list: [`rke2-images-core.linux-amd64.txt`](https://github.com/rancher/rke2/releases/download/v1.35.5%2Brke2r2/rke2-images-core.linux-amd64.txt)

SHA-256: `923c06d468a5ce1542698300e729c62d4071484ab1c7d254402f5cee18d90e6c`

```text
docker.io/rancher/rke2-runtime:v1.35.5-rke2r2
docker.io/rancher/hardened-kubernetes:v1.35.5-rke2r2-build20260521
docker.io/rancher/hardened-coredns:v1.14.3-build20260511
docker.io/rancher/hardened-cluster-autoscaler:v1.10.3-build20260511
docker.io/rancher/hardened-dns-node-cache:1.26.8-build20260511
docker.io/rancher/hardened-etcd:v3.6.7-k3s1-build20260512
docker.io/rancher/hardened-k8s-metrics-server:v0.8.1-build20260513
docker.io/rancher/hardened-addon-resizer:1.8.23-build20260511
docker.io/rancher/klipper-helm:v0.10.0-build20260513
docker.io/rancher/klipper-lb:v0.4.17
docker.io/rancher/mirrored-pause:3.6
docker.io/rancher/kube-webhook-certgen:v1.14.5-hardened2
docker.io/rancher/nginx-ingress-controller:v1.14.5-hardened2
docker.io/rancher/rke2-cloud-provider:v1.35.4-0.20260415195656-e51c0636351d-build20260415
docker.io/rancher/hardened-snapshot-controller:v8.5.0-build20260513
```

The bundle includes conditional components. For example, ingress-nginx images
remain in the core bundle even though this deployment selects Traefik and the
smoke contract requires ingress-nginx to be absent.

### Calico Bundle

Official list: [`rke2-images-calico.linux-amd64.txt`](https://github.com/rancher/rke2/releases/download/v1.35.5%2Brke2r2/rke2-images-calico.linux-amd64.txt)

SHA-256: `fd359f603575306cdd06190d3eab2df2e3e293773d61804b76edae8294346e54`

```text
docker.io/rancher/mirrored-calico-operator:v1.42.0
docker.io/rancher/mirrored-calico-ctl:v3.32.0
docker.io/rancher/mirrored-calico-kube-controllers:v3.32.0
docker.io/rancher/mirrored-calico-typha:v3.32.0
docker.io/rancher/mirrored-calico-node:v3.32.0
docker.io/rancher/mirrored-calico-pod2daemon-flexvol:v3.32.0
docker.io/rancher/mirrored-calico-cni:v3.32.0
docker.io/rancher/mirrored-calico-apiserver:v3.32.0
docker.io/rancher/mirrored-calico-csi:v3.32.0
docker.io/rancher/mirrored-calico-node-driver-registrar:v3.32.0
docker.io/rancher/mirrored-calico-envoy-gateway:v3.32.0
docker.io/rancher/mirrored-calico-envoy-proxy:v3.32.0
docker.io/rancher/mirrored-calico-envoy-ratelimit:v3.32.0
docker.io/rancher/mirrored-calico-goldmane:v3.32.0
docker.io/rancher/mirrored-calico-whisker:v3.32.0
docker.io/rancher/mirrored-calico-whisker-backend:v3.32.0
```

Calico API, Typha, CSI, Envoy, Goldmane, and Whisker images are bundle members
but may remain unused depending on rendered chart defaults and cluster scale.

### Traefik Bundle

Official list: [`rke2-images-traefik.linux-amd64.txt`](https://github.com/rancher/rke2/releases/download/v1.35.5%2Brke2r2/rke2-images-traefik.linux-amd64.txt)

SHA-256: `a46a34494489ba954f8396f6aa324d5fd6c1c35989dd6bf52ec1e52fab78fa4a`

```text
docker.io/rancher/hardened-traefik:v3.6.16-build20260512
```

RKE2 packages the selected Calico, CoreDNS, metrics-server, snapshot-controller,
and Traefik charts with the release. The online installation does not separately
download those chart archives. The runtime image carries the packaged
manifests, and Helm Controller jobs pull the referenced images.

## kube-vip Sources

The role writes a local `HelmChart` manifest but the Helm Controller fetches the
repository index and chart archive at runtime.

| Artifact | Exact upstream source or identity |
| --- | --- |
| Helm index | `https://kube-vip.github.io/helm-charts/index.yaml` |
| Chart archive | `https://github.com/kube-vip/helm-charts/releases/download/kube-vip-0.9.9/kube-vip-0.9.9.tgz` |
| Published chart SHA-256 | `106dc112b119abdbac82ea4be13dc8d815028972d101a45bd7a448d68611f1f6` |
| Image selected by role | `ghcr.io/kube-vip/kube-vip:v1.2.1` |
| Published multi-architecture image digest | `sha256:49b77655f9f109bedc5eb25723bb0e4c57d8513ba33cc69c31be3f243eb2386d` |

The role pins chart and image versions but does not currently enforce the
published chart checksum or image digest. The chart archive URL redirects to a
temporary GitHub release-asset URL. GHCR pulls also resolve authentication,
manifest, blob, and package-delivery endpoints dynamically. Allowing only
`kube-vip.github.io` and `ghcr.io` is therefore not a complete firewall policy.

## Internal Registry Boundary

The qualified development configuration maps only the internal registry's own
hostname to its HTTPS endpoint and CA. It does not mirror `docker.io`, `ghcr.io`,
or a wildcard.

Consequently:

- RKE2 and Traefik images use Docker Hub.
- kube-vip uses GHCR.
- only references already named with the internal registry hostname use Zot.
- containerd may fall back to a public registry endpoint after a configured
  mirror fails unless that fallback is explicitly disabled.

### Optional Public Registry Mirrors

Private inventory can use `rke2_registry_mirrors` to route unchanged
`docker.io/...` RKE2 and `ghcr.io/...` kube-vip image references through HTTPS
OCI pull-through mirrors. Set `rke2_disable_default_registry_endpoint` to
prevent fallback:

```yaml
rke2_registry_mirrors:
  docker.io:
    endpoint:
      - https://nexus.example.test/repository/docker-hub/v2
  ghcr.io:
    endpoint:
      - https://nexus.example.test/repository/docker-ghcr/v2
rke2_disable_default_registry_endpoint: true
```

For a path-based Nexus repository, configure the Docker Distribution API root;
the examples therefore include the explicit `/v2` suffix. Every mirror entry
must contain at least one credential-free HTTPS endpoint. The role requires the
global fallback setting whenever a `docker.io` or `ghcr.io` mirror is present.
That RKE2 setting disables default-endpoint fallback for every registry that has
a mirror entry; registries without mirror entries retain their normal default
endpoint behavior. Mirror endpoint definitions remain independent entries.

The `ghcr.io` mirror covers the kube-vip image only. It does not proxy the
kube-vip Helm index or chart archive, which continue to use the sources in
[kube-vip Sources](#kube-vip-sources) unless `rke2_kube_vip_chart_repo` selects
an approved internal Helm repository.

If the mirror certificate is not already trusted by the host image, RKE2 can
reuse the optional `registry_ca_trust` role. Its
`registry_ca_trust_source`, `registry_ca_trust_sha256`, and
`registry_ca_trust_target` variables describe a controller-side file, not inline
YAML content:

```yaml
registry_ca_trust_source: >-
  {{ inventory_dir | dirname | dirname }}/files/registry/<environment>/ca-bundle.crt
registry_ca_trust_sha256: >-
  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
registry_ca_trust_target: >-
  /etc/pki/ca-trust/source/anchors/registry-ca-bundle.crt
```

Both source and digest are empty by default, making system trust installation a
no-op. In no-op mode the role does not inspect or verify preinstalled trust;
another managed host baseline must guarantee that the mirror validates on every
current and replacement node. When enabled, Ansible verifies the source digest,
installs the anchor, runs `update-ca-trust extract`, and restarts RKE2 through
its existing guarded readiness path when trust changes. A private inventory may
track a reviewed public registry CA under
`config/files/registry/<environment>/ca-bundle.crt`; the local operator and a
future CI job then consume the same file from their immutable private checkout.
No GitLab File variable or public pipeline change is required.

System trust applies to every process on the node. Review the complete bundle and
prefer only the issuing CA chain required by the mirror. The RKE2-specific
`rke2_registry_ca_src` and `rke2_registry_configs` variables remain available for
a CA scoped only to a configured containerd registry endpoint.

When preserving upstream image references, a disconnected design must mirror
each source registry, configure explicit `docker.io` and `ghcr.io` entries,
disable their default endpoint fallback, and verify that every rendered workload
resolves internally. A design that rewrites supported references or uses
`system-default-registry` may use different routing, but it still requires a
complete digest inventory and proof that no rendered reference reaches upstream.

## Operational Image Egress

`platform-config` does not build or publish an operational image. The qualified
dev binding selects the maintained upstream image directly from GHCR by release
tag and OCI index digest:

```text
ghcr.io/ansible/community-ansible-dev-tools:v26.8.0@sha256:70f705fee2386deb320598ea011812292598111cca85f0107ee9479062628e79
```

The Runner resolves GHCR authentication, the selected manifest, its Linux
`amd64` child, image configuration, and layers. The public components verify the
complete image reference and architecture. They also require Ansible Core
`2.21.x`; RKE2 requires `ansible.posix` `2.2.2`, while OpenBao status uses only
built-in modules and requires no external collection. Jobs install no runtime
packages or collections.

At job time, the Runner needs the digest-pinned operational image and the
self-managed GitLab repositories selected by immutable commits. The operational
container needs the same GitLab HTTPS endpoint, managed-host SSH endpoints, and
internal API/smoke endpoints. These are private operational paths, not public
artifact sources.

Attended local commands may build `Containerfile.dev` and therefore also require
its base-image, APT, pip, and Galaxy sources. That developer build chain is not
separately qualified here.

## Firewall Policy

Direct online installation uses dynamic services. The following names describe
configured or observed entry points, not an exhaustive permanent allowlist:

- `rpm.rancher.io`
- `mirrors.rockylinux.org` plus mirror hosts returned by its response
- `index.docker.io`, Docker Hub authentication, registry, blob, and CDN hosts
- `kube-vip.github.io`
- `github.com` plus temporary GitHub release-asset hosts
- `ghcr.io` plus GitHub package-delivery hosts

Authentication, blob, CDN, mirror, and redirect hosts vary by provider behavior,
geography, and time. Derive the actual set from controlled egress logs for the
qualified run; do not promote one observation into a permanent provider contract.
Do not build an IP allowlist from current DNS answers, redirect destinations, or
one mirror response. A finite, reviewable egress policy requires:

1. Fixed or internally snapshotted qualified OS and Rancher repositories.
2. Internally mirrored RKE2, Calico, Traefik, and kube-vip images addressed by
   reviewed digests.
3. An internally hosted checksum-verified kube-vip chart archive or repository.
4. When preserving upstream references, explicit containerd mirror entries with
   public fallback disabled through `rke2_disable_default_registry_endpoint`.
5. A separately mirrored and reproducible CI image build chain.

## Qualification Procedure

For each release change:

1. Record exact direct package NEVRAs and resolve the complete RPM closure
   against the intended immutable Rocky and Rancher snapshots.
2. Download the official core, selected CNI, and selected ingress image lists
   from the exact RKE2 release and verify their published SHA-256 values.
3. Mirror every bundle member by digest, even when the current rendered chart
   does not schedule an optional member.
4. Fetch and checksum the exact kube-vip chart, render its workloads, and mirror
   every referenced image by digest.
5. Run the attended fresh-install sequence with egress logging enabled at the
   controlled gateway or mirrors.
6. Enumerate containerd images on every node and all rendered Kubernetes image
   references; reconcile them against the reviewed bundle and mirror inventory.
7. Repeat with public egress denied. Require bootstrap, smoke, and second-apply
   idempotency to pass before adopting the release in CI.

## Authoritative Sources

- [RKE2 release `v1.35.5+rke2r2`](https://github.com/rancher/rke2/releases/tag/v1.35.5%2Brke2r2)
- [RKE2 private registry behavior](https://docs.rke2.io/install/private_registry)
- [RKE2 packaged components](https://docs.rke2.io/install/packaged_components)
- [RKE2 air-gap installation](https://docs.rke2.io/install/airgap)
- [kube-vip Helm repository index](https://kube-vip.github.io/helm-charts/index.yaml)
- [kube-vip chart `0.9.9`](https://github.com/kube-vip/helm-charts/releases/tag/kube-vip-0.9.9)
- [kube-vip `v1.2.1`](https://github.com/kube-vip/kube-vip/releases/tag/v1.2.1)
- [GitHub connectivity and changing IP ranges](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses)
