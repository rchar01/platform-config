# Registry

The dev registry is a Zot OCI registry deployed by `zot_registry` on hosts in the `registry` group. Registry client smoke tooling is installed by `registry_client_tools` on hosts in the `registry_clients` group.

## Registry Client Tools

`registry_client_tools` installs tools needed by optional registry smoke tests. It is wired into `playbooks/registry.yml` and currently installs:

- Helm `v4.2.2` to `/usr/local/bin/helm` from `get.helm.sh` with a pinned SHA-256 checksum.

It does not install Podman. Hosts that run image smoke tests must get Podman from the existing `podman_host` role, usually by also being in `container_hosts`.

## Smoke Tests

Run registry smoke checks with:

```bash
make smoke-registry ENV=dev
```

The smoke playbook has three tiers.

| Test | Enabled By | Requires | What It Verifies |
|---|---|---|---|
| Zot service/API/firewall/UI | Registry host vars | `systemctl`, `firewall-offline-cmd`, Python Ansible modules | Zot is active, `/v2/` responds, firewalld exposure matches vars, and the UI root serves HTML when enabled. |
| Raw OCI API push/pull | Always on `registry_clients` | Python Ansible modules only | Zot accepts a minimal OCI config blob and manifest over the Distribution API. Set smoke credentials when registry auth is enabled. |
| Podman image push/pull/run | `zot_registry_smoke_image_enabled: true` | Podman on `registry_clients` | A real `hello-world` image can be pulled, retagged, pushed to Zot, pulled back, and run. |
| Helm OCI chart push/pull | `zot_registry_smoke_helm_enabled: true` | Helm from `registry_client_tools` | A temporary Helm chart can be packaged, pushed as an OCI artifact, and pulled back. |

## Smoke Artifacts

The smoke tests intentionally leave separate artifacts in Zot so each client path is visible and debuggable.

| Repository/Artifact | Test | Type | Meaning |
|---|---|---|---|
| `platform-smoke/empty:ansible-smoke` | Raw OCI API push/pull | Minimal OCI manifest | Verifies Zot Distribution API behavior without Podman, Helm, ORAS, or Skopeo. |
| `platform-smoke/hello-world:podman-smoke` | Podman image push/pull/run | Runnable container image | Verifies normal container image client behavior. |
| `platform-smoke/charts/platform-smoke-chart:0.1.0` | Helm OCI chart push/pull | Helm chart OCI artifact | Verifies Helm chart storage via OCI. |

The Helm chart appears in the Zot UI alongside images because Zot stores Helm charts as OCI artifacts. It is not a runnable container image.

## Enabling Optional Tool Tests

Enable optional image and Helm checks in private inventory vars for `registry_clients`:

```yaml
zot_registry_smoke_base_url: "{{ platform_registry_url }}"
zot_registry_smoke_validate_certs: false
zot_registry_smoke_image_enabled: true
zot_registry_smoke_helm_enabled: true
zot_registry_smoke_username: registry-admin
zot_registry_smoke_password: "replace-with-secret-password"
```

`zot_registry_smoke_validate_certs: false` makes Podman use `--tls-verify=false` and Helm use `--insecure-skip-tls-verify` during smoke tests. Keep this aligned with whether the client host trusts the registry CA.

Set both `zot_registry_smoke_username` and `zot_registry_smoke_password`, or
neither. Authenticated registries require both values for raw OCI API, Podman,
and Helm smoke checks. Store real smoke passwords outside public Git.

## UI And Network Access

Enable the Zot UI with:

```yaml
zot_registry_ui_enabled: true
```

The UI is served on the same HTTPS listener as the registry API. Enabling the UI also enables Zot's required `search` extension.

Restrict registry and UI access with source-scoped firewalld rich rules:

```yaml
zot_registry_firewalld_allowed_sources:
  - 192.0.2.0/24
```

When this allowlist is non-empty, the broad permanent registry port is closed and only the listed CIDRs are allowed.

The focused registry playbook installs firewalld and its Python bindings before
configuring these rules. The current platform baseline keeps the daemon disabled
and stopped, so rules are stored permanently but are not actively enforced.
Run `make smoke-firewalld ENV=<environment>` to verify that baseline. See
[Firewalld Readiness And Enablement](firewalld.md) before enabling active
enforcement.

The role refuses to deploy a broadly reachable anonymous registry by default. A
deployment must enable htpasswd authentication, configure a source allowlist
that this role manages with firewalld, or explicitly set
`zot_registry_allow_insecure_anonymous_access: true` for an isolated development
environment.

## Security Model

The registry role is safe by default. It requires authentication, source-scoped
network access, or an explicit development-only override before opening the
registry listener broadly.

| Area | Current Dev Setup | Production Recommendation |
|---|---|---|
| TLS | Enabled with platform PKI service certificate. | Enabled with a CA trusted by all users, CI hosts, and Kubernetes nodes. |
| Client certificate validation | Smoke tests disable validation with client flags. | Do not use `--tls-verify=false` or `--insecure-skip-tls-verify`; install the registry CA instead. |
| Authentication | Required for broad exposure unless explicitly overridden. | Enable registry authentication before exposing beyond trusted admin networks. |
| Authorization | Example policy grants a registry admin full access. | Use least-privilege repository policies for humans, CI, and admins. |
| Image signing | Not configured. | Sign release images and enforce signed-only deployment with registry trust and Kubernetes admission policy. |
| Network access | Firewalld source allowlist for local CIDRs. | Keep firewall, VPN, or site routing restrictions in addition to registry auth. |
| Kubernetes pulls | RKE2 nodes trust the registry CA. | Add node-level registry auth, `imagePullSecrets`, or both when the registry requires login. |
| Test artifacts | Stored under `platform-smoke/*`. | Keep smoke artifacts separate from real app repositories. |

Use DNS names for production image references, not raw IP addresses. For example, use `registry.example.com/platform/app:v1.0.0` rather than `192.0.2.10/platform/app:v1.0.0`.

## Registry Authentication

Zot can use an `htpasswd` file for username/password authentication. The file contains usernames and bcrypt-hashed passwords and must live outside Git.

The role already has auth inputs:

```yaml
zot_registry_auth_enabled: true
zot_registry_auth_htpasswd_src: /outside-git/path/htpasswd
```

For isolated development only, anonymous registry access can be made explicit:

```yaml
zot_registry_allow_insecure_anonymous_access: true
```

Do not use that override for shared, routed, production, or CI-facing registries.

Create bcrypt htpasswd entries with a tool such as:

```bash
htpasswd -bBn ci-builder 'replace-with-secret-password'
```

Do not commit the generated htpasswd file. Store it in an outside-Git secret location, such as the platform infrastructure config secret store.

Authentication only proves who the caller is. Authorization is separate.

Zot `accessControl` defines what authenticated users can do. A production policy should define who can `read`, `create`, `update`, or `delete` each repository path. For example:

```yaml
zot_registry_extra_config:
  http:
    accessControl:
      repositories:
        "platform/**":
          policies:
            - users:
                - ci-builder
              actions:
                - read
                - create
                - update
            - users:
                - developer
              actions:
                - read
      adminPolicy:
        users:
          - registry-admin
        actions:
          - read
          - create
          - update
          - delete
```

If this becomes a standard production requirement, prefer adding first-class role variables for access control rather than relying only on `zot_registry_extra_config`.

## Kubernetes Pull Credentials

When registry authentication is enabled, Kubernetes needs credentials to pull private images.

Two common approaches are available:

| Approach | Scope | Use Case |
|---|---|---|
| RKE2/containerd registry auth | Node-level | Platform-wide registry credentials that apply to image pulls on every configured node. |
| Kubernetes `imagePullSecrets` | Namespace or ServiceAccount | Per-application or per-namespace registry credentials. |

`imagePullSecrets` are Kubernetes Secrets containing Docker/Podman-style registry credentials. Pods reference them directly or inherit them from a ServiceAccount.

Example pod-level shape:

```yaml
imagePullSecrets:
  - name: registry-pull
```

Production hardening should also add authenticated smoke tests that verify:

- anonymous push and pull fail when auth is enabled;
- authenticated Podman image push/pull succeeds;
- authenticated Helm OCI chart push/pull succeeds;
- Kubernetes can pull an authenticated test image through the chosen credential path.

## Image Signing And Signed-Only Enforcement

Image signing and signed-only enforcement are separate controls.

Signing proves who produced an image and whether the image digest matches what was signed. Enforcement decides where unsigned or untrusted images are rejected.

Recommended production model:

- CI builds images and pushes them to Zot.
- CI signs immutable image digests with Cosign or Notation.
- Signatures are stored as OCI artifacts in the registry.
- Workloads reference immutable digests or versioned tags, not `latest`.
- Kubernetes admission policy rejects images without a valid signature from trusted identities or keys.

Zot supports a `trust` extension for verifying uploaded image signatures with Cosign and/or Notation. A production Zot config can enable this through `zot_registry_extra_config` or a future first-class role variable:

```yaml
zot_registry_extra_config:
  extensions:
    trust:
      enable: true
      cosign: true
      notation: true
```

Zot trust requires the corresponding public keys or certificates to be available to Zot. Store key material and certificate bundles outside public Git. Document the key ownership and rotation process before enforcing this in production.

Registry-side trust is useful, but do not rely on it as the only signed-only control for Kubernetes. It protects registry contents and upload policy, but Kubernetes still needs an enforcement point before a Pod is admitted or run.

Common Kubernetes enforcement options include:

| Option | Where It Enforces | Notes |
|---|---|---|
| Kyverno `verifyImages` | Kubernetes admission | Practical policy engine for requiring Cosign signatures per registry, namespace, or image pattern. |
| Sigstore Policy Controller | Kubernetes admission | Sigstore-focused admission control for Cosign/keyless policies. |
| Gatekeeper or custom admission webhook | Kubernetes admission | Flexible, but signature verification usually requires additional integration. |
| Node/runtime policy | Container runtime or node | Stronger runtime boundary, but more platform-specific and not currently configured here. |

For this platform, the likely hardening sequence is:

1. Add CI signing for platform images, starting with `platform/bootstrap-token-issuer` and later `platform/bootstrap-cert-controller`.
2. Store signatures in Zot with the images.
3. Add registry smoke tests that sign a small image and verify the signature can be checked.
4. Add Kubernetes admission policy in audit or warn mode.
5. Move to enforce mode after all platform workloads use signed images.
6. Add negative smoke tests that confirm unsigned images are rejected.

Do not enable signed-only enforcement until image publishing, key management, emergency break-glass, and upgrade workflows are documented. Otherwise a lost key, expired identity policy, or unsigned urgent fix can block deployments.
