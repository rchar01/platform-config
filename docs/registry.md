# Registry

The dev registry is a Zot OCI registry deployed by `zot_registry` on hosts in the `registry` group. Registry client smoke tooling is installed by `registry_client_tools` on hosts in the `registry_clients` group.

## Host-Local PKI Development

The `playbooks/registry-pki-*.yml` playbooks are operator-only host-local
certificate entry points. They are not imported by `site.yml` or normal
registry convergence. The implemented workflow imports one explicit
digest-pinned authenticated signer outcome after deployment evidence export. It
does not automate signing, controlled-media transport, or renewal.

The trust playbook is a separate initial-install-only bootstrap. It requires an
explicit exact five-key `pki_host_local_certificate_trust_sources` mapping to
mode-`0600` reviewed public files outside this repository and matching values
in `pki_host_local_certificate_trust_sha256`. A fixed action plugin pins each
controller source and ancestor by descriptor, validates metadata and digest,
rechecks identity throughout transfer, and sends only the validated in-memory
bytes to protected target ingress. It validates schema-2 policy, lowercase
principals, Ed25519 OpenSSH public-key blobs, matching requester membership in
request and deployment trust, and exact policy-pinned approver and response
sets. The target helper holds the
same state lock used by request generation, pins the target state hierarchy,
validates protected ingress, journals the stage device and inode, stages on the
trust filesystem, fsyncs the transaction, and publishes the complete five-file
directory with a descriptor-relative no-clobber rename. Recovery and cleanup
mutate only journal-bound descriptor-relative entries. It accepts only initial
install or an inode-preserving exact protected no-op. The no-op permits validated
canonical `active`, `rollback`, `validation-boundary`, and `evidence` lifecycle
siblings but rejects unresolved journals and unknown state. It does not
implement trust rotation.

The request entry point validates preinstalled frozen target trust, installs the
reviewed request helper, and generates or revalidates one root-owned local P-384
key, CSR, canonical request, and SSH signature. Outside check mode, its fixed
action collects only `tls.csr`, `request`, and `request.sig` into the protected
controller exchange and publishes a frozen copy of the reviewed trust beside
the request. The separate
`scripts/platform-pki-gitlab-package` helper can validate and publish an already
collected canonical request package to one exact GitLab Generic Package
coordinate; it does not collect from the target or create the receipt or stage
manifest. See [GitLab PKI Package Exchange](pki-gitlab-package.md).

Place an externally produced response in one protected controller directory
containing exactly `artifact`, `tls.crt`, `ca-chain.crt`, `fullchain.crt`,
`response`, and `response.sig`. Response check authenticates and immutably
publishes that response entirely on the controller; it does not contact Zot or
mutate the target. Activation then performs exact response ingress, requires the
operator to type
`activate SERVICE REQUEST_ID ARTIFACT_SHA256`, updates Zot transactionally, and
validates strict HTTPS `GET /v2/` behavior from exactly one distinct reviewed
runner. Explicit recovery acts only on a journal-bound interrupted transaction.

Use these Make entry points with one exact registry `LIMIT` and carry the exact
request, artifact, and deployment coordinates returned by each phase:

```bash
make registry-pki-validation-material ENV=dev LIMIT=registry-example \
  RUNNER_LIMIT=registry-validator-example
make registry-pki-request ENV=dev LIMIT=registry-example
make registry-pki-request ENV=dev LIMIT=registry-example \
  REQUEST_TTL_SECONDS=604800
make registry-pki-abandon-expired-request ENV=dev LIMIT=registry-example \
  REQUEST_ID=<expired-request-id>
make registry-pki-cancel-request ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> REQUEST_SHA256=<request-sha256>
make registry-pki-status ENV=dev LIMIT=registry-example
make registry-pki-response-check ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  RESPONSE_DIR=/outside-git/protected-response
make registry-pki-activate ENV=dev LIMIT=registry-example \
  RUNNER_LIMIT=registry-validator-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256>
make registry-pki-publish-rolled-back-evidence ENV=dev \
  LIMIT=registry-example RUNNER_LIMIT=registry-validator-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256>
make registry-pki-evidence-export ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  DEPLOYMENT_SHA256=<deployment-sha256>
make registry-pki-status ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  DEPLOYMENT_SHA256=<deployment-sha256>
make registry-pki-decision-preflight ENV=dev LIMIT=registry-example \
  RUNNER_LIMIT=registry-validator-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  DEPLOYMENT_SHA256=<deployment-sha256>
make registry-pki-outcome-import ENV=dev LIMIT=registry-example \
  REQUEST_ID=<request-id> ARTIFACT_SHA256=<artifact-sha256> \
  DEPLOYMENT_SHA256=<deployment-sha256> \
  OUTCOME_SHA256=<outcome-manifest-sha256> \
  OUTCOME_DIR=/outside-git/export/csr-outcomes/v1/artifacts/registry-dev/<request-id>
```

Request lifetime defaults to 3600 seconds. `REQUEST_TTL_SECONDS` is an explicit
per-invocation override from 1 through the schema-2 policy maximum of 604800;
it is not persisted in private inventory. Expired request abandonment requires
the exact request ID, refuses unexpired or response-bearing state, removes only
the unused pending request and key, and never changes Zot's active TLS paths.
Exact cancellation is a separate on-demand operation that requires both the
request ID and request digest and applies the same consumer-state guards.
After recovery restores an activated candidate's predecessor, rolled-back
evidence publication strictly revalidates that predecessor locally and from the
reviewed runner before signing evidence and clearing the retained journal.
Migration requests canonicalize the first leaf from Zot's current certificate
file, so a deployed fullchain binds the signer-managed leaf digest rather than
the concatenated file digest.

Validation material provisioning is a separate prerequisite boundary. It pins
current-user-owned mode-`0600` reviewed CA and validation-boundary controller
sources outside this public repository, validates their exact contents, and
installs them at the existing lifecycle target and runner destination
coordinates on the one selected registry and one distinct delegated runner.
The reviewed CA must contain exactly the profiled intermediate followed by its
self-signed root, with valid chain signatures.
The CA uses the configured mode (`0600` or `0644`); the boundary and all parent
directories remain private. Set the controller paths with
`pki_host_local_validation_material_reviewed_ca_src` and
`pki_host_local_validation_material_boundary_src`; the role reuses the existing
certificate lifecycle destination and digest variables. The lifecycle role does
not import this provisioning role.

Trust bootstrap remains a separate one-time action without a dedicated Make
wrapper:

```bash
make apply ENV=dev PLAYBOOK=playbooks/registry-pki-trust.yml \
  LIMIT=registry-example
```

Trust check mode is non-mutating. Exact installed trust can be revalidated; an
absent install requires the helper, protected state root and lock, and complete
protected ingress to exist already before it can report `would-install`.
Interrupted journaled state fails rather than being recovered in check mode.
Request check mode similarly runs the request helper's complete non-mutating
preflight and requires the reviewed helper and state lock to be installed
already; it fails rather than reporting incomplete readiness. Activation check
mode validates the installed response and candidate without transfer, prompts,
service restart, runner invocation, or cleanup. Status, response check, evidence
export, and decision preflight remain read-only with respect to Zot.

Outcome import accepts exactly `outcome`, `outcome.sig`, `deployment`,
`deployment.sig`, `deployers.allowed_signers`, and `decision` from one explicit
current-user-owned mode-`0700` controller directory. Every file must be a
single-link mode-`0600` regular file. The controller independently verifies the
outcome signature with frozen response trust and verifies deployment evidence
with frozen deployer trust. The target repeats both checks against its own frozen
trust and requires the deployment and signature to equal its exact evidence
attempt. Normal mode uses a protected randomized transient target stage. Check
mode fully authenticates and rechecks the controller package, then invokes a
read-only target preflight with canonical scalar outcome coordinates through the
safely quoted, become-aware low-level connection path. It executes no Ansible
module, creates no AnsiballZ payload, remote stage, or Ansible transfer path, and
leaves lifecycle and Zot state unchanged. Target preflight authenticates active
state from named public version files, signed request material when available,
the signed response, artifact/certificate chain, and matching signed target
evidence. It does not enumerate or access the private-key version entry and does
not claim to authenticate the package signature. No private key crosses either
boundary.
More strictly, the importer never stats, opens, reads, hashes, stages, or
transfers candidate/version/restored-managed private-key files. Managed rollback
validation parses the restored Zot TLS path object but accesses only its selected
public certificate chain. Other target bindings use authenticated public outcome
and deployment records, exact target evidence, certificate digests, and
active/rollback records.

Accepted immutable history is stored at
`STATE_ROOT/outcomes/REQUEST_ID/OUTCOME_SHA256/`; the authenticated pointer is
`STATE_ROOT/accepted-outcome`. A finalized outcome reports `status=complete`,
`signer_outcome_state=finalized`, `evidence_state=controller-exported`, and
`required_action=none` only while current target active state remains consistent.
`renewal_eligible` remains false because authenticated renewal completion is not
implemented by this workflow.
An abandoned outcome with no predecessor or authenticated managed-migration
rollback reports
`status=signer-outcome-abandoned` without treating the abandoned candidate as
active. Finalized managed predecessors must exactly match rollback
certificate/SPKI/public-chain state; managed response, artifact, deployment, and
decision history fields are `none`. Managed rollback abandonment additionally
requires signed served leaf/intermediate evidence to match the restored
Zot-selected public certificate chain. Host-local predecessor
outcomes fail closed until rollback history records authenticated predecessor
intermediate, response, deployment, and decision digests. Abandonment with a
non-managed predecessor also fails closed because terminal cleanup removes the
candidate rollback record required to prove it. Missing outcomes preserve
`evidence-exported` and `await-signer-outcome`. Historical signer packages are
evidence, not live authority; target active state remains mandatory.

Pointer publication is atomic and no-clobber. If interruption leaves immutable
history without `accepted-outcome`, status fails closed; rerun the import with the
same exact digests and source package to authenticate that history and publish
the pointer. Ordinary failures remove the randomized remote stage and temporary
pointer stage. If remote stage identity changes or verified cleanup is
impossible, the action fails and reports the retained canonical stage. Preserve
that stage as failure evidence, confirm no import remains active, and inspect it
under the approved host-local PKI recovery procedure before removing only that
exact reported path. A retained `.accepted-outcome-stage-*` similarly blocks
import as ambiguous lifecycle state until that exact root-owned stage is reviewed
and recovered. Never use wildcard stage cleanup.

Managed Zot TLS custody remains the default. After activation has authenticated
an active version, private inventory may set:

```yaml
zot_registry_tls_custody: host-local
zot_registry_tls_host_local_target: registry-example
```

Normal registry convergence then resolves the immutable `fullchain.crt` and
`tls.key` paths through the lifecycle helper; inventory cannot select those
paths. The role refuses any host-local rendered configuration drift rather than
invalidating the authenticated active record. Do not run a live request,
activation, or package publication until private inventory, reviewed trust and
CA files, the validation boundary, runner identity, controlled-media process,
and any GitLab project controls have been separately approved.

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
