# Registry Operations

The fixed registry routes configure a fresh, already-provisioned Zot host using
target-local filesystem certificate exchange. `platform-ci` owns the GitLab jobs;
private inventory owns topology, trust, storage intent and component/source pins.
VM creation remains in `platform-infra`.

## Prerequisites

- Complete the [Rocky Ansible-access preparation](ansible-host-bootstrap.md).
  SSH, the inventory-selected Python interpreter and passwordless non-TTY sudo
  must already work. Host configuration does not bootstrap its own connection.
- Require exactly one `registry` host in `rocky`, `container_hosts` and
  `storage_volume_hosts`, disjoint from `registry_clients`, `gitlab_runners`,
  RKE2 and OpenBao. Client preparation and smoke require nonempty
  `registry_clients`; clients may be Runner hosts.
- Select `pki_host_local_certificate_transport: filesystem`, initial `issue`,
  adapter `zot-v1`, and empty controller certificate/key sources. Configure the
  existing lifecycle identity, reviewed trust/CA pins and fixed exchange root/UID.
  See [PKI Exchange Setup](pki-exchange-setup.md).
- Pre-provision operator transfer access. Only the signed three-file request and
  six-file response use the host exchange directories; pending private keys,
  trust and lifecycle state are outside that access.
- Review storage disk identity and initialization intent before any apply. Exactly
  one declared mounted volume must contain `zot_registry_data_dir`; unrelated or
  overlapping data mounts fail. Stage also verifies the actual mounted storage
  before reaching Zot tasks. Keep registry images and the operational controller
  image independently available.

## Fixed Routes

Each invocation accepts only `--inventory ABS` and `--controller-vars ABS`:

```bash
./scripts/in-container bash scripts/platform-config-operation registry-host-plan \
  --inventory /outside-git/inventory/hosts.yml \
  --controller-vars /outside-git/controller-vars.json
```

Paths must be accessible inside the container. Controller JSON is an owner-private
regular file using the existing [transport-only schema](storage-check.md#storage-apply).
It cannot override lifecycle state, certificate coordinates or inventory values.
The launcher validates and snapshots it before inventory execution, then checks
selected-host key coverage. It accepts no node, limit, arbitrary playbook or extra
arguments.

| Automatic plan | Separately approved action | Scope and work |
| --- | --- | --- |
| `registry-host-plan` | `registry-host-apply` | Registry only: existing bootstrap and base-OS playbooks, each checked before apply and zero-change post-checked. |
| `registry-storage-plan` | `registry-storage-apply` | Registry only: storage check, apply, real second zero-change apply, read-only mounted verification. |
| `registry-stage-plan` | `registry-stage-apply` | Registry only: existing registry playbook, including firewalld, Podman, dormant Zot and reviewed CA trust. |
| `registry-clients-plan` | `registry-clients-apply` | All declared clients: existing client tools and CA trust roles, with zero-change post-check. |
| `registry-pki-request-plan` | `registry-pki-request` | Registry only: read-only readiness, then existing target-local request/export route. |
| `registry-pki-activate-plan` | `registry-pki-activate` | Registry only: read-only authenticated lifecycle readiness, then existing response import/activation route. |
| `registry-smoke-plan` | `registry-smoke` | Registry and all clients: input/trust plan, then existing API/UI/OCI/Podman/Helm smoke and zero-change registry/client post-check. |

Every phase requires complete successful evidence before the next command. A zero
Ansible exit code with missing, failed, unreachable, ignored or rescued host
results is insufficient. Plans allow predicted changes; preflights, post-checks,
storage verification and the second storage apply must report zero changes.

Host, storage and staging routes require an absent or masked/stopped Zot service,
empty/absent registry data, and no existing PKI lifecycle state. They are fresh
preparation routes, not active-registry maintenance. Staging installs the native
PKI helper and its Python cryptography dependency while leaving Zot dormant.
Inventory defaults are resolved separately so explicit values retain precedence.

Request/activation plans do not invoke certificate mutation in Ansible check
mode. Request readiness verifies staged bytes, signing tools/key metadata,
protected source pins and exchange parents; existing pending requests still go
through the helper's authenticated replay validation on apply. An initial issue
cannot create a new request over an active predecessor.

Activation uses authenticated target status. Completed replay is allowed without
needing an offline response again. An interrupted journal can require recovery;
restoring safety is not proof of successful activation. Terminal failed states
fail preflight, and the action still requires final `complete/none`. Actionable
activation checks the reviewed CA source before response import. The existing
helper owns validation and rollback.

## GitLab Deployment Sequence

The `platform-ci` `registry-operations` component uses seven closed selectors and
two visible jobs: automatic plan and dependent blocking manual action. It stages
only selected SSH identities and the public files needed by the selected phase, fetches
an immutable config revision, and invokes the fixed routes. See that component's
`docs/registry-operations.md` for its exact File-variable contract.

Host/storage need only source-fetch CA trust. Stage/clients/smoke also need the
registry validation CA. Both PKI phases additionally need the four reviewed
signer/policy trust sources. Request planning and execution share the same
read-only filesystem path checks; execution repeats them before writing.

1. Publish reviewed config/component revisions and bind their immutable private
   pins and an independently available operations-image digest. Qualify target
   GitLab CI expansion and protected variable/Runner access.
2. After the infrastructure/access handoff, select `registry-host`, then
   `registry-storage`, reviewing each plan before manual apply. After authorized
   disk initialization, commit `initialize: false` privately and start new plans
   on that revision.
3. Select `registry-stage`, then `registry-clients`. Confirm dormant Zot and
   reviewed client trust before requesting a certificate.
4. Select `registry-pki-request`. Retrieve only `tls.csr`, `request` and
   `request.sig` from the pre-provisioned host exchange. Carry the authenticated
   request ID through the separately authorized offline approval/signing process.
   Choose inventory TTL to accommodate the signer policy and actual turnaround.
5. Upload exactly `artifact`, `tls.crt`, `ca-chain.crt`, `fullchain.crt`, `response`
   and `response.sig` with the required ownership/modes to the host response
   directory. Select `registry-pki-activate` and separately approve its action.
6. Select `registry-smoke`. This is a mutating acceptance test: it writes retained
   OCI/image/chart artifacts. Its plan checks inputs and trust, not future
   push/pull success. Complete strict TLS and zero-change post-checks before
   recording acceptance; qualify reboot persistence separately.

CI never receives the exchange payloads, leaf keys or offline signer keys, and
publishes no PKI artifacts. Source-fetch TLS trust is independent of registry CA
trust. Mutation jobs use the existing shared writer lock; finish all plans/reads
before mutation and exclude out-of-band work. Cancellation is not rollback.

The filesystem lane is issue-only. Active certificate renewal, authenticated
registry credential delivery, image publication, RKE2 worker pulls and production
qualification need their own reviewed procedures. Offline tests do not establish
the fresh VM, GitLab permissions, transfer access or live service acceptance.
