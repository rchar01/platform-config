# openbao

Stages one node of the approved three-node OpenBao Integrated Storage design.
The role is disabled by default, and the service remains disabled and stopped
by default after configuration is enabled.

The role owns:

- the immutable OpenBao `2.6.1` `linux/amd64` image reference;
- canonical three-node identity and retry-join validation;
- host-network backend and cluster listeners;
- outside-Git public CA installation and authenticated host-local leaf custody;
- manual Shamir sealing by omission of any Auto Unseal stanza;
- non-root Quadlet execution with swap disabled at the service boundary;
- native `operator validate-config` candidate validation inside the pinned
  image before atomic configuration replacement; and
- reconciled backend and cluster firewalld rules.

The selected standard image is pinned to the GHCR `linux/amd64` platform
manifest `sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0`.
Inspection of that exact artifact reports OpenBao `2.6.1`, architecture `amd64`,
runtime user `openbao`, UID `100`, and GID `1000`. Those numeric IDs are an
artifact-specific contract, not a promise made by the mutable Alpine image
source.

## Required Inputs

Set `openbao_enabled: true` only after the public CA source and all four service
mounts exist. Provide exactly three canonical members:

```yaml
openbao_cluster_members:
  - name: openbao-01
    node_id: bao-1
    address: 192.0.2.63
    dns: bao-1.internal.invalid
  - name: openbao-02
    node_id: bao-2
    address: 192.0.2.64
    dns: bao-2.internal.invalid
  - name: openbao-03
    node_id: bao-3
    address: 192.0.2.65
    dns: bao-3.internal.invalid
```

Each host's `openbao_node_name`, `openbao_node_address`, and
`openbao_node_dns` must exactly match its canonical mapping. The role verifies
that the local address exists before rendering a host-network listener.

By default these paths must already be separate mounts:

- `/var/lib/openbao`
- `/var/log/openbao/audit-1`
- `/var/log/openbao/audit-2`
- `/var/lib/openbao-backup-staging`

The role never creates, formats, or mounts service storage. It sets ownership
only on the existing mount roots and does not recursively rewrite persisted
data.

The stable `/etc/openbao/openbao.hcl` base configuration, declarative
`/etc/openbao/audit.hcl`, and adapter-owned `/etc/openbao/listener.hcl` are
mounted together at `/openbao/config`. Before a host-local PKI request exists,
the role may stage only the exact dormant listener on pristine storage while
the service is stopped and disabled. Its `/openbao/config/tls/tls.crt` and
`tls.key` selections must remain absent; the role never creates placeholders or
transfers leaf material from the controller.

Once lifecycle state exists, the role invokes the fixed
`openbao-pristine-v1` `openbao-custody` adapter and accepts only its strict
authenticated schema-2 result. Authenticated versions remain under
`/etc/openbao/tls-versions/<request-id>/`, visible through the existing config
directory mount at `/openbao/config/tls-versions/<request-id>/`. Normal
convergence validates but does not replace the adapter-owned active listener.

## Activation Boundary

Normal convergence does not initialize or unseal OpenBao, handle custody
material, create credentials, restore data, configure HAProxy, or activate a
VIP. Leave:

```yaml
openbao_service_enabled: false
openbao_service_state: stopped
```

until the owning HA plan's storage, PKI, direct-backend, and pre-initialization
runtime gates pass. Keepalived remains independently disabled until HAProxy,
network, observer, and canary acceptance passes.

When explicitly started, the role verifies the node-specific backend endpoint
with the installed CA and DNS identity. It accepts active, standby, sealed, or
uninitialized health status only as process-readiness evidence; it does not call
those states cluster acceptance. Post-initialization health, voter membership,
manual unseal, and rolling restart gates remain separate workflows.

Use `playbooks/maintenance/openbao-bootstrap-start.yml` only once against exact
pristine staged storage. It requires the private bootstrap readiness gate, an
explicit full-cluster limit, canonical member DNS resolution, immediate evidence
revalidation, and three uninitialized sealed TLS processes. It leaves the
services running without boot enablement and writes root-only non-secret markers
for the manual custody checkpoint.

Two approved custodians then initialize exactly one node with five Shamir shares
and threshold three, store shares and the initial root token outside Ansible,
unseal all voters, verify both declarative file audit devices, create the
least-privilege status identity, and retain the initial root token in approved
custody until named administrator authentication is configured and verified.
Neither bootstrap playbook accepts shares or the root token.

For a pending cluster created before `audit.hcl` was staged, use the guarded
`playbooks/maintenance/openbao-audit-migrate.yml` path. Normal convergence
refuses this transition because declarative audit paths cannot adopt devices
previously enabled through the API. The attended migration requires an approved
root session to prove that no API-created devices exist; the root token remains
outside Ansible.

`playbooks/maintenance/openbao-bootstrap-complete.yml` verifies the unchanged
pending markers, two audit devices, one active and two standbys, exact stable
three-voter Raft state, and then renders generated boot enablement. Unknown or
partially initialized state is preserved for reviewed recovery rather than reset.

Post-initialization changes that may restart OpenBao belong in the explicit
`playbooks/maintenance/openbao-rolling-restart.yml` workflow. The role reports
`openbao_restart_required` only when restart-notifying content changed while the
service is enabled and requested started. The maintenance playbook owns
standby-first serial ordering, the manual-unseal pause, and strict voter recovery
before another node can converge.
