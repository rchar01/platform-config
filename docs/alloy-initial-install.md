# Fresh Host-Native Alloy Installation

This workflow installs one fresh Alloy collector using the existing client PKI
exchange and guarded initial-start tasks. Initial issuance has **no predecessor**:
use `issue`, not `renew`. The renewal preflight is for a later lifecycle and is
not part of this sequence.

All playbooks require `--limit` naming exactly one inventory host. Use reviewed
private inventory for host settings, identities, trust, transport and source pins.
The playbooks select fixed task entries; they do not enroll groups or run through
`site.yml` or the blocked combined `monitoring.yml` playbook.

## Inputs

Before creating a request, review the
[Alloy initial inputs](../roles/grafana_alloy/README.md#guarded-initial-start) and
[client PKI inputs](../roles/pki_host_local_certificate/README.md#initial-client-request-and-staging).
Use separate Loki and Mimir services, subjects, keys and roots when both outputs
are configured. Both requests must bind the same final signer-inventory snapshot.

For each writer, the private PKI variables must select:

```yaml
pki_host_local_certificate_operation: issue
pki_host_local_certificate_profile: client-p384-sha384-v1
pki_host_local_certificate_service_adapter: client-stage-v1
pki_host_local_certificate_current_cert_sha256: "none"
pki_host_local_certificate_current_cert_path: ""
```

The service must match `grafana_alloy_initial_writers[writer].service`; target and
requester principal must match the inventory hostname. Bind the reviewed subject,
duration, trust ID, final inventory hash and minimum remaining validity through
the existing PKI variables. For `<writer>` equal to `loki` or `mimir`, use:

| PKI variable | Alloy initial path |
| --- | --- |
| `pki_host_local_certificate_state_root` | `/var/lib/platform-config/pki/alloy/<writer>` |
| `pki_host_local_certificate_pending_root` | `/etc/alloy/pki/<writer>/tls-pending` |
| `pki_host_local_certificate_versions_root` | `/etc/alloy/pki/<writer>/tls-versions` |

Provision the protected parent directories, reviewed trust sources, request signer
and selected exchange access as described in [PKI Exchange Setup](pki-exchange-setup.md).
Keep each writer's exchange/config/spool paths separate. The generic PKI plays
consume one reviewed service's variables per invocation; they do not infer a writer
from path names or select package coordinates. The existing PKI repository-policy
dependency and all client validators still apply.

## Ordered Workflow

| Step | Playbook | Result |
| --- | --- | --- |
| 1 | `grafana-alloy-boundary.yml` | Controller-only pre-CSR boundary hashes; supports check mode |
| 2 | `pki-client-request.yml` | Target-local fresh key and signed public request for one writer |
| Handoff | Existing `platform-tools` offline signing and exchange | Reviewed signed response; the leaf key stays on the target |
| 3 | `pki-client-stage.yml` | Authenticated immutable client version for that writer |
| 4 | `grafana-alloy-stage.yml` | Installed/configured Alloy with disabled/stopped intent |
| 5 | `grafana-alloy-initial-prepare.yml` | Exact initial control inputs and process-owner protection |
| 6 | `grafana-alloy-initial-start.yml` | Guarded first enable/start after reviewed active intent |

1. Run boundary review with draft signer inventory, its matching hash, the pinned
   tools artifact and intended Alloy settings. Review and insert the emitted
   boundary hashes into signer inventory, then update its SHA-256 references before
   issuing either request. Version IDs are normalized during boundary generation;
   certificate paths are not needed until staging/configuration.
2. Run request publication once for each configured writer using its own private
   variable set. Complete the separate offline approval/signing/transfer handoff,
   then run response staging with the same reviewed inputs.
3. Record the returned authenticated `version_path` in the private Alloy settings:
   `<version_path>/fullchain.crt` and `<version_path>/tls.key`. Provision the reviewed
   server CA file matching each configured CA hash. Keep role intent
   `grafana_alloy_enabled: true`, `grafana_alloy_service_enabled: false`,
   `grafana_alloy_service_state: stopped`.
4. Run Alloy staging. It rejects active, enabled, masked, foreign or unknown units and
   retained process-owner protection before ordinary convergence. It reuses the
   existing role for RPM/configuration installation. Check mode can predict
   changes; it does not prove native config validation on an absent RPM.
5. Run initial preparation after staging has completed, including its handlers.
   Preparation authenticates the credentials and installed configuration and
   installs only absent control inputs. From this point ordinary convergence is
   blocked: use the initial status/start/recovery entries.
6. For an approved first start, change the reviewed private service intent to
   `grafana_alloy_service_enabled: true` and `grafana_alloy_service_state: started`.
   Invoke initial start separately. It uses the already prepared files, checks
   signed validity admission, starts Alloy and records local readiness.

The existing Make entry points run Ansible in the dev container. For example,
using an illustrative host name and a reviewed writer-variable file available
inside that container:

```bash
make check ENV=dev PLAYBOOK=playbooks/grafana-alloy-boundary.yml LIMIT=collector-01
make apply ENV=dev PLAYBOOK=playbooks/pki-client-request.yml LIMIT=collector-01 \
  EXTRA_ARGS='-e @/platform-private/config/pki/collector-01-loki.yml'
# Offline review, signing and response transfer occur here.
make apply ENV=dev PLAYBOOK=playbooks/pki-client-stage.yml LIMIT=collector-01 \
  EXTRA_ARGS='-e @/platform-private/config/pki/collector-01-loki.yml'
# Repeat request/signing/staging for Mimir if configured, then record direct paths.
make apply ENV=dev PLAYBOOK=playbooks/grafana-alloy-stage.yml LIMIT=collector-01
make apply ENV=dev PLAYBOOK=playbooks/grafana-alloy-initial-prepare.yml LIMIT=collector-01
# Review active desired state and approve first start before this separate action.
make apply ENV=dev PLAYBOOK=playbooks/grafana-alloy-initial-start.yml LIMIT=collector-01
```

Request, response-stage, initial-prepare, initial-start and initial-recover reject
check mode. Boundary, stopped staging and initial status support it. Examples are
separate phases, not an unattended installation script.

## Status, Recovery And Acceptance

`grafana-alloy-initial-status.yml` authenticates the prepared initial inputs and
reports their status without mutation. An interrupted start uses
`grafana-alloy-initial-recover.yml`, which authenticates retained intent and
restores disabled/inactive state. Recovery does not retry the start or turn a
failed activation into success. Preserve unknown or failed records for review.

Keep lifecycle work and out-of-band file/service edits exclusive during the
sequence. A local `/-/ready` result does not establish Loki/Mimir ingestion:
receiver deployment, routing, strict TLS/client identity acceptance and a stored
canary query remain separate acceptance work. These initial-only plays do not
implement certificate rotation or operational rollback.
