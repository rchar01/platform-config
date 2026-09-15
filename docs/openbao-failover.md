# OpenBao HAProxy Failover and Recovery

The fixed Ansible maintenance operation tests one approved HAProxy failure on
the current OpenBao VIP owner. It restores HAProxy and verifies the complete
cluster before releasing its transaction guards. GitLab provides the read-only
plan, protected manual test, and independently selectable manual recovery job.
Operator controllers use the same playbook with exact TTY-bound approval.

A fresh test is deliberately disruptive and needs a fresh approval. Repeating
an existing transaction performs recovery or verification without another stop.
Offline tests establish orchestration behavior, not live VRRP, network, TLS, or
service qualification.

## Prerequisites

- Exactly three canonical OpenBao hosts, initialized and active, with healthy
  three-voter Raft state, the reviewed status identity, and strict controller CA
  trust and hostname resolution.
- HAProxy and Keepalived desired state explicitly enabled/started on all hosts,
  with actual boot enablement and healthy paths. Keep activation readiness false.
  Services are fixed to `haproxy.service` and `keepalived.service`.
- Successful full VIP smoke. Actual Keepalived configuration must match the
  reviewed template, tracking HAProxy eligibility and the client port. Plans
  bind configuration/CA checksums, cluster identity, topology, timing, and owner.
- Clean, committed public source and private inventory checkouts. Keep plan
  evidence, access policy, credentials and operational reports private.
- Serialized lifecycle work. Shared target edge guards exclude supported
  activation and failover operations; CI mutations also use the canonical
  resource group. These guards do not coordinate root, rolling operations, or
  out-of-band changes. Finish existing reads and prohibit concurrent lifecycle
  and configuration changes until the test or recovery completes.

The operation stops only the planned owner's HAProxy, preserving boot enablement.
It does not converge configurations, restart OpenBao, change Keepalived lifecycle,
or manipulate Raft or storage.

## Fixed Routes

All routes require one absolute inventory path and an owner-private controller
JSON file using the existing OpenBao transport/status-source contract. The
launcher selects the complete `openbao` group; it accepts no node selector or
arbitrary Ansible arguments.

| Route | Plan argument | Behavior |
| --- | --- | --- |
| `openbao-haproxy-failover-plan` | Required, new output file | Read-only baseline and owner-bound plan |
| `openbao-haproxy-failover` | Required, reviewed input file | One approved fault, restore, and smoke; retained transactions recover/verify only |
| `openbao-haproxy-failover-recover` | Forbidden | Discover retained target records, restore their recorded owner, and verify |

On the reviewed Ansible controller, with these variables set to absolute paths
visible to that controller:

```bash
scripts/platform-config-operation openbao-haproxy-failover-plan \
  --inventory "$INVENTORY" --controller-vars "$CONTROLLER_VARS" --plan "$PLAN"

scripts/platform-config-operation openbao-haproxy-failover \
  --inventory "$INVENTORY" --controller-vars "$CONTROLLER_VARS" --plan "$PLAN"

# After interruption or a retained recovery obligation:
scripts/platform-config-operation openbao-haproxy-failover-recover \
  --inventory "$INVENTORY" --controller-vars "$CONTROLLER_VARS"
```

Operator plan output is a new `0600` file in an existing current-owner `0700`
non-symlink directory outside every Git repository. Test and recovery require
an interactive terminal and exact approval. Use the Podman development controller
for Ansible tooling; do not install project Python dependencies on the host.

### GitLab Jobs

Private composition selects `openbao-haproxy-failover` to create
`<prefix>-haproxy-failover-plan` and its dependent protected manual
`<prefix>-haproxy-failover-test`. Review the exact owner and digest before starting
the manual job. Fresh stop authorization expires after 1800 seconds;
revalidation must still pass before arming.

The only plan artifact is `.openbao-plans/haproxy-failover.json`, with Maintainer
access and 30-minute expiry, downloaded only by the matching test. The component
stages it outside the private checkout before cleanliness checks. All three jobs
have `retry: 0` and are non-interruptible. Planning has a 30-minute timeout; test
and recovery have two-hour execution allowances and share the mutation lock.
Native manual approval is a GitLab permission/UI boundary, not API-proof approval.

Select `openbao-haproxy-failover-recover` in a later protected web pipeline to
create `<prefix>-haproxy-failover-recover`. It requires no old artifact. Keep the
same public/private revisions, inventory, environment, CI project, image, and job
family as the retained record; only pipeline identity and expired stop deadline
may differ for recovery. Do not advance those pins while recovery is outstanding.
Private composition must pin published config and component revisions containing
these routes before selecting them.

## Proof, Timing, and Results

After all three guards are claimed, Ansible rechecks full baseline and exact plan
evidence. It persists one stop intent on the owner before stopping HAProxy, then
verifies actual inactive state and retained boot enablement. After a bounded
tracking/election interval it requires a different stable single VIP owner,
strict TLS HTTP `200` through forced-VIP and ordinary name resolution, and the
original healthy OpenBao cluster identity and quorum.

Restoration starts only the recorded owner's HAProxy. Ownership is sampled
through configured delayed preemption, then full direct-node, all-HAProxy, and
VIP smoke must pass on all three hosts before release. The normal 300-second
preemption delay is respected; failback is not assumed immediate.

The failover-only timing envelope accepts preemption delay 60–1000 seconds;
advertisement/script intervals and fall/rise counts 1–10; status request timeout
1–5 seconds, retries 1–10, retry delay 0–2 seconds, stability observations 2–3,
and observation delay 1–2 seconds. Timing values must agree across the cluster.
At the maximum, the status request/retry allowance is 459 seconds per execution;
six executions across four phases sum conservatively to 2754 seconds. Recovery
settling adds at most 1152 seconds and fault detection 152 seconds. The two-hour
CI allowance leaves time for SSH, Ansible and remaining checks; it is not a
guarantee against a hung process or controller failure.

Reports retain separate per-host fields:

- `failover_test_result`: `passed`, `failed`, or `not_run`;
- `recovery_result`: `passed`, `failed`, or `not_required`;
- `final_smoke_result`: `passed`, `failed`, or `not_run`;
- `failover_elapsed_seconds`: fault start through successful global proof;
- `transaction_elapsed_seconds`: fault start through recovery completion.

Unmeasured timing remains null. Missing host reports cannot produce success.
A failed test remains failed even if recovery and final smoke pass. A later
recovery-only job can succeed while reporting the historical failed proof.

If initial plan validation rejects a fresh test, its failed task and summary
show an allowlisted reason without printing the private plan:

| Code | Meaning |
| --- | --- |
| `PLAN_EXPIRED` | The 1800-second authorization expired before validation, including time spent on baseline checks. |
| `PLAN_NOT_YET_VALID` | The plan creation time is in the future relative to the controller clock. |
| `VIP_OWNER_CHANGED` | Current ownership differs from the approved owner. |
| `BASELINE_CHANGED` | Current baseline evidence differs from the plan. |
| `SOURCE_OR_CI_IDENTITY_CHANGED` | Source, inventory, scope, environment, or CI identity validation failed. |
| `INVALID_PLAN_ARTIFACT` | Plan reading, schema, or digest validation failed. |
| `PLAN_VALIDATION_FAILED` | Validation failed without a recognized public reason. |

This pre-fault rejection reports `not_run` / `not_required` / `not_run`, with
unmeasured timings and overall failure. No guard acquisition or HAProxy stop is
attempted. Inspect the reason before generating a fresh plan; the checks and
authorization deadline remain mandatory. Protected evidence stays under `no_log`.

## Recovery and Persistent Records

The target-root helper uses `/var/lib/platform-config/openbao-edge-guard`, sharing
the existing mutex and `active/owner.json` exclusion with edge activation. Each
`consumed/<plan_id>` failover record permanently retains the exact plan, nonce,
host, phase and outcome. Consumption records are never deleted. A lost arm
response is not permission to issue a stop again.

Ordinary failures trigger reachable-owner restoration in the same playbook.
Process death, cancellation, Runner loss and unreachable hosts can prevent that
attempt. Non-interruptible jobs and Ansible recovery blocks do not guarantee
restoration after controller loss. Retained records block another fault until
the recovery route verifies the complete restored cluster.

Recovery inspects every host before acting. Partial acquisition is supported
only when all present records prove an unarmed claim or its failed cleanup.
Missing records combined with an armed/proven record, foreign ownership,
malformed files or incomplete publication require separately reviewed root
recovery. A test artifact naming a different active transaction is rejected;
use the recovery-only route for the discovered transaction.

### Incomplete Initial Publication

A crash between writing `active/owner.json` and publishing consumption leaves a
fail-closed guard. Automated recovery cannot infer a complete plan from that
owner file. The conservative procedure for this specific condition is:

1. Stop other lifecycle work and obtain approval for the exact affected hosts
   and records. Preserve root-private copies of the guard trees and available
   private plan/job evidence outside Git. Keep raw evidence out of public reports.
2. Inspect all three hosts through authenticated root access. Validate safe file
   types/ownership, exact operation `haproxy-failover`, plan ID and nonce, and
   correlate every present plan. Establish that the only discrepancy is missing
   initial consumption publication. If any record is armed/proven, another
   operation owns a guard, or evidence is inconsistent, stop this procedure and
   resolve that distinct incident; do not infer that no stop occurred.
3. Verify HAProxy active/enabled on all hosts and pass full VIP smoke with unchanged
   OpenBao identity. If restoration is needed, obtain approval for the exact
   HAProxy start and then repeat full smoke.
4. Retire the interrupted identity under reviewed root custody. Preserve every
   existing consumption record. Where consumption was never published, create a
   permanent root-owned `0600` retirement record at that exact
   `consumed/<plan_id>` containing the observed owner identity and the explicit
   failed-before-arm recovery decision. This tombstone is deliberately not a
   successful failover record and is rejected by normal replay. Never recreate
   approval or claim that the experiment passed.
5. Only after verified restoration, retire the exact matching incomplete active
   directory and incomplete temporary publication files to the approved
   root-private evidence location outside the guard tree. Preserve other owners'
   records and all permanent consumption. Reinspect every guard, repeat smoke,
   and record the reviewed resolution before allowing a fresh plan.

This is a manual root procedure, not automatic unlock or timeout-based cleanup.
Normal complete retained records use the fixed Ansible recovery route instead.

## Offline Verification

```bash
PLATFORM_CONFIG_CONTAINER_PROFILE=test ./scripts/in-container python -m pytest -n 0 -q \
  tests/python/test_openbao_failover_plan.py \
  tests/python/test_openbao_failover_guard.py \
  tests/python/test_openbao_failover_orchestration.py \
  tests/python/test_openbao_failover_operations.py
```

Filesystem and orchestration fixtures exercise real plan/transaction logic,
including interruption and repeat behavior. Service, network and timing doubles
do not establish live failover. A separately approved dev exercise and recorded
GitLab pipeline/job/source identities remain required for live qualification.
