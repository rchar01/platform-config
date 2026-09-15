# AGENTS.md

## Repository Boundary

- `platform-config` is public Ansible code: roles, playbooks, examples, docs, and helper scripts only.
- Real inventories, host/group vars, access policies, CA files, and non-secret environment config belong in `../platform-private/config/`; kubeconfigs, tokens, private keys, and other secrets belong outside Git.
- Do not commit working plans, test plans, incident notes, or environment-specific operational notes here. Store them under `../platform-plans/config/plans/`; publish only sanitized summaries or durable public docs.
- Do not create Proxmox, OpenTofu, VM-template, or VM-lifecycle code here; those belong to other platform repos.
- Public inventories under `inventories/` are `.example` files only; real `hosts.yml`, `group_vars/*.yml`, and `host_vars/*.yml` are intentionally ignored.
- Human and CI PKI package commands belong in `platform-tools`. GitLab exchange
  uses only `platform-pki gitlab-package`; an inventory-selected target-local
  filesystem exchange may expose only the signed request and response payloads
  through pre-provisioned access. Keep Ansible orchestration, target-local
  facades or fixed exchange directories, protected spools, reviewed trust
  installation, and host-local lifecycle actions here. Do not add
  direct/controller-local transport, SSH access provisioning, or
  operator-supplied package coordinates.

- `rocky-ansible-host-prepare` owns the fixed `rocky`-only `!requiretty` exception
  and detached non-TTY sudo check. Only approved `apply` may atomically upgrade
  its exact previous root-owned `0440` one-line policy; `check` remains read-only.
  Reject custom/unsafe policy and retain account/key checks. Its lock coordinates
  helper applies only; prohibit concurrent out-of-band sudoers edits. See
  [Host Bootstrap](docs/ansible-host-bootstrap.md#non-tty-sudo-and-existing-prepared-hosts).

## Kubernetes Bastion Boundary

- `platform-config` owns installing and configuring bastion hosts with Ansible.
- `platform-k8s-bastion` owns runtime commands, libraries, operator tools, and runtime metadata.
- Default bastion runtime source is `vendor/platform-k8s-bastion/runtime`; add `platform-k8s-bastion` as a git submodule when this repo is a git checkout.
- Do not copy runtime scripts from `platform-k8s-bastion` into Ansible roles; install them from the submodule via `k8s_bastion_runtime_src`.
- Real bastion access policies and CA files are private files referenced by vars such as `k8s_bastion_policy_src` and `k8s_bastion_ca_src`; real admin kubeconfigs referenced by `k8s_bastion_admin_kubeconfig_src` belong under `~/.config/platform-infrastructure/config/` or another outside-Git secret store.

## GitLab Runner Pull Policy

- `gitlab_runner_docker_pull_policy` accepts exactly the strings `always` and
  `if-not-present`; preserve the `always` default and registered-config drift
  failure. The temporary override is for dedicated trusted runners with exact
  digest images preloaded into the rootful Podman store; missing images still
  pull. Existing runners use a reviewed in-place policy edit preserving the token,
  without force registration when the full contract matches. No automatic
  migration or re-registration; self-bootstrap remains `always`-only. See
  [Temporary Offline Preload](roles/gitlab_runner/README.md#temporary-offline-preload).

## RKE2 Runner Boundary

- Standalone kube-vip and Runner smoke must resolve optional role defaults in
  a separate namespace, with explicit inventory values taking precedence.
  Do not invoke role convergence or load defaults over inventory to obtain them.
  Test the complete standalone smoke paths with role-default inputs omitted.

- `rke2_coredns_static_hosts` is an optional private IPv4/FQDN list, public default
  empty. Preserve the qualified RKE2 `v1.35.5+rke2r2` / CoreDNS chart `1.45.212`
  server/plugin contract and Rancher's cluster-domain prepend. Guard ownership
  and fixed source paths on all servers before base-role mutation; only the
  bootstrap server publishes. Empty unmanaged configuration preserves foreign
  customization; owned empty configuration resets values without deleting the
  resource. Wait for desired HCC/Corefile/pod specification and rollout after all
  base nodes, before add-ons. Smoke is task-only and must not invoke role
  dependencies. Node aliases, pod DNS and Helm-job CA trust remain separate;
  qualify real application lookups and strict TLS. See
  [Static DNS for Pods](docs/rke2-operations.md#static-dns-for-pods).
- Optional `rke2_kube_vip_chart_repo_ca_*` and
  `rke2_gitlab_runner_chart_repo_ca_*` source/SHA pairs supply exact reviewed bytes
  via HelmChart `spec.repoCA`. Preserve paired validation, bounded regular-file
  reads, the decoded-content digest check, empty defaults and strict TLS. Do not
  infer these trust selections from Runner `certsSecretName` or node trust.

- `rke2_rpm_repo_gpgcheck` is a strict boolean, default `true`. An explicit private
  inventory exception changes only metadata-signature checking on the common and
  version RKE2 RPM repositories. Keep package `gpgcheck: true`, HTTPS, key
  checksum/fingerprint and exact package checks. Validate types in the shared
  source validator before bootstrap mutation; never skip source preflight or
  infer an exception from a proxy URL. See [RPM Repository Trust](docs/rke2-operations.md#rpm-repository-trust).

- `rke2-host-aliases-plan/apply` select the complete coherent RKE2 cluster, with
  exactly one server/agent role per host, independently of storage or installed
  RKE2. Validate and snapshot transport-only controller JSON before inventory.
  Keep `common/tasks/host_aliases.yml` shared with ordinary common convergence;
  the fixed preparation play uses only that entry point after read-only all-host
  guards under linear execution. Reject invalid aliases, unsafe `/etc/hosts`,
  malformed markers, and conflicting unmanaged entries before any alias write.
  Preserve the existing cloud-init selector and guards. Plan permits predicted
  changes; apply requires fresh check, alias-only apply, zero-change post-check,
  and read-only node NSS verification of every alias. Resolution runs only after
  apply, never in check mode. Require complete successful per-host phase evidence;
  no selectors, path flags, retries, rollback, or bootstrap alias repair. Private
  CI owns native manual approval and revision bindings. See
  [RKE2 Host Aliases](docs/rke2-host-aliases.md).

- Both bootstrap routes must run the shared all-node pristine/source preflight
  before host mutation. Keep RPM key HTTPS 200 plus mandatory in-memory SHA-256
  validation and unique explicit registry v2 probes node-side, strict-TLS,
  read-only, and active in check mode. Require preinstalled node trust; never
  install a controller CA during preflight. Registry API success is not image
  pull, token-exchange, RPM dependency, or Helm qualification. See
  [Bootstrap Source Preflight](docs/rke2-operations.md#bootstrap-source-preflight).

- `storage-check` is check-only and accepts one literal RKE2 storage host through
  `--node`; it never accepts arbitrary playbooks or apply flags. Predicted
  changes are plan output, not a failure. CI may repeat this route sequentially
  across its reviewed scope and must retain failure status for any failed node.
- `storage-apply` uses the same exact-node scope and fixed storage role: inventory,
  ping, fresh `--check --diff`, apply, second real apply, and read-only mounted-state
  verification. Gate each next command on complete successful evidence; the second
  apply must report zero changes and no failed/unreachable/ignored/rescued tasks.
  No lists/all, arbitrary arguments, automatic retries, or initialization override.
  Apply alone accepts only the documented transport-only controller JSON schema;
  validate and snapshot it before inventory execution. Reject effective non-mounted
  inventory volume states before ping. Keep the schema aligned with the generated
  `platform-ci/templates/storage-apply.yml` map and transport fields.
  Private CI owns per-node check/manual-apply pairs and native UI confirmation;
  this is not API-proof approval. Interruptions are not rollback. Keep layouts and
  excluded service paths in reviewed private inventory, not public launcher logic.
  See [Storage Apply](docs/storage-check.md#storage-apply).

- In-cluster Runner Helm repository overrides belong in private inventory via
  `rke2_gitlab_runner_chart_repo`. Preserve the public upstream default, indexed
  chart/version convention, and reviewed image pins. Keep rendering and smoke
  aligned; a repository override does not establish Helm-job CA trust.
- Keep `rke2_gitlab_runner_clone_url` optional and empty by default. A private
  HTTPS clone origin affects Runner checkout only, not the operational source
  fetch or TLS verification; preserve those independent access checks.

## OpenBao Activation Boundary

- `openbao-haproxy-failover-plan`/`openbao-haproxy-failover` require an exact
  owner-bound private plan; `openbao-haproxy-failover-recover` discovers retained
  target records without an artifact. Require complete three-host baseline and
  final smoke, active desired services, protected manual CI or exact TTY approval,
  and fresh 1800-second authorization before one HAProxy-only stop. Preserve boot
  enablement. The shared edge mutex/active namespace excludes activation; permanent
  consumption and durable stop intent prevent repeat faults. Recovery may ignore
  expiration/pipeline only, preserving source/private/project/image/lane identity.
  Failed proof remains failed after restoration; reports separate test, recovery,
  smoke and nullable proof/transaction timing. Retain unknown/partial records;
  never automatically unlock or delete consumption. CI allows two hours for
  test/recovery with the failover-only bounded timing envelope. Other lifecycle
  work must be excluded procedurally. See [OpenBao Failover](docs/openbao-failover.md).
  Initial plan rejection exposes only allowlisted reason codes and reports
  not-run/not-required outcomes before any claim or stop; keep plan evidence private.

- DNS infrastructure is optional; preserve `openbao_service_dns` and required
  certificate DNS SAN identity. Use existing private controller
  `container.hostaliases` (or `PLATFORM_CONFIG_CONTAINER_HOST_ALIASES_FILE`
  exported before wrapper launch), `gitlab_runner_docker_extra_hosts` for Docker
  jobs/helpers/services, and separate managed-host `platform_host_aliases`.
  Keep public alias defaults empty; no new flags or lookup/TLS bypasses.
  See [OpenBao Without DNS](docs/private-workflow.md#openbao-without-dns).
- Standalone dev OpenBao acceptance has no monitoring-stack or observer
  dependency; production monitoring remains required. Allow acceptance traffic
  only until named administrator access, local audit rotation, and recovery gates
  pass and normal onboarding is separately authorized. Do not equate offline
  tests or merged orchestration with live qualification.
- Distinguish the scoped standalone dev endpoint release from broader operational
  onboarding. Its closeout requires successful activation, active-state handoff,
  VIP smoke, one separately approved HAProxy-owner stop/failover/restore check,
  and basic named-administrator handoff. Backup/restore, NAS, the wider fault
  campaign, and monitoring are separate work, not endpoint-release gates. Closing
  that scope does not waive ordinary-onboarding rules or claim production/DR
  readiness. Independent RKE2 and OpenBao qualification does not establish
  Kubernetes authentication or workload secret-consumption integration.
- `playbooks/openbao.yml` is pristine inactive staging only and is forbidden for
  active or initialized clusters. Do not use ordinary staging after activation.
- HAProxy activation must select its built-in-only `activation_enable.yml`, not
  ordinary role convergence. Verify staged SELinux client, metrics, and backend
  port labels and firewall policy without changing them; bind SELinux observations
  into plan evidence.
- Stage HAProxy's public CA copy under `/etc/haproxy`, separate from OpenBao's
  private `:Z` tree. Bind CA identity, exact configuration, and prospective
  service-domain access into preflight; never repair CA paths during activation.
  Rollback may reset only HAProxy's observed failed latch after successful
  stop/disable; skip reset for verified inactive state. It must still prove exact
  inactive/disabled state before releasing its guard. Path qualification allows
  ten strict TLS health attempts with one-second retry delays, requires HTTP 200,
  and rolls back all hosts after exhausted qualification.
- HAProxy caller preflight reads target `SSH_CONNECTION` without become, rejects
  missing or excluded IPv4 peers, and binds stable per-host peer/destination
  observations into the plan. Recheck before enablement. This requires direct
  SSH and stable controller egress; an SSH peer is not proof of HTTPS routing
  through arbitrary proxies. Keep strict post-start client-path qualification.
- `platform-tools` owns the `platform-openbao-edge` human/CI facade; keep its six
  fixed routes in `scripts/platform-config-operation`, not a generic wrapper.
  Both HAProxy and Keepalived use the shared schema-1 plan/action contract with
  TTL 1800 seconds, clean committed source/private inventory identity, exact
  environment/hosts/evidence/lane binding, and CI image/project/pipeline/plan-job
  identity. The four facade plan/activation commands require `--plan`; existing
  Make activation targets remain direct interactive entry points.
- Plan mode is read-only and may inspect readiness false. Activation requires
  exactly boolean true on all hosts: commit the reviewed readiness declaration
  before planning an approved activation. Changing readiness after planning
  invalidates the private inventory SHA. Operator approval is exact and TTY-bound;
  CI is a matching same-pipeline protected manual job with no TTY continuation.
- Operator activation plans stay outside every Git repository, not in the working
  plan repo. Publish only a new `0600` file in an existing current-owner `0700`
  non-symlink directory; never overwrite. CI uses only its fixed restricted
  artifact. Do not expose plan evidence in public docs or reports.
- The target-root guard at `/var/lib/platform-config/openbao-edge-guard` uses
  `active/owner.json` and permanent `consumed/<plan_id>` records. Acquire across
  all hosts and consume before final preflight. It coordinates only supported
  HAProxy/Keepalived activation, not root, out-of-band, or rolling operations;
  prohibit concurrent other lifecycle work. Partial acquisition, interruption,
  unknown rollback, or unverified release retains affected records for reviewed
  operator recovery. No automatic unlock or consumed-record deletion. Success or
  per-host verified rollback releases owned guards, never plan consumption;
  retries require fresh plans after recovery.
- Keep CI planning, manual start, qualification, rollback, and reporting in CI.
  Reports must show lifecycle handoff keys, but neither lane may automatically
  mutate or push private desired state. Require reviewed private commits and a
  reviewed firewall lifecycle/policy prerequisite matching plan evidence. Neither
  edge route automatically changes the firewall service lifecycle; enabling
  enforcement, when chosen, requires separate approval, not universal enablement.
- For enabled HAProxy/Keepalived roles with managed firewall policy, require an
  explicit `firewalld_service_enabled` boolean and `firewalld_service_state` pair:
  `false`/`stopped` requires actual inactive/boot-disabled firewalld and offline
  permanent configuration/rule validation; `true`/`started` requires actual
  active/boot-enabled firewalld and correct runtime and permanent rules. Reject
  mixed pairs, string booleans, and missing lifecycle declarations. Keep
  `*_firewalld_manage: true`; do not use legacy `firewalld_enabled`, new flags, or
  a generic framework to select this mode. Disabled mode skips only daemon-running
  and runtime-rule-enforcement checks, not policy or other activation gates.
  Firewalld off provides no host-firewall enforcement from firewalld; its configured
  allowlists are not operative. Do not claim equivalent security or production
  qualification, or automatically edit source/private inventory or change the
  firewall service to satisfy a gate.
- Keep `smoke-openbao` direct-node plus all-three-HAProxy only for the pre-VIP
  phase. `smoke-openbao-vip` imports that smoke and adds active desired Keepalived
  validation, actual active/enabled state on all three hosts, repeated exact
  single-owner checks on the configured interface, strict forced-VIP service-hostname
  TLS and ordinary service-name resolution (DNS or static host mapping), and
  cluster identity agreement. Run VIP smoke only after successful activation and
  the reviewed active desired-state handoff; a lookup alone proves no TLS success.
- `activate-openbao-keepalived` requires an explicit full-cluster limit, private
  `openbao_keepalived_activation_ready: true`, and fresh exact approval for each
  activation in its operator or CI lane after network, peer VRRP, anti-spoofing,
  and duplicate-address detection prerequisites. Start backup-priority members before the preferred
  member. Roll back only Keepalived on all reachable hosts; require VIP absence
  on all local interfaces and report unknown/unreachable hosts as unverified.
- After successful activation, record `keepalived_vip_service_enabled: true` and
  `keepalived_vip_service_state: started` in private desired state and reset
  `openbao_keepalived_activation_ready: false`; then use VIP smoke, not staging.
  For CI, commit and push this handoff and create a fresh smoke pipeline on that
  revision. Do not retry a smoke job bound to the pre-activation declaration or
  weaken the desired-state assertion. Readiness is one-time authorization, not
  service health; desired state and runtime observations remain distinct.
- Keepalived's default tracking script lives under `/usr/libexec/keepalived` for
  the target policy's `keepalived_unconfined_script_exec_t` label. Stage policy
  `_default` contexts only on the script and its directory with built-in modules.
  The read-only native SELinux guard precedes UID-only readiness and binds mode,
  full contexts, prospective `keepalived_t` to `keepalived_unconfined_script_t`
  transition, and dependency decisions into existing plan evidence. Require
  source execute, process transition, and target entrypoint for both domain
  transitions; all five dependencies must retain the exact script domain and
  allow execute plus execute_no_trans, including in permissive mode.
  Custom paths must pass actual-label validation; preflight/start never repair
  labels. Neither native policy queries nor `runuser` prove actual daemon-script
  execution; verify that separately after reviewed stopped-artifact repair.

## Setup And Checks

- Use the Podman dev container for Ansible and lint tooling; do not install project Python packages on the host. Build it with `make deps` or run commands through `./scripts/in-container`.
- Main syntax checks use a private inventory: `make syntax ENV=dev` and `make syntax ENV=dev PLAYBOOK=playbooks/k8s-bastion-access.yml`.
- Bastion smoke checks after apply: `make smoke-k8s-bastion ENV=dev LIMIT=k8s-bastion-01`.
- Lint checks: `make lint` and `make yamllint`.
- Default tests: `make test` runs the authoritative serial pytest suite.
- Focused iterations use exact pytest files/node IDs with `-x` and durations;
  never append `.` to a selected-file command. Run any bounded `timeout` inside
  `scripts/in-container` so expiry terminates the container command. Batch input
  matrices through the real validator; keep full lifecycle/transport checks for
  their specific boundaries rather than repeating them for every input variant.
- Focused offline OpenBao VIP checks use `PLATFORM_CONFIG_CONTAINER_PROFILE=test
  ./scripts/in-container python -m pytest -n 0` with
  `tests/python/test_openbao_keepalived_activation.py`,
  `tests/python/test_openbao_vip_smoke.py`, and
  `tests/python/test_keepalived_vip_render.py`. They do not qualify live networking
  or authorize activation.
- Supplemental parallel tests: `make test-parallel`; override worker count with
  `TEST_WORKERS=<count>`.
- Supplemental fast verification: `make verify-parallel`; use serial
  `make verify` as the authoritative merge oracle.
- Helper scripts source `../platform-private/config/<env>.ansible.env` when present; use `PLATFORM_CONFIG_INVENTORY=...`, `PLATFORM_CONFIG_ENV_FILE=...`, or `-i/--inventory` overrides for focused runs.

## How To Investigate

- Read `README.md`, `ansible.cfg`, `requirements.yml`, `requirements-dev.txt`, `docs/development.md`, and relevant role docs before editing.
- For bastion work, read `docs/k8s-bastion.md`, `roles/k8s_bastion_access/defaults/main.yml`, and `vendor/README.md` before touching tasks.
- Prefer executable sources of truth over prose: role defaults, task files, scripts, and `ansible.cfg` override docs if they conflict.
- If architecture is still unclear, inspect the relevant playbook and role task chain rather than random leaf files.

## Agent Workflow Expectations

- Read relevant code before editing.
- Prefer simple, focused changes and avoid overengineering.
- Keep `README.md`, `AGENTS.md`, and skill docs current when repository behavior changes.
- If your runtime provides specialized tools or subagents for codebase exploration, use them when repository structure, ownership boundaries, or relevant files are unclear.
- If your runtime provides specialized tools or subagents for verification, use them for non-trivial test runs, runtime-backed checks, or command-heavy validation.
- If your runtime provides specialized tools or subagents for review, use them after substantial edits to catch regressions, missing updates, or doc/code drift.
- If your runtime provides specialized tools or subagents for research, use them when behavior depends on external tooling or upstream docs.
- Prefer local repository docs, scripts, and configuration first; use web research when local sources are insufficient or freshness matters.
- Summarize any specialist-tool or subagent findings you rely on.
- Do not revert unrelated worktree changes.
