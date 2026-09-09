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

## Kubernetes Bastion Boundary

- `platform-config` owns installing and configuring bastion hosts with Ansible.
- `platform-k8s-bastion` owns runtime commands, libraries, operator tools, and runtime metadata.
- Default bastion runtime source is `vendor/platform-k8s-bastion/runtime`; add `platform-k8s-bastion` as a git submodule when this repo is a git checkout.
- Do not copy runtime scripts from `platform-k8s-bastion` into Ansible roles; install them from the submodule via `k8s_bastion_runtime_src`.
- Real bastion access policies and CA files are private files referenced by vars such as `k8s_bastion_policy_src` and `k8s_bastion_ca_src`; real admin kubeconfigs referenced by `k8s_bastion_admin_kubeconfig_src` belong under `~/.config/platform-infrastructure/config/` or another outside-Git secret store.

## RKE2 Runner Boundary

- In-cluster Runner Helm repository overrides belong in private inventory via
  `rke2_gitlab_runner_chart_repo`. Preserve the public upstream default, indexed
  chart/version convention, and reviewed image pins. Keep rendering and smoke
  aligned; a repository override does not establish Helm-job CA trust.
- Keep `rke2_gitlab_runner_clone_url` optional and empty by default. A private
  HTTPS clone origin affects Runner checkout only, not the operational source
  fetch or TLS verification; preserve those independent access checks.

## OpenBao Activation Boundary

- Standalone dev OpenBao acceptance has no monitoring-stack or observer
  dependency; production monitoring remains required. Allow acceptance traffic
  only until named administrator access, local audit rotation, and recovery gates
  pass and normal onboarding is separately authorized. Do not equate offline
  tests or merged orchestration with live qualification.
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
  single-owner checks on the configured interface, strict forced-VIP service-DNS
  TLS and actual DNS-path checks, and cluster identity agreement.
- `activate-openbao-keepalived` requires an explicit full-cluster limit, private
  `openbao_keepalived_activation_ready: true`, and fresh exact approval for each
  activation in its operator or CI lane after network, peer VRRP, anti-spoofing,
  and duplicate-address detection prerequisites. Start backup-priority members before the preferred
  member. Roll back only Keepalived on all reachable hosts; require VIP absence
  on all local interfaces and report unknown/unreachable hosts as unverified.
- After successful activation, record `keepalived_vip_service_enabled: true` and
  `keepalived_vip_service_state: started` in private desired state and reset
  `openbao_keepalived_activation_ready: false`; then use VIP smoke, not staging.

## Setup And Checks

- Use the Podman dev container for Ansible and lint tooling; do not install project Python packages on the host. Build it with `make deps` or run commands through `./scripts/in-container`.
- Main syntax checks use a private inventory: `make syntax ENV=dev` and `make syntax ENV=dev PLAYBOOK=playbooks/k8s-bastion-access.yml`.
- Bastion smoke checks after apply: `make smoke-k8s-bastion ENV=dev LIMIT=k8s-bastion-01`.
- Lint checks: `make lint` and `make yamllint`.
- Default tests: `make test` runs the authoritative serial pytest suite.
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
