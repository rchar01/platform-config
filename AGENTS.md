# AGENTS.md

## Repository Boundary

- `platform-config` is public Ansible code: roles, playbooks, examples, docs, and helper scripts only.
- Real inventories, host/group vars, access policies, CA files, and non-secret environment config belong in `../platform-private/config/`; kubeconfigs, tokens, private keys, and other secrets belong outside Git.
- Do not commit working plans, test plans, incident notes, or environment-specific operational notes here. Store them under `../platform-plans/config/plans/`; publish only sanitized summaries or durable public docs.
- Do not create Proxmox, OpenTofu, VM-template, or VM-lifecycle code here; those belong to other platform repos.
- Public inventories under `inventories/` are `.example` files only; real `hosts.yml`, `group_vars/*.yml`, and `host_vars/*.yml` are intentionally ignored.

## Kubernetes Bastion Boundary

- `platform-config` owns installing and configuring bastion hosts with Ansible.
- `platform-k8s-bastion` owns runtime commands, libraries, operator tools, and runtime metadata.
- Default bastion runtime source is `vendor/platform-k8s-bastion/runtime`; add `platform-k8s-bastion` as a git submodule when this repo is a git checkout.
- Do not copy runtime scripts from `platform-k8s-bastion` into Ansible roles; install them from the submodule via `k8s_bastion_runtime_src`.
- Real bastion access policies and CA files are private files referenced by vars such as `k8s_bastion_policy_src` and `k8s_bastion_ca_src`; real admin kubeconfigs referenced by `k8s_bastion_admin_kubeconfig_src` belong under `~/.config/platform-infrastructure/config/` or another outside-Git secret store.

## Setup And Checks

- Local setup requires control-node Python 3.12+: `python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt`.
- Install collections before Ansible checks: `ansible-galaxy collection install -r requirements.yml`.
- Main syntax checks use a private inventory: `source ../platform-private/config/dev.ansible.env && ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml --syntax-check` and `ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/k8s-bastion-access.yml --syntax-check`.
- Bastion smoke checks after apply: `ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/k8s-bastion-smoke.yml --limit k8s-bastion-01`.
- Lint checks, when available: `ansible-lint playbooks/ roles/` and `yamllint .`.
- Helper scripts source `../platform-private/config/<env>.ansible.env` when present; use `PLATFORM_CONFIG_INVENTORY=...`, `PLATFORM_CONFIG_ENV_FILE=...`, or `-i/--inventory` overrides for focused runs.

## How To Investigate

- Read `README.md`, `ansible.cfg`, `requirements.yml`, `requirements-dev.txt`, `docs/development.md`, and relevant role docs before editing.
- For bastion work, read `docs/k8s-bastion.md`, `roles/k8s_bastion_access/defaults/main.yml`, and `vendor/README.md` before touching tasks.
- Prefer executable sources of truth over prose: role defaults, task files, scripts, and `ansible.cfg` override docs if they conflict.
- If architecture is still unclear, inspect the relevant playbook and role task chain rather than random leaf files.

## Agent Workflow Expectations

- Read relevant code before editing.
- Prefer minimal changes that match existing patterns.
- Keep `README.md`, `AGENTS.md`, and skill docs current when repository behavior changes.
- If your runtime provides specialized tools or subagents for codebase exploration, use them when repository structure, ownership boundaries, or relevant files are unclear.
- If your runtime provides specialized tools or subagents for verification, use them for non-trivial test runs, runtime-backed checks, or command-heavy validation.
- If your runtime provides specialized tools or subagents for review, use them after substantial edits to catch regressions, missing updates, or doc/code drift.
- If your runtime provides specialized tools or subagents for research, use them when behavior depends on external tooling or upstream docs.
- Prefer local repository docs, scripts, and configuration first; use web research when local sources are insufficient or freshness matters.
- Summarize any specialist-tool or subagent findings you rely on.
- Do not revert unrelated worktree changes.
