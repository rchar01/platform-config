SHELL := /bin/sh
.DEFAULT_GOAL := help
MAKEFLAGS += --no-print-directory

ENV ?= homelab
PRIVATE_CONFIG_ROOT ?= ../platform-private/config
ENV_FILE ?= $(PRIVATE_CONFIG_ROOT)/$(ENV).ansible.env
INVENTORY ?= $(PRIVATE_CONFIG_ROOT)/inventories/$(ENV)/hosts.yml
PLAYBOOK ?= playbooks/site.yml
LIMIT ?=
EXTRA_ARGS ?=
STAGING_MODE ?= preflight
DEV_IMAGE ?= platform-config-dev:latest
IN_CONTAINER ?= ./scripts/in-container
ANSIBLE ?= ansible
ANSIBLE_PLAYBOOK ?= ansible-playbook
ANSIBLE_INVENTORY ?= ansible-inventory
ANSIBLE_LINT ?= ansible-lint
YAMLLINT ?= yamllint

LIMIT_ARG := $(if $(strip $(LIMIT)),--limit $(LIMIT),)

.PHONY: help deps shell container-build inventory ping syntax check apply verify lint yamllint test deploy-bootstrap-token-issuer-staging smoke-firewalld smoke-container smoke-registry smoke-openbao smoke-gitlab smoke-runners smoke-monitoring smoke-rke2 smoke-rke2-kube-vip smoke-kong-ingress smoke-workload-lb smoke-k8s-bastion clean _guard-inventory _guard-env-file _guard-staging-mode

## Show available commands
help:
	@printf '%s\n' 'Available targets:'
	@awk '\
		/^## / { help = substr($$0, 4); next } \
		/^[a-zA-Z0-9_.-]+:/ { \
			if (help != "") { \
				target = $$1; \
				sub(/:.*/, "", target); \
				printf "  %-24s %s\n", target, help; \
				help = ""; \
			} \
		} \
	' $(MAKEFILE_LIST) | sort
	@printf '\n%s\n' 'Variables:'
	@printf '  %-24s %s\n' 'ENV' 'Environment name, default: homelab'
	@printf '  %-24s %s\n' 'ENV_FILE' 'Private env file, default follows ENV'
	@printf '  %-24s %s\n' 'INVENTORY' 'Inventory path, default follows ENV'
	@printf '  %-24s %s\n' 'PLAYBOOK' 'Playbook for syntax/check/apply, default: playbooks/site.yml'
	@printf '  %-24s %s\n' 'LIMIT' 'Optional Ansible --limit value'
	@printf '  %-24s %s\n' 'EXTRA_ARGS' 'Extra arguments passed to Ansible commands'
	@printf '  %-24s %s\n' 'STAGING_MODE' 'Issuer workflow mode: preflight, rollback_rehearsal, or validate'
	@printf '\n%s\n' 'Examples:'
	@printf '  %s\n' 'make deps'
	@printf '  %s\n' 'make shell'
	@printf '  %s\n' 'make inventory ENV=dev'
	@printf '  %s\n' 'make check ENV=homelab PLAYBOOK=playbooks/gitlab.yml'
	@printf '  %s\n' 'make apply ENV=dev PLAYBOOK=playbooks/registry.yml LIMIT=registry-01'
	@printf '  %s\n' 'make smoke-firewalld ENV=dev'
	@printf '  %s\n' 'make smoke-gitlab'
	@printf '  %s\n' 'make smoke-runners ENV=dev'
	@printf '  %s\n' 'make smoke-monitoring ENV=dev'
	@printf '  %s\n' 'make smoke-rke2 ENV=dev'
	@printf '  %s\n' 'make smoke-rke2-kube-vip ENV=dev'
	@printf '  %s\n' 'make smoke-kong-ingress ENV=dev'
	@printf '  %s\n' 'make smoke-workload-lb ENV=dev'
	@printf '  %s\n' 'make smoke-k8s-bastion ENV=dev'
	@printf '  %s\n' 'make deploy-bootstrap-token-issuer-staging ENV=dev LIMIT=k8s-bastion-01 STAGING_MODE=preflight'

## Build the development container image
container-build:
	@podman build -f Containerfile.dev -t "$(DEV_IMAGE)" .

## Prepare the development container image
deps: container-build

## Open an interactive development container shell
shell:
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" ./scripts/devshell

## Show selected environment inventory graph
inventory: _guard-env-file _guard-inventory
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" sh -c '. "$(ENV_FILE)" && "$(ANSIBLE_INVENTORY)" -i "$(INVENTORY)" --graph $(EXTRA_ARGS)'

## Ping all hosts in the selected environment
ping: _guard-env-file _guard-inventory
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" sh -c '. "$(ENV_FILE)" && "$(ANSIBLE)" -i "$(INVENTORY)" all -m ping $(LIMIT_ARG) $(EXTRA_ARGS)'

## Syntax-check PLAYBOOK in the selected environment
syntax: _guard-env-file _guard-inventory
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" sh -c '. "$(ENV_FILE)" && "$(ANSIBLE_PLAYBOOK)" -i "$(INVENTORY)" "$(PLAYBOOK)" --syntax-check $(LIMIT_ARG) $(EXTRA_ARGS)'

## Run PLAYBOOK in check mode with diff
check: _guard-env-file _guard-inventory
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" sh -c '. "$(ENV_FILE)" && "$(ANSIBLE_PLAYBOOK)" -i "$(INVENTORY)" "$(PLAYBOOK)" --check --diff $(LIMIT_ARG) $(EXTRA_ARGS)'

## Apply PLAYBOOK to the selected environment
apply: _guard-env-file _guard-inventory
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" sh -c '. "$(ENV_FILE)" && "$(ANSIBLE_PLAYBOOK)" -i "$(INVENTORY)" "$(PLAYBOOK)" $(LIMIT_ARG) $(EXTRA_ARGS)'

## Run ansible-lint
lint:
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" "$(ANSIBLE_LINT)" playbooks/ roles/

## Run yamllint for public files
yamllint:
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" "$(YAMLLINT)" .

## Run repository tests
test:
	@bash tests/run-all.sh

## Run all local static checks
verify: yamllint lint test

## Deploy and validate the bootstrap token issuer staging candidate
deploy-bootstrap-token-issuer-staging: _guard-staging-mode
	@$(MAKE) apply PLAYBOOK=playbooks/bootstrap-token-issuer-staging.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS) -e bootstrap_token_issuer_staging_mode=$(STAGING_MODE) $(if $(filter rollback_rehearsal,$(STAGING_MODE)),-e bootstrap_token_issuer_staging_controlled_failure=true,)"

## Smoke test inactive firewalld baseline
smoke-firewalld:
	@$(MAKE) apply PLAYBOOK=playbooks/firewalld-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test container runtime hosts
smoke-container:
	@$(MAKE) apply PLAYBOOK=playbooks/container-runtime-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test Zot registry
smoke-registry:
	@$(MAKE) apply PLAYBOOK=playbooks/registry-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test OpenBao status
smoke-openbao:
	@$(MAKE) apply PLAYBOOK=playbooks/maintenance/openbao-status.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test GitLab CE
smoke-gitlab:
	@$(MAKE) apply PLAYBOOK=playbooks/gitlab-smoke.yml ENV=homelab LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test GitLab runners
smoke-runners:
	@$(MAKE) apply PLAYBOOK=playbooks/gitlab-runners-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test monitoring stack and exporters
smoke-monitoring:
	@$(MAKE) apply PLAYBOOK=playbooks/monitoring-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test RKE2 cluster
smoke-rke2:
	@$(MAKE) apply PLAYBOOK=playbooks/rke2-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test RKE2 kube-vip API HA
smoke-rke2-kube-vip:
	@$(MAKE) apply PLAYBOOK=playbooks/rke2-kube-vip-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test Kong ingress controller
smoke-kong-ingress:
	@$(MAKE) apply PLAYBOOK=playbooks/kong-ingress-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test external workload load balancers
smoke-workload-lb:
	@$(MAKE) apply PLAYBOOK=playbooks/workload-lb-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test Kubernetes bastion hosts
smoke-k8s-bastion:
	@$(MAKE) apply PLAYBOOK=playbooks/k8s-bastion-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Remove local Ansible runtime cache
clean:
	@rm -rf .ansible

_guard-env-file:
	@test -f "$(ENV_FILE)" || { printf 'Environment file not found: %s\n' "$(ENV_FILE)" >&2; exit 1; }

_guard-inventory:
	@test -f "$(INVENTORY)" || { printf 'Inventory not found: %s\n' "$(INVENTORY)" >&2; exit 1; }

_guard-staging-mode:
	@case "$(STAGING_MODE)" in preflight|rollback_rehearsal|validate) ;; *) printf 'Invalid STAGING_MODE: %s\n' "$(STAGING_MODE)" >&2; exit 1 ;; esac
