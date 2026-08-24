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
TEST_IN_CONTAINER ?= $(IN_CONTAINER)
TEST_WORKERS ?= 2
MIN_CONTROLLER_FREE_GIB ?=
MIN_ROOT_FREE_GIB ?=
CONTROLLER_ROOT ?=
EXPORT_ARCHIVE ?=
REQUEST_TTL_SECONDS ?= 3600

LIMIT_ARG := $(if $(strip $(LIMIT)),--limit $(LIMIT),)
sh_quote = '$(subst ','"'"',$(1))'
CONTROLLER_ROOT_ARG := $(if $(strip $(CONTROLLER_ROOT)),--controller-root $(call sh_quote,$(CONTROLLER_ROOT)))

.PHONY: help deps shell container-build inventory ping syntax check apply verify verify-parallel lint yamllint test test-parallel check-dev-toolchain check-test-container-profile check-container-wrapper test-keepalived-vip-rocky test-keepalived-vip-behavior test-podman-host-rocky test-gitlab-runner-podman-rocky test-platform-external-probe-alloy test-openbao-haproxy-rocky test-monitoring-haproxy-capabilities test-monitoring-artifact-identities test-monitoring-etcd-image test-monitoring-etcd-cluster test-monitoring-garage-cluster test-monitoring-garage-loki test-monitoring-garage-loki-cluster test-monitoring-garage-mimir test-monitoring-grafana-postgresql test-openbao-image test-openbao-rocky storage-test-preflight storage-test-initialize storage-test-check storage-test-converge storage-test-reboot deploy-bootstrap-token-issuer-staging deploy-openbao-observers syntax-openbao-observers status-openbao roll-openbao smoke-firewalld smoke-container smoke-registry smoke-openbao smoke-openbao-observers smoke-gitlab smoke-runners smoke-monitoring smoke-rke2 smoke-rke2-kube-vip smoke-kong-ingress smoke-workload-lb smoke-k8s-bastion clean _guard-inventory _guard-env-file _guard-staging-mode _guard-storage-test _guard-pki-env _guard-pki-limit _guard-pki-request-ttl

.PHONY: activate-monitoring-etcd status-monitoring-etcd
.PHONY: runner-self-bootstrap-export runner-self-bootstrap-inspect runner-self-bootstrap-build runner-self-bootstrap-connect runner-self-bootstrap-all

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
	@printf '  %-24s %s\n' 'TEST_WORKERS' 'Parallel pytest worker count, default: 2'
	@printf '  %-24s %s\n' 'MIN_CONTROLLER_FREE_GIB' 'Required controller/rootless-Podman free-space gate'
	@printf '  %-24s %s\n' 'MIN_ROOT_FREE_GIB' 'Required managed-root free-space gate'
	@printf '  %-24s %s\n' 'CONTROLLER_ROOT' 'Optional dedicated self-bootstrap controller filesystem root'
	@printf '  %-24s %s\n' 'EXPORT_ARCHIVE' 'Required output path for the self-bootstrap source export'
	@printf '  %-24s %s\n' 'REQUEST_TTL_SECONDS' 'Per-request PKI lifetime, default: 3600, maximum: 604800'
	@printf '\n%s\n' 'Examples:'
	@printf '  %s\n' 'make deps'
	@printf '  %s\n' 'make shell'
	@printf '  %s\n' 'make inventory ENV=dev'
	@printf '  %s\n' 'make check ENV=homelab PLAYBOOK=playbooks/gitlab.yml'
	@printf '  %s\n' 'make apply ENV=dev PLAYBOOK=playbooks/registry.yml LIMIT=registry-01'
	@printf '  %s\n' 'make smoke-firewalld ENV=dev'
	@printf '  %s\n' 'make smoke-gitlab'
	@printf '  %s\n' 'make smoke-runners ENV=dev'
	@printf '  %s\n' 'make smoke-monitoring ENV=dev  # blocked until HA replacement'
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
	@PLATFORM_CONFIG_CONTAINER_PROFILE=test PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(TEST_IN_CONTAINER)" "$(ANSIBLE_LINT)" playbooks/ roles/ migrations/

## Run yamllint for public files
yamllint:
	@PLATFORM_CONFIG_CONTAINER_PROFILE=test PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(TEST_IN_CONTAINER)" "$(YAMLLINT)" .

## Verify development and test tool dependencies
check-dev-toolchain:
	@PLATFORM_CONFIG_CONTAINER_PROFILE=test PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(TEST_IN_CONTAINER)" ./scripts/check-dev-toolchain

## Verify the sanitized test container boundary
check-test-container-profile:
	@PLATFORM_CONFIG_CONTAINER_PROFILE=test PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(TEST_IN_CONTAINER)" ./scripts/check-test-container-profile

## Verify container wrapper exit, interruption, and cleanup behavior
check-container-wrapper:
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" bash scripts/check-container-wrapper

## Create an attended history-free first-runner source export
runner-self-bootstrap-export:
	@./scripts/gitlab-runner-self-bootstrap-export --env "$(ENV)" --output "$(EXPORT_ARCHIVE)"

## Inspect first-runner self-bootstrap host prerequisites (operator-attended only)
runner-self-bootstrap-inspect:
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" ./scripts/gitlab-runner-self-bootstrap-preflight inspect --env "$(ENV)" --limit "$(LIMIT)" --min-controller-free-gib "$(MIN_CONTROLLER_FREE_GIB)" --min-root-free-gib "$(MIN_ROOT_FREE_GIB)" $(CONTROLLER_ROOT_ARG)

## Rebuild and validate the first-runner controller image (operator-attended only)
runner-self-bootstrap-build:
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" ./scripts/gitlab-runner-self-bootstrap-preflight build --env "$(ENV)" --limit "$(LIMIT)" --min-controller-free-gib "$(MIN_CONTROLLER_FREE_GIB)" --min-root-free-gib "$(MIN_ROOT_FREE_GIB)" $(CONTROLLER_ROOT_ARG)

## Validate first-runner private inventory and self-SSH (operator-attended only)
runner-self-bootstrap-connect:
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" ./scripts/gitlab-runner-self-bootstrap-preflight connect --env "$(ENV)" --limit "$(LIMIT)" --min-controller-free-gib "$(MIN_CONTROLLER_FREE_GIB)" --min-root-free-gib "$(MIN_ROOT_FREE_GIB)" $(CONTROLLER_ROOT_ARG)

## Run the complete first-runner preflight (operator-attended only)
runner-self-bootstrap-all:
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" ./scripts/gitlab-runner-self-bootstrap-preflight all --env "$(ENV)" --limit "$(LIMIT)" --min-controller-free-gib "$(MIN_CONTROLLER_FREE_GIB)" --min-root-free-gib "$(MIN_ROOT_FREE_GIB)" $(CONTROLLER_ROOT_ARG)

## Run the authoritative serial pytest suite
test:
	@PLATFORM_CONFIG_CONTAINER_PROFILE=test PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(TEST_IN_CONTAINER)" python -m pytest -n 0

## Run parallel-safe tests, then timing-sensitive tests serially
test-parallel:
	@PLATFORM_CONFIG_CONTAINER_PROFILE=test PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(TEST_IN_CONTAINER)" python -m pytest -n "$(TEST_WORKERS)" -m "not serial"
	@PLATFORM_CONFIG_CONTAINER_PROFILE=test PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(TEST_IN_CONTAINER)" python -m pytest -n 0 -m serial

## Run the opt-in Keepalived role test in disposable Rocky systemd
test-keepalived-vip-rocky:
	@bash tests/integration/test-keepalived-vip-rocky.sh

## Exercise three-node Keepalived election, fault, and ownership behavior
test-keepalived-vip-behavior:
	@bash tests/integration/test-keepalived-vip-behavior.sh

## Run the opt-in Podman host and Quadlet integration check
test-podman-host-rocky:
	@bash tests/integration/test-podman-host-rocky.sh

## Run the opt-in GitLab Runner manager-only Podman socket check
test-gitlab-runner-podman-rocky:
	@bash tests/integration/test-gitlab-runner-podman-rocky.sh

## Run the opt-in external probe and exact Alloy integration check
test-platform-external-probe-alloy:
	@bash tests/integration/test-platform-external-probe-alloy.sh

## Run the opt-in OpenBao HAProxy integration check
test-openbao-haproxy-rocky:
	@bash tests/integration/test-openbao-haproxy-rocky.sh

## Run the opt-in monitoring HAProxy Phase 0 capability check
test-monitoring-haproxy-capabilities:
	@bash tests/integration/test-monitoring-haproxy-capabilities.sh

## Run the opt-in monitoring HAProxy role lifecycle check
.PHONY: test-monitoring-haproxy-rocky
test-monitoring-haproxy-rocky:
	@bash tests/integration/test-monitoring-haproxy-rocky.sh

## Resolve and qualify exact monitoring component image identities
test-monitoring-artifact-identities:
	@bash tests/integration/test-monitoring-artifact-identities.sh

## Qualify the exact monitoring etcd image and disposable runtime
test-monitoring-etcd-image:
	@bash tests/integration/test-monitoring-etcd-image.sh

## Exercise disposable monitoring etcd mTLS and quorum behavior
test-monitoring-etcd-cluster:
	@bash tests/integration/test-monitoring-etcd-cluster.sh

.PHONY: test-monitoring-etcd-rocky
## Exercise inactive monitoring etcd role convergence on disposable Rocky
test-monitoring-etcd-rocky:
	@bash tests/integration/test-monitoring-etcd-rocky.sh

## Exercise disposable Garage RF=3 quorum and signed S3 behavior
test-monitoring-garage-cluster:
	@bash tests/integration/test-monitoring-garage-cluster.sh

## Exercise Loki writes, Garage upload, and fresh-state query compatibility
test-monitoring-garage-loki:
	@MONITORING_GARAGE_TEST_LOKI=true bash tests/integration/test-monitoring-garage-cluster.sh

## Exercise three-node Loki failure, compaction, retention, and Garage recovery
test-monitoring-garage-loki-cluster:
	@MONITORING_GARAGE_TEST_LOKI_CLUSTER=true bash tests/integration/test-monitoring-garage-cluster.sh

## Exercise three-node Mimir failure, compaction, retention, and Garage recovery
test-monitoring-garage-mimir:
	@MONITORING_GARAGE_TEST_MIMIR=true bash tests/integration/test-monitoring-garage-cluster.sh

## Qualify Grafana concurrency and recovery against PostgreSQL
test-monitoring-grafana-postgresql:
	@bash tests/integration/test-monitoring-grafana-postgresql.sh

## Validate OpenBao configuration with the exact 2.6.1 image
test-openbao-image:
	@bash tests/integration/test-openbao-image.sh

## Run the opt-in OpenBao role test in disposable Rocky systemd
test-openbao-rocky:
	@bash tests/integration/test-openbao-rocky.sh

.PHONY: registry-pki-request-publish registry-pki-response-activate syntax-registry-pki-ci

## Run all local static checks
verify: check-dev-toolchain check-test-container-profile check-container-wrapper yamllint lint test

## Run local static checks with supplemental parallel pytest
verify-parallel: check-dev-toolchain check-test-container-profile check-container-wrapper yamllint lint test-parallel

## Create and publish the only target-local schema-2 PKI request
registry-pki-request-publish: _guard-pki-env _guard-pki-limit _guard-pki-request-ttl
	@$(MAKE) apply PLAYBOOK=playbooks/registry-pki-request.yml ENV=$(call sh_quote,$(ENV)) LIMIT=$(call sh_quote,$(LIMIT)) EXTRA_ARGS=$(call sh_quote,-e registry_pki_request_ttl_seconds=$(REQUEST_TTL_SECONDS))

## Download and locally activate the only authenticated schema-2 response
registry-pki-response-activate: _guard-pki-env _guard-pki-limit
	@$(MAKE) apply PLAYBOOK=playbooks/registry-pki-activate.yml ENV=$(call sh_quote,$(ENV)) LIMIT=$(call sh_quote,$(LIMIT)) EXTRA_ARGS=

## Run read-only pristine storage fixture checks
storage-test-preflight: _guard-storage-test
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" ./scripts/storage-volume-test preflight --env-file "$(ENV_FILE)" --inventory "$(INVENTORY)" --limit "$(LIMIT)"

## Initialize the approved pristine storage fixture
storage-test-initialize: _guard-storage-test
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" ./scripts/storage-volume-test initialize --env-file "$(ENV_FILE)" --inventory "$(INVENTORY)" --limit "$(LIMIT)"

## Prove final storage convergence is read-only in check mode
storage-test-check: _guard-storage-test
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" ./scripts/storage-volume-test check --env-file "$(ENV_FILE)" --inventory "$(INVENTORY)" --limit "$(LIMIT)"

## Converge the final storage fixture twice and require idempotency
storage-test-converge: _guard-storage-test
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" ./scripts/storage-volume-test converge --env-file "$(ENV_FILE)" --inventory "$(INVENTORY)" --limit "$(LIMIT)"

## Reboot the storage fixture and prove persistent idempotency
storage-test-reboot: _guard-storage-test
	@PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" "$(IN_CONTAINER)" ./scripts/storage-volume-test reboot --env-file "$(ENV_FILE)" --inventory "$(INVENTORY)" --limit "$(LIMIT)"

## Deploy and validate the bootstrap token issuer staging candidate
deploy-bootstrap-token-issuer-staging: _guard-staging-mode
	@$(MAKE) apply PLAYBOOK=playbooks/bootstrap-token-issuer-staging.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS) -e bootstrap_token_issuer_staging_mode=$(STAGING_MODE) $(if $(filter rollback_rehearsal,$(STAGING_MODE)),-e bootstrap_token_issuer_staging_controlled_failure=true,)"

## Syntax-check OpenBao-hosted observer orchestration
syntax-openbao-observers:
	@$(MAKE) syntax PLAYBOOK=playbooks/openbao-observers.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"
	@$(MAKE) syntax PLAYBOOK=playbooks/openbao-observers-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Syntax-check CI-safe registry PKI entry points
syntax-registry-pki-ci:
	@$(MAKE) syntax PLAYBOOK=playbooks/registry-pki-request.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"
	@$(MAKE) syntax PLAYBOOK=playbooks/registry-pki-activate.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Converge staged or explicitly active OpenBao-hosted observers
deploy-openbao-observers:
	@$(MAKE) apply PLAYBOOK=playbooks/openbao-observers.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Activate the bootstrapped monitoring etcd cluster
activate-monitoring-etcd:
	@$(MAKE) apply PLAYBOOK=playbooks/maintenance/monitoring-etcd-activate.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Check strict read-only monitoring etcd status
status-monitoring-etcd:
	@$(MAKE) apply PLAYBOOK=playbooks/maintenance/monitoring-etcd-status.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Check strict read-only OpenBao direct-node and Raft status
status-openbao:
	@$(MAKE) apply PLAYBOOK=playbooks/maintenance/openbao-status.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Roll OpenBao voters through explicit manual-unseal maintenance
roll-openbao:
	@$(MAKE) apply PLAYBOOK=playbooks/maintenance/openbao-rolling-restart.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS) -e openbao_rolling_restart_confirm=true"

## Smoke test inactive firewalld baseline
smoke-firewalld:
	@$(MAKE) apply PLAYBOOK=playbooks/firewalld-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test container runtime hosts
smoke-container:
	@$(MAKE) apply PLAYBOOK=playbooks/container-runtime-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test Zot registry
smoke-registry:
	@$(MAKE) apply PLAYBOOK=playbooks/registry-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Report that OpenBao HA smoke checks are not implemented
smoke-openbao:
	@printf '%s\n' 'OpenBao HA smoke checks are not implemented; the legacy check is blocked.' >&2
	@exit 1

## Smoke test active OpenBao-hosted observers
smoke-openbao-observers:
	@$(MAKE) apply PLAYBOOK=playbooks/openbao-observers-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test GitLab CE
smoke-gitlab:
	@$(MAKE) apply PLAYBOOK=playbooks/gitlab-smoke.yml ENV=homelab LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Smoke test GitLab runners
smoke-runners:
	@$(MAKE) apply PLAYBOOK=playbooks/gitlab-runners-smoke.yml ENV=$(ENV) LIMIT="$(LIMIT)" EXTRA_ARGS="$(EXTRA_ARGS)"

## Report that monitoring HA smoke checks are not implemented
smoke-monitoring:
	@printf '%s\n' 'Monitoring HA smoke checks are not implemented; the legacy check is blocked.' >&2
	@exit 1

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

_guard-storage-test:
	@test "$(ENV)" = config-test || { printf '%s\n' 'Storage fixture targets require ENV=config-test.' >&2; exit 1; }
	@test -n "$(strip $(LIMIT))" || { printf '%s\n' 'Storage fixture targets require nonempty LIMIT with the literal fixture host.' >&2; exit 1; }

_guard-pki-env:
	@value=$(call sh_quote,$(ENV)); test "$${#value}" -le 63 && case "$$value" in [a-z0-9]*) true ;; *) false ;; esac && case "$$value" in *[!a-z0-9._-]*) false ;; *) true ;; esac || { printf '%s\n' 'ENV must be one canonical lowercase environment name.' >&2; exit 1; }

_guard-pki-limit:
	@value=$(call sh_quote,$(LIMIT)); test "$${#value}" -le 253 && case "$$value" in [a-z0-9]*) true ;; *) false ;; esac && case "$$value" in *[!a-z0-9.-]*) false ;; *) true ;; esac || { printf '%s\n' 'LIMIT must name one canonical lowercase registry inventory host.' >&2; exit 1; }

_guard-pki-request-ttl:
	@value=$(call sh_quote,$(REQUEST_TTL_SECONDS)); test "$${#value}" -le 6 && case "$$value" in 0|0*|*[!0-9]*) false ;; *) true ;; esac && test "$$value" -le 604800 || { printf '%s\n' 'REQUEST_TTL_SECONDS must be a canonical integer from 1 through 604800.' >&2; exit 1; }
