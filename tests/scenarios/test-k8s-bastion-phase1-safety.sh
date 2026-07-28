#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
DEFAULTS="${ROOT_DIR}/roles/k8s_bastion_access/defaults/main.yml"
PREFLIGHT="${ROOT_DIR}/roles/k8s_bastion_access/tasks/preflight.yml"
BOOTSTRAP_VALIDATION="${ROOT_DIR}/roles/k8s_bastion_access/tasks/validate_bootstrap.yml"
HOST_CONFIG="${ROOT_DIR}/roles/k8s_bastion_access/tasks/host_config.yml"
USERS_TASKS="${ROOT_DIR}/roles/k8s_bastion_access/tasks/users.yml"
USER_SELECTION_TASKS="${ROOT_DIR}/roles/k8s_bastion_access/tasks/select_bootstrap_users.yml"
USER_SELECTOR="${ROOT_DIR}/roles/k8s_bastion_access/templates/select-bootstrap-users.sh.j2"
SYSTEMD_TASKS="${ROOT_DIR}/roles/k8s_bastion_access/tasks/systemd.yml"
RUNTIME_TASKS="${ROOT_DIR}/roles/k8s_bastion_access/tasks/runtime.yml"
BOOTSTRAPD_UNIT="${ROOT_DIR}/roles/k8s_bastion_access/templates/bastion-bootstrapd.service.j2"
LOGIN_PROFILE="${ROOT_DIR}/roles/k8s_bastion_access/templates/bastion-login.sh.j2"
PUBLIC_EXAMPLE="${ROOT_DIR}/inventories/dev/group_vars/k8s_bastion_user_access.yml.example"
PUBLIC_DOC="${ROOT_DIR}/docs/k8s-bastion.md"
VALIDATION_FIXTURE="${ROOT_DIR}/tests/fixtures/k8s-bastion-phase1/validate-bootstrap.yml"
RENDER_FIXTURE="${ROOT_DIR}/tests/fixtures/k8s-bastion-phase1/render-behavior.yml"
USER_SELECTION_FIXTURE="${ROOT_DIR}/tests/fixtures/k8s-bastion-phase1/select-users.yml"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"

  grep -qE -- "$pattern" "$file" || fail "$message"
}

assert_not_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"

  if grep -qE -- "$pattern" "$file"; then
    fail "$message"
  fi
}

test_bootstrapd_write_allowlist_is_narrow() {
  assert_contains "$BOOTSTRAPD_UNIT" '^ProtectSystem=strict$' \
    'Bootstrap daemon no longer preserves ProtectSystem=strict'
  assert_contains "$BOOTSTRAPD_UNIT" '^ProtectHome=false$' \
    'Bootstrap daemon cannot write authorized user-home credential paths'
  assert_contains "$BOOTSTRAPD_UNIT" '^ReadWritePaths=/run/bastion-bootstrapd /home /var/lib/bastion/bootstrap-tokens$' \
    'Bootstrap daemon write allowlist is not limited to runtime, homes, and token ownership'
  assert_not_contains "$BOOTSTRAPD_UNIT" '^ReadWritePaths=.* /var/lib/bastion($| )' \
    'Bootstrap daemon grants write access to broad /var/lib/bastion state'
  assert_contains "$HOST_CONFIG" '^[[:space:]]+- path: /var/lib/bastion/bootstrap-tokens$' \
    'Bootstrap token ownership directory is not created before systemd starts the daemon'
  assert_contains "$HOST_CONFIG" 'mode: "0700"' \
    'Bootstrap token ownership directory is not private'
}

test_bootstrap_modes_are_safe_by_default() {
  assert_contains "$DEFAULTS" '^k8s_bastion_initial_user_bootstrap_mode: disabled$' \
    'Initial user bootstrap is not disabled by default'
  assert_contains "$DEFAULTS" '^k8s_bastion_enable_automatic_user_bootstrap: false$' \
    'Automatic login bootstrap is not disabled by default'
  assert_contains "$PREFLIGHT" 'import_tasks: validate_bootstrap.yml' \
    'Bastion preflight does not execute focused bootstrap validation'
  assert_contains "$BOOTSTRAP_VALIDATION" "k8s_bastion_initial_user_bootstrap_mode in \['disabled', 'online', 'offline'\]" \
    'Initial bootstrap modes are not structurally validated'
  assert_contains "$BOOTSTRAP_VALIDATION" 'k8s_bastion_enable_bootstrapd is not defined' \
    'Legacy bootstrap controls are silently accepted instead of requiring migration'
  assert_contains "$BOOTSTRAP_VALIDATION" 'k8s_bastion_enable_automatic_user_bootstrap \| bool' \
    'Automatic bootstrap conditions do not normalize boolean-compatible values'
  assert_contains "$BOOTSTRAP_VALIDATION" "or k8s_bastion_initial_user_bootstrap_mode == 'disabled'" \
    'Automatic login bootstrap does not reject an overlapping initial mode'
  assert_contains "$BOOTSTRAP_VALIDATION" 'Block automatic login bootstrap pending runtime admin exclusion' \
    'Automatic login bootstrap lacks a fail-closed runtime dependency gate'
  assert_contains "$LOGIN_PROFILE" '^\{% if k8s_bastion_enable_automatic_user_bootstrap \| bool %\}$' \
    'Login bootstrap is not gated by explicit automatic-bootstrap approval'
  assert_contains "$SYSTEMD_TASKS" 'enabled: "\{\{ k8s_bastion_enable_automatic_user_bootstrap \| bool \}\}"' \
    'Bootstrap daemon enablement is not tied to automatic login bootstrap'
}

test_ansible_bootstrap_validation_and_rendering() {
  local mode output value

  for mode in disabled online offline; do
    for value in false no off 0; do
      ansible-playbook "$VALIDATION_FIXTURE" \
        --extra-vars "{\"phase1_initial_mode\":\"${mode}\",\"phase1_automatic_bootstrap\":\"${value}\"}" \
        >/dev/null
    done
  done

  ansible-playbook "$VALIDATION_FIXTURE" \
    --extra-vars '{"phase1_automatic_bootstrap":false}' \
    >/dev/null

  for value in invalid maybe 2 ''; do
    if output="$(ansible-playbook "$VALIDATION_FIXTURE" \
      --extra-vars "{\"phase1_automatic_bootstrap\":\"${value}\"}" 2>&1)"; then
      fail "Invalid automatic-bootstrap value '${value}' passed Ansible validation"
    fi
    grep -q 'must be a boolean or a boolean-compatible' <<< "$output" \
      || fail "Invalid automatic-bootstrap value '${value}' did not reach boolean validation"
  done

  for value in true yes on 1; do
    if output="$(ansible-playbook "$VALIDATION_FIXTURE" \
      --extra-vars "{\"phase1_automatic_bootstrap\":\"${value}\"}" 2>&1)"; then
      fail "Truthy automatic-bootstrap value '${value}' passed without a compatible runtime release"
    fi
    grep -q 'login recovery does not exclude policy admins' <<< "$output" \
      || fail "Truthy automatic-bootstrap value '${value}' did not reach the runtime dependency gate"
  done

  if output="$(ansible-playbook "$VALIDATION_FIXTURE" \
    --extra-vars '{"phase1_automatic_bootstrap":true}' 2>&1)"; then
    fail 'Native true automatic-bootstrap value passed without a compatible runtime release'
  fi
  grep -q 'login recovery does not exclude policy admins' <<< "$output" \
    || fail 'Native true automatic-bootstrap value did not reach the runtime dependency gate'

  ansible-playbook "$RENDER_FIXTURE" >/dev/null
}

test_initial_bootstrap_excludes_admins_and_all_user_mode() {
  assert_contains "$USERS_TASKS" 'import_tasks: select_bootstrap_users.yml' \
    'Initial bootstrap does not execute the tested eligible-user selector'
  assert_contains "$USER_SELECTION_TASKS" 'k8s_bastion_admin_group not in' \
    'Eligible-user selector does not exclude policy admins'
  assert_contains "$USER_SELECTION_TASKS" "lookup\('template', 'select-bootstrap-users.sh.j2'\)" \
    'Eligible-user task does not execute its tested credential-state selector'
  assert_contains "$USERS_TASKS" '--user \{\{ item \}\}' \
    'Initial bootstrap does not issue credentials per selected non-admin user'
  assert_not_contains "$USERS_TASKS" '--all' \
    'Initial bootstrap still delegates indiscriminate all-user issuance to the runtime'
  assert_contains "$USERS_TASKS" "k8s_bastion_initial_user_bootstrap_mode == 'offline'" \
    'Offline scaffolding is not an explicit initial bootstrap mode'
  ansible-playbook "$USER_SELECTION_FIXTURE" >/dev/null
}

test_future_interfaces_are_inert_and_sanitized() {
  local variable
  for variable in \
    k8s_bastion_enable_issuer_convergence \
    k8s_bastion_enable_controller_staging \
    k8s_bastion_enable_controller_convergence \
    k8s_bastion_enable_controller_cutover \
    k8s_bastion_enable_automatic_user_bootstrap; do
    assert_contains "$DEFAULTS" "^${variable}: false$" \
      "Future integration gate ${variable} is not disabled by default"
    assert_contains "$PUBLIC_EXAMPLE" "^${variable}: false$" \
      "Public example does not keep ${variable} disabled"
  done

  assert_contains "$PUBLIC_EXAMPLE" 'registry\.example\.invalid/' \
    'Public artifact examples do not use the reserved invalid domain'
  assert_contains "$PUBLIC_EXAMPLE" '192\.0\.2\.10/32' \
    'Public network example does not use a documentation-only address'
  assert_contains "$PUBLIC_EXAMPLE" '^k8s_bastion_controller_policy_config_map:$' \
    'Public example omits the external policy ConfigMap reference shape'
  assert_contains "$PUBLIC_EXAMPLE" '^k8s_bastion_controller_signing_secret:$' \
    'Public example omits the external signing Secret reference shape'
  assert_not_contains "$PUBLIC_EXAMPLE" 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|client-certificate-data:|token: [A-Za-z0-9]' \
    'Public integration example contains credential-shaped data'
}

test_public_rbac_and_ownership_boundaries_are_explicit() {
  assert_contains "$PUBLIC_DOC" 'Issuer.*Secret verbs.*exactly `create` and `delete`' \
    'Public bastion documentation does not state exact issuer Secret verbs'
  assert_contains "$PUBLIC_DOC" 'approver.*Secret `get`' \
    'Public bastion documentation conflates approver Secret read with issuer RBAC'
  assert_contains "$DEFAULTS" 'vendor/platform-k8s-bastion/runtime' \
    'Bastion role no longer installs runtime from the external runtime source'
  assert_contains "$RUNTIME_TASKS" 'src:.*k8s_bastion_runtime_src' \
    'Bastion role no longer copies commands from the external runtime source'
  assert_not_contains "$RUNTIME_TASKS" 'src: files/' \
    'Bastion role copies runtime commands from role-owned files'
}

test_bootstrapd_write_allowlist_is_narrow
test_bootstrap_modes_are_safe_by_default
test_ansible_bootstrap_validation_and_rendering
test_initial_bootstrap_excludes_admins_and_all_user_mode
test_future_interfaces_are_inert_and_sanitized
test_public_rbac_and_ownership_boundaries_are_explicit

printf 'Kubernetes bastion Phase 1 safety check passed\n'
