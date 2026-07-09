#!/usr/bin/env bash
set -euo pipefail

env_name="${PLATFORM_CONFIG_ENVIRONMENT:-homelab}"
env_file="${PLATFORM_CONFIG_ENV_FILE:-../platform-private/config/${env_name}.ansible.env}"

if [[ -f "$env_file" ]]; then
  # shellcheck source=/dev/null
  source "$env_file"
fi

inventory="${PLATFORM_CONFIG_INVENTORY:-../platform-private/config/inventories/${env_name}/hosts.yml}"

if [[ $# -gt 0 ]]; then
  inventory="$1"
  shift
fi

if [[ ! -f "$inventory" ]]; then
  printf 'Inventory not found: %s\n' "$inventory" >&2
  printf 'Create it in platform-private or pass an explicit inventory path.\n' >&2
  exit 1
fi

ansible -i "$inventory" all -m ping "$@"
