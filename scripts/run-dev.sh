#!/usr/bin/env bash
set -euo pipefail

env_file="${PLATFORM_CONFIG_ENV_FILE:-../platform-private/config/dev.ansible.env}"

if [[ -f "$env_file" ]]; then
  # shellcheck source=/dev/null
  source "$env_file"
fi

inventory="${PLATFORM_CONFIG_INVENTORY:-../platform-private/config/inventories/dev/hosts.yml}"

if [[ "${1:-}" == "-i" || "${1:-}" == "--inventory" ]]; then
  if [[ -z "${2:-}" ]]; then
    printf 'Missing inventory path after %s\n' "$1" >&2
    exit 1
  fi
  inventory="$2"
  shift 2
fi

if [[ ! -f "$inventory" ]]; then
  printf 'Inventory not found: %s\n' "$inventory" >&2
  printf 'Create it in platform-private or set PLATFORM_CONFIG_INVENTORY.\n' >&2
  exit 1
fi

ansible-playbook -i "$inventory" playbooks/site.yml "$@"
