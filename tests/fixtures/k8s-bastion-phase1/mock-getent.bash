getent() {
  local user="${2:-}"

  if [[ "${1:-}" != passwd ]]; then
    command getent "$@"
    return
  fi

  case "$user" in
    admin-user | eligible-user | config-user | bootstrap-user)
      printf '%s:x:2000:2000:Phase 1 fixture:%s/state/%s:/bin/bash\n' \
        "$user" "$PHASE1_FIXTURE_ROOT" "$user"
      ;;
    missing-user)
      return 2
      ;;
    *)
      command getent "$@"
      ;;
  esac
}

export -f getent
