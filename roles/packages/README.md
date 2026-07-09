# packages

Installs `platform_base_packages` from inventory variables.

The shared baseline is intentionally small and should contain packages useful on
all managed VMs:

```yaml
platform_base_packages:
  - bash-completion
  - curl
  - git
  - jq
  - lsof
  - sysstat
  - tar
  - wget
```

Keep role-specific runtime requirements in role variables instead of the global
baseline. Examples include `podman_host_packages`, `storage_volume_packages`,
`root_lvm_packages`, `firewalld_package`, and `chrony_package`.

Do not add editor or shell-session preferences such as `vim`, `nano`, or `tmux`
to the global baseline. Use the base image editor, normally `vi`, or add local
operator conveniences through environment-specific private variables when there
is a real need.
