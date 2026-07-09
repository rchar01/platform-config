# firewalld

Installs firewalld and manages its systemd enabled/state settings. Open services and ports are controlled by inventory variables when `firewalld_service_state` is `started`.

Use `firewalld_service_enabled` and `firewalld_service_state` when the boot enabled state and runtime state must differ. The older `firewalld_enabled` variable remains the default source for both values.

Inventory values for `firewalld_service_enabled` and `firewalld_service_state` override the derived defaults from `firewalld_enabled`.
