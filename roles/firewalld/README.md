# firewalld

Installs firewalld and its managed-host Python bindings, verifies that Ansible's
Python interpreter can import them, and manages the systemd enabled/runtime
state. The default baseline keeps firewalld disabled at boot and stopped at
runtime while service roles maintain permanent rules offline.

Use `firewalld_service_enabled` and `firewalld_service_state` when the boot
enabled state and runtime state must differ. The older `firewalld_enabled`
variable remains the default source for both values.

Inventory values for `firewalld_service_enabled` and
`firewalld_service_state` override the derived defaults from
`firewalld_enabled`. Set both to an active policy only after all required live
rules and reload behavior have been validated.

Open services and ports declared through this baseline role are managed only
when `firewalld_manage_rules` is true. Service roles use permanent,
offline-capable module operations while the daemon is stopped and apply the
same rules immediately when inventory opts into active enforcement.

Run only this baseline with:

```bash
make check ENV=dev PLAYBOOK=playbooks/firewalld.yml
make apply ENV=dev PLAYBOOK=playbooks/firewalld.yml
make smoke-firewalld ENV=dev
```

See [Firewalld Readiness And Enablement](../../docs/firewalld.md) for public
rule examples, the readiness checklist, canary activation, validation,
fleet rollout, rollback, and known gaps.
