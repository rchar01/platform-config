# Development

Use a local Python virtual environment for Ansible and lint tooling.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
ansible-galaxy collection install -r requirements.yml
```

The repository Makefile wraps the same setup and common Ansible operations:

```bash
make deps
make help
make syntax ENV=dev
make verify
```

Required local tools:

- Python 3.12+ on the control node
- Ansible from `requirements-dev.txt`
- Ansible Galaxy collections from `requirements.yml`
- Git when using `vendor/platform-k8s-bastion` as a submodule

Useful checks:

```bash
source ../platform-private/config/dev.ansible.env
ansible-inventory -i "$PLATFORM_CONFIG_INVENTORY" --graph
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/site.yml --syntax-check
ansible-playbook -i "$PLATFORM_CONFIG_INVENTORY" playbooks/k8s-bastion-access.yml --syntax-check
ansible-lint playbooks/ roles/
yamllint .
bash tests/run-all.sh
```

`ansible-lint`, `yamllint`, and `tests/run-all.sh` are development checks. They are not required on managed hosts. Their local configuration excludes `.venv/` and the vendored bastion runtime.

See [Operator Runbook](operator-runbook.md) for the full homelab and dev bring-up sequence.

## Managed Host Requirements

Managed hosts need:

- Linux with systemd
- Python 3 for Ansible execution
- SSH access for the Ansible user
- sudo or root privilege escalation
- outbound HTTPS access or a configured corporate proxy/mirror for external CLI downloads
- writable `/usr/local/bin`, `/usr/local/sbin`, `/usr/local/lib/bastion`, `/etc/bastion`, and `/etc/systemd/system`

The `k8s_bastion_access` role installs required OS packages where possible, including Podman and runtime support packages.
