# Development

Use the Podman development container for Ansible and lint tooling. This keeps
Python packages, Ansible collections, and linters out of the host environment.

```bash
make deps
make shell
```

The repository Makefile wraps the container and common Ansible operations:

```bash
make help
make syntax ENV=dev
make verify
```

Required local tools:

- Podman on the workstation or CI runner
- Git and Make
- Ansible from `requirements-dev.txt`, installed inside `Containerfile.dev`
- Ansible Galaxy collections from `requirements.yml`, installed inside `Containerfile.dev`
- Git when using `vendor/platform-k8s-bastion` as a submodule

Useful checks:

```bash
make inventory ENV=dev
make syntax ENV=dev
make syntax ENV=dev PLAYBOOK=playbooks/k8s-bastion-access.yml
make lint
make yamllint
make test
```

`ansible-lint`, `yamllint`, and `make test` are development checks. They are not required on managed hosts. The Make targets run tool-dependent checks in the development container, and their configuration excludes `.ansible/` and the vendored bastion runtime.

The dev container mounts this repository at `/workspace`. If
`../platform-private` exists next to the repository, it is mounted read-only at
`/platform-private` so the default relative private paths still work from
`/workspace`. If `~/.config/platform-infrastructure` exists, it is mounted
read-only under the container home so env files that derive outside-Git secret
paths from `$HOME` continue to work.

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
