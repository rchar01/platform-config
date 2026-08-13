# Rocky Linux Minor Alignment

`platform-config` provides one isolated migration from Rocky Linux 10.1 to
10.2. It is a historical transition for explicitly eligible hosts, not normal
desired-state convergence. No regular playbook imports it.

The migration accepts only these states:

- Rocky 10.1 with an exact `/etc/dnf/vars/releasever` value of `10.1` and no
  completion marker: preflight or apply may proceed.
- Rocky 10.2 without a release override: verify and skip.
- Rocky 10.0, another distribution or release, or inconsistent marker state:
  fail without attempting an upgrade.

## Private Inventory

Keep a replacement host outside the normal environment inventory until its new
SSH identity is authenticated. Create a private isolated inventory at:

```text
../platform-private/config/inventories/<env>-rocky-alignment/hosts.yml
```

That inventory must contain exactly one `rocky_alignment_hosts` member. Its host
variables must explicitly enable this transition and record the exact reviewed
standard Rocky repository origins and signature policy:

```yaml
ansible_connection: ansible.builtin.ssh
rocky_10_1_to_10_2_enabled: true
rocky_10_1_to_10_2_repositories:
  baseos:
    baseurl: []
    gpgcheck: true
    gpgkey:
      - file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10
    metalink: null
    mirrorlist: https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=BaseOS-10
    repo_gpgcheck: false
```

Record every enabled repository from the untouched clone, including exact ID,
base URLs, mirrorlist or metalink, GPG key URLs, and both GPG-check booleans. Do
not copy the partial BaseOS example without inspection. Every repository must
use `file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10`. Vault, `ptb-*`, testing,
development, local, non-HTTPS package origins, alternate signing keys, and
disabled package-signature checks are prohibited.

Rocky repository substitution remains on the supported major stream
(`releasever=10`), not a forced `10.2` repository path. The migration separately
requires that this stream resolves exactly one incoming `rocky-release` version
of 10.2.

## Run Preflight

Use the containerized launcher. It derives the isolated inventory and matching
private environment file, requires one literal hostname, and validates strict
SSH settings before invoking Ansible:

```bash
./scripts/in-container ./scripts/rocky-minor-alignment \
  preflight --env dev --limit dev-registry-runner-01
```

Preflight refreshes repository metadata and resolves the target transaction, so
it is not cache-only. It does not remove the release override, install packages,
restart services, or reboot.

## Apply

Apply repeats preflight, verifies conservative free-space margins for the DNF
cache and protected transaction staging filesystems, downloads the exact
transaction, records a deterministic RPM manifest and complete installed-state
digest, and prints both SHA-256 values. It requires interactive approval
containing both values:

```bash
./scripts/in-container ./scripts/rocky-minor-alignment \
  apply --env dev --limit dev-registry-runner-01
```

After approval, the workflow acquires the qualified DNF 4.20 RPMDB lock,
rechecks installed RPM state, RPM bytes, and the complete local-only DNF action
set before removing the release override. It executes that same locked DNF
transaction, reboots, and requires Rocky 10.2, current Rocky release packages,
a packaged running kernel, healthy DNF state, reviewed repositories, no pending
package update, and no failed units.

The helper deliberately fails when the DNF implementation differs from the
qualified Rocky 10 DNF 4.20 implementation. The lock coordinates DNF clients;
operators must keep direct `rpm` use and other package automation stopped during
the approval and apply window.

The qualified DNF transaction implementation was observed unchanged in these
Rocky packages on 2026-08-13:

```text
Rocky 10.1: dnf/python3-dnf 4.20.0-18.el10.rocky.0.1,
            libdnf 0.73.1-12.el10.rocky.0.1
Rocky 10.2: dnf/python3-dnf 4.20.0-22.el10_2.rocky.0.1,
            libdnf 0.73.1-15.el10_2.rocky.0.1
```

Requalifying another build requires inspecting its installed DNF Python source,
reviewing lock and transaction semantics, updating the source digest deliberately,
and rerunning the disposable Rocky prepare/apply reconstruction test.

If apply starts, the protected transaction directory retains an
`apply-started.json` phase record. It adds `transaction-complete.json` only after
DNF succeeds. On any package or reboot ambiguity, stop and retain that directory
for diagnosis; do not restore `releasever=10.1`, rerun apply, or improvise a
package rollback.

Failures before `apply-started.json` are pre-mutation failures. Their evidence is
the retained protected staging directory and Ansible output; the workflow does
not write a separate host-side failure marker before mutation.

The completion marker is written only after verification:

```text
/var/lib/platform-config/migrations/2026-08-rocky-10.1-to-10.2.done
```

Restoring `releasever=10.1` is not rollback. For the initial disposable Runner
campaign, recover by recreating the VM after correcting the failed transition or
repository policy.
