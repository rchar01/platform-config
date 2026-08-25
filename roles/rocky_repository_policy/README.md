# rocky_repository_policy

Validates the exact effective set of enabled DNF repositories on a Rocky host.
The role reads DNF configuration without loading repository metadata and never
creates, enables, disables, or rewrites a repository.

Validation is disabled by default. Private inventory enables it and supplies a
nonempty mapping keyed by repository ID. Every entry must contain exactly these
fields:

```yaml
rocky_repository_policy_enabled: true
rocky_repository_policy_allow_http: false
rocky_repository_policy_releasever: "10"
rocky_repository_policy:
  baseos:
    baseurl: []
    gpgcheck: true
    gpgkey:
      - file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10
    metalink: null
    mirrorlist: https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=BaseOS-10
    repo_gpgcheck: false
```

The expected release version must be a nonempty string and must exactly match
DNF's effective `releasever`. Each repository must use exactly one of `baseurl`,
`metalink`, or `mirrorlist`. Package origins must be credential-free HTTPS by
default. A private inventory may set `rocky_repository_policy_allow_http: true`
for an explicit temporary HTTP `baseurl` exception; mirrorlists and metalinks
remain HTTPS-only, and local signing keys plus package signature checking remain
mandatory. Lists are compared without regard to order; IDs and all six effective
fields must otherwise match exactly. Failure output identifies a release
mismatch or differing IDs or field names without printing private URL values.

The policy validates configured repository identity and security settings. It
does not prove network reachability, metadata freshness, package availability,
or immutable repository content. True content pinning requires an immutable
snapshot or publication URL.

Allowing HTTP does not authenticate repository metadata or prevent interception
or replay. Keep the exception narrowly scoped and remove it before promotion to
a trusted environment.

The role validates configured signing-key URLs, not the ownership, mode, or
digest of the referenced key files. Environments that require key-content
qualification must verify it separately, as the Rocky migration workflow does.

Every role that invokes Ansible's package or DNF modules depends on this role,
so an enabled policy runs before package operations even in focused playbooks.
Run the read-only gate independently with:

```bash
make check ENV=dev \
  PLAYBOOK=playbooks/maintenance/rocky-repository-policy.yml \
  LIMIT=dev-example-01
```
