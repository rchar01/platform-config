# vendor

This directory contains checked-out runtime repositories used by Ansible roles.

For Kubernetes bastion tooling, `platform-config` installs from the runtime directory inside a checkout:

1. Sibling checkout:

   `../platform-k8s-bastion/runtime`

2. Vendored checkout or git submodule:

   `vendor/platform-k8s-bastion/runtime`

The Ansible variable `k8s_bastion_runtime_src` selects which path is used.

The recommended workflow is a git submodule:

```bash
git submodule add https://codeberg.org/rch/platform-k8s-bastion.git vendor/platform-k8s-bastion
git submodule update --init --recursive
```

For local-only development, a sibling checkout can be used as the submodule source:

```bash
git -c protocol.file.allow=always submodule add ../platform-k8s-bastion vendor/platform-k8s-bastion
```

This pins the exact bastion runtime revision used by `platform-config`.

When the submodule already exists and uses a local path, initialize or restore it with:

```bash
git -c protocol.file.allow=always submodule update --init vendor/platform-k8s-bastion
```

`git submodule status` prefixes are useful diagnostics:

- `-` means the submodule is registered but not checked out.
- `+` means the working tree is checked out at a different commit than the parent repo has pinned.
- No prefix means the checked-out submodule commit matches the parent repo index.

Before publishing a shared repository, prefer changing `.gitmodules` to a URL other users and CI can access:

```bash
git submodule set-url vendor/platform-k8s-bastion https://codeberg.org/rch/platform-k8s-bastion.git
```

To update the pinned runtime later:

```bash
git -C vendor/platform-k8s-bastion fetch origin tag vX.Y.Z
git -C vendor/platform-k8s-bastion checkout vX.Y.Z
git add vendor/platform-k8s-bastion
```

For local-only development, the tag must exist in the sibling runtime checkout referenced by `.gitmodules`. Keep the local URL until the runtime repository is published to a shared remote.
