# Private Config Examples

These files are safe examples for `../platform-private/config/*.ansible.env`.

Copy them into `platform-private/config/` and remove the `.example` suffix. Source
them from the `platform-config` repository root, or set
`PLATFORM_PRIVATE_CONFIG_ROOT` to an absolute config-directory path for another
layout. They should contain paths and environment selection only, not secret
values.
