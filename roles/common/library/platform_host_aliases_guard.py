#!/usr/bin/python
"""Read-only, node-side guards for the fixed RKE2 aliases-only route."""

import ipaddress
import os
import re
import socket
import stat

from ansible.module_utils.basic import AnsibleModule


DOCUMENTATION = r"""
---
module: platform_host_aliases_guard
short_description: Validate RKE2 alias preparation or applied NSS resolution
description:
  - Read-only checks of alias declarations and the fixed /etc/hosts file.
  - Resolution verification is intended only after apply and is skipped in check mode.
options:
  aliases:
    description: Nonempty list of address and names mappings, validated without coercion.
    required: true
    type: raw
  verify_resolution:
    description: Verify every name using the node system resolver after apply.
    type: bool
    default: false
author:
  - platform-config
"""
EXAMPLES = r"""
- name: Check alias preparation
  platform_host_aliases_guard:
    aliases: "{{ platform_host_aliases }}"
"""
RETURN = r""""""

ETC = "/etc"
HOSTS = "/etc/hosts"
MARKER = b"ANSIBLE MANAGED PLATFORM HOST ALIASES"
BEGIN = b"# BEGIN " + MARKER
END = b"# END " + MARKER
LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


def address(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Alias addresses must be literal unscoped IP strings")
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Invalid alias IP address") from None


def declarations(aliases):
    if not isinstance(aliases, list) or not aliases:
        raise ValueError("Host aliases must be a nonempty list")
    desired = {}
    for alias in aliases:
        if not isinstance(alias, dict) or set(alias) != {"address", "names"}:
            raise ValueError("Each alias must contain exactly address and names")
        expected = address(alias["address"])
        names = alias["names"]
        if not isinstance(names, list) or not names:
            raise ValueError("Alias names must be a nonempty list")
        for name in names:
            if (not isinstance(name, str) or len(name) > 253
                    or not all(LABEL.fullmatch(label) for label in name.split("."))):
                raise ValueError("Invalid alias hostname")
            try:
                ipaddress.ip_address(name)
            except ValueError:
                pass
            else:
                raise ValueError("An alias hostname cannot be an IP address")
            key = name.lower()
            if key in desired:
                raise ValueError("Alias names must be unique, regardless of case or address")
            desired[key] = expected
    return desired


def trusted(details, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(details.st_mode) or details.st_uid != 0 or details.st_gid != 0
            or stat.S_IMODE(details.st_mode) & 0o7022):
        raise ValueError("Alias paths must be root-owned, non-symlink, safe directories/files")


def outside_block(data):
    """Reject ambiguous markers rather than letting blockinfile choose a boundary."""
    inside = False
    seen = False
    outside = []
    for line in data.splitlines(keepends=True):
        marker = line.rstrip(b"\n")
        if MARKER in line:
            if marker == BEGIN and not seen:
                inside = seen = True
            elif marker == END and inside:
                inside = False
            else:
                raise ValueError("Malformed or duplicate common host alias markers")
        elif not inside:
            outside.append(line)
    if inside:
        raise ValueError("Unclosed common host alias marker")
    return b"".join(outside)


def check_hosts(desired):
    trusted(os.lstat(ETC), directory=True)
    trusted(os.lstat(HOSTS))
    descriptor = os.open(HOSTS, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        trusted(os.fstat(stream.fileno()))
        data = outside_block(stream.read())
    for line in data.splitlines():
        fields = line.split(b"#", 1)[0].split()
        if len(fields) < 2:
            continue
        # Only desired names matter; unrelated bytes remain owned by their writer.
        names = {field.decode("ascii", errors="replace").lower() for field in fields[1:]}
        for name in names & desired.keys():
            if address(fields[0].decode("ascii", errors="replace")) != desired[name]:
                raise ValueError("Existing unmanaged hosts entry conflicts with a desired alias")


def check_resolution(desired):
    for name, expected in desired.items():
        results = socket.getaddrinfo(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        observed = {address(result[4][0]) for result in results}
        if observed != {expected}:
            raise ValueError("Applied alias NSS resolution does not match its declared address")


def main():
    module = AnsibleModule(
        argument_spec={
            "aliases": {"type": "raw", "required": True},
            "verify_resolution": {"type": "bool", "default": False},
        },
        supports_check_mode=True,
    )
    try:
        desired = declarations(module.params["aliases"])
        if module.params["verify_resolution"]:
            if not module.check_mode:
                check_resolution(desired)
        else:
            check_hosts(desired)
    except ValueError as error:
        module.fail_json(msg=str(error), changed=False)
    except OSError:
        module.fail_json(msg="Cannot inspect alias paths or resolve applied aliases", changed=False)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
