"""Controller-side URL validation before any Alloy host lifecycle work."""

import ipaddress
import re
from urllib.parse import urlsplit


def grafana_alloy_https_url_valid(value):
    if not isinstance(value, str) or not value.startswith("https://"):
        return False
    # urlsplit strips some control characters; reject them before parsing.
    if any(ord(char) <= 32 or ord(char) >= 127 for char in value) or "#" in value:
        return False
    try:
        url = urlsplit(value)
        host = url.hostname
        port = url.port
    except ValueError:
        return False
    if not host or "@" in url.netloc or url.netloc.endswith(":"):
        return False
    if port is not None and not 1 <= port <= 65535:
        return False
    if url.netloc.startswith("["):
        # Only unscoped IPv6 may use brackets, with nothing but a port after ].
        if not re.fullmatch(r"\[[0-9a-fA-F:.]+\](?::[0-9]+)?", url.netloc):
            return False
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
        return True
    if re.fullmatch(r"[0-9.]+", host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return False
        return True
    # DNS absolute names may end in one dot. Reject escaping, empty labels,
    # underscores and ambiguous characters rather than passing them to Alloy.
    name = host[:-1] if host.endswith(".") else host
    return len(name) <= 253 and re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*",
        name,
    ) is not None


class FilterModule:
    def filters(self):
        return {"grafana_alloy_https_url_valid": grafana_alloy_https_url_valid}
