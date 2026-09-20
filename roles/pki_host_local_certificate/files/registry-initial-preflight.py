"""Read-only initial Zot readiness; no helper installation or lifecycle writes."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def protected_path(path):
    for parent in reversed(Path(path).parents):
        if parent.exists() or parent.is_symlink():
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                    and not info.st_mode & 0o022, "unsafe registry path ancestor")


def regular(path, mode, digest):
    protected_path(path)
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode,
            "unsafe staged registry file")
    require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest,
            "staged registry file differs from reviewed source")


def main():
    values = json.loads(sys.argv[1])
    result = subprocess.run(
        ["systemctl", "show", "--all", "zot.service", "--property=LoadState,ActiveState,SubState,UnitFileState"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    require(result.returncode in (0, 4) and not result.stderr, "cannot inspect Zot service")
    lines = result.stdout.splitlines()
    service = dict(line.split("=", 1) for line in lines)
    require(len(lines) == 4 and set(service) == {"LoadState", "ActiveState", "SubState", "UnitFileState"},
            "incomplete Zot service observation")
    require(service["ActiveState"] == "inactive" and service["SubState"] == "dead",
            "initial registry operation requires inactive Zot")
    absent = service["LoadState"] == "not-found" and service["UnitFileState"] == ""
    dormant = (result.returncode == 0 and service["LoadState"] == "masked"
               and service["UnitFileState"] == "masked")
    require(dormant or (absent and not values["request"]), "Zot must be absent or staged masked")
    for key in ("state", "pending", "versions", "config", "cert", "key"):
        protected_path(values[key])
    require(not any(os.path.lexists(values[key]) for key in ("cert", "key")),
            "initial registry operation requires absent managed TLS material")
    if os.path.lexists(values["config"]):
        regular(values["config"], 0o644, values["config_sha256"])
    else:
        require(not values["request"] and absent, "request requires staged Zot configuration")
    if os.path.lexists(values["quadlet"]):
        regular(values["quadlet"], 0o644, values["quadlet_sha256"])
    else:
        require(not values["request"], "request requires staged Zot Quadlet")
    if not values["request"]:
        require(not any(os.path.lexists(values[key]) for key in ("state", "pending", "versions")),
                "host/storage/stage requires fresh registry lifecycle state")
        protected_path(values["data"])
        if os.path.lexists(values["data"]):
            info = os.lstat(values["data"])
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                    and not info.st_mode & 0o022 and not os.listdir(values["data"]),
                    "host/storage/stage requires absent or empty registry data")
        return
    regular(values["helper"], 0o755, values["helper_sha256"])
    if not os.path.lexists(values["state"]):
        require(not any(os.path.lexists(values[key]) for key in ("pending", "versions")),
                "orphaned registry lifecycle state")
        return
    require(not os.path.lexists(os.path.join(values["state"], "active")),
            "issue requires no active predecessor")
    result = subprocess.run([
        values["helper"], "zot-custody", "--state-root", values["state"],
        "--pending-root", values["pending"], "--versions-root", values["versions"],
        "--service", values["service"], "--target", values["target"], "--operation", "issue",
        "--zot-config", values["config"], "--managed-cert", values["cert"],
        "--managed-key", values["key"], "--managed-config-sha256", values["config_sha256"],
    ], capture_output=True, text=True, check=False, timeout=30)
    require(result.returncode == 0 and not result.stderr, "cannot authenticate dormant registry custody")
    custody = json.loads(result.stdout)
    require(custody["custody"] == "dormant" and custody["request_id"] == "none",
            "request requires dormant registry custody")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as exc:
        sys.exit(f"Registry initial preflight: {exc}")
