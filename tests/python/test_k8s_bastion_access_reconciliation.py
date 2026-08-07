from __future__ import annotations

import re
from pathlib import Path

import pytest


def _assert_contains(text: str, pattern: str, message: str) -> None:
    assert re.search(pattern, text, re.MULTILINE), message


def _assert_order(text: str, first: str, second: str, message: str) -> None:
    first_match = re.search(first, text, re.MULTILINE)
    second_match = re.search(second, text, re.MULTILINE)
    assert first_match and second_match and first_match.start() < second_match.start(), message


@pytest.fixture(scope="module")
def users_tasks(repo_root: Path) -> str:
    return (repo_root / "roles/k8s_bastion_access/tasks/users.yml").read_text(
        encoding="utf-8"
    )


def test_policy_demotion_uses_previous_manifest(users_tasks: str) -> None:
    _assert_contains(
        users_tasks,
        r"manifest=\{\{ k8s_bastion_policy_access_managed_manifest_path \| quote \}\}",
        "policy reconciliation does not reference the managed policy access manifest",
    )
    _assert_contains(
        users_tasks,
        r"yq -r '\(\.managedGroups // \[\]\) \| \.\[\]' \"\$manifest\"",
        "policy reconciliation does not include previously managed groups",
    )
    _assert_contains(
        users_tasks,
        r"printf 'extra-membership %s %s\\n' \"\$member\" \"\$group\"",
        "policy drift check does not report extra managed memberships",
    )
    _assert_contains(
        users_tasks,
        r"gpasswd -d \"\$member\" \"\$group\"",
        "policy reconciliation does not remove stale group memberships",
    )
    _assert_contains(
        users_tasks,
        r"select\('match', '\^extra-membership '\)",
        "stale membership changed_when is not tied to extra-membership drift",
    )


def test_reconcile_disabled_preserves_manifest_context(users_tasks: str) -> None:
    _assert_order(
        users_tasks,
        "Collect Kubernetes bastion current managed policy groups",
        "Check Kubernetes bastion user group drift",
        "current managed groups must be collected before drift checks",
    )
    _assert_contains(
        users_tasks,
        r"- k8s_bastion_reconcile_policy_access",
        "managed policy access tasks are not gated by reconciliation",
    )
    _assert_order(
        users_tasks,
        "Revoke stale Kubernetes bastion admin kubeconfigs from policy",
        "Write Kubernetes bastion managed policy access manifest",
        "managed policy manifest must be updated after stale access cleanup",
    )


def test_admin_kubeconfig_cleanup_is_precise(users_tasks: str) -> None:
    _assert_contains(
        users_tasks,
        r"cmp -s \"\$admin_kubeconfig\" \"\$config\" \|\| continue",
        "admin cleanup does not byte-compare the managed kubeconfig",
    )
    _assert_contains(
        users_tasks,
        (
            r"USER_KEY=\"\$user\" ADMIN_GROUP=\"\$admin_group\" yq -e "
            r"'\(\.users\[strenv\(USER_KEY\)\]\.ensureGroups // \[\]\) \| "
            r"contains\(\[strenv\(ADMIN_GROUP\)\]\)' \"\$policy\" >/dev/null 2>&1 && continue"
        ),
        "admin cleanup does not preserve users in the configured admin group",
    )
    _assert_contains(
        users_tasks,
        r"rm -f \"\$config\"",
        "admin cleanup does not remove stale managed kubeconfigs",
    )
    _assert_contains(
        users_tasks,
        r"--admin-group \{\{ k8s_bastion_admin_group \}\}",
        "admin bootstrap command does not pass the configured admin group",
    )


def test_reconciliation_scanner_rejects_missing_cleanup(users_tasks: str) -> None:
    mutated = users_tasks.replace('rm -f "$config"', ': preserve "$config"', 1)
    with pytest.raises(AssertionError):
        _assert_contains(
            mutated,
            r"rm -f \"\$config\"",
            "admin cleanup does not remove stale managed kubeconfigs",
        )
