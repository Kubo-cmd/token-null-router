#!/usr/bin/env python3
"""Fail closed if the PyPI workflow drifts from its approved contract."""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/publish.yml"
EXPECTED_WORKFLOW_SHA256 = "1b94310e131b2d87e8ebb548e512b0a0445ac31416ee8bc76a3ad38208dcba2c"
EXPECTED_ACTIONS = {
    "actions/checkout": "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "pypa/gh-action-pypi-publish": "dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
}
EXPECTED_VALUES = {
    "commit": "f834b135a21f9e6a64f9dd45401bd7672bfb7d14",
    "wheel": "77ac4b249ffa802df4bb75505545e7a211099716c8af59ed473f0e3b9a665cb2",
    "sdist": "25c4a24252083e7a51ff3c8513542b3e6d975c5a9593f6d9b6679887e32c6720",
    "manifest": "c6b9da9834dc0f4e33a391846717716775da72f8845ec0204dc5d8f3074f7a6e",
    "checksums": "ae88c9257ebd4aba6de7c0482916eba7bafeb9f2f7e125c82aabb666a5416d2e",
}
REQUIRED_SNIPPETS = (
    "workflow_dispatch:",
    "if: github.ref == 'refs/heads/main' && inputs.tag == 'v0.1.0'",
    "name: pypi",
    "id-token: write",
    "contents: read",
    "ref: refs/tags/v0.1.0",
    "persist-credentials: false",
    "GH_TOKEN: ${{ github.token }}",
    "set -euo pipefail",
    "authority\"] == \"NONE\"",
    "packages-dir: dist/",
    "repository-url: https://upload.pypi.org/legacy/",
    "verify-metadata: true",
    "skip-existing: false",
    "attestations: false",
)
FORBIDDEN_SNIPPETS = (
    "pull_request_target:",
    "schedule:",
    "TWINE_PASSWORD",
    "secrets.",
    "password:",
    "skip-existing: true",
    "attestations: true",
)


def verify(path: Path = WORKFLOW) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    uses = re.findall(r"^\s*uses:\s*([^@\s]+)@([^\s#]+)", text, re.MULTILINE)
    checks: dict[str, bool] = {
        "exact_workflow_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()
        == EXPECTED_WORKFLOW_SHA256,
        "manual_only": "workflow_dispatch:" in text
        and not any(trigger in text for trigger in ("\n  push:", "\n  pull_request:", "\n  release:", "\n  schedule:")),
        "required_snippets": all(snippet in text for snippet in REQUIRED_SNIPPETS),
        "forbidden_snippets_absent": not any(snippet in text for snippet in FORBIDDEN_SNIPPETS),
        "exact_actions": dict(uses) == EXPECTED_ACTIONS,
        "all_actions_sha_pinned": bool(uses)
        and all(re.fullmatch(r"[0-9a-f]{40}", revision) for _, revision in uses),
        "exact_values": all(value in text for value in EXPECTED_VALUES.values()),
        "exact_asset_names": all(
            text.count(name) >= 3
            for name in (
                "token_null_router-0.1.0-py3-none-any.whl",
                "token_null_router-0.1.0.tar.gz",
            )
        ),
        "no_wildcard_download": "--pattern '*'" not in text and '--pattern "*"' not in text,
        "oidc_without_token_secret": "id-token: write" in text
        and "secrets." not in text
        and "TWINE_PASSWORD" not in text,
    }
    return {"checks": checks, "valid": all(checks.values())}


def main() -> int:
    try:
        result = verify()
    except (OSError, UnicodeDecodeError) as exc:
        result = {"error": type(exc).__name__, "valid": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
