#!/usr/bin/env python3
"""Verify repository/relic consistency without claiming external authenticity."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
RELIC_NAME = "RELIC.json"
VERIFIER_NAME = "scripts/verify_relic.py"
SCOPE = f"all tracked and non-ignored repository files except {RELIC_NAME} and {VERIFIER_NAME}"
EXCLUDED = {RELIC_NAME, VERIFIER_NAME}
REQUIRED_FIELDS = {
    "artifact",
    "version",
    "sigil",
    "content_digest",
    "content_digest_scope",
    "verifier",
    "verifier_digest",
    "metadata_digest",
}


def repository_files(root: Path = ROOT) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    names = sorted(name for name in result.stdout.decode("utf-8").split("\0") if name)
    paths = [root / name for name in names if name not in EXCLUDED]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise RuntimeError("relic input must contain regular files only")
    return paths


def content_digest(paths: list[Path], root: Path = ROOT) -> str:
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def metadata_digest(relic: dict[str, Any]) -> str:
    bound = {key: value for key, value in relic.items() if key != "metadata_digest"}
    encoded = json.dumps(bound, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def declared_versions(root: Path = ROOT) -> tuple[str | None, str | None]:
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    package = (root / "src/token_null_router/__init__.py").read_text(encoding="utf-8")
    project_match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    package_match = re.search(r'^__version__\s*=\s*"([^"]+)"', package, re.MULTILINE)
    return (
        project_match.group(1) if project_match else None,
        package_match.group(1) if package_match else None,
    )


def verify(root: Path = ROOT, verifier: Path = SELF) -> dict[str, Any]:
    relic = json.loads((root / RELIC_NAME).read_text(encoding="utf-8"))
    if not isinstance(relic, dict):
        raise ValueError("relic must be a JSON object")
    digest = content_digest(repository_files(root), root)
    verifier_digest = hashlib.sha256(verifier.read_bytes()).hexdigest()
    expected_sigil = f"TNR-ZERO-v010-{digest[:12].upper()}"
    project_version, package_version = declared_versions(root)
    checks = {
        "schema": set(relic) == REQUIRED_FIELDS,
        "artifact": relic.get("artifact") == "TOKEN NULL ROUTER",
        "version": relic.get("version") == project_version == package_version,
        "content_digest_scope": relic.get("content_digest_scope") == SCOPE,
        "verifier": relic.get("verifier") == VERIFIER_NAME,
        "content_digest": relic.get("content_digest") == digest,
        "sigil": relic.get("sigil") == expected_sigil,
        "verifier_digest": relic.get("verifier_digest") == verifier_digest,
        "metadata_digest": relic.get("metadata_digest") == metadata_digest(relic),
    }
    return {"checks": checks, "sigil": expected_sigil, "valid": all(checks.values())}


def main() -> int:
    try:
        output = verify()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        output = {"error": type(exc).__name__, "valid": False}
    print(json.dumps(output, sort_keys=True))
    return 0 if output["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
