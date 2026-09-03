#!/usr/bin/env python3
"""Build, install, and smoke-test the current package in isolation."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IGNORED = {
    ".git",
    ".github",
    ".pytest_cache",
    ".ruff_cache",
    ".state",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}
REQUIRED_MEMBERS = {
    "token_null_router/__init__.py",
    "token_null_router/cli.py",
    "token_null_router/router.py",
}


def run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def ignore(_directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name in IGNORED or name.endswith(".egg-info") or name.endswith((".pyc", ".pyo"))
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="token-null-verify-") as raw_tmp:
        tmp = Path(raw_tmp)
        source = tmp / "source"
        wheelhouse = tmp / "wheelhouse"
        environment = tmp / "venv"
        shutil.copytree(ROOT, source, ignore=ignore)
        wheelhouse.mkdir()

        run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(wheelhouse),
                ".",
            ],
            cwd=source,
        )
        wheels = sorted(wheelhouse.glob("token_null_router-*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"expected one wheel, found {len(wheels)}")
        wheel = wheels[0]
        with zipfile.ZipFile(wheel) as archive:
            members = set(archive.namelist())
        missing = sorted(REQUIRED_MEMBERS - members)
        if missing:
            raise RuntimeError(f"wheel is missing required members: {missing}")

        venv.EnvBuilder(with_pip=True, clear=True).create(environment)
        scripts = environment / ("Scripts" if sys.platform == "win32" else "bin")
        python = scripts / ("python.exe" if sys.platform == "win32" else "python")
        cli = scripts / ("token-null.exe" if sys.platform == "win32" else "token-null")
        run(
            [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
            cwd=tmp,
        )
        imported = run(
            [str(python), "-c", "import token_null_router; print(token_null_router.__version__)"],
            cwd=tmp,
        ).stdout.strip()
        state = tmp / "state"
        routed = json.loads(
            run([str(cli), "--state-dir", str(state), "route", "ping"], cwd=tmp).stdout
        )
        verified = json.loads(
            run([str(cli), "--state-dir", str(state), "verify"], cwd=tmp).stdout
        )
        if routed.get("route") != "ZERO" or routed.get("model_tokens") != 0:
            raise RuntimeError("installed CLI did not produce the expected proven route")
        if verified != {"receipts": 1, "valid": True}:
            raise RuntimeError(f"installed CLI receipt verification failed: {verified}")

        print(
            json.dumps(
                {
                    "installed_version": imported,
                    "required_members_present": True,
                    "route": routed["route"],
                    "model_tokens": routed["model_tokens"],
                    "receipt_chain_valid": verified["valid"],
                    "receipts": verified["receipts"],
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
