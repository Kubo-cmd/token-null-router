import importlib.util
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_publish_workflow", ROOT / "scripts/verify_publish_workflow.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def test_publish_workflow_matches_approved_contract():
    result = VERIFY.verify()
    assert result["valid"] is True
    assert all(result["checks"].values())


def _write_mutation(tmp_path, workflow):
    path = tmp_path / "publish.yml"
    path.write_text(workflow, encoding="utf-8")
    return path


def test_publish_workflow_rejects_secret_and_mutable_action(tmp_path):
    workflow = VERIFY.WORKFLOW.read_text(encoding="utf-8")
    mutated = workflow.replace(
        "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
        "pypa/gh-action-pypi-publish@release/v1",
    ).replace(
        "verbose: true",
        "verbose: true\n          password: ${{ secrets.PYPI_API_TOKEN }}",
    )
    result = VERIFY.verify(_write_mutation(tmp_path, mutated))
    assert result["valid"] is False
    assert result["checks"]["exact_workflow_sha256"] is False
    assert result["checks"]["exact_actions"] is False
    assert result["checks"]["all_actions_sha_pinned"] is False
    assert result["checks"]["forbidden_snippets_absent"] is False
    assert result["checks"]["oidc_without_token_secret"] is False


@pytest.mark.parametrize(
    "old,new",
    [
        ("name: pypi", "name: untrusted"),
        ("contents: read", "contents: write"),
        ("attestations: false", "attestations: ${{ true }}"),
        ("  workflow_dispatch:", "  push : {}\n  workflow_dispatch:"),
        (
            "cp release-assets/token_null_router-0.1.0.tar.gz dist/",
            "cp release-assets/token_null_router-0.1.0.tar.gz dist/\n          cp release-assets/RELEASE-MANIFEST.json dist/",
        ),
    ],
)
def test_publish_workflow_rejects_any_byte_drift(tmp_path, old, new):
    workflow = VERIFY.WORKFLOW.read_text(encoding="utf-8")
    assert old in workflow
    result = VERIFY.verify(_write_mutation(tmp_path, workflow.replace(old, new, 1)))
    assert result["valid"] is False
    assert result["checks"]["exact_workflow_sha256"] is False


def test_embedded_manifest_validator_accepts_pinned_manifest_shape(tmp_path):
    workflow = VERIFY.WORKFLOW.read_text(encoding="utf-8")
    marker = "          python3 - <<'PY'\n"
    start = workflow.index(marker) + len(marker)
    end = workflow.index("\n          PY", start)
    embedded = textwrap.dedent(workflow[start:end])

    release_assets = tmp_path / "release-assets"
    release_assets.mkdir()
    manifest = {
        "authority": "NONE",
        "version": "0.1.0",
        "source_commit": VERIFY.EXPECTED_VALUES["commit"],
        "artifacts": {
            "token_null_router-0.1.0-py3-none-any.whl": {
                "sha256": VERIFY.EXPECTED_VALUES["wheel"],
                "bytes": 10410,
            },
            "token_null_router-0.1.0.tar.gz": {
                "sha256": VERIFY.EXPECTED_VALUES["sdist"],
                "bytes": 12596,
            },
        },
    }
    (release_assets / "RELEASE-MANIFEST.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    environment = os.environ.copy()
    environment.update(
        {
            "EXPECTED_COMMIT": VERIFY.EXPECTED_VALUES["commit"],
            "EXPECTED_WHEEL_SHA256": VERIFY.EXPECTED_VALUES["wheel"],
            "EXPECTED_SDIST_SHA256": VERIFY.EXPECTED_VALUES["sdist"],
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", embedded],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
