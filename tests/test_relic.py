import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_relic", ROOT / "scripts/verify_relic.py"
)
assert SPEC and SPEC.loader
VERIFY_RELIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY_RELIC)


def test_checked_in_relic_matches_candidate():
    result = VERIFY_RELIC.verify(ROOT, ROOT / "scripts/verify_relic.py")
    assert result["valid"] is True
    assert all(result["checks"].values())


def test_relic_metadata_digest_binds_every_asserted_field():
    relic = json.loads((ROOT / "RELIC.json").read_text(encoding="utf-8"))
    expected = relic["metadata_digest"]
    for field in sorted(VERIFY_RELIC.REQUIRED_FIELDS - {"metadata_digest"}):
        mutated = dict(relic)
        mutated[field] = f"{mutated[field]}-forged"
        assert VERIFY_RELIC.metadata_digest(mutated) != expected, field


def test_relic_schema_rejects_unbound_fields():
    relic = json.loads((ROOT / "RELIC.json").read_text(encoding="utf-8"))
    relic["claim"] = "unsupported"
    assert set(relic) != VERIFY_RELIC.REQUIRED_FIELDS
