import json
import os
import stat

import pytest

from token_null_router import TokenNullRouter
from token_null_router.cli import main

EVIDENCE = "a" * 64


def test_builtin_is_literal_zero(tmp_path):
    result = TokenNullRouter(tmp_path).route("  PING  ")
    assert result.route == "ZERO"
    assert result.response == "pong"
    assert result.model_tokens == 0
    assert result.receipt["reason"] == "builtin_exact"


def test_novel_input_fails_closed(tmp_path):
    result = TokenNullRouter(tmp_path).route("invent a new theorem")
    assert result.route == "ESCALATE"
    assert result.response is None
    assert result.model_tokens is None


def test_exact_cache_requires_context_match(tmp_path):
    router = TokenNullRouter(tmp_path)
    router.put(
        "release status",
        "green",
        context_digest="commit-a",
        evidence_digest=EVIDENCE,
    )
    hit = router.route("release   status", context_digest="commit-a")
    miss = router.route("release status", context_digest="commit-b")
    assert (hit.route, hit.model_tokens, hit.response) == ("ZERO", 0, "green")
    assert hit.reason == "caller_attested_exact_cache"
    assert miss.route == "ESCALATE"
    assert miss.reason == "novel_input"


def test_stale_cache_escalates(tmp_path):
    router = TokenNullRouter(tmp_path)
    router.put("status", "old", evidence_digest=EVIDENCE, ttl_seconds=0)
    result = router.route("status")
    assert result.route == "ESCALATE"
    assert result.reason == "stale_cache"


def test_unsafe_never_uses_cache(tmp_path):
    router = TokenNullRouter(tmp_path)
    router.put("delete backups", "done", evidence_digest=EVIDENCE)
    result = router.route("delete backups")
    assert result.route == "ESCALATE"
    assert result.reason == "unsafe_or_side_effecting"


def test_bad_evidence_rejected(tmp_path):
    router = TokenNullRouter(tmp_path)
    try:
        router.put("x", "y", evidence_digest="not-a-digest")
    except ValueError as exc:
        assert "SHA-256" in str(exc)
    else:
        raise AssertionError("invalid evidence was accepted")


@pytest.mark.parametrize("ttl", [float("nan"), float("inf"), float("-inf"), True])
def test_nonfinite_or_boolean_ttl_rejected_without_cache_write(tmp_path, ttl):
    router = TokenNullRouter(tmp_path)
    with pytest.raises((TypeError, ValueError), match="finite number"):
        router.put("x", "y", evidence_digest=EVIDENCE, ttl_seconds=ttl)
    assert router.route("x").reason == "novel_input"


def test_public_route_cannot_override_expiration_clock(tmp_path):
    router = TokenNullRouter(tmp_path)
    router.put("x", "y", evidence_digest=EVIDENCE, ttl_seconds=0)
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        router.route("x", now=0)  # type: ignore[call-arg]
    assert router.route("x").reason == "stale_cache"


def test_declared_side_effect_escalates_even_without_keyword_match(tmp_path):
    router = TokenNullRouter(tmp_path)
    router.put("email credentials", "done", evidence_digest=EVIDENCE)
    result = router.route("email credentials", side_effects=["send an email"])
    assert result.route == "ESCALATE"
    assert result.reason == "unsafe_or_side_effecting"


def test_malformed_side_effect_declaration_is_rejected(tmp_path):
    router = TokenNullRouter(tmp_path)
    with pytest.raises(TypeError, match="list or tuple of strings"):
        router.route("ping", side_effects="send email")  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_prompt", [None, 7, b"ping"])
def test_non_string_prompt_is_rejected_before_routing(tmp_path, bad_prompt):
    router = TokenNullRouter(tmp_path)
    with pytest.raises(TypeError, match="prompt must be a string"):
        router.route(bad_prompt)  # type: ignore[arg-type]
    assert router.verify_ledger() == (True, 0)


def test_non_string_put_metadata_is_rejected(tmp_path):
    router = TokenNullRouter(tmp_path)
    with pytest.raises(TypeError, match="context_digest must be a string"):
        router.put("x", "y", context_digest=None, evidence_digest=EVIDENCE)  # type: ignore[arg-type]


def test_nfkc_normalized_unsafe_marker_escalates(tmp_path):
    router = TokenNullRouter(tmp_path)
    assert router.route("ＤＥＬＥＴＥ backups").route == "ESCALATE"


def test_cli_side_effect_declaration_exits_with_escalation(tmp_path, capsys):
    code = main(
        [
            "--state-dir",
            str(tmp_path),
            "route",
            "notify the team",
            "--side-effect",
            "send an email",
        ]
    )
    output = capsys.readouterr().out
    assert code == 3
    assert '"route": "ESCALATE"' in output


def test_malformed_ledger_stats_reports_invalid_state(tmp_path):
    router = TokenNullRouter(tmp_path)
    router.route("ping")
    router.ledger_path.write_text("{bad json}\n", encoding="utf-8")
    stats = router.stats()
    assert stats["ledger_valid"] is False
    assert stats["receipts"] == 0
    assert stats["zero_routes"] == 0
    assert stats["escalations"] == 0


def test_invalid_utf8_ledger_fails_verification_and_cli(tmp_path, capsys):
    router = TokenNullRouter(tmp_path)
    router.ledger_path.write_bytes(b"\xff\xe2\x82")
    assert router.verify_ledger() == (False, 0)
    assert router.stats()["ledger_valid"] is False
    code = main(["--state-dir", str(tmp_path), "verify"])
    output = capsys.readouterr().out
    assert code == 2
    assert '"valid": false' in output


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("response", ""),
        ("response", b"bytes"),
        ("evidence_digest", "z" * 64),
        ("created_at", float("inf")),
        ("expires_at", float("inf")),
        ("expires_at", 0.0),
    ],
)
def test_malformed_cache_rows_escalate(tmp_path, column, value):
    router = TokenNullRouter(tmp_path)
    router.put("x", "y", evidence_digest=EVIDENCE)
    with router._connect() as conn:
        conn.execute(f"UPDATE cache SET {column} = ?", (value,))
    result = router.route("x")
    assert result.route == "ESCALATE"
    assert result.reason == "malformed_cache"


def test_receipt_chain_detects_tampering(tmp_path):
    router = TokenNullRouter(tmp_path)
    router.route("ping")
    router.route("novel")
    assert router.verify_ledger() == (True, 2)
    text = router.ledger_path.read_text()
    router.ledger_path.write_text(text.replace('"reason":"builtin_exact"', '"reason":"forged"'))
    assert router.verify_ledger()[0] is False


@pytest.mark.parametrize("tampered_index", [0, 1, 2])
def test_tampered_ledger_refuses_append(tmp_path, tampered_index):
    router = TokenNullRouter(tmp_path)
    router.route("ping")
    router.route("novel one")
    router.route("novel two")
    lines = router.ledger_path.read_text(encoding="utf-8").splitlines()
    lines[tampered_index] = lines[tampered_index].replace(
        '"reason":"builtin_exact"', '"reason":"forged"'
    ).replace('"reason":"novel_input"', '"reason":"forged"')
    router.ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    before = router.ledger_path.read_bytes()
    with pytest.raises(RuntimeError, match="malformed"):
        router.route("ping")
    assert router.ledger_path.read_bytes() == before


def test_stats_are_observed_not_estimated(tmp_path):
    router = TokenNullRouter(tmp_path)
    router.route("ping")
    router.route("unknown")
    stats = router.stats()
    assert stats["cache_valid"] is True
    assert stats["zero_routes"] == 1
    assert stats["escalations"] == 1
    assert stats["ledger_valid"] is True


def test_state_and_cache_files_are_private_even_with_common_umask(tmp_path):
    previous = os.umask(0o022)
    try:
        router = TokenNullRouter(tmp_path / "state")
        router.route("ping")
        router.put("cached", "value", evidence_digest=EVIDENCE)
    finally:
        os.umask(previous)

    assert stat.S_IMODE(router.state_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(router.db_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(router.ledger_path.stat().st_mode) == 0o600
    for suffix in ("-wal", "-shm"):
        sidecar = router.db_path.with_name(router.db_path.name + suffix)
        if sidecar.exists():
            assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600


def test_existing_permissive_state_modes_are_tightened(tmp_path):
    state = tmp_path / "state"
    router = TokenNullRouter(state)
    router.route("ping")
    state.chmod(0o755)
    router.db_path.chmod(0o644)
    router.ledger_path.chmod(0o644)

    reopened = TokenNullRouter(state)
    reopened.route("ping")

    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE(reopened.db_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(reopened.ledger_path.stat().st_mode) == 0o600


def test_corrupt_existing_cache_fails_closed_without_blocking_builtins(tmp_path, capsys):
    state = tmp_path / "state"
    original = TokenNullRouter(state)
    original.put("cached", "value", evidence_digest=EVIDENCE)
    for suffix in ("-wal", "-shm"):
        sidecar = original.db_path.with_name(original.db_path.name + suffix)
        if sidecar.exists():
            sidecar.unlink()
    original.db_path.write_bytes(b"not a sqlite database" * 256)

    router = TokenNullRouter(state)
    miss = router.route("requires cache lookup")
    builtin = router.route("ping")
    stats = router.stats()

    assert miss.route == "ESCALATE"
    assert miss.reason == "cache_unavailable"
    assert builtin.route == "ZERO"
    assert stats["cache_valid"] is False
    assert stats["cache_entries"] is None
    with pytest.raises(RuntimeError, match="cache database is unavailable"):
        router.put("new", "value", evidence_digest=EVIDENCE)

    cli_state = tmp_path / "cli-state"
    cli_router = TokenNullRouter(cli_state)
    for suffix in ("-wal", "-shm"):
        sidecar = cli_router.db_path.with_name(cli_router.db_path.name + suffix)
        if sidecar.exists():
            sidecar.unlink()
    cli_router.db_path.write_bytes(b"not a sqlite database" * 256)
    code = main(["--state-dir", str(cli_state), "route", "another cache lookup"])
    output = json.loads(capsys.readouterr().out)
    assert code == 3
    assert output["route"] == "ESCALATE"
    assert output["reason"] == "cache_unavailable"
