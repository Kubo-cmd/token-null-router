from token_null_router import TokenNullRouter

EVIDENCE = "a" * 64


def test_builtin_is_literal_zero(tmp_path):
    result = TokenNullRouter(tmp_path).route("  PING  ")
    assert result.route == "ZERO"
    assert result.response == "pong"
    assert result.model_tokens == 0
    assert result.proof["reason"] == "builtin_exact"


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


def test_receipt_chain_detects_tampering(tmp_path):
    router = TokenNullRouter(tmp_path)
    router.route("ping")
    router.route("novel")
    assert router.verify_ledger() == (True, 2)
    text = router.ledger_path.read_text()
    router.ledger_path.write_text(text.replace('"reason":"builtin_exact"', '"reason":"forged"'))
    assert router.verify_ledger()[0] is False


def test_stats_are_observed_not_estimated(tmp_path):
    router = TokenNullRouter(tmp_path)
    router.route("ping")
    router.route("unknown")
    stats = router.stats()
    assert stats["zero_routes"] == 1
    assert stats["escalations"] == 1
    assert stats["ledger_valid"] is True
