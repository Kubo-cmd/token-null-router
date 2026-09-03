from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import time
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_SCHEMA = "1"
_UNSAFE = re.compile(
    r"\b(delete|remove|send|publish|purchase|pay|transfer|password|secret|api[ _-]?key|sudo|execute|run command)\b",
    re.IGNORECASE,
)
_BUILTINS = {
    "ping": "pong",
    "token null health": "TOKEN_NULL_OK",
    "what is token null": (
        "A deterministic local fast path. Exact matches use zero model tokens; "
        "novel, stale, or declared side-effecting inputs escalate."
    ),
}


def _canonical(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).strip().lower()
    return " ".join(normalized.split())


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return value


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _finite_number(value: int | float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be a finite number")
    return result


def _receipt_summary(lines: list[str]) -> tuple[bool, int, str, int, int]:
    prev = "0" * 64
    count = zero = escalate = 0
    for raw in lines:
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
            if not isinstance(item, dict):
                return False, count, prev, zero, escalate
            claimed = item.pop("receipt_hash")
        except (json.JSONDecodeError, KeyError, TypeError):
            return False, count, prev, zero, escalate
        if (
            not isinstance(claimed, str)
            or not re.fullmatch(r"[0-9a-f]{64}", claimed)
            or item.get("prev_hash") != prev
            or _digest(_canonical_json(item)) != claimed
        ):
            return False, count, prev, zero, escalate
        route = item.get("route")
        zero += route == "ZERO"
        escalate += route == "ESCALATE"
        prev = claimed
        count += 1
    return True, count, prev, zero, escalate


@dataclass(frozen=True)
class Decision:
    route: str
    response: str | None
    model_tokens: int | None
    reason: str
    receipt: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TokenNullRouter:
    """Resolve only inputs that match a configured local fast path.

    Unknown, unsafe, context-mismatched, and expired inputs fail closed to
    ESCALATE. Malformed API values raise before routing, and malformed receipt
    state refuses append or verification. This class never invokes a model.
    """

    def __init__(self, state_dir: str | Path):
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.state_dir / "cache.sqlite3"
        self.ledger_path = self.state_dir / "receipts.jsonl"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    response TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )"""
            )

    @staticmethod
    def cache_key(prompt: str, namespace: str, context_digest: str) -> str:
        prompt = _text(prompt, "prompt")
        namespace = _text(namespace, "namespace")
        context_digest = _text(context_digest, "context_digest")
        material = _canonical_json(
            {
                "schema": _SCHEMA,
                "namespace": namespace,
                "prompt": _canonical(prompt),
                "context_digest": context_digest,
            }
        )
        return _digest(material)

    def put(
        self,
        prompt: str,
        response: str,
        *,
        namespace: str = "default",
        context_digest: str = "static",
        evidence_digest: str,
        ttl_seconds: float = 3600,
    ) -> str:
        prompt = _text(prompt, "prompt")
        response = _text(response, "response")
        namespace = _text(namespace, "namespace")
        context_digest = _text(context_digest, "context_digest")
        evidence_digest = _text(evidence_digest, "evidence_digest")
        if not prompt.strip() or not response.strip():
            raise ValueError("prompt and response must be non-empty")
        if not re.fullmatch(r"[0-9a-f]{64}", evidence_digest):
            raise ValueError("evidence_digest must be a lowercase SHA-256 hex digest")
        ttl = _finite_number(ttl_seconds, "ttl_seconds")
        if ttl < 0:
            raise ValueError("ttl_seconds must be non-negative")
        now = time.time()
        key = self.cache_key(prompt, namespace, context_digest)
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO cache
                (key, namespace, prompt, context_digest, response, evidence_digest, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    key,
                    namespace,
                    _canonical(prompt),
                    context_digest,
                    response,
                    evidence_digest,
                    now,
                    now + ttl,
                ),
            )
        return key

    def route(
        self,
        prompt: str,
        *,
        namespace: str = "default",
        context_digest: str = "static",
        side_effects: list[str] | tuple[str, ...] = (),
    ) -> Decision:
        prompt = _text(prompt, "prompt")
        namespace = _text(namespace, "namespace")
        context_digest = _text(context_digest, "context_digest")
        if not isinstance(side_effects, (list, tuple)) or any(
            not isinstance(item, str) for item in side_effects
        ):
            raise TypeError("side_effects must be a list or tuple of strings")
        canonical = _canonical(prompt)
        if not canonical:
            return self._escalate("empty_input", canonical, namespace, context_digest)
        if side_effects or _UNSAFE.search(canonical):
            return self._escalate("unsafe_or_side_effecting", canonical, namespace, context_digest)
        if canonical in _BUILTINS:
            response = _BUILTINS[canonical]
            return self._zero(
                response,
                "builtin_exact",
                canonical,
                namespace,
                context_digest,
                evidence_digest=_digest("builtin:" + canonical + ":" + response),
            )

        key = self.cache_key(canonical, namespace, context_digest)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT response, evidence_digest, created_at, expires_at FROM cache WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return self._escalate("novel_input", canonical, namespace, context_digest)
        response, evidence_digest, created_at, expires_at = row
        valid_row = (
            isinstance(response, str)
            and bool(response.strip())
            and isinstance(evidence_digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", evidence_digest) is not None
            and isinstance(created_at, (int, float))
            and not isinstance(created_at, bool)
            and math.isfinite(float(created_at))
            and isinstance(expires_at, (int, float))
            and not isinstance(expires_at, bool)
            and math.isfinite(float(expires_at))
            and float(expires_at) >= float(created_at)
        )
        if not valid_row:
            return self._escalate("malformed_cache", canonical, namespace, context_digest)
        clock = time.time()
        if expires_at <= clock:
            return self._escalate("stale_cache", canonical, namespace, context_digest)
        return self._zero(
            response,
            "caller_attested_exact_cache",
            canonical,
            namespace,
            context_digest,
            evidence_digest=evidence_digest,
        )

    def _zero(
        self,
        response: str,
        reason: str,
        prompt: str,
        namespace: str,
        context_digest: str,
        *,
        evidence_digest: str,
    ) -> Decision:
        receipt = {
            "schema": _SCHEMA,
            "route": "ZERO",
            "model_tokens": 0,
            "reason": reason,
            "prompt_digest": _digest(prompt),
            "response_digest": _digest(response),
            "evidence_digest": evidence_digest,
            "namespace": namespace,
            "context_digest": context_digest,
            "timestamp_ns": time.time_ns(),
        }
        committed = self._append_receipt(receipt)
        return Decision("ZERO", response, 0, reason, committed)

    def _escalate(
        self, reason: str, prompt: str, namespace: str, context_digest: str
    ) -> Decision:
        receipt = {
            "schema": _SCHEMA,
            "route": "ESCALATE",
            "model_tokens": None,
            "reason": reason,
            "prompt_digest": _digest(prompt),
            "namespace": namespace,
            "context_digest": context_digest,
            "timestamp_ns": time.time_ns(),
        }
        committed = self._append_receipt(receipt)
        return Decision("ESCALATE", None, None, reason, committed)

    def _append_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        self.ledger_path.touch(mode=0o600, exist_ok=True)
        with self.ledger_path.open("r+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                try:
                    lines = handle.read().splitlines()
                except UnicodeDecodeError as exc:
                    raise RuntimeError("receipt ledger is malformed; refusing to append") from exc
                valid, _, prev, _, _ = _receipt_summary(lines)
                if not valid:
                    raise RuntimeError("receipt ledger is malformed; refusing to append")
                committed = dict(receipt, prev_hash=prev)
                committed["receipt_hash"] = _digest(_canonical_json(committed))
                handle.seek(0, os.SEEK_END)
                handle.write(_canonical_json(committed) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return committed

    def verify_ledger(self) -> tuple[bool, int]:
        if not self.ledger_path.exists():
            return True, 0
        try:
            with self.ledger_path.open("r", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
                try:
                    lines = handle.read().splitlines()
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (OSError, UnicodeDecodeError):
            return False, 0
        valid, count, _, _, _ = _receipt_summary(lines)
        return valid, count

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            cache_entries = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
        valid, receipts = self.verify_ledger()
        zero = escalate = 0
        if valid and self.ledger_path.exists():
            try:
                with self.ledger_path.open("r", encoding="utf-8") as handle:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
                    try:
                        lines = handle.read().splitlines()
                    finally:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                valid, receipts, _, zero, escalate = _receipt_summary(lines)
            except (OSError, UnicodeDecodeError):
                valid = False
                zero = escalate = 0
        return {
            "cache_entries": cache_entries,
            "receipts": receipts,
            "ledger_valid": valid,
            "zero_routes": zero,
            "escalations": escalate,
            "model_tokens_avoided_lower_bound": zero,
        }
