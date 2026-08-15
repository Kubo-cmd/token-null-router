from __future__ import annotations

import fcntl
import hashlib
import json
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
        "A proof-carrying deterministic fast path. Verified matches use zero model tokens; "
        "novel, stale, or unsafe inputs escalate."
    ),
}


def _canonical(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).strip().lower()
    return " ".join(normalized.split())


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class Decision:
    route: str
    response: str | None
    model_tokens: int | None
    reason: str
    proof: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TokenNullRouter:
    """Resolve only inputs whose zero-token answer can be proven locally.

    Unknown, unsafe, context-mismatched, expired, or malformed entries fail
    closed to ESCALATE. This class never invokes a model itself.
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
        if not prompt.strip() or not response.strip():
            raise ValueError("prompt and response must be non-empty")
        if not re.fullmatch(r"[0-9a-f]{64}", evidence_digest):
            raise ValueError("evidence_digest must be a lowercase SHA-256 hex digest")
        if ttl_seconds < 0:
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
                    now + ttl_seconds,
                ),
            )
        return key

    def route(
        self,
        prompt: str,
        *,
        namespace: str = "default",
        context_digest: str = "static",
        now: float | None = None,
    ) -> Decision:
        canonical = _canonical(prompt)
        if not canonical:
            return self._escalate("empty_input", canonical, namespace, context_digest)
        if _UNSAFE.search(canonical):
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
                "SELECT response, evidence_digest, expires_at FROM cache WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return self._escalate("novel_input", canonical, namespace, context_digest)
        response, evidence_digest, expires_at = row
        clock = time.time() if now is None else now
        if expires_at <= clock:
            return self._escalate("stale_cache", canonical, namespace, context_digest)
        return self._zero(
            response,
            "verified_exact_cache",
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
        proof = self._append_receipt(receipt)
        return Decision("ZERO", response, 0, reason, proof)

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
        proof = self._append_receipt(receipt)
        return Decision("ESCALATE", None, None, reason, proof)

    def _append_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        self.ledger_path.touch(mode=0o600, exist_ok=True)
        with self.ledger_path.open("r+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            lines = [line for line in handle.read().splitlines() if line.strip()]
            prev = "0" * 64
            if lines:
                try:
                    prev = json.loads(lines[-1])["receipt_hash"]
                except (json.JSONDecodeError, KeyError, TypeError):
                    raise RuntimeError("receipt ledger is malformed; refusing to append")
            committed = dict(receipt, prev_hash=prev)
            committed["receipt_hash"] = _digest(_canonical_json(committed))
            handle.seek(0, os.SEEK_END)
            handle.write(_canonical_json(committed) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return committed

    def verify_ledger(self) -> tuple[bool, int]:
        if not self.ledger_path.exists():
            return True, 0
        prev = "0" * 64
        count = 0
        for raw in self.ledger_path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                item = json.loads(raw)
                claimed = item.pop("receipt_hash")
            except (json.JSONDecodeError, KeyError, TypeError):
                return False, count
            if item.get("prev_hash") != prev or _digest(_canonical_json(item)) != claimed:
                return False, count
            prev = claimed
            count += 1
        return True, count

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            cache_entries = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
        valid, receipts = self.verify_ledger()
        zero = escalate = 0
        if self.ledger_path.exists():
            for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                route = json.loads(line).get("route")
                zero += route == "ZERO"
                escalate += route == "ESCALATE"
        return {
            "cache_entries": cache_entries,
            "receipts": receipts,
            "ledger_valid": valid,
            "zero_routes": zero,
            "escalations": escalate,
            "model_tokens_avoided_lower_bound": zero,
        }
