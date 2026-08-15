# Token Null Router

A local, proof-carrying fast path that spends **zero model tokens** only when an answer is deterministically justified.

It does not promise impossible zero-token reasoning for arbitrary requests. It returns one of two routes:

- `ZERO`: exact builtin or evidence-bound exact cache hit; `model_tokens` is literally `0`.
- `ESCALATE`: novel, stale, context-mismatched, empty, or side-effecting input. No answer is fabricated.

Every decision is appended to an fsync-backed SHA-256 receipt chain. Cache entries are namespaced, context-bound, evidence-bound, and expire.

## Run

```bash
cd /Users/test/projects/token-null-router
python3 -m venv .venv
.venv/bin/pip install -e . pytest
.venv/bin/token-null route ping
```

Add a response only after local evidence exists:

```bash
EVIDENCE=$(.venv/bin/token-null digest 'verified local evidence')
.venv/bin/token-null put 'release status' 'green' \
  --context-digest commit-a --evidence-digest "$EVIDENCE" --ttl 300
.venv/bin/token-null route 'release status' --context-digest commit-a
```

Unknown inputs exit `3` so a wrapper can invoke Hermes only on escalation:

```bash
.venv/bin/token-null route "$INPUT" || hermes chat
```

## Safety properties

- No network or model client exists in this package.
- Unsafe/side-effecting wording always escalates, even if cached.
- A different context digest cannot reuse a response.
- Expired entries cannot answer.
- A malformed receipt chain fails verification.
- `model_tokens_avoided_lower_bound` counts verified zero routes, not estimated token volume.

## Tests

```bash
.venv/bin/pytest -q
.venv/bin/token-null verify
```
