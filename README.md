# Token Null Router

A local, proof-carrying fast path that spends **zero model tokens** only when an answer is deterministically justified.

It does not promise impossible zero-token reasoning for arbitrary requests. It returns one of two routes:

- `ZERO`: exact builtin or evidence-bound exact cache hit; `model_tokens` is literally `0`.
- `ESCALATE`: novel, stale, context-mismatched, empty, or side-effecting input. No answer is fabricated.

Every decision is appended to an fsync-backed SHA-256 receipt chain. Cache entries are namespaced, context-bound, evidence-bound, and expire.

## Run

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
token-null --state-dir .state route ping
```

Windows PowerShell and no-activation commands are documented in
[`docs/PORTABLE_SETUP.md`](docs/PORTABLE_SETUP.md).

Add a response only after local evidence exists:

```bash
EVIDENCE=$(token-null digest 'verified local evidence')
token-null --state-dir .state put 'release status' 'green' \
  --context-digest commit-a --evidence-digest "$EVIDENCE" --ttl 300
token-null --state-dir .state route 'release status' --context-digest commit-a
```

Unknown inputs exit `3` so a wrapper can invoke Hermes only on escalation:

```bash
token-null --state-dir .state route "$INPUT"
```

Exit code `3` means a separate wrapper should invoke its configured model path.
This package does not choose or call that model.

## Safety properties

- No network or model client exists in this package.
- Unsafe/side-effecting wording always escalates, even if cached.
- A different context digest cannot reuse a response.
- Expired entries cannot answer.
- A malformed receipt chain fails verification.
- `model_tokens_avoided_lower_bound` counts verified zero routes, not estimated token volume.

## Tests

```bash
python -m pytest --collect-only -q
python -m pytest -q
python scripts/verify_clean_package.py
token-null --state-dir .state verify
```

The clean-package gate builds from a temporary copy, installs the wheel into a
fresh virtual environment without an index, then exercises the installed CLI.

## Project policies

- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [MIT license](LICENSE)
