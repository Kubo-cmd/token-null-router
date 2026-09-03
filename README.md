# Token Null Router

A local deterministic fast path that spends **zero model tokens** on canonical exact builtins and configured cache hits.

It does not promise impossible zero-token reasoning for arbitrary requests. It returns one of two routes:

- `ZERO`: canonical exact builtin or caller-attested cache hit; `model_tokens` is literally `0`.
- `ESCALATE`: novel, stale, context-mismatched, empty, or declared side-effecting input. No answer is fabricated.

Every decision is appended to an fsync-backed SHA-256 receipt chain. Cache entries are namespaced, context-bound, carry a caller-supplied evidence digest, and expire. Canonical matching normalizes Unicode compatibility forms, letter case, and whitespace.

An evidence digest is an integrity label supplied by the caller. The router checks its format but does not establish that the evidence or cached answer is true. `ZERO` records only that this package invoked no model for that route. The receipt hash chain supports consistency checks; it is not an external signature and cannot prevent a full rewrite by someone who controls the state directory.

## Run

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
token-null --state-dir .state route ping
```

POSIX setup and no-activation commands are documented in
[`docs/PORTABLE_SETUP.md`](docs/PORTABLE_SETUP.md). Windows is not currently supported because receipt locking uses `fcntl`.

Add a response only after you have checked its source evidence:

```bash
EVIDENCE=$(token-null digest 'caller-checked local evidence')
token-null --state-dir .state put 'release status' 'green' \
  --context-digest commit-a --evidence-digest "$EVIDENCE" --ttl 300
token-null --state-dir .state route 'release status' --context-digest commit-a
```

If a request requires any external action, declare it. Any declaration forces escalation:

```bash
token-null --state-dir .state route 'notify the team' --side-effect 'send an email'
```

Unknown inputs exit `3` so a wrapper can invoke Hermes only on escalation:

```bash
token-null --state-dir .state route "$INPUT"
```

Exit code `3` means a separate wrapper should invoke its configured model path.
This package does not choose or call that model.

## Safety properties

- No network or model client exists in this package.
- Any non-empty `side_effects` declaration escalates. A small keyword denylist is defense in depth, not a complete semantic safety classifier.
- A different context digest cannot reuse a response.
- Expired entries cannot answer.
- A malformed receipt chain fails verification.
- `model_tokens_avoided_lower_bound` counts recorded zero routes, not estimated token volume or answer correctness.

## Tests

```bash
python -m pytest --collect-only -q
python -m pytest -q
python scripts/verify_clean_package.py
python scripts/verify_relic.py
token-null --state-dir .state verify
```

The clean-package gate builds from a temporary copy, installs the wheel into a
fresh virtual environment without an index, then exercises the installed CLI.

## Project policies

- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [MIT license](LICENSE)
