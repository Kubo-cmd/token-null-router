# Contributing

Contributions should be small, reviewable, and backed by tests that exercise production code.

## Local setup

Create and activate a Python 3.10 or newer virtual environment, then run:

```console
python -m pip install -e ".[test]"
python -m pytest --collect-only -q
python -m pytest -q
python scripts/verify_clean_package.py
```

Platform-specific environment commands are in `docs/PORTABLE_SETUP.md`.

## Change requirements

- Preserve fail-closed behavior for unknown, stale, malformed, context-mismatched, and side-effecting requests.
- Add a regression test for behavior changes.
- Do not add model, telemetry, or network clients without an explicit design review.
- Keep credentials, generated state, virtual environments, caches, and build artifacts out of Git.
- Update documentation when commands or public behavior change.

## Pull requests

Describe the problem, the bounded change, and the exact verification commands and results. Passing local tests are not remote CI evidence. Do not claim formal verification, production readiness, or performance improvements without direct supporting evidence.
