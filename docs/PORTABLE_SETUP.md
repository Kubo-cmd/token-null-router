# Portable Setup

Token Null Router supports Python 3.10 or newer on Linux and macOS and has no runtime dependencies outside the Python standard library. Windows is not currently supported because receipt locking uses the POSIX-only `fcntl` module.

## POSIX shells

```console
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
python -m pytest -q
python scripts/verify_clean_package.py
```

## Run without activation

POSIX:

```console
.venv/bin/python -m pytest -q
.venv/bin/token-null --state-dir .state route ping
```

## Clean-package gate

`scripts/verify_clean_package.py` copies the candidate into a temporary directory, builds a wheel without dependency downloads, checks required wheel members, installs the wheel into a fresh virtual environment without an index, imports the installed package, exercises the installed CLI, and verifies its receipt chain.

The build frontend and declared build backend must already be available in the environment. The gate never uploads an artifact.

## Exit codes

- `0`: local `ZERO` route or successful command.
- `2`: receipt-chain verification failed.
- `3`: the request requires escalation.
