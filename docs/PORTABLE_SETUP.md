# Portable Setup

Token Null Router supports Python 3.10 or newer and has no runtime dependencies outside the Python standard library.

## POSIX shells

```console
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
python -m pytest -q
python scripts/verify_clean_package.py
```

## Windows PowerShell

```console
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
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

Windows:

```console
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\token-null.exe --state-dir .state route ping
```

## Clean-package gate

`scripts/verify_clean_package.py` copies the candidate into a temporary directory, builds a wheel without dependency downloads, checks required wheel members, installs the wheel into a fresh virtual environment without an index, imports the installed package, exercises the installed CLI, and verifies its receipt chain.

The build frontend and declared build backend must already be available in the environment. The gate never uploads an artifact.

## Exit codes

- `0`: locally proven route or successful command.
- `2`: receipt-chain verification failed.
- `3`: the request requires escalation.
