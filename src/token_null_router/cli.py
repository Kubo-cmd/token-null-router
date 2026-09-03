from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .router import TokenNullRouter


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="token-null")
    parser.add_argument(
        "--state-dir", default="~/.token-null-router", help="Local cache and receipt directory"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    route = sub.add_parser("route", help="Resolve locally or emit a fail-closed escalation")
    route.add_argument("text")
    route.add_argument("--namespace", default="default")
    route.add_argument("--context-digest", default="static")
    route.add_argument(
        "--side-effect",
        action="append",
        default=[],
        help="Declare a required side effect; any declaration forces escalation",
    )

    put = sub.add_parser("put", help="Add a caller-attested exact response")
    put.add_argument("text")
    put.add_argument("response")
    put.add_argument("--evidence-digest", required=True)
    put.add_argument("--ttl", type=float, default=3600)
    put.add_argument("--namespace", default="default")
    put.add_argument("--context-digest", default="static")

    sub.add_parser("stats", help="Show cache and receipt-ledger health")
    sub.add_parser("verify", help="Verify the complete receipt hash chain")
    digest = sub.add_parser("digest", help="SHA-256 a caller-supplied evidence string")
    digest.add_argument("text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "digest":
        print(hashlib.sha256(args.text.encode("utf-8")).hexdigest())
        return 0

    router = TokenNullRouter(Path(args.state_dir))
    if args.command == "route":
        result = router.route(
            args.text,
            namespace=args.namespace,
            context_digest=args.context_digest,
            side_effects=args.side_effect,
        )
        print(json.dumps(result.to_dict(), sort_keys=True))
        return 0 if result.route == "ZERO" else 3
    if args.command == "put":
        key = router.put(
            args.text,
            args.response,
            namespace=args.namespace,
            context_digest=args.context_digest,
            evidence_digest=args.evidence_digest,
            ttl_seconds=args.ttl,
        )
        print(json.dumps({"stored": True, "key": key}, sort_keys=True))
        return 0
    if args.command == "stats":
        print(json.dumps(router.stats(), sort_keys=True))
        return 0
    valid, count = router.verify_ledger()
    print(json.dumps({"valid": valid, "receipts": count}, sort_keys=True))
    return 0 if valid else 2


if __name__ == "__main__":
    raise SystemExit(main())
