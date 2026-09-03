# Security Policy

## Supported versions

Security fixes are applied to the current `0.1.x` line. Older snapshots are not supported.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include secrets, private data, or exploit details in public logs.

Use the repository's **Security** tab and select **Report a vulnerability**. Private vulnerability reporting is enabled. If GitHub does not show the private form, open a public issue asking for a private channel without including exploit details, secrets, or private data.

Include:

- the affected version or commit;
- a minimal reproduction;
- expected and observed behavior;
- impact and preconditions;
- suggested remediation, if known.

A report should receive an acknowledgement within seven days. No response-time guarantee is made before a public support channel exists.

## Scope

Important security properties include fail-closed escalation, context binding, finite cache expiration, receipt-chain integrity, and avoiding unintended model or network calls. Evidence digests are caller attestations and do not prove semantic truth. Keyword screening is defense in depth; callers must declare side effects explicitly.
