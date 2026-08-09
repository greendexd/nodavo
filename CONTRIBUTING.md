<!-- doc-id: contributing; lang: en; revision: 2 -->

# Contributing to Nodavo

Thank you for helping build Nodavo. The project is currently in planning and feasibility work, so the most valuable contributions are design review, threat analysis, reproducible platform research, documentation, and focused M0 experiments.

## Before contributing

1. Read the [product plan](docs/product-plan.md), [architecture](docs/architecture.md), and [clean-room policy](docs/clean-room-policy.md).
2. Search existing issues and discussions before proposing work.
3. For a substantial change, open an issue or RFC before implementation.
4. Never include secrets, real clipboard contents, private filenames, IP addresses, or personal paths in logs and fixtures.

M0 code is limited to small, disposable feasibility spikes approved in an issue before implementation. General core implementation pull requests will open after the M0 path is documented; this prevents contributors from building against unresolved platform assumptions.

## Clean implementation requirement

Nodavo does not accept copied or mechanically translated code from Deskflow, Lan Mouse, Input Leap, Barrier, Synergy, ShareMouse, or other implementations. Contributions must come from platform documentation, public protocol specifications, independently written requirements, and original implementation work. Record non-obvious provenance in the pull request.

## Language parity

User-facing documentation is maintained in English and Russian. When a paired document changes, update its translation and keep the same `doc-id` and `revision` metadata. Technical specifications are canonical in English when wording differs.

## Development workflow

- Branch from `main` and keep changes focused.
- Add tests for behavior changes or explain why a test is not yet possible.
- Run formatting, linting, tests, and documentation checks.
- Update both changelogs for user-visible changes.
- Do not add telemetry, network destinations, elevated services, or new trust capabilities without a threat-model update.

## Developer Certificate of Origin

Every contributor commit submitted through a pull request must be signed off with:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s`. The sign-off certifies that you have the right to submit the contribution under the repository license. Read the complete [Developer Certificate of Origin 1.1](DCO); CI checks every pull request commit and rejects sign-offs that do not match the commit author identity.

## Review expectations

Protocol, identity, pairing, updates, platform input, clipboard, and file-transfer changes require maintainer review. Security-sensitive changes should be small, documented, and independently testable.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).
