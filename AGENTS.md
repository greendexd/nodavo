# Nodavo contributor instructions

These rules apply to the entire repository.

## Product status

Nodavo is pre-alpha. Do not describe planned capabilities as implemented. Update the English and Russian feature/status tables together.

## Clean-room development

- Read and follow `docs/clean-room-policy.md` before implementation.
- Do not copy, translate, mechanically rewrite, or ask an AI tool to port GPL or proprietary KVM source.
- Use official platform documentation, public standards, independently written requirements, and original code.
- Record non-obvious design provenance in the pull request or ADR.

## Architecture and security

- Preserve local-first operation, mutual authentication, explicit capability grants, bounded decoding, emergency disconnect, and disabled-by-default telemetry.
- Protocol, pairing, identity, updates, input injection, clipboard, file transfer, or privilege changes require security-model updates and focused tests.
- Do not log keystrokes, clipboard/file contents, private filenames, pairing codes, private keys, or stable network identifiers.

## Documentation

- User-facing documents are bilingual. Keep `doc-id` and `revision` metadata aligned.
- English technical specifications are canonical when wording differs.
- Run `python3 .github/scripts/check_docs.py` before handoff.

## Code quality

- Prefer small crates with explicit trust boundaries.
- Avoid `unsafe`; any future exception requires an ADR, safety invariants, and tests.
- Add unit/property tests, integration coverage, and fuzz targets at every untrusted parser boundary.
- Use DCO sign-off on commits.

