<!-- doc-id: clean-room-policy; lang: en; revision: 2 -->

# Clean-room implementation policy

[English](clean-room-policy.md) · [Русский](clean-room-policy.ru.md)

Nodavo is planned as an original Apache-2.0 implementation. This policy reduces copyright and license risk and makes contributor provenance reviewable. It is a project rule, not legal advice.

## Allowed sources

- Official Apple, Microsoft, IETF, W3C, Unicode, USB-IF, Rust, and library documentation.
- Public protocol specifications and standards.
- Independently written product requirements, interoperability observations, and black-box test results.
- Permissively licensed dependencies approved by dependency policy.
- Small code examples only when their license and attribution are explicitly compatible and recorded.

## Prohibited reuse

- Copying, translating, restructuring, or mechanically reproducing source from GPL or proprietary KVM implementations.
- Importing code, assets, test fixtures, messages, UI text, branding, or generated artifacts from Deskflow, Lan Mouse, Input Leap, Barrier, Synergy, ShareMouse, Logitech Flow, Across, or similar products without explicit compatible permission.
- Asking an AI coding tool to port, rewrite, imitate, or conceal incompatible source.
- Removing attribution, license notices, or commit history to make reused work appear original.

## Reference use

Other products may be used to identify expected behavior, platform edge cases, interoperability requirements, and gaps in the market. Deskflow protocol documentation may inform a future optional compatibility adapter, but the adapter requires an independent specification and provenance review before implementation.

## Contribution provenance

Pull requests must identify non-obvious sources used to design the change. Reviewers may request a simpler reimplementation, additional attribution, dependency removal, or rejection when provenance is unclear.

As implementation work appears, the repository will keep:

- ADRs for major architectural decisions, beginning with the current ADR template.
- Third-party notices and dependency license reports for included dependencies.
- DCO sign-offs in contributor commits.
- Golden protocol vectors after Nodavo's own protocol specification exists.

## Strict clean-room option

If legal or interoperability risk warrants stronger separation, one contributor documents behavior and test requirements without source excerpts, while a different contributor implements only from that specification. The separation and inputs must be recorded in the relevant issue or ADR.

## Incident response

If incompatible material enters the repository, stop distribution of affected artifacts, isolate the commit range, document the incident privately, replace the implementation from an independent specification, and publish required notices or corrections after review.
