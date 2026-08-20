<!-- doc-id: adr-0006-semantic-peer-placement; lang: en; revision: 1 -->

# ADR-0006: Persist semantic peer placement, derive ephemeral edge routes

[English](0006-semantic-peer-placement.md) · [Русский](0006-semantic-peer-placement.ru.md)

- Status: accepted for the pre-alpha bidirectional KVM implementation
- Date: 2026-08-20

## Context

Seamless edge switching needs a user-authored relationship between two computers. Native display identifiers, session display identifiers, monitor order, coordinates, scale, and active topology are unstable across reconnect, sleep, hot-plug, and process restart. Persisting a concrete display-to-display route would make stale hardware state authoritative and could route input to a removed or reused identity.

The initial product also needs a usable layout control before a full per-display drag editor is qualified. That control must not bypass input grants, topology acknowledgement, focus ownership, pointer-entry acknowledgement, or safety recovery.

## Decision

Each active trust record stores exactly one `PeerPlacement`: disabled, left, right, above, or below. Legacy trust records migrate to disabled. The schema cannot encode a native or session display identifier. Revoked peers cannot mutate placement.

After both current topologies are committed, the peer input grant is active, and any local revision directionally published for inbound control is exactly acknowledged, the session derives at most 32 deterministic exterior `Stretch` routes. An outbound-only local graph is intentionally not published and needs only the same stable committed snapshot. A topology transition, grant removal, placement change, or stale/invalid acknowledgement clears every derived route. Focus recovery and restoration of local ownership clear the active route and pending pointer entry. The ordinary focus lease, reliable pointer-entry acknowledgement, debounce, hysteresis, and cooldown remain mandatory.

Placement is persisted before an in-session notification. Mutation and session publication share one peer-bound lock ordering, so a new session cannot start with a stale value between those steps. If the active focus is non-local, or if live application is ambiguous, the agent restores local ownership and closes the session. The saved placement remains authoritative for reconnect.

Both local UIs send a placement mutation once. They accept only an exact peer-and-placement acknowledgement; every ambiguous outcome is reconciled with a fresh bounded trusted-peer listing and never by resending the mutation.

## Security and privacy impact

The persistent value reveals only a coarse relationship chosen by the local user. It contains no monitor identity, geometry, route, endpoint, peer-issued grant, or input content. Public trusted-peer summaries remain bounded to 32 records and add only this enum.

No placement creates authority. Without the exact peer input grant, current committed topologies, and acknowledgement of every directionally published local revision, the route set is empty. Changing placement cannot preserve a non-local lease or pending pointer entry.

## Alternatives rejected

- Persist native or session display identifiers: they are ephemeral and can be removed or reused.
- Persist concrete edge routes: they bind stale topology and mix user policy with session state.
- Continue with environment-provided numeric routes: not a native user workflow and unsafe as release policy.
- Build the full per-display drag editor first: it expands geometry, accessibility, persistence, and hardware qualification before the basic workstation relationship is usable.
- Optimistically update or resend after timeout: acknowledgement loss is outcome-unknown because persistence may already have succeeded.

## Provenance

The decision follows Nodavo's independently written product, topology, focus-lease, and capability requirements. Implementation inputs were the repository's original protocol/state model and official Rust, Apple, and Microsoft platform documentation already cited by their platform boundaries. No source, UI text, asset, or test fixture from another KVM product was consulted or reused.
