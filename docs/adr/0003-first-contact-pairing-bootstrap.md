<!-- doc-id: adr-0003-pairing-bootstrap; lang: en; revision: 1 -->

# ADR-0003: First-contact pairing bootstrap

[English](0003-first-contact-pairing-bootstrap.md) · [Русский](0003-first-contact-pairing-bootstrap.ru.md)

- Status: accepted for pre-alpha M1 implementation
- Date: 2026-08-10

## Context

Nodavo does not trust mDNS or a manually entered address. The first QUIC connection must be encrypted, but two never-paired devices do not yet know which self-signed ephemeral TLS certificate to pin. Accepting any certificate through a permissive TLS verifier would introduce a hidden trust-on-first-use path and weaken review of the transport boundary.

## Decision

An explicit pairing attempt opens a short-lived, bounded TCP preflight at the same discovered or manually entered location. The preflight exchanges only:

- a fixed magic value and protocol version;
- a fresh ephemeral certificate in bounded DER form;
- its bounded TLS server name.

The preflight is deliberately unauthenticated and its values are treated as attacker-controlled. Each peer pins the exact received certificate before creating the TLS 1.3 QUIC pairing connection. No input, clipboard, file, persistent identity secret, capability authorization, or trust record is accepted over TCP.

After QUIC is established, the pairing reducer derives a six-digit SAS from a role-ordered transcript that includes the TLS exporter, protocol version, both nonces, both persistent Ed25519 identities, both persistent TLS certificate hashes, and proposed grants. Both local UIs must display and confirm the same SAS. Both persistent identities then sign acceptance before either side commits trust.

The agent permits only one active pairing transaction, bounds bootstrap and pairing frames before allocation, applies deadlines, and closes on malformed state. Routine logs exclude addresses, certificates, identities, SAS values, and pairing payloads.

## Security consequences

- A network attacker can replace or relay preflight metadata, but cannot silently create persistent trust. A conventional MITM produces different TLS exporters/transcripts and therefore different SAS values on the two real devices.
- The six-digit SAS is a human comparison, not a password. Attempts must be rate-limited and time-bounded, and users must not confirm mismatched values.
- Plaintext is not an application compatibility mode: the preflight publishes only untrusted first-contact metadata that could be public without granting a capability.
- Persistent reconnect never reuses the preflight. It requires mutually pinned certificates restored from authenticated protected storage.

## Alternatives rejected

- Permissive certificate verification or silent TOFU: conflicts with the threat model.
- Publishing a persistent key or fingerprint through mDNS as identity: discovery is not trust.
- A cloud rendezvous/account service: conflicts with the local-first 1.0 scope.
- Shipping a private project CA: creates a new high-value secret and distribution problem.

## Storage note

The pre-alpha local smoke path uses an explicitly development-only, bounded and private file fallback. Stable builds must replace it with Keychain on macOS and DPAPI/CNG-backed storage on Windows before release qualification.
