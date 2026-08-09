<!-- doc-id: peer-protocol; lang: en; revision: 3 -->

# Nodavo peer protocol

[English](protocol.md) · [Русский](protocol.ru.md)

## Status

This document describes the current pre-alpha wire foundation implemented by `nodavo-protocol` and the channel contract implemented by `nodavo-transport`. It is not a stable 1.0 specification. Tags and structures may change until the release-candidate protocol is frozen; incompatible changes must update the protocol version and this document together.

Pairing and trust establishment are defined by the [security model](security-model.md). Discovery supplies a network location only and is never accepted as peer identity.

## Transport and channel separation

Peers use QUIC over TLS 1.3. A connection has independent backpressure domains so replaceable motion cannot delay keys, control, clipboard, or files.

| Data | QUIC path | Reliability rule | Hard application limit |
| --- | --- | --- | ---: |
| Negotiation, grants, sessions, focus, liveness, errors | Bidirectional control stream | Ordered and reliable | 64 KiB per protocol message |
| Keys, pointer buttons, forced release | Reliable input stream | Ordered and reliable | 1 KiB per protocol message |
| Pointer motion and high-frequency scroll | QUIC datagrams | Sequenced, latest valid event wins | 1,200 bytes |
| Pointer fallback | Short-lived reliable stream | Used when datagrams are unavailable; only replaceable pointer events are accepted | 1 KiB per protocol message; 1 MiB transport frame |
| Clipboard representations | Bounded streams per revision | Reliable, content-addressed | 256 KiB chunk; representation-specific totals |
| File manifest and content | Manifest plus unidirectional file streams | Reliable, staged, hashed | 1 MiB manifest; 10,000 entries; 10 GiB aggregate |

The transport rejects empty datagrams, frames over its negotiated or hard limit, more than 64 open application channels, invalid channel ownership, and operations exceeding configured deadlines.

## Canonical envelope

Control and semantic input messages use a numeric-keyed canonical CBOR map:

| Key | Field | Meaning |
| ---: | --- | --- |
| `0` | `version` | Major and minor protocol version |
| `1` | `tag` | Numeric message type |
| `2` | `critical` | Whether an unknown receiver must reject the message |
| `3` | `payload` | CBOR bytes for the tagged body |

Decoders enforce the channel-specific size limit before decoding, require the envelope and body to re-encode identically, reject unknown critical tags, and preserve bounded unknown non-critical messages as opaque data. Version `0.x` is invalid. The current peer-message codec accepts exactly pre-alpha version `1.1`; this does not change the separate pairing-preflight version. It also does not mean the product itself is released as 1.0.

## Current tags

| Range/tag | Meaning | Channel |
| --- | --- | --- |
| `0` | Hello and version/capability negotiation | Control |
| `1`–`2` | Capability grant and revoke | Control |
| `3`–`4` | Session open and close | Control |
| `5`–`7` | Focus lease request, grant, and release | Control |
| `8`–`9` | Ping and pong | Control |
| `10` | Emergency disconnect | Control |
| `11` | Bounded protocol error | Control |
| `0x1000`–`0x1001` | Key and pointer-button events | Reliable input |
| `0x1002`–`0x1003` | Pointer motion and scroll | Datagram or pointer fallback |
| `0x1004` | Forced release of all pressed state | Reliable input |
| `0x2000`–`0x2004` | Clipboard offer, clear, request, chunk, and abort | Clipboard |
| `0x3000`–`0x3003` | File manifest, resume, cancel, and complete | File manifest |
| `0x4000` | File content chunk | File data |

Clipboard and transfer messages now have pre-alpha canonical codecs and reserved ranges. They enforce per-kind clipboard limits, 256 KiB chunks, a 1 MiB/10,000-entry/10 GiB file manifest boundary, normalized safe relative paths, exact 32-byte hashes, nonzero transfer identifiers, channel separation, and content/path-redacted debug output. They are not an available product feature until the agent and both platform adapters complete the end-to-end capability-checked session path.

## Identity, freshness, and capability context

Every input event carries:

- a random session identifier;
- the authenticated origin device identifier;
- a monotonically checked sequence in its control, reliable-input, or replaceable-input lane;
- the current grant epoch;
- exactly the remote-input capability;
- the nonzero identifier of the focus lease authorizing the event, including forced release-all.

Focus leases have a nonzero lease identifier and a bounded time-to-live. A receiver validates the complete event, active lease, direction-specific grant, and lane watermark before committing a new sequence. It rejects stale grants, stale sequences, wrong origins, wrong sessions, malformed zero identifiers, or events without the required grant. A normal authenticated focus release clears pressed state and returns focus to local ownership while the session remains ready. Emergency stop, lock, sleep, link loss, grant invalidation, and lease expiry synchronously clear the lease and pressed-state model and close the session before input routing can resume.

Capabilities are explicit and separately represented for remote input, clipboard read, clipboard write, and file transfer. The local grant authorizing peer input is tracked independently from the peer grant authorizing outbound local input. Clipboard requests require exactly the read capability; offers, clear operations, and content chunks require exactly the write capability. File manifests, resume/cancel/complete control, and data chunks require exactly file transfer. A transport connection alone never grants a capability.

## Input semantics

Keyboard events use USB HID usage page and usage identifiers rather than platform virtual-key codes. Unknown modifier bits are rejected. Pointer positions identify a nonzero display and use normalized fixed-point coordinates; the receiving platform maps them to its current display geometry and DPI. Scroll events explicitly use either `Lines` for discrete wheel detents or `Precise` for high-resolution device-independent deltas; a zero/zero scroll is malformed. Pointer motion and scroll keep their complete metadata when delivered as datagrams or through the pointer-fallback codec. The regular reliable-input codec rejects replaceable events, and the fallback codec rejects keys, buttons, and release-all. Nodavo-injected events carry a platform tag and capture adapters reject them to prevent amplification loops.

Text input for layouts, dead keys, AltGr, and IME fallback remains a 1.0 implementation item and will be specified before the protocol freeze.

## Compatibility rules

- Peers must negotiate a mutually supported major/minor version before opening a session.
- A changed meaning for an existing field or tag requires an incompatible version change.
- Additive optional behavior uses a new non-critical tag or an explicitly optional field with a deterministic default.
- Unknown capability bits, malformed canonical encoding, limit violations, and critical unknown tags fail closed.
- No plaintext mode, early-data input, discovery-derived trust, or silent trust-on-first-use is permitted.

## Logging and diagnostics

Routine logs may include bounded error categories and transient state, but never input contents, clipboard or file contents, private filenames, pairing codes, private keys, stable device identifiers, or stable network identifiers.
