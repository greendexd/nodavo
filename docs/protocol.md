<!-- doc-id: peer-protocol; lang: en; revision: 7 -->

# Nodavo peer protocol

[English](protocol.md) · [Русский](protocol.ru.md)

## Status

This document describes the current pre-alpha wire foundation implemented by `nodavo-protocol` and the channel contract implemented by `nodavo-transport`. It is not a stable 1.0 specification. Tags and structures may change until the release-candidate protocol is frozen; incompatible changes must update the protocol version and this document together.

Pairing and trust establishment are defined by the [security model](security-model.md). Discovery supplies a network location only and is never accepted as peer identity.

## Transport and channel separation

Peers use QUIC over TLS 1.3. A connection has independent backpressure domains so replaceable motion cannot delay keys, control, clipboard, or files.

| Data | QUIC path | Reliability rule | Hard application limit |
| --- | --- | --- | ---: |
| Negotiation, grants, sessions, focus, display topology, liveness, errors | Bidirectional control stream | Ordered and reliable | 64 KiB per protocol message |
| Keys, pointer buttons, reliable pointer entry, forced release | Reliable input stream | Ordered and reliable | 1 KiB per protocol message |
| Relative pointer delta and high-frequency scroll | QUIC datagrams | Sequenced; recent valid motion is applied | 1,200 bytes |
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

Decoders enforce the channel-specific size limit before decoding, require the envelope and body to re-encode identically, reject unknown critical tags, and preserve bounded unknown non-critical messages as opaque data. Version `0.x` is invalid. The current peer-message codec accepts exactly pre-alpha version `1.4`; the minor version changed for directional grant epochs and authenticated post-pair capability updates and does not change the separate pairing-preflight version. It also does not mean the product itself is released as 1.0.

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
| `12`–`13` | Versioned display-topology snapshot and acknowledgement | Control |
| `14` | Reliable pointer-entry acknowledgement | Control |
| `0x1000`–`0x1001` | Key and pointer-button events | Reliable input |
| `0x1002`–`0x1003` | Pointer motion and scroll | Datagram or pointer fallback |
| `0x1004` | Forced release of all pressed state | Reliable input |
| `0x1005` | Bounded relative pointer delta | Datagram or pointer fallback |
| `0x1006` | Initial absolute pointer entry | Reliable input |
| `0x2000`–`0x2004` | Clipboard offer, clear, request, chunk, and abort | Clipboard |
| `0x3000`–`0x3003` | File manifest, resume, cancel, and complete | File manifest |
| `0x4000` | File content chunk | File data |

Clipboard and transfer messages now have pre-alpha canonical codecs and reserved ranges. They enforce per-kind clipboard limits, 256 KiB chunks, a 1 MiB/10,000-entry/10 GiB file manifest boundary, normalized safe relative paths, exact 32-byte hashes, nonzero transfer identifiers, channel separation, and content/path-redacted debug output. They are not an available product feature until the agent and both platform adapters complete the end-to-end capability-checked session path.

## Identity, freshness, and capability context

Every input event carries:

- a random session identifier;
- the authenticated origin device identifier;
- a monotonically checked sequence in its control, reliable-input, or replaceable-input lane;
- the receiver-issued local grant epoch currently authorizing the sender;
- exactly the remote-input capability;
- the nonzero identifier of the focus lease authorizing the event, including forced release-all.

Focus leases have a nonzero lease identifier and a bounded time-to-live. A request states whether a reliable pointer entry is required. When required, the controller does not enable native suppression or send relative motion until the receiver has installed the reliable entry position and returned a session-bound acknowledgement. A receiver validates the complete event, active lease, direction-specific grant, entry gate, and lane watermark before committing a new sequence. It rejects stale grants, stale sequences, wrong origins, wrong sessions, malformed zero identifiers, or events without the required grant. A normal authenticated focus release clears pressed state and returns focus to local ownership while the session remains ready. Emergency stop, lock, sleep, link loss, and lease expiry synchronously clear the lease, entry gate, and pressed-state model and close the session before input routing can resume. An accepted grant-epoch transition releases the active lease, aborts or suspends affected content work, and closes the old session so a fresh mutually authenticated connection must negotiate the new policy before routing resumes.

Display topology is a critical, bounded control message with its own schema version, nonzero revision, at most 32 displays, bounded pixel geometry, and bounded scale/origin values. It shares the authenticated control replay lane. A sender assigns opaque display identifiers for the current session; platform-native display identifiers never cross the connection. A snapshot becomes routable only after reducer authorization and an exact-revision acknowledgement. The normal focus reducer rejects a focus request until the topology needed for that direction is installed or acknowledged.

Capabilities are explicit and separately represented for remote input, clipboard read, clipboard write, and file transfer. Each endpoint maintains two independent values: its persisted local grant and epoch, which validate inbound messages, and the authenticated peer grant and epoch, which are cited by outbound metadata. Reconnect negotiation exchanges each side's complete capability set and nonzero epoch. A post-pair change is an ordered reliable `CapabilityGrant` or `CapabilityRevoke` targeted to the recipient device, carries exactly one changed capability, and must advance the sender's epoch by exactly one; a replay, gap, wrong target, or redundant delta fails closed. The receiver updates only its peer-grant view. Clipboard requests require exactly the read capability; offers, clear operations, and content chunks require exactly the write capability. File manifests, resume/cancel/complete control, and data chunks require exactly file transfer. A transport connection alone never grants a capability.

## Input semantics

Keyboard events use USB HID usage page and usage identifiers rather than platform virtual-key codes. Unknown modifier bits are rejected. The initial pointer entry identifies a nonzero session-scoped display and uses normalized fixed-point coordinates; the receiving agent resolves that token through its local session map before injection. After acknowledgement, physical movement is represented as a nonzero bounded signed `PointerDelta` with no display identity. macOS derives it from CGEvent deltas and injects it from the current cursor location; Windows uses Raw Input deltas and relative `SendInput`. Scroll events explicitly use either `Lines` for discrete wheel detents or `Precise` for high-resolution device-independent deltas; a zero/zero scroll is malformed. Delta and scroll preserve complete metadata through datagrams or pointer fallback. Relative deltas coalesce only when their exact sum remains bounded; overflow remains as separate queued motion rather than being silently truncated. The regular reliable-input codec accepts pointer entry but rejects replaceable events, and the fallback codec rejects keys, buttons, entry, and release-all. Nodavo-injected events carry a platform tag and capture adapters reject them to prevent amplification loops.

Edge adjacency is local configuration, not peer-provided topology authority. Empty adjacency disables automatic edge switching. Configured routes use bounded logical-DPI transforms, dwell/debounce, hysteresis, and cooldown, but still request the ordinary authenticated focus lease. Local focus uses absolute positions only for edge detection; after reliable entry acknowledgement, authenticated routing uses physical relative deltas so movement can continue beyond the local OS edge. This path has focused and cross-target compile tests but still requires real macOS/Windows hardware validation before it can be described as release-proven 1.0 behavior.

Text input for layouts, dead keys, AltGr, and IME fallback remains a 1.0 implementation item and will be specified before the protocol freeze.

## Compatibility rules

- Peers must negotiate a mutually supported major/minor version before opening a session.
- A changed meaning for an existing field or tag requires an incompatible version change.
- Additive optional behavior uses a new non-critical tag or an explicitly optional field with a deterministic default.
- Unknown capability bits, malformed canonical encoding, limit violations, and critical unknown tags fail closed.
- No plaintext mode, early-data input, discovery-derived trust, or silent trust-on-first-use is permitted.

## Logging and diagnostics

Routine logs may include bounded error categories and transient state, but never input contents, clipboard or file contents, private filenames, pairing codes, private keys, stable device identifiers, or stable network identifiers.
