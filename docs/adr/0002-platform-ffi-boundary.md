# ADR-0002: Isolated platform FFI boundary

- Status: Accepted
- Date: 2026-08-09

## Context

CoreGraphics event taps, macOS accessibility APIs, Raw Input, `SendInput`, Win32 clipboard/OLE, credential storage, and installer integration ultimately cross native FFI boundaries. A workspace-wide `unsafe_code = "forbid"` makes the production adapters impossible, while allowing unsafe code generally would weaken review.

## Decision

The workspace lint is `unsafe_code = "deny"`. Core, protocol, identity, transport semantics, session, clipboard, transfer, update, agent orchestration, and test-support crates must not override it. Only crates named `nodavo-platform-macos` and `nodavo-platform-windows` may use crate-local `#![allow(unsafe_code)]`, and only inside modules named `ffi`.

Every unsafe block must state the native preconditions it upholds. FFI wrappers must:

- validate pointers, lengths, enum values, thread requirements, and object ownership before constructing safe types;
- keep callbacks alive for at least as long as the OS registration and unregister them before captured state is dropped;
- tag injected events and prevent their recapture;
- bound native buffers before copying;
- expose semantic Rust values rather than native handles;
- fail closed on permission, session, secure-desktop, or API errors;
- release tracked keys and buttons during disconnect, lock, sleep, timeout, crash recovery, and emergency stop.

## Consequences

- CI rejects unsafe code outside the two platform crates.
- Platform FFI requires focused compile/runtime evidence on every supported architecture before M0/M2 claims are made.
- Fuzz, sanitizers, lifecycle stress, and real-hardware validation remain release gates after feature completion.
- A new privileged component or another unsafe crate requires a separate ADR and threat-model update.
