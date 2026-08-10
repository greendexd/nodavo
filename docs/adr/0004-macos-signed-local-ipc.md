<!-- doc-id: adr-0004-macos-signed-local-ipc; lang: en; revision: 2 -->

# ADR-0004: Per-message signed XPC for macOS local IPC

[English](0004-macos-signed-local-ipc.md) · [Русский](0004-macos-signed-local-ipc.ru.md)

- Status: accepted for pre-alpha macOS implementation; revision 1 security claim withdrawn
- Date: 2026-08-10

## Context

Revision 1 authenticated a Unix-domain-socket peer by reading `LOCAL_PEERTOKEN`, resolving its current `audit_token_t` to a dynamic `SecCode`, and rechecking the token around frame reads. That design is not a sound message-provenance boundary. A same-user process can connect and queue a complete command while unsigned, exec the correctly signed Nodavo UI in the same process, and let the agent authenticate the post-exec task before consuming the pre-exec bytes. `LOCAL_PEERTOKEN` describes the current task associated with the socket's last PID; it does not label already queued bytes. More token gates, `FD_CLOEXEC`, or a finite challenge do not repair that mismatch.

Release IPC therefore needs an OS primitive that enforces code identity on every delivered message, not a snapshot inferred from a byte stream. The implementation must remain bounded, fail closed, avoid paths/PIDs/tokens as authority, and not log payload or process identity data.

## Decision

The packaged per-user agent LaunchAgent advertises the fixed Mach service `dev.nodavo.agent.ipc`. Release builds use XPC exclusively; there is no release UDS fallback and `NODAVO_IPC_PATH` is not consulted.

Before activation, the agent installs `xpc_connection_set_peer_code_signing_requirement` on the Mach-service listener and again on every accepted peer connection. The local SDK contract states that all messages received on a configured connection are checked. The fixed UI requirement demands:

- Apple generic anchor, Developer ID Application leaf, and Developer ID intermediate;
- exact identifier `dev.nodavo.macos` and compile-time ten-character Team ID;
- exact `com.apple.application-identifier` and `com.apple.developer.team-identifier` entitlements;
- absence of `com.apple.security.get-task-allow`.

The Swift release UI installs the reciprocal requirement for the exact `dev.nodavo.agent` helper, Team ID, Developer ID chain, application/team entitlements, and absent `get-task-allow` before activating its XPC connection. Thus the implemented release path authenticates the UI to the agent and the agent to the UI per message. Live mutual qualification remains unproven until a real Nodavo Developer ID/provisioning/notarization build is exercised.

Each XPC request and reply is a dictionary with exactly one `frame` data value containing the existing JSON command/event contract. Data is limited to 64 KiB; unknown command fields are rejected. Native admission allows at most 16 peers, four outstanding requests per peer, and 32 globally. Rust queues at most 32 requests and aborts dispatch at 350 seconds; native and Swift reply capabilities expire at 360 seconds, longer than the dispatcher's five-minute bounded operation. Reply capabilities are single-use, cancel on abandonment, and never expose an authentication token to Rust or Swift. Shutdown cancels the listener and outstanding tasks.

Native XPC, ARC, and dispatch operations remain inside the existing Objective-C/Rust FFI module. The safe listener is deliberately neither `Send` nor `Sync`, callbacks cannot unwind across FFI, and request/reply ownership is transferred exactly once. The safe agent adapter routes decoded XPC commands through the same exhaustive authority dispatcher used by the other platform transports.

The non-default compile-time Cargo feature `development-unverified-local-ipc` retains the private UDS solely for source-tree and development packaging. It requires the same effective UID, sets `FD_CLOEXEC` in Swift, is marked unsafe and non-distributable, does not advertise the release Mach service, and can never be selected by release packaging.

Release packaging embeds a validated Team ID in Rust and signed app metadata, asserts XPC signed-mutual policy with a bounded pre-sign `--self-check`, registers the Mach service, and verifies the actual signed universal UI/helper requirements, entitlements, hardened runtime, architectures, Keychain separation, notarization, and Gatekeeper results. The self-check is policy evidence, not signed runtime proof.

## Security and privacy impact

For a correctly signed release, per-message XPC enforcement prevents the queued-byte/exec laundering that invalidated revision 1 and rejects independent same-user, ad-hoc, wrong-team, wrong-identifier, and `get-task-allow` clients. It does not protect a process after arbitrary code injection/compromise, a compromised signing identity, kernel/XPC/Security.framework compromise, or a development bypass build.

Payloads, audit tokens, PIDs, process paths, private filenames, signing subjects, and Team IDs are not written to runtime logs. Failures remain generic. The old audit-token reducer is retained only as tested evidence for the unsafe development/socket analysis; it is not release message provenance.

## Alternatives rejected

- UDS plus audit-token rechecks: authenticates current task state, not the sender of queued bytes.
- UDS plus a finite challenge: a process can queue or relay protocol bytes across an exec boundary; it still does not give the stream per-byte code provenance.
- Same-UID credentials only: every process owned by the user could issue authority-bearing commands.
- PID or executable-path lookup: races with exec/PID reuse and trusts mutable path state.
- A shared UI secret: expands secret distribution and makes extraction by another same-user process the boundary.
- Runtime bypass variables: environment mutation could silently weaken a distributable build.

## Provenance

The decision uses the repository's independently written requirements and the local official Apple SDK/XPC, Security.framework, launchd, and public XNU interface contracts. The key correction follows the documented distinction between current socket peer state and XPC's all-received-message code requirement. No KVM implementation source or asset was consulted or reused.
