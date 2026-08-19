<!-- doc-id: adr-0005-stable-update-supervision; lang: en; revision: 2 -->

# ADR-0005: Stable external supervision for update activation

[English](0005-stable-update-supervision.md) · [Русский](0005-stable-update-supervision.ru.md)

- Status: accepted for the pre-alpha supervision core; production activation remains disabled
- Date: 2026-08-19

## Context

Nodavo can verify a signed release and stage a content-addressed artifact, but the application, UI, and session agent are all replaced by an update. None of those processes can be the sole recovery owner when the candidate never starts, exits before health, or the machine loses power after activation. Platform package transactions also cannot prove application health after a successful file or package replacement.

Activation changes executable code and must not inherit the existing **Download and stage** decision. Recovery must survive process and machine restart, reject stale process signals, retain an exact predecessor artifact, and never retire that predecessor before the durable anti-rollback floor advances.

## Decision

Production activation will be owned by a small, separately signed, per-user supervisor installed outside the application target being replaced. The supervisor is not a peer-session component and receives no input, clipboard, file-transfer, discovery, or network-peer authority. The current agent remains responsible only for release checks, verified staging, a distinct one-shot **Install and restart** decision, permanent bounded quiescence, and content-free status projection.

The only ordinary API that can create an install request consumes the exact `ReadyToInstall` session after that distinct decision. It returns a bounded handoff containing only a nonzero one-shot request ID and the exact original signed manifest envelope retained by release verification. The codec cannot carry a caller-selected filesystem path, installation plan, artifact name, transaction, process attempt, phase, or reducer action, and ordinary callers cannot construct it from raw envelope bytes. The default agent build can inspect the request ID and encode the request, but cannot decode it or link supervisor admission, host, reducer, or action APIs. Those receiving APIs are behind the non-default `supervisor-host` feature, and repository plus platform packaging gates reject that feature from agent artifacts. This is a packaging/build trust boundary only; it does not replace mutual process authentication, protected storage, or exclusive locking.

The platform-neutral `nodavo-update` crate defines a bounded write-ahead reducer. Its authenticated journal binds:

- a nonzero one-shot install-request identifier and a random supervisor-generated transaction identifier;
- an exact candidate artifact, install target, version, rollback epoch, and per-attempt process identity;
- an exact retained predecessor artifact and installer evidence;
- bounded candidate-start, health, predecessor-start, and old-process-exit attempts;
- the current phase and the rollback floor that must result from a healthy install.

Initial supervisor admission provisionally reserves the request without durably consuming it and proves that no active journal exists while holding the exclusive lock. Before initial persistence it authenticates the exact old process and fixed installed target/version, loads a fresh rollback floor, re-verifies the exact original signed envelope under supervisor-local policy, derives the plan internally, reopens and rehashes the exact sealed content-addressed artifact, and generates the transaction and old-process-attempt identities. It then atomically commits the request replay tombstone, exact old-process binding, and schema 3 journal and reloads the exact authenticated bytes. Failures before the persistence call authorize no action. Once persistence is called, any error or non-exact authenticated reload is commit-ambiguous: admission and the lock remain closed, and only authenticated-store recovery may establish whether a retry, reducer action, or new request is allowed.

Every subsequent external effect is authorized by one already-durable phase. The supervisor persists the next phase before prepare, activation, process start, rollback, or backup retirement. Timeout alone never authorizes a second process or replacement while the previous exact process may still be alive; a process-bound stop and exit observation is required first.

The commit order is:

1. authenticate the exact candidate and record health;
2. advance the durable rollback floor while the predecessor remains available;
3. record `FloorAdvanced`;
4. retire the exact predecessor;
5. clear the active journal.

Before `FloorAdvanced`, failure restores the exact retained predecessor and authenticates its restart. After `FloorAdvanced`, recovery can retry cleanup but cannot downgrade. Missing, corrupt, unauthenticated, deleted, stale, or oversized supervision state fails closed.

Platform adapters remain effect boundaries. macOS requires an exact signed/notarized universal bundle, a private immutable candidate slot, same-volume atomic exchange, and a separately registered signed supervisor. Direct-signed Windows distribution requires exact candidate and predecessor MSIXBundles, four-part package identities, a separately installed supervisor package, and platform package staging/registration. Microsoft Store builds use Store-owned updates and do not claim Nodavo-controlled downgrade unless a separately approved design is qualified.

The current pre-alpha source implements this bounded handoff contract, feature-gated pure supervision policy, and non-activating platform validation/staging primitives only. It does not provide authenticated supervisor IPC, a protected production store, a supervisor executable, activation or process adapters, package installation, or power-loss qualification.

## Security and privacy impact

The stable supervisor removes candidate code from the recovery trust root and makes consent, process identity, artifact identity, retries, and rollback order explicit. Consuming the staged session prevents reuse of one decision to mint multiple handoffs, while exact-envelope re-verification and request-ID binding prevent the old agent from supplying an authoritative plan or replaying a committed request. Treating every post-persistence result as outcome-unknown prevents an ambiguous commit from authorizing a second transaction or effect. Supervisor IPC must use fixed mutual signed-code requirements equivalent to the existing UI/agent boundary. Public status and logs contain only bounded phases, versions, and generic failure categories; they omit paths, artifact names, hashes, process identifiers, package family names, request/transaction identifiers, signing subjects, and keys.

User-owned storage cannot prevent arbitrary denial of service by the account owner. macOS production state therefore requires a supervisor-only Data Protection Keychain entitlement. Windows DPAPI and user-owned files protect confidentiality and accidental corruption but do not satisfy a claim of rollback resistance against an invasive same-user process; the 1.0 security model excludes compromise of already authorized processes, and stronger persistence claims require a separately qualified principal or broker.

## Alternatives rejected

- The running agent replaces itself: it does not survive candidate startup failure or power loss.
- The UI performs replacement: it is part of the target and cannot independently recover itself.
- A helper nested only inside the replaced application: it is replaced in the same transaction.
- Direct unprivileged cross-parent bundle exchange on macOS: sealing both trees against same-user mutation removes the directory write authority required by `RENAME_SWAP`; weakening that seal would reopen substitution races. The current platform API therefore remains validation-only.
- Reusing download consent for activation: it does not disclose restart or executable replacement.
- Timeout followed immediately by retry or rollback: the timed-out process may still be alive.
- Advancing the floor after deleting the backup: a persistence failure can leave neither a safe rollback nor the intended durable floor.
- Shell, elevation, or arbitrary installer execution: it expands authority and permits artifact-controlled behavior.

## Provenance

This decision uses the repository's independently written requirements and official local Apple Security, launchd, ServiceManagement, filesystem, Microsoft Appx packaging, package-deployment, and process contracts. No source, message, test fixture, or asset from another KVM product was used.
