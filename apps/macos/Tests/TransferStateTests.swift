import Foundation
import Testing
@testable import NodavoMac

private let instanceOne = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
private let instanceTwo = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
private let transferOne = "123e4567-e89b-12d3-a456-426614174000"
private let transferTwo = "223e4567-e89b-42d3-a456-426614174001"

@Test func transferDecoderAcceptsExactBoundedSnapshotAndZeroByteProgress() throws {
    let snapshot = try decodeTransferSnapshot(#"""
    {
      "event":"transfers",
      "instance_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      "revision":1,
      "truncated":false,
      "transfers":[{
        "transfer_id":"123e4567-e89b-12d3-a456-426614174000",
        "direction":"outbound",
        "phase":"queued",
        "processed_bytes":0,
        "total_bytes":0,
        "cancellable":true,
        "failure":null
      }]
    }
    """#)

    #expect(snapshot.instanceID == instanceOne)
    #expect(snapshot.revision == 1)
    #expect(snapshot.transfers[0].processedBytes == 0)
    #expect(snapshot.transfers[0].totalBytes == 0)
    #expect(snapshot.transfers[0].phase == .queued)
    #expect(snapshot.transfers[0].redactedID == "••••••••-14174000")
}

@Test func transferDecoderMirrorsEveryPhaseAndFailureShape() throws {
    for (phase, counters, failure) in [
        ("preparing", #""processed_bytes":null,"total_bytes":null"#, "null"),
        ("preparing", #""processed_bytes":0,"total_bytes":8"#, "null"),
        ("queued", #""processed_bytes":0,"total_bytes":8"#, "null"),
        ("transferring", #""processed_bytes":3,"total_bytes":8"#, "null"),
        ("paused", #""processed_bytes":3,"total_bytes":8"#, "null"),
        ("finalizing", #""processed_bytes":8,"total_bytes":8"#, "null"),
        ("cancel_requested", #""processed_bytes":null,"total_bytes":null"#, "null"),
        ("cancel_requested", #""processed_bytes":3,"total_bytes":8"#, "null"),
        ("completed", #""processed_bytes":8,"total_bytes":8"#, "null"),
        ("cancelled", #""processed_bytes":null,"total_bytes":null"#, "null"),
        ("cancelled", #""processed_bytes":3,"total_bytes":8"#, "null"),
        ("failed", #""processed_bytes":null,"total_bytes":null"#, #""admission_failed""#),
        ("failed", #""processed_bytes":3,"total_bytes":8"#, #""transport_failed""#),
    ] {
        _ = try decodeTransferSnapshot(snapshotJSON(phase: phase, counters: counters, failure: failure))
    }

    for failure in [
        "admission_failed", "source_unavailable", "authorization_revoked", "transport_failed",
        "cleanup_failed", "internal",
    ] {
        _ = try decodeTransferSnapshot(snapshotJSON(
            phase: "failed",
            counters: #""processed_bytes":0,"total_bytes":1"#,
            failure: "\"\(failure)\""
        ))
    }
}

@Test func transferDecoderRejectsMissingExtraPrivateUnknownAndMalformedRows() {
    let invalid = [
        snapshotJSON(phase: "queued", counters: #""processed_bytes":0"#, failure: "null"),
        snapshotJSON(phase: "queued", counters: #""processed_bytes":0,"total_bytes":1,"path":"/private""#, failure: "null"),
        snapshotJSON(phase: "copying", counters: #""processed_bytes":0,"total_bytes":1"#, failure: "null"),
        snapshotJSON(phase: "queued", counters: #""processed_bytes":0,"total_bytes":1"#, failure: #""transport_failed""#),
        snapshotJSON(phase: "failed", counters: #""processed_bytes":0,"total_bytes":1"#, failure: "null"),
        snapshotJSON(phase: "failed", counters: #""processed_bytes":0,"total_bytes":1"#, failure: #""unknown_failure""#),
        snapshotJSON(phase: "failed", counters: #""processed_bytes":0,"total_bytes":1"#, failure: #""preparation_failed""#),
        snapshotJSON(phase: "completed", counters: #""processed_bytes":0,"total_bytes":1"#, failure: "null"),
        snapshotJSON(phase: "transferring", counters: #""processed_bytes":2,"total_bytes":1"#, failure: "null"),
        snapshotJSON(phase: "queued", counters: #""processed_bytes":0,"total_bytes":10737418241"#, failure: "null"),
        snapshotJSON(phase: "preparing", counters: #""processed_bytes":null,"total_bytes":1"#, failure: "null"),
        snapshotJSON(phase: "queued", counters: #""processed_bytes":null,"total_bytes":null"#, failure: "null"),
        snapshotJSON(phase: "completed", counters: #""processed_bytes":null,"total_bytes":null"#, failure: "null"),
        snapshotJSON(phase: "cancel_requested", counters: #""processed_bytes":0,"total_bytes":1"#, failure: "null", cancellable: true),
        snapshotJSON(phase: "completed", counters: #""processed_bytes":1,"total_bytes":1"#, failure: "null", cancellable: true),
        snapshotJSON(phase: "cancelled", counters: #""processed_bytes":0,"total_bytes":1"#, failure: "null", cancellable: true),
        snapshotJSON(phase: "failed", counters: #""processed_bytes":0,"total_bytes":1"#, failure: #""internal""#, cancellable: true),
        snapshotJSON(phase: "queued", counters: #""processed_bytes":0,"total_bytes":1"#, failure: "null", direction: "sideways"),
        snapshotJSON(phase: "queued", counters: #""processed_bytes":0,"total_bytes":1"#, failure: "null", transferID: "123E4567-E89B-12D3-A456-426614174000"),
        snapshotJSON(phase: "queued", counters: #""processed_bytes":0,"total_bytes":1"#, failure: "null", transferID: "00000000-0000-0000-0000-000000000000"),
    ]
    for payload in invalid {
        #expect(throws: AgentClientError.self) {
            try decodeTransferSnapshot(payload)
        }
    }
}

@Test func transferDecoderAcceptsExactlyMaximumUniqueRowsAndByteBound() throws {
    let rows: [[String: Any]] = (1 ... TransferSnapshot.maximumTransfers).map { index in
        [
            "transfer_id": String(format: "00000000-0000-4000-8000-%012x", index),
            "direction": index.isMultiple(of: 2) ? "inbound" : "outbound",
            "phase": "transferring",
            "processed_bytes": 0,
            "total_bytes": TransferSummary.maximumBytes,
            "cancellable": true,
            "failure": NSNull(),
        ]
    }
    let payload: [String: Any] = [
        "event": "transfers",
        "instance_id": instanceOne,
        "revision": 1,
        "truncated": true,
        "transfers": rows,
    ]
    let snapshot = try AgentResponseDecoder.transferSnapshot(
        JSONSerialization.data(withJSONObject: payload)
    )
    #expect(snapshot.transfers.count == TransferSnapshot.maximumTransfers)
    #expect(snapshot.transfers.last?.totalBytes == 10_737_418_240)
    #expect(snapshot.truncated)
}

@Test func transferDecoderRejectsInvalidEnvelopeDuplicateIDsAndMoreThanMaximumRows() throws {
    for payload in [
        snapshotJSON(revision: 0),
        snapshotJSON(instanceID: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
        snapshotJSON(instanceID: "00000000-0000-0000-0000-000000000000"),
        snapshotJSON(extraEnvelope: #", "peer_name":"private""#),
        snapshotJSON(event: "transfer_list"),
        #"{"event":"transfers","instance_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","revision":1,"transfers":[]}"#,
    ] {
        #expect(throws: AgentClientError.self) { try decodeTransferSnapshot(payload) }
    }

    let row: [String: Any] = [
        "transfer_id": transferOne,
        "direction": "inbound",
        "phase": "queued",
        "processed_bytes": 0,
        "total_bytes": 1,
        "cancellable": true,
        "failure": NSNull(),
    ]
    for rows in [[row, row], Array(repeating: row, count: 161)] {
        let payload: [String: Any] = [
            "event": "transfers",
            "instance_id": instanceOne,
            "revision": 1,
            "truncated": false,
            "transfers": rows,
        ]
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.transferSnapshot(
                JSONSerialization.data(withJSONObject: payload)
            )
        }
    }
}

@Test func transferSnapshotRejectsDuplicateEnvelopeAndRowKeysBeforeDecoding() {
    let valid = snapshotJSON()
    let duplicateEnvelope = valid.replacingOccurrences(
        of: #""revision":1"#,
        with: #""revision":1,"revision":2"#
    )
    let duplicateRow = valid.replacingOccurrences(
        of: #""phase":"queued""#,
        with: #""phase":"queued","phase":"queued""#
    )
    for payload in [duplicateEnvelope, duplicateRow] {
        #expect(throws: AgentClientError.self) {
            try decodeTransferSnapshot(payload)
        }
    }
}

@Test func duplicateKeyValidatorCoversNestedObjectsWithoutScanningStringContents() throws {
    #expect(throws: StrictJSONDuplicateKeyValidator.ValidationError.self) {
        try StrictJSONDuplicateKeyValidator.validate(
            Data(#"{"outer":[{"value":1,"value":2}]}"#.utf8)
        )
    }
    try StrictJSONDuplicateKeyValidator.validate(
        Data(#"{"text":"\"value\":1,\"value\":2 value value","items":[{"value":1},{"value":2}]}"#.utf8)
    )
}

@Test func duplicateKeyValidatorHasRawSizeAndNestingBounds() {
    #expect(throws: StrictJSONDuplicateKeyValidator.ValidationError.self) {
        try StrictJSONDuplicateKeyValidator.validate(
            Data(repeating: 0x20, count: StrictJSONDuplicateKeyValidator.maximumBytes + 1)
        )
    }
    let tooDeep = String(repeating: "[", count: 65) + "0" + String(repeating: "]", count: 65)
    #expect(throws: StrictJSONDuplicateKeyValidator.ValidationError.self) {
        try StrictJSONDuplicateKeyValidator.validate(Data(tooDeep.utf8))
    }
}

@Test func transferCommandDeadlinesSeparateAdmissionFromStatusMutations() {
    #expect(TransferCommandDeadline.admissionSeconds == 15)
    #expect(TransferCommandDeadline.admissionSeconds > 10)
    #expect(TransferCommandDeadline.statusSeconds == 8)
}

@Test func completedEmptyTransferUsesDeterminateCompletionPresentation() throws {
    let completedEmpty = try makeTransfer(
        id: transferOne,
        phase: .completed,
        processed: 0,
        total: 0
    )
    #expect(completedEmpty.progressMode == .completedEmpty)

    let queuedEmpty = try makeTransfer(id: transferTwo, phase: .queued, processed: 0, total: 0)
    #expect(queuedEmpty.progressMode == .indeterminate)

    let completedNonempty = try makeTransfer(
        id: transferTwo,
        phase: .completed,
        processed: 8,
        total: 8
    )
    #expect(completedNonempty.progressMode == .determinate(processed: 8, total: 8))
}

@Test func transferCommandsUseExactWireNamesAndCancellationID() throws {
    let list = try encodedObject(AgentCommand.simple("list_transfers"))
    #expect(list as NSDictionary == ["command": "list_transfers"] as NSDictionary)

    let cancel = try encodedObject(AgentCommand(
        command: "cancel_transfer",
        transferID: transferOne
    ))
    #expect(cancel as NSDictionary == [
        "command": "cancel_transfer",
        "transfer_id": transferOne,
    ] as NSDictionary)
}

@Test func authoritativeReducerRejectsStaleRevisionAndReplacesWholeSnapshot() throws {
    var state = TransferSessionState()
    let first = try makeSnapshot(instanceID: instanceOne, revision: 4, transfers: [
        makeTransfer(id: transferOne, phase: .transferring),
    ])
    #expect(state.apply(first) == .newInstance)

    let stale = try makeSnapshot(instanceID: instanceOne, revision: 3, transfers: [])
    #expect(state.apply(stale) == .stale)
    #expect(state.transfers.map(\.transferID) == [transferOne])
    #expect(state.apply(first) == .unchanged)

    let replacement = try makeSnapshot(instanceID: instanceOne, revision: 5, transfers: [
        makeTransfer(id: transferTwo, phase: .queued),
    ])
    #expect(state.apply(replacement) == .updated)
    #expect(state.transfers.map(\.transferID) == [transferTwo])
}

@Test func truncatedSnapshotRetainsPendingRowButFullSnapshotRemovesIt() throws {
    var state = TransferSessionState()
    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 1, transfers: [
        makeTransfer(id: transferOne, phase: .transferring),
        makeTransfer(id: transferTwo, phase: .queued),
    ]))

    _ = state.apply(
        try makeSnapshot(
            instanceID: instanceOne,
            revision: 2,
            truncated: true,
            transfers: [makeTransfer(id: transferTwo, phase: .transferring)]
        ),
        retainingIDs: [transferOne]
    )
    #expect(state.transfers.map(\.transferID) == [transferTwo, transferOne])
    #expect(state.transfers.first(where: { $0.transferID == transferOne })?.phase == .transferring)

    _ = state.apply(try makeSnapshot(
        instanceID: instanceOne,
        revision: 3,
        transfers: [makeTransfer(id: transferTwo, phase: .completed, processed: 8, total: 8)]
    ), retainingIDs: [transferOne])
    #expect(state.transfers.map(\.transferID) == [transferTwo])
}

@Test func truncatedRetentionNeverExceedsWireRowBound() throws {
    var state = TransferSessionState()
    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 1, transfers: [
        makeTransfer(id: transferOne, phase: .transferring),
    ]))
    let incoming = try (1 ... TransferSnapshot.maximumTransfers).map { index in
        try makeTransfer(
            id: String(format: "00000000-0000-4000-8000-%012x", index),
            phase: .transferring
        )
    }
    _ = state.apply(
        try makeSnapshot(
            instanceID: instanceOne,
            revision: 2,
            truncated: true,
            transfers: incoming
        ),
        retainingIDs: [transferOne]
    )
    #expect(state.transfers.count == TransferSnapshot.maximumTransfers)
    #expect(state.transfers.contains { $0.transferID == transferOne })
}

@Test func sessionAndAdmissionTrackingStayBoundedAndPruneToPendingIDs() throws {
    var state = TransferSessionState()
    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 1, transfers: []))
    let ids = (1 ... 200).map {
        String(format: "00000000-0000-4000-8000-%012x", $0)
    }
    ids.forEach { state.noteAdmittedTransfer($0) }
    #expect(state.trackedAdmissionCount == TransferSnapshot.maximumTransfers)
    #expect(state.trackedSessionCount == TransferSnapshot.maximumTransfers)

    _ = state.apply(
        try makeSnapshot(
            instanceID: instanceOne,
            revision: 2,
            truncated: true,
            transfers: []
        )
    )
    #expect(state.trackedAdmissionCount == TransferSnapshot.maximumTransfers)
    #expect(state.trackedSessionCount == 0)

    _ = state.apply(try makeSnapshot(
        instanceID: instanceOne,
        revision: 3,
        truncated: true,
        transfers: [makeTransfer(id: ids[0], phase: .transferring)]
    ))
    #expect(state.trackedAdmissionCount == TransferSnapshot.maximumTransfers - 1)

    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 4, transfers: []))
    #expect(state.trackedAdmissionCount == 0)
}

@Test func newAgentInstanceClearsOldRowsAndSessionHistory() throws {
    var state = TransferSessionState()
    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 2, transfers: [
        makeTransfer(id: transferOne, phase: .transferring),
    ]))
    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 3, transfers: [
        makeTransfer(id: transferOne, phase: .completed, processed: 8, total: 8),
    ]))
    #expect(state.recentTransfers.map(\.transferID) == [transferOne])

    #expect(state.apply(try makeSnapshot(instanceID: instanceTwo, revision: 1, transfers: [])) == .newInstance)
    #expect(state.transfers.isEmpty)
    #expect(state.recentTransfers.isEmpty)
}

@Test func cancellationConvergesOnlyThroughNewerAuthoritativeSnapshot() throws {
    var state = TransferSessionState()
    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 10, transfers: [
        makeTransfer(id: transferOne, phase: .transferring),
    ]))
    #expect(state.apply(try makeSnapshot(instanceID: instanceOne, revision: 10, transfers: [
        makeTransfer(id: transferOne, phase: .cancelRequested),
    ])) == .unchanged)
    #expect(state.currentTransfers[0].phase == .transferring)

    #expect(state.apply(try makeSnapshot(instanceID: instanceOne, revision: 11, transfers: [
        makeTransfer(id: transferOne, phase: .cancelRequested),
    ])) == .updated)
    #expect(state.currentTransfers[0].phase == .cancelRequested)

    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 12, transfers: [
        makeTransfer(id: transferOne, phase: .cancelled),
    ]))
    #expect(state.currentTransfers.isEmpty)
    #expect(state.recentTransfers[0].phase == .cancelled)
}

@Test func terminalRowsPresentBeforeThisSessionAreNotCalledRecent() throws {
    var state = TransferSessionState()
    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 1, transfers: [
        makeTransfer(id: transferOne, phase: .completed, processed: 8, total: 8),
        makeTransfer(id: transferTwo, phase: .transferring),
    ]))
    #expect(state.recentTransfers.isEmpty)
    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 2, transfers: [
        makeTransfer(id: transferTwo, phase: .completed, processed: 8, total: 8),
    ]))
    #expect(state.recentTransfers.map(\.transferID) == [transferTwo])
}

@Test func locallyAdmittedTransferFinishingBeforeFirstPollIsRecent() throws {
    var state = TransferSessionState()
    state.noteAdmittedTransfer(transferOne)
    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 1, transfers: [
        makeTransfer(id: transferOne, phase: .completed, processed: 8, total: 8),
    ]))
    #expect(state.recentTransfers.map(\.transferID) == [transferOne])
}

@Test func initialTruncatedSnapshotKeepsUnseenAdmissionPendingUntilFullSnapshot() throws {
    var state = TransferSessionState()
    state.noteAdmittedTransfer(transferOne)
    _ = state.apply(try makeSnapshot(
        instanceID: instanceOne,
        revision: 1,
        truncated: true,
        transfers: []
    ))
    #expect(state.hasPendingAdmissions)
    #expect(state.trackedAdmissionCount == 1)

    _ = state.apply(try makeSnapshot(instanceID: instanceOne, revision: 2, transfers: []))
    #expect(!state.hasPendingAdmissions)
}

@Test func transferPollingOwnershipStartsOnceAndStopsWhenHiddenOrTerminal() {
    var owner = TransferPollingOwner()
    #expect(owner.begin(force: true, needsPolling: true) == nil)
    owner.setVisible(true)
    let first = owner.begin(force: true, needsPolling: false)
    #expect(first != nil)
    #expect(owner.begin(force: true, needsPolling: true) == nil)
    #expect(owner.finish(first!) == true)
    #expect(owner.begin(force: false, needsPolling: false) == nil)

    let active = owner.begin(force: false, needsPolling: true)
    #expect(active != nil)
    owner.setVisible(false)
    #expect(owner.owns(active!) == false)
    #expect(owner.begin(force: true, needsPolling: true) == nil)
}

@Test func forcedTransferPollInvalidatesOlderGenerationBeforeRestart() throws {
    var owner = TransferPollingOwner()
    owner.setVisible(true)
    let oldCandidate = owner.begin(force: true, needsPolling: true)
    let old = try #require(oldCandidate)
    owner.stop()
    let replacementCandidate = owner.begin(force: true, needsPolling: true)
    let replacement = try #require(replacementCandidate)
    #expect(replacement != old)
    #expect(!owner.owns(old))
    #expect(owner.owns(replacement))
}

@Test func transferPollingBackoffIsBoundedAfterTransientOrStaleResults() {
    #expect(TransferPollBackoff.delayMilliseconds(consecutiveFailures: 0) == 1_000)
    #expect(TransferPollBackoff.delayMilliseconds(consecutiveFailures: 1) == 1_000)
    #expect(TransferPollBackoff.delayMilliseconds(consecutiveFailures: 2) == 2_000)
    #expect(TransferPollBackoff.delayMilliseconds(consecutiveFailures: 3) == 4_000)
    #expect(TransferPollBackoff.delayMilliseconds(consecutiveFailures: 4) == 8_000)
    #expect(TransferPollBackoff.delayMilliseconds(consecutiveFailures: 100) == 8_000)
    #expect(TransferPollBackoff.delayMilliseconds(consecutiveFailures: Int.min) == 1_000)
}

@Test func ambiguousCancellationGloballyLocksToSameTransferUntilConvergence() throws {
    var authority = TransferCancellationAuthority()
    let firstCandidate = authority.begin(transferID: transferOne, eligible: true)
    let first = try #require(firstCandidate)
    #expect(authority.begin(transferID: transferTwo, eligible: true) == nil)
    authority.markAmbiguous(transferID: transferOne, generation: first)
    #expect(authority.needsRetry)
    #expect(authority.begin(transferID: transferTwo, eligible: true) == nil)

    let retryCandidate = authority.begin(transferID: transferOne, eligible: true)
    let retry = try #require(retryCandidate)
    let oldConverged = try makeSnapshot(instanceID: instanceOne, revision: 1, transfers: [
        makeTransfer(id: transferOne, phase: .cancelRequested),
    ])
    authority.reconcile(snapshot: oldConverged, application: .stale)
    #expect(authority.owns(transferID: transferOne, generation: retry))

    let partialWithoutTransfer = try makeSnapshot(
        instanceID: instanceOne,
        revision: 3,
        truncated: true,
        transfers: [makeTransfer(id: transferTwo, phase: .transferring)]
    )
    authority.reconcile(snapshot: partialWithoutTransfer, application: .updated)
    #expect(authority.owns(transferID: transferOne, generation: retry))

    authority.markAmbiguous(transferID: transferOne, generation: retry)
    let fullWithoutTransfer = try makeSnapshot(
        instanceID: instanceOne,
        revision: 4,
        transfers: [makeTransfer(id: transferTwo, phase: .transferring)]
    )
    authority.reconcile(snapshot: fullWithoutTransfer, application: .updated)
    #expect(!authority.isActive)
    #expect(authority.begin(transferID: transferTwo, eligible: true) != nil)
}

@Test func authoritativeCancelRequestedRowConvergesCancellationAuthority() throws {
    var authority = TransferCancellationAuthority()
    _ = authority.begin(transferID: transferOne, eligible: true)
    let snapshot = try makeSnapshot(instanceID: instanceOne, revision: 2, transfers: [
        makeTransfer(id: transferOne, phase: .cancelRequested),
    ])
    authority.reconcile(snapshot: snapshot, application: .updated)
    #expect(!authority.isActive)
}

@Test func deterministicCancellationRejectionReleasesGlobalAuthority() throws {
    var authority = TransferCancellationAuthority()
    let generationCandidate = authority.begin(transferID: transferOne, eligible: true)
    let generation = try #require(generationCandidate)
    authority.markRejected(transferID: transferOne, generation: generation)
    #expect(!authority.isActive)
    #expect(authority.begin(transferID: transferTwo, eligible: true) != nil)
}

@Test func admissionFailurePolicyNeverBlindlyRetriesUnknownOutcome() {
    #expect(TransferAdmissionFailureDisposition.classify(AgentClientError.unsafeValue) == .invalidSelection)
    #expect(TransferAdmissionFailureDisposition.classify(AgentClientError.requestTooLarge) == .invalidSelection)
    #expect(TransferAdmissionFailureDisposition.classify(
        AgentClientError.agent(code: "not_authorized", message: "rejected")
    ) == .rejected)
    #expect(TransferAdmissionFailureDisposition.classify(AgentClientError.agentUnavailable) == .outcomeUnknown)
    #expect(TransferAdmissionFailureDisposition.classify(AgentClientError.messageTooLarge) == .outcomeUnknown)
    #expect(TransferAdmissionFailureDisposition.classify(AgentClientError.invalidResponse) == .outcomeUnknown)
    #expect(TransferAdmissionFailureDisposition.classify(AgentClientError.system(ETIMEDOUT)) == .outcomeUnknown)
}

private func decodeTransferSnapshot(_ payload: String) throws -> TransferSnapshot {
    try AgentResponseDecoder.transferSnapshot(Data(payload.utf8))
}

private func encodedObject(_ command: AgentCommand) throws -> [String: Any] {
    try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(command)) as? [String: Any]
    )
}

private func snapshotJSON(
    phase: String = "queued",
    counters: String = #""processed_bytes":0,"total_bytes":1"#,
    failure: String = "null",
    direction: String = "outbound",
    transferID: String = transferOne,
    instanceID: String = instanceOne,
    revision: UInt64 = 1,
    event: String = "transfers",
    extraEnvelope: String = "",
    cancellable: Bool? = nil
) -> String {
    let defaultsToCancellable = phase != "cancel_requested"
        && phase != "completed"
        && phase != "cancelled"
        && phase != "failed"
    let cancellableValue = cancellable ?? defaultsToCancellable
    return #"{"event":"\#(event)","instance_id":"\#(instanceID)","revision":\#(revision),"truncated":false,"transfers":[{"transfer_id":"\#(transferID)","direction":"\#(direction)","phase":"\#(phase)",\#(counters),"cancellable":\#(cancellableValue),"failure":\#(failure)}]\#(extraEnvelope)}"#
}

private func makeTransfer(
    id: String,
    phase: TransferPhase,
    processed: UInt64 = 3,
    total: UInt64 = 8
) throws -> TransferSummary {
    try TransferSummary(
        transferID: id,
        direction: .outbound,
        phase: phase,
        processedBytes: processed,
        totalBytes: total,
        cancellable: phase != .cancelRequested && !phase.isTerminal,
        failure: phase == .failed ? .transportFailed : nil
    )
}

private func makeSnapshot(
    instanceID: String,
    revision: UInt64,
    truncated: Bool = false,
    transfers: [TransferSummary]
) throws -> TransferSnapshot {
    try TransferSnapshot(
        instanceID: instanceID,
        revision: revision,
        truncated: truncated,
        transfers: transfers
    )
}
