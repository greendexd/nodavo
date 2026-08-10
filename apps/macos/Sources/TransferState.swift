import Foundation

enum TransferCommandDeadline {
    static let admissionSeconds = 15
    static let statusSeconds = 8
}

enum TransferAdmissionFailureDisposition: Equatable {
    case invalidSelection
    case rejected
    case outcomeUnknown

    static func classify(_ error: Error) -> Self {
        guard let clientError = error as? AgentClientError else { return .outcomeUnknown }
        switch clientError {
        case .unsafePath, .unsafeValue, .requestTooLarge:
            return .invalidSelection
        case .agent:
            return .rejected
        case .agentUnavailable, .messageTooLarge, .invalidResponse, .system:
            return .outcomeUnknown
        }
    }
}

enum TransferDirection: String, Decodable, Sendable {
    case inbound
    case outbound
}

enum TransferPhase: String, Decodable, Sendable {
    case preparing
    case queued
    case transferring
    case paused
    case finalizing
    case cancelRequested = "cancel_requested"
    case completed
    case cancelled
    case failed

    var isTerminal: Bool {
        self == .completed || self == .cancelled || self == .failed
    }
}

enum TransferFailure: String, Decodable, Sendable {
    case admissionFailed = "admission_failed"
    case sourceUnavailable = "source_unavailable"
    case authorizationRevoked = "authorization_revoked"
    case transportFailed = "transport_failed"
    case cleanupFailed = "cleanup_failed"
    case `internal`
}

enum TransferProgressMode: Equatable {
    case determinate(processed: UInt64, total: UInt64)
    case completedEmpty
    case indeterminate
    case hidden
}

struct TransferSummary: Decodable, Equatable, Identifiable, Sendable {
    static let maximumBytes: UInt64 = 10 * 1024 * 1024 * 1024

    let transferID: String
    let direction: TransferDirection
    let phase: TransferPhase
    let processedBytes: UInt64?
    let totalBytes: UInt64?
    let cancellable: Bool
    let failure: TransferFailure?

    var id: String { transferID }

    var redactedID: String {
        "••••••••-" + transferID.suffix(8)
    }

    var progressMode: TransferProgressMode {
        if phase == .completed, processedBytes == 0, totalBytes == 0 {
            return .completedEmpty
        }
        if let processedBytes, let totalBytes, totalBytes > 0 {
            return .determinate(processed: processedBytes, total: totalBytes)
        }
        if totalBytes == 0 || !phase.isTerminal {
            return .indeterminate
        }
        return .hidden
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case transferID = "transfer_id"
        case direction
        case phase
        case processedBytes = "processed_bytes"
        case totalBytes = "total_bytes"
        case cancellable
        case failure
    }

    init(
        transferID: String,
        direction: TransferDirection,
        phase: TransferPhase,
        processedBytes: UInt64?,
        totalBytes: UInt64?,
        cancellable: Bool,
        failure: TransferFailure?
    ) throws {
        guard Self.isCanonicalNonNilUUID(transferID),
              Self.validShape(
                  phase: phase,
                  processedBytes: processedBytes,
                  totalBytes: totalBytes,
                  cancellable: cancellable,
                  failure: failure
              )
        else {
            throw AgentClientError.invalidResponse
        }
        self.transferID = transferID
        self.direction = direction
        self.phase = phase
        self.processedBytes = processedBytes
        self.totalBytes = totalBytes
        self.cancellable = cancellable
        self.failure = failure
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyTransferCodingKey.self)
        guard Set(container.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue))
        else {
            throw AgentClientError.invalidResponse
        }
        try self.init(
            transferID: container.decode(String.self, forKey: .init("transfer_id")),
            direction: container.decode(TransferDirection.self, forKey: .init("direction")),
            phase: container.decode(TransferPhase.self, forKey: .init("phase")),
            processedBytes: container.decodeIfPresent(UInt64.self, forKey: .init("processed_bytes")),
            totalBytes: container.decodeIfPresent(UInt64.self, forKey: .init("total_bytes")),
            cancellable: container.decode(Bool.self, forKey: .init("cancellable")),
            failure: container.decodeIfPresent(TransferFailure.self, forKey: .init("failure"))
        )
    }

    static func isCanonicalNonNilUUID(_ value: String) -> Bool {
        guard value.utf8.count == 36,
              value != "00000000-0000-0000-0000-000000000000",
              let parsed = UUID(uuidString: value)
        else { return false }
        return parsed.uuidString.lowercased() == value
    }

    private static func validShape(
        phase: TransferPhase,
        processedBytes: UInt64?,
        totalBytes: UInt64?,
        cancellable: Bool,
        failure: TransferFailure?
    ) -> Bool {
        let countersValid: Bool
        let phaseAllowsAbsentCounters = phase == .preparing
            || phase == .cancelRequested
            || phase == .cancelled
            || phase == .failed
        if phaseAllowsAbsentCounters, processedBytes == nil, totalBytes == nil {
            countersValid = true
        } else if let processedBytes, let totalBytes {
            countersValid = processedBytes <= totalBytes && totalBytes <= maximumBytes
        } else {
            countersValid = false
        }
        let cancellationIsValid = !cancellable || (phase != .cancelRequested && !phase.isTerminal)
        guard countersValid,
              cancellationIsValid,
              (phase == .failed) == (failure != nil)
        else { return false }
        return phase != .completed || processedBytes == totalBytes
    }
}

struct TransferSnapshot: Decodable, Equatable, Sendable {
    static let maximumTransfers = 160

    let instanceID: String
    let revision: UInt64
    let truncated: Bool
    let transfers: [TransferSummary]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case event
        case instanceID = "instance_id"
        case revision
        case truncated
        case transfers
    }

    init(instanceID: String, revision: UInt64, truncated: Bool, transfers: [TransferSummary]) throws {
        guard TransferSummary.isCanonicalNonNilUUID(instanceID),
              revision > 0,
              transfers.count <= Self.maximumTransfers,
              Set(transfers.map(\.transferID)).count == transfers.count
        else {
            throw AgentClientError.invalidResponse
        }
        self.instanceID = instanceID
        self.revision = revision
        self.truncated = truncated
        self.transfers = transfers
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyTransferCodingKey.self)
        guard Set(container.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)),
              try container.decode(String.self, forKey: .init("event")) == "transfers"
        else {
            throw AgentClientError.invalidResponse
        }
        try self.init(
            instanceID: container.decode(String.self, forKey: .init("instance_id")),
            revision: container.decode(UInt64.self, forKey: .init("revision")),
            truncated: container.decode(Bool.self, forKey: .init("truncated")),
            transfers: container.decode([TransferSummary].self, forKey: .init("transfers"))
        )
    }
}

struct TransferSessionState: Equatable {
    enum Application: Equatable {
        case newInstance
        case updated
        case unchanged
        case stale
    }

    private(set) var instanceID: String?
    private(set) var revision: UInt64?
    private(set) var transfers = [TransferSummary]()
    private(set) var sessionTransferIDs = Set<String>()
    private(set) var truncated = false
    private var notedAdmittedTransferIDs = Set<String>()

    var trackedAdmissionCount: Int { notedAdmittedTransferIDs.count }
    var trackedSessionCount: Int { sessionTransferIDs.count }
    var hasPendingAdmissions: Bool { !notedAdmittedTransferIDs.isEmpty }

    var currentTransfers: [TransferSummary] {
        transfers.filter { !$0.phase.isTerminal }
    }

    var recentTransfers: [TransferSummary] {
        transfers.filter { $0.phase.isTerminal && sessionTransferIDs.contains($0.transferID) }
    }

    mutating func noteAdmittedTransfer(_ transferID: String) {
        guard TransferSummary.isCanonicalNonNilUUID(transferID) else { return }
        if !notedAdmittedTransferIDs.contains(transferID),
           notedAdmittedTransferIDs.count >= TransferSnapshot.maximumTransfers {
            return
        }
        sessionTransferIDs.insert(transferID)
        notedAdmittedTransferIDs.insert(transferID)
    }

    mutating func apply(
        _ snapshot: TransferSnapshot,
        retainingIDs: Set<String> = []
    ) -> Application {
        guard snapshot.instanceID == instanceID else {
            let isFirstSnapshot = instanceID == nil
            instanceID = snapshot.instanceID
            revision = snapshot.revision
            transfers = snapshot.transfers
            truncated = snapshot.truncated
            let snapshotIDs = Set(snapshot.transfers.map(\.transferID))
            sessionTransferIDs = Set(
                snapshot.transfers.lazy
                    .filter { !$0.phase.isTerminal }
                    .map(\.transferID)
            )
            if isFirstSnapshot {
                sessionTransferIDs.formUnion(notedAdmittedTransferIDs.intersection(snapshotIDs))
                notedAdmittedTransferIDs.subtract(snapshotIDs)
                if !snapshot.truncated {
                    notedAdmittedTransferIDs.removeAll()
                }
            } else {
                notedAdmittedTransferIDs.removeAll()
            }
            pruneTrackedIDs()
            return .newInstance
        }
        guard let revision else { return .stale }
        if snapshot.revision == revision { return .unchanged }
        guard snapshot.revision > revision else { return .stale }
        let knownIDs = Set(transfers.map(\.transferID))
        sessionTransferIDs.formUnion(
            snapshot.transfers.lazy
                .filter { !knownIDs.contains($0.transferID) }
                .map(\.transferID)
        )
        self.revision = snapshot.revision
        transfers = snapshot.truncated
            ? Self.mergeTruncated(
                incoming: snapshot.transfers,
                previous: transfers,
                retainingIDs: retainingIDs
            )
            : snapshot.transfers
        truncated = snapshot.truncated
        let incomingIDs = Set(snapshot.transfers.map(\.transferID))
        notedAdmittedTransferIDs.subtract(incomingIDs)
        if !snapshot.truncated {
            notedAdmittedTransferIDs.removeAll()
        }
        pruneTrackedIDs()
        return .updated
    }

    private mutating func pruneTrackedIDs() {
        let retainedRowIDs = Set(transfers.map(\.transferID))
        sessionTransferIDs.formIntersection(retainedRowIDs)
        if sessionTransferIDs.count > TransferSnapshot.maximumTransfers {
            sessionTransferIDs = Set(sessionTransferIDs.sorted().prefix(TransferSnapshot.maximumTransfers))
        }
        if notedAdmittedTransferIDs.count > TransferSnapshot.maximumTransfers {
            notedAdmittedTransferIDs = Set(
                notedAdmittedTransferIDs.sorted().prefix(TransferSnapshot.maximumTransfers)
            )
        }
    }

    private static func mergeTruncated(
        incoming: [TransferSummary],
        previous: [TransferSummary],
        retainingIDs: Set<String>
    ) -> [TransferSummary] {
        let incomingIDs = Set(incoming.map(\.transferID))
        let explicitlyRetained = previous.filter {
            retainingIDs.contains($0.transferID) && !incomingIDs.contains($0.transferID)
        }
        let incomingCapacity = max(
            0,
            TransferSnapshot.maximumTransfers - explicitlyRetained.count
        )
        var merged = Array(incoming.prefix(incomingCapacity))
        merged.append(contentsOf: explicitlyRetained.prefix(
            TransferSnapshot.maximumTransfers - merged.count
        ))
        let mergedIDs = Set(merged.map(\.transferID))
        let priorNonterminal = previous.filter {
            !$0.phase.isTerminal
                && !incomingIDs.contains($0.transferID)
                && !mergedIDs.contains($0.transferID)
        }
        merged.append(contentsOf: priorNonterminal.prefix(
            TransferSnapshot.maximumTransfers - merged.count
        ))
        return merged
    }
}

enum TransferPollBackoff {
    static func delayMilliseconds(consecutiveFailures: Int) -> Int {
        let normalizedFailures = max(consecutiveFailures, 1)
        let exponent = min(normalizedFailures - 1, 3)
        return 1_000 << exponent
    }
}

struct TransferCancellationAuthority: Equatable {
    private(set) var transferID: String?
    private(set) var inFlightGeneration: UInt64?
    private(set) var needsRetry = false
    private var nextGeneration: UInt64 = 0

    var isActive: Bool { transferID != nil }

    mutating func begin(transferID: String, eligible: Bool) -> UInt64? {
        guard eligible,
              self.transferID == nil || self.transferID == transferID,
              inFlightGeneration == nil
        else { return nil }
        self.transferID = transferID
        nextGeneration &+= 1
        inFlightGeneration = nextGeneration
        needsRetry = false
        return nextGeneration
    }

    func owns(transferID: String, generation: UInt64) -> Bool {
        self.transferID == transferID && inFlightGeneration == generation
    }

    mutating func markAmbiguous(transferID: String, generation: UInt64) {
        guard owns(transferID: transferID, generation: generation) else { return }
        inFlightGeneration = nil
        needsRetry = true
    }

    mutating func markRejected(transferID: String, generation: UInt64) {
        guard owns(transferID: transferID, generation: generation) else { return }
        clear()
    }

    mutating func reconcile(
        snapshot: TransferSnapshot,
        application: TransferSessionState.Application
    ) {
        guard let transferID else { return }
        if application == .newInstance {
            clear()
            return
        }
        guard application == .updated else { return }
        if let row = snapshot.transfers.first(where: { $0.transferID == transferID }) {
            if row.phase == .cancelRequested || row.phase.isTerminal {
                clear()
            }
        } else if !snapshot.truncated {
            clear()
        }
    }

    mutating func clear() {
        transferID = nil
        inFlightGeneration = nil
        needsRetry = false
    }
}

struct TransferPollingOwner: Equatable {
    private(set) var generation: UInt64 = 0
    private(set) var isVisible = false
    private(set) var isRequestInProgress = false

    mutating func setVisible(_ visible: Bool) {
        guard isVisible != visible else { return }
        generation &+= 1
        isVisible = visible
        if !visible { isRequestInProgress = false }
    }

    mutating func begin(force: Bool, needsPolling: Bool) -> UInt64? {
        guard isVisible, !isRequestInProgress, force || needsPolling else { return nil }
        generation &+= 1
        isRequestInProgress = true
        return generation
    }

    func owns(_ candidate: UInt64) -> Bool {
        isVisible && isRequestInProgress && generation == candidate
    }

    mutating func finish(_ candidate: UInt64) -> Bool {
        guard owns(candidate) else { return false }
        isRequestInProgress = false
        return true
    }

    mutating func stop() {
        generation &+= 1
        isRequestInProgress = false
    }
}

private struct AnyTransferCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int?

    init(_ stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(stringValue: String) { self.init(stringValue) }
    init?(intValue: Int) { return nil }
}
