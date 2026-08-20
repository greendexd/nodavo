import Foundation

enum PeerPlacementMutationFailureDisposition: Equatable {
    case rejected
    case outcomeUnknown

    static func classify(_ error: Error) -> Self {
        guard let clientError = error as? AgentClientError else {
            return .outcomeUnknown
        }
        switch clientError {
        case let .agent(code, _)
            where code == "peer_not_found" || code == "storage_unavailable":
            return .rejected
        case .unsafePath, .unsafeValue, .requestTooLarge:
            return .rejected
        case .agent, .agentUnavailable, .messageTooLarge, .invalidResponse, .system:
            return .outcomeUnknown
        }
    }
}

struct PeerPlacementMutationOwner {
    private(set) var generation: UInt64 = 0
    private(set) var peerID: String?
    private(set) var requestedPlacement: PeerPlacement?
    private(set) var needsReconciliation = false

    var isActive: Bool { peerID != nil }

    mutating func begin(
        peerID: String,
        currentPlacement: PeerPlacement,
        requestedPlacement: PeerPlacement,
        eligible: Bool
    ) -> UInt64? {
        guard eligible, !isActive, currentPlacement != requestedPlacement else { return nil }
        generation &+= 1
        self.peerID = peerID
        self.requestedPlacement = requestedPlacement
        needsReconciliation = false
        return generation
    }

    func owns(_ candidate: UInt64, peerID candidatePeerID: String) -> Bool {
        isActive && candidate == generation && candidatePeerID == peerID
    }

    mutating func acceptAcknowledgement(
        generation candidate: UInt64,
        peerID candidatePeerID: String,
        placement: PeerPlacement
    ) -> Bool {
        guard owns(candidate, peerID: candidatePeerID),
              placement == requestedPlacement,
              !needsReconciliation
        else { return false }
        clear()
        return true
    }

    mutating func markAmbiguous(
        generation candidate: UInt64,
        peerID candidatePeerID: String
    ) -> Bool {
        guard owns(candidate, peerID: candidatePeerID), !needsReconciliation else { return false }
        needsReconciliation = true
        return true
    }

    mutating func finishReconciliation(
        generation candidate: UInt64,
        peerID candidatePeerID: String
    ) -> Bool {
        guard owns(candidate, peerID: candidatePeerID), needsReconciliation else { return false }
        clear()
        return true
    }

    mutating func reject(
        generation candidate: UInt64,
        peerID candidatePeerID: String
    ) -> Bool {
        guard owns(candidate, peerID: candidatePeerID), !needsReconciliation else { return false }
        clear()
        return true
    }

    private mutating func clear() {
        peerID = nil
        requestedPlacement = nil
        needsReconciliation = false
    }
}
