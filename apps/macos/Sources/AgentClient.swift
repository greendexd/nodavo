import Darwin
import Foundation
import XPC

enum AgentClientError: Error, Sendable {
    case agentUnavailable
    case unsafePath
    case unsafeValue
    case requestTooLarge
    case messageTooLarge
    case invalidResponse
    case agent(code: String, message: String)
    case system(Int32)
}

struct AgentXpcConfiguration: Equatable, Sendable {
    static let expectedServiceName = "dev.nodavo.agent.ipc"
    static let agentIdentifier = "dev.nodavo.agent"

    let serviceName: String
    let teamIdentifier: String

    static func load(infoDictionary: [String: Any]? = Bundle.main.infoDictionary) throws -> Self {
        guard let serviceName = infoDictionary?["NodavoAgentMachService"] as? String,
              serviceName == expectedServiceName,
              let teamIdentifier = infoDictionary?["NodavoAppleTeamIdentifier"] as? String,
              validTeamIdentifier(teamIdentifier)
        else {
            throw AgentClientError.agentUnavailable
        }
        return Self(serviceName: serviceName, teamIdentifier: teamIdentifier)
    }

    var peerCodeSigningRequirement: String {
        "anchor apple generic and identifier \"\(Self.agentIdentifier)\" "
            + "and certificate leaf[subject.OU] = \"\(teamIdentifier)\" "
            + "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
            + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
            + "and entitlement[\"com.apple.application-identifier\"] = "
            + "\"\(teamIdentifier).\(Self.agentIdentifier)\" "
            + "and entitlement[\"com.apple.developer.team-identifier\"] = "
            + "\"\(teamIdentifier)\" "
            + "and entitlement[\"com.apple.security.get-task-allow\"] absent"
    }

    private static func validTeamIdentifier(_ value: String) -> Bool {
        value.utf8.count == 10 && value.utf8.allSatisfy { byte in
            (65 ... 90).contains(byte) || (48 ... 57).contains(byte)
        }
    }
}

private final class XpcReplyWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var result: Result<Data, AgentClientError>?

    func finish(_ candidate: Result<Data, AgentClientError>) {
        lock.lock()
        defer { lock.unlock() }
        guard result == nil else { return }
        result = candidate
        semaphore.signal()
    }

    func wait(seconds: Int) -> Result<Data, AgentClientError>? {
        guard semaphore.wait(timeout: .now() + .seconds(seconds)) == .success else {
            return nil
        }
        lock.lock()
        defer { lock.unlock() }
        return result
    }
}

enum PairingCapability: String, CaseIterable, Hashable, Identifiable, Codable {
    case input
    case clipboardRead = "clipboard_read"
    case clipboardWrite = "clipboard_write"
    case files

    var id: String { rawValue }
}

struct AgentCommand: Encodable {
    let command: String
    let endpoint: String?
    let pairingID: String?
    let accepted: Bool?
    let peerID: String?
    let capability: String?
    let enabled: Bool?
    let placement: PeerPlacement?
    let capabilities: [String]?
    let paths: [String]?
    let ttlMs: UInt32?
    let offerID: String?
    let transferID: String?

    enum CodingKeys: String, CodingKey {
        case command
        case endpoint
        case pairingID = "pairing_id"
        case accepted
        case peerID = "peer_id"
        case capability
        case enabled
        case placement
        case capabilities
        case paths
        case ttlMs = "ttl_ms"
        case offerID = "offer_id"
        case transferID = "transfer_id"
    }

    init(
        command: String,
        endpoint: String? = nil,
        pairingID: String? = nil,
        accepted: Bool? = nil,
        peerID: String? = nil,
        capability: String? = nil,
        enabled: Bool? = nil,
        placement: PeerPlacement? = nil,
        capabilities: [String]? = nil,
        paths: [String]? = nil,
        ttlMs: UInt32? = nil,
        offerID: String? = nil,
        transferID: String? = nil
    ) {
        self.command = command
        self.endpoint = endpoint
        self.pairingID = pairingID
        self.accepted = accepted
        self.peerID = peerID
        self.capability = capability
        self.enabled = enabled
        self.placement = placement
        self.capabilities = capabilities
        self.paths = paths
        self.ttlMs = ttlMs
        self.offerID = offerID
        self.transferID = transferID
    }

    static func simple(_ command: String) -> Self {
        Self(command: command)
    }

    static func updateDecision(offerID: String, accepted: Bool) -> Self {
        Self(command: "decide_update", accepted: accepted, offerID: offerID)
    }
}

struct AgentPeerResponse: Decodable {
    let peerID: String
    let displayName: String
    let state: TrustedPeerState
    let localGrants: [PairingCapability]
    let placement: PeerPlacement

    enum CodingKeys: String, CodingKey, CaseIterable {
        case peerID = "peer_id"
        case displayName = "display_name"
        case state
        case localGrants = "local_grants"
        case placement
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        guard Set(container.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue))
        else {
            throw AgentClientError.invalidResponse
        }
        peerID = try container.decode(String.self, forKey: AnyCodingKey("peer_id"))
        displayName = try container.decode(String.self, forKey: AnyCodingKey("display_name"))
        state = try container.decode(TrustedPeerState.self, forKey: AnyCodingKey("state"))
        localGrants = try container.decode(
            [PairingCapability].self,
            forKey: AnyCodingKey("local_grants")
        )
        placement = try container.decode(PeerPlacement.self, forKey: AnyCodingKey("placement"))
    }
}

struct AgentResponse: Decodable {
    let event: String
    let phase: String?
    let connectedPeer: String?
    let inputOwner: String?
    let focusState: String?
    let pairingID: String?
    let peerName: String?
    let code: String?
    let paired: Bool?
    let peerID: String?
    let capability: PairingCapability?
    let enabled: Bool?
    let placement: PeerPlacement?
    let peers: [AgentPeerResponse]?
    let message: String?
    let offerID: String?
    let version: String?
    let receivedBytes: UInt64?
    let totalBytes: UInt64?
    let failure: String?
    let readiness: AgentReadiness?

    enum CodingKeys: String, CodingKey {
        case event
        case phase
        case connectedPeer = "connected_peer"
        case inputOwner = "input_owner"
        case focusState = "focus_state"
        case pairingID = "pairing_id"
        case peerName = "peer_name"
        case code
        case paired
        case peerID = "peer_id"
        case capability
        case enabled
        case placement
        case peers
        case message
        case offerID = "offer_id"
        case version
        case receivedBytes = "received_bytes"
        case totalBytes = "total_bytes"
        case failure
        case readiness
    }
}

struct AgentStatusResponse {
    let phase: String
    let connectedPeer: String?
    let inputOwner: String
    let focusState: String
    let readiness: AgentReadiness
}

private struct AgentStatusEnvelope: Decodable {
    let event: String
    let phase: String
    let connectedPeer: String?
    let inputOwner: String
    let focusState: String
    let readiness: AgentReadiness

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case event
        case phase
        case connectedPeer = "connected_peer"
        case inputOwner = "input_owner"
        case focusState = "focus_state"
        case readiness
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        guard Set(container.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue))
        else {
            throw AgentClientError.invalidResponse
        }
        event = try container.decode(String.self, forKey: AnyCodingKey("event"))
        phase = try container.decode(String.self, forKey: AnyCodingKey("phase"))
        connectedPeer = try container.decodeIfPresent(
            String.self,
            forKey: AnyCodingKey("connected_peer")
        )
        inputOwner = try container.decode(String.self, forKey: AnyCodingKey("input_owner"))
        focusState = try container.decode(String.self, forKey: AnyCodingKey("focus_state"))
        readiness = try container.decode(AgentReadiness.self, forKey: AnyCodingKey("readiness"))
    }
}

private struct AgentErrorEnvelope: Decodable {
    let event: String
    let code: String
    let message: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case event
        case code
        case message
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        guard Set(container.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue))
        else {
            throw AgentClientError.invalidResponse
        }
        event = try container.decode(String.self, forKey: AnyCodingKey("event"))
        code = try container.decode(String.self, forKey: AnyCodingKey("code"))
        message = try container.decode(String.self, forKey: AnyCodingKey("message"))
    }
}

enum AccessibilityReadiness: String, CaseIterable, Decodable {
    case granted
    case actionRequired = "action_required"
    case notApplicable = "not_applicable"
    case unavailable
}

enum InputReadiness: String, CaseIterable, Decodable {
    case ready
    case blockedByPermission = "blocked_by_permission"
    case blockedByDesktop = "blocked_by_desktop"
    case unavailable
}

enum LocalTopologyReadiness: String, CaseIterable, Decodable {
    case available
    case unavailable
}

enum SessionTopologyReadiness: String, CaseIterable, Decodable {
    case notConnected = "not_connected"
    case synchronizing
    case ready
}

struct AgentReadiness: Equatable, Decodable {
    let accessibility: AccessibilityReadiness
    let input: InputReadiness
    let localTopology: LocalTopologyReadiness
    let sessionTopology: SessionTopologyReadiness

    enum CodingKeys: String, CodingKey, CaseIterable {
        case accessibility
        case input
        case localTopology = "local_topology"
        case sessionTopology = "session_topology"
    }

    init(
        accessibility: AccessibilityReadiness,
        input: InputReadiness,
        localTopology: LocalTopologyReadiness,
        sessionTopology: SessionTopologyReadiness
    ) {
        self.accessibility = accessibility
        self.input = input
        self.localTopology = localTopology
        self.sessionTopology = sessionTopology
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        guard Set(container.allKeys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "Unexpected readiness fields")
            )
        }
        accessibility = try container.decode(
            AccessibilityReadiness.self,
            forKey: AnyCodingKey("accessibility")
        )
        input = try container.decode(InputReadiness.self, forKey: AnyCodingKey("input"))
        localTopology = try container.decode(
            LocalTopologyReadiness.self,
            forKey: AnyCodingKey("local_topology")
        )
        sessionTopology = try container.decode(
            SessionTopologyReadiness.self,
            forKey: AnyCodingKey("session_topology")
        )
    }

    static let unavailable = Self(
        accessibility: .unavailable,
        input: .unavailable,
        localTopology: .unavailable,
        sessionTopology: .notConnected
    )
}

private struct AnyCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int?

    init(_ stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(stringValue: String) {
        self.init(stringValue)
    }

    init?(intValue: Int) {
        return nil
    }
}

struct PairingPrompt: Equatable {
    let pairingID: String
    let peerName: String
    let code: String
}

enum TrustedPeerState: String, Decodable {
    case active
    case revoked
}

enum PeerPlacement: String, CaseIterable, Hashable, Identifiable, Codable {
    case disabled
    case left
    case right
    case above
    case below

    var id: String { rawValue }
}

struct TrustedPeerSummary: Identifiable, Equatable {
    let peerID: String
    let displayName: String
    var state: TrustedPeerState
    var localGrants: Set<PairingCapability>
    var placement: PeerPlacement

    var id: String { peerID }

    var redactedID: String {
        String(peerID.prefix(8)) + "…"
    }
}

private struct TrustedPeersResponse: Decodable {
    let peers: [AgentPeerResponse]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case event
        case peers
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        guard Set(container.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)),
              try container.decode(String.self, forKey: AnyCodingKey("event")) == "trusted_peers"
        else {
            throw AgentClientError.invalidResponse
        }
        peers = try container.decode([AgentPeerResponse].self, forKey: AnyCodingKey("peers"))
    }
}

private struct PeerPlacementChangedResponse: Decodable {
    let peerID: String
    let placement: PeerPlacement

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case event
        case peerID = "peer_id"
        case placement
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        guard Set(container.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)),
              try container.decode(String.self, forKey: AnyCodingKey("event"))
                == "peer_placement_changed"
        else {
            throw AgentClientError.invalidResponse
        }
        peerID = try container.decode(String.self, forKey: AnyCodingKey("peer_id"))
        placement = try container.decode(PeerPlacement.self, forKey: AnyCodingKey("placement"))
    }
}

struct QueuedTransferReference: Equatable {
    let transferID: String

    var redactedID: String {
        "••••••••-" + transferID.suffix(8)
    }
}

private struct TransferAdmissionResponse: Decodable {
    let transferID: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case event
        case transferID = "transfer_id"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)
        guard Set(container.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue)),
              try container.decode(String.self, forKey: AnyCodingKey("event")) == "transfer_queued"
        else {
            throw AgentClientError.invalidResponse
        }
        let transferID = try container.decode(String.self, forKey: AnyCodingKey("transfer_id"))
        guard TransferSummary.isCanonicalNonNilUUID(transferID) else {
            throw AgentClientError.invalidResponse
        }
        self.transferID = transferID
    }
}

enum UpdatePhase: String, CaseIterable, Equatable {
    case idle
    case checking
    case upToDate = "up_to_date"
    case offerAvailable = "offer_available"
    case consentRecorded = "consent_recorded"
    case downloading
    case downloadPaused = "download_paused"
    case verifiedStaged = "verified_staged"
    case declined
    case unavailable
    case failed

    var acceptsPositiveDecision: Bool {
        self == .offerAvailable || self == .downloadPaused
    }

    var acceptsDecline: Bool {
        self == .offerAvailable
    }

    var requiresAutomaticPolling: Bool {
        self == .consentRecorded || self == .downloading
    }
}

enum UpdateFailureCode: String, CaseIterable, Equatable {
    case notConfigured = "not_configured"
    case busy
    case manifestRejected = "manifest_rejected"
    case network
    case staging
    case verification
    case `internal`
}

struct UpdateStatusSnapshot: Equatable {
    let phase: UpdatePhase
    let offerID: String?
    let version: String?
    let receivedBytes: UInt64?
    let totalBytes: UInt64?
    let failure: UpdateFailureCode?

    static let idle = Self(
        phase: .idle,
        offerID: nil,
        version: nil,
        receivedBytes: nil,
        totalBytes: nil,
        failure: nil
    )
}

enum AgentResponseDecoder {
    static let maximumTrustedPeers = 32
    static let maximumPeerIDBytes = 128
    static let maximumDisplayNameBytes = 256
    static let maximumUpdateVersionBytes = 128
    static let maximumUpdateArtifactBytes: UInt64 = 16 * 1024 * 1024 * 1024
    private static let allowedAgentErrorCodes: Set<String> = [
        "busy",
        "invalid_endpoint",
        "discovery_unavailable",
        "pairing_timed_out",
        "reconnect_failed",
        "pairing_not_found",
        "already_confirmed",
        "peer_not_found",
        "storage_unavailable",
        "grant_epoch_exhausted",
        "receive_destination_unavailable",
        "placement_apply_failed",
        "pairing_failed",
        "not_connected",
        "focus_rejected",
        "safety_recovery_failed",
        "transfer_failed",
        "transfer_not_found",
        "transfer_not_cancellable",
        "unsupported_platform",
        "readiness_unavailable",
        "update_not_configured",
        "update_busy",
        "update_offer_mismatch",
        "update_invalid_transition",
        "update_internal",
    ]

    static func validateStrictJSON(_ payload: Data) throws {
        do {
            try StrictJSONDuplicateKeyValidator.validate(payload)
        } catch {
            throw AgentClientError.invalidResponse
        }
    }

    static func transferAdmission(_ payload: Data) throws -> QueuedTransferReference {
        do {
            try validateStrictJSON(payload)
            let response = try JSONDecoder().decode(TransferAdmissionResponse.self, from: payload)
            return QueuedTransferReference(transferID: response.transferID)
        } catch let error as AgentClientError {
            throw error
        } catch {
            throw AgentClientError.invalidResponse
        }
    }

    static func transferSnapshot(_ payload: Data) throws -> TransferSnapshot {
        do {
            try validateStrictJSON(payload)
            return try JSONDecoder().decode(TransferSnapshot.self, from: payload)
        } catch let error as AgentClientError {
            throw error
        } catch {
            throw AgentClientError.invalidResponse
        }
    }

    static func trustedPeers(_ payload: Data) throws -> [TrustedPeerSummary] {
        do {
            try StrictJSONDuplicateKeyValidator.validate(payload)
            let response = try JSONDecoder().decode(TrustedPeersResponse.self, from: payload)
            return try trustedPeers(response.peers)
        } catch let error as AgentClientError {
            throw error
        } catch {
            throw AgentClientError.invalidResponse
        }
    }

    static func peerPlacementAcknowledgement(
        _ payload: Data,
        peerID: String,
        placement: PeerPlacement
    ) throws {
        do {
            try StrictJSONDuplicateKeyValidator.validate(payload)
            let response = try JSONDecoder().decode(PeerPlacementChangedResponse.self, from: payload)
            guard response.peerID == peerID, response.placement == placement else {
                throw AgentClientError.invalidResponse
            }
        } catch let error as AgentClientError {
            throw error
        } catch {
            throw AgentClientError.invalidResponse
        }
    }

    private static func trustedPeers(_ peers: [AgentPeerResponse]) throws -> [TrustedPeerSummary] {
        guard peers.count <= maximumTrustedPeers,
              Set(peers.map(\.peerID)).count == peers.count
        else {
            throw AgentClientError.invalidResponse
        }
        return try peers.map { peer in
            guard !peer.peerID.isEmpty,
                  peer.peerID.utf8.count <= maximumPeerIDBytes,
                  !containsControlCharacter(peer.peerID),
                  !peer.displayName.isEmpty,
                  peer.displayName.utf8.count <= maximumDisplayNameBytes,
                  !containsControlCharacter(peer.displayName),
                  peer.localGrants.count <= PairingCapability.allCases.count,
                  Set(peer.localGrants).count == peer.localGrants.count
            else {
                throw AgentClientError.invalidResponse
            }
            return TrustedPeerSummary(
                peerID: peer.peerID,
                displayName: peer.displayName,
                state: peer.state,
                localGrants: Set(peer.localGrants),
                placement: peer.placement
            )
        }
    }

    static func status(_ payload: Data) throws -> AgentStatusResponse {
        let response: AgentStatusEnvelope
        do {
            try validateStrictJSON(payload)
            response = try JSONDecoder().decode(AgentStatusEnvelope.self, from: payload)
        } catch let error as AgentClientError {
            throw error
        } catch {
            throw AgentClientError.invalidResponse
        }
        let validPhases = ["starting", "ready", "pairing", "connected", "stopping"]
        let validFocusStates = ["local", "controlling_peer", "controlled_by_peer"]
        guard response.event == "status",
              validPhases.contains(response.phase),
              response.inputOwner == "local" || response.inputOwner == "remote",
              validFocusStates.contains(response.focusState),
              response.connectedPeer?.isEmpty != true,
              response.connectedPeer?.utf8.count ?? 0 <= 256,
              response.connectedPeer.map(containsControlCharacter) != true
        else {
            throw AgentClientError.invalidResponse
        }
        return AgentStatusResponse(
            phase: response.phase,
            connectedPeer: response.connectedPeer,
            inputOwner: response.inputOwner,
            focusState: response.focusState,
            readiness: response.readiness
        )
    }

    static func agentError(_ payload: Data) throws -> AgentClientError? {
        do {
            try validateStrictJSON(payload)
            let discriminator = try JSONDecoder().decode(AgentResponse.self, from: payload)
            guard discriminator.event == "error" else { return nil }
            let response = try JSONDecoder().decode(AgentErrorEnvelope.self, from: payload)
            guard response.event == "error",
                  allowedAgentErrorCodes.contains(response.code),
                  !response.code.isEmpty,
                  response.code.utf8.count <= 128,
                  response.code == response.code.trimmingCharacters(in: .whitespacesAndNewlines),
                  !containsControlCharacter(response.code),
                  !response.message.isEmpty,
                  response.message.utf8.count <= 1_024,
                  response.message == response.message.trimmingCharacters(in: .whitespacesAndNewlines),
                  !containsControlCharacter(response.message)
            else {
                throw AgentClientError.invalidResponse
            }
            return AgentClientError.agent(code: response.code, message: response.message)
        } catch let error as AgentClientError {
            throw error
        } catch {
            throw AgentClientError.invalidResponse
        }
    }

    static func updateStatus(_ response: AgentResponse) throws -> UpdateStatusSnapshot {
        guard response.event == "update_status",
              let phaseText = response.phase,
              let phase = UpdatePhase(rawValue: phaseText)
        else {
            throw AgentClientError.invalidResponse
        }

        let offerID = try response.offerID.map(validateCanonicalOfferID)
        let version = try response.version.map(validateSemanticVersion)
        let failure = try response.failure.map { value in
            guard let code = UpdateFailureCode(rawValue: value) else {
                throw AgentClientError.invalidResponse
            }
            return code
        }

        guard validUpdateShape(
            phase: phase,
            offerID: offerID,
            version: version,
            received: response.receivedBytes,
            total: response.totalBytes,
            failure: failure
        ) else {
            throw AgentClientError.invalidResponse
        }

        return UpdateStatusSnapshot(
            phase: phase,
            offerID: offerID,
            version: version,
            receivedBytes: response.receivedBytes,
            totalBytes: response.totalBytes,
            failure: failure
        )
    }

    static func validateCanonicalOfferID(_ value: String) throws -> String {
        guard value.utf8.count == 36,
              let parsed = UUID(uuidString: value),
              parsed.uuidString.lowercased() == value
        else {
            throw AgentClientError.invalidResponse
        }
        return value
    }

    private static func validateSemanticVersion(_ value: String) throws -> String {
        guard isSemanticVersion(value) else {
            throw AgentClientError.invalidResponse
        }
        return value
    }

    private static func validUpdateShape(
        phase: UpdatePhase,
        offerID: String?,
        version: String?,
        received: UInt64?,
        total: UInt64?,
        failure: UpdateFailureCode?
    ) -> Bool {
        switch phase {
        case .idle, .checking, .upToDate, .declined:
            offerID == nil
                && version == nil
                && received == nil
                && total == nil
                && failure == nil
        case .offerAvailable, .consentRecorded:
            offerID != nil
                && version != nil
                && received == nil
                && validTotal(total)
                && failure == nil
        case .downloading, .downloadPaused:
            offerID != nil
                && version != nil
                && validProgress(received: received, total: total, mustBeComplete: false)
                && failure == nil
        case .verifiedStaged:
            offerID != nil
                && version != nil
                && validProgress(received: received, total: total, mustBeComplete: true)
                && failure == nil
        case .unavailable, .failed:
            offerID == nil
                && version == nil
                && received == nil
                && total == nil
                && failure != nil
        }
    }

    private static func validTotal(_ total: UInt64?) -> Bool {
        guard let total else { return false }
        return total > 0 && total <= maximumUpdateArtifactBytes
    }

    private static func validProgress(
        received: UInt64?,
        total: UInt64?,
        mustBeComplete: Bool
    ) -> Bool {
        guard let received, let total, validTotal(total), received <= total else {
            return false
        }
        return !mustBeComplete || received == total
    }

    private static func isSemanticVersion(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.utf8.count <= maximumUpdateVersionBytes,
              value.unicodeScalars.allSatisfy(\.isASCII)
        else {
            return false
        }

        let buildSplit = value.split(separator: "+", omittingEmptySubsequences: false)
        guard buildSplit.count <= 2,
              buildSplit.last.map({ validIdentifiers($0, rejectLeadingZeroNumbers: false) }) != false
        else {
            return false
        }

        let precedence = buildSplit[0]
        let prereleaseSplit = precedence.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        guard prereleaseSplit.count <= 2,
              prereleaseSplit.last.map({ part in
                  prereleaseSplit.count == 1 || validIdentifiers(part, rejectLeadingZeroNumbers: true)
              }) != false
        else {
            return false
        }

        let core = prereleaseSplit[0].split(separator: ".", omittingEmptySubsequences: false)
        return core.count == 3 && core.allSatisfy(validCoreNumber)
    }

    private static func validCoreNumber(_ value: Substring) -> Bool {
        !value.isEmpty
            && value.allSatisfy { $0.isASCII && $0.isNumber }
            && (value == "0" || value.first != "0")
    }

    private static func validIdentifiers(
        _ value: Substring,
        rejectLeadingZeroNumbers: Bool
    ) -> Bool {
        let identifiers = value.split(separator: ".", omittingEmptySubsequences: false)
        return !identifiers.isEmpty && identifiers.allSatisfy { identifier in
            guard !identifier.isEmpty,
                  identifier.allSatisfy({ character in
                      character.isASCII && (character.isLetter || character.isNumber || character == "-")
                  })
            else {
                return false
            }
            return !rejectLeadingZeroNumbers
                || !identifier.allSatisfy(\.isNumber)
                || identifier == "0"
                || identifier.first != "0"
        }
    }
}

actor AgentClient {
    private static let maximumMessageSize = 64 * 1024
    // Existing non-transfer commands retain their current bounded ceiling.
    // Admission, transfer polling, and cancellation override it below.
    private static let defaultReplyDeadlineSeconds = 360
    private static let statusReplyDeadlineSeconds = 8
    private static let emergencyReplyDeadlineSeconds = 25
    private static let trustedPeersReplyDeadlineSeconds = 15
    private static let placementReplyDeadlineSeconds = 15
    private let maximumEndpointBytes = 512
    static let maximumSelectedPaths = 32
    static let maximumSelectedPathBytes = 4 * 1024

    func status() throws -> AgentStatusResponse {
        try requestStatus(
            AgentCommand.simple("get_status"),
            deadlineSeconds: Self.statusReplyDeadlineSeconds
        )
    }

    func requestAccessibilityPermission() throws -> AgentStatusResponse {
        try requestStatus(
            AgentCommand.simple("request_accessibility_permission"),
            deadlineSeconds: Self.statusReplyDeadlineSeconds
        )
    }

    func emergencyStop() throws -> AgentStatusResponse {
        try requestStatus(
            AgentCommand.simple("emergency_stop"),
            deadlineSeconds: Self.emergencyReplyDeadlineSeconds
        )
    }

    func requestRemoteFocus() throws -> AgentStatusResponse {
        try requestStatus(
            AgentCommand(
                command: "request_remote_focus",
                ttlMs: FocusCommandContract.acquireLeaseMilliseconds
            ),
            deadlineSeconds: FocusCommandContract.mutationDeadlineSeconds
        )
    }

    func releaseFocus() throws -> AgentStatusResponse {
        try requestStatus(
            AgentCommand.simple("release_focus"),
            deadlineSeconds: FocusCommandContract.mutationDeadlineSeconds
        )
    }

    func focusStatus() throws -> AgentStatusResponse {
        try requestStatus(
            AgentCommand.simple("get_status"),
            deadlineSeconds: FocusCommandContract.reconciliationDeadlineSeconds
        )
    }

    func beginPairing(
        endpoint: String,
        capabilities: [PairingCapability]
    ) throws -> PairingPrompt {
        guard !endpoint.isEmpty,
              endpoint.utf8.count <= maximumEndpointBytes,
              !endpoint.contains(where: \Character.isNewline),
              capabilities.count <= PairingCapability.allCases.count,
              Set(capabilities).count == capabilities.count
        else {
            throw AgentClientError.unsafeValue
        }
        let response = try request(AgentCommand(
            command: "begin_pairing",
            endpoint: endpoint,
            capabilities: capabilities.map(\.rawValue).sorted()
        ))
        guard response.event == "pairing_code",
              let pairingID = response.pairingID,
              let peerName = response.peerName,
              let code = response.code,
              pairingID.utf8.count <= 128,
              !pairingID.isEmpty,
              peerName.utf8.count <= 256,
              !peerName.isEmpty,
              !containsControlCharacter(peerName),
              code.count == 6,
              code.allSatisfy(\.isNumber)
        else {
            throw AgentClientError.invalidResponse
        }
        return PairingPrompt(pairingID: pairingID, peerName: peerName, code: code)
    }

    func confirmPairing(pairingID: String, accepted: Bool) throws -> Bool {
        guard !pairingID.isEmpty, pairingID.utf8.count <= 128 else {
            throw AgentClientError.unsafeValue
        }
        let response = try request(AgentCommand(
            command: "confirm_pairing",
            pairingID: pairingID,
            accepted: accepted
        ))
        guard response.event == "pairing_finished", response.pairingID == pairingID,
              let paired = response.paired
        else {
            throw AgentClientError.invalidResponse
        }
        return paired
    }

    func listTrustedPeers() throws -> [TrustedPeerSummary] {
        let payload = try requestData(
            AgentCommand.simple("list_trusted_peers"),
            deadlineSeconds: Self.trustedPeersReplyDeadlineSeconds
        )
        try AgentResponseDecoder.validateStrictJSON(payload)
        try throwAgentErrorIfPresent(payload)
        return try AgentResponseDecoder.trustedPeers(payload)
    }

    func setCapability(
        peerID: String,
        capability: PairingCapability,
        enabled: Bool
    ) throws {
        try validatePeerID(peerID)
        let response = try request(AgentCommand(
            command: "set_capability",
            peerID: peerID,
            capability: capability.rawValue,
            enabled: enabled
        ))
        guard response.event == "capability_changed",
              response.peerID == peerID,
              response.capability == capability,
              response.enabled == enabled
        else {
            throw AgentClientError.invalidResponse
        }
    }

    func setPeerPlacement(peerID: String, placement: PeerPlacement) throws {
        try validatePeerID(peerID)
        let payload = try requestData(
            AgentCommand(
                command: "set_peer_placement",
                peerID: peerID,
                placement: placement
            ),
            deadlineSeconds: Self.placementReplyDeadlineSeconds
        )
        try AgentResponseDecoder.validateStrictJSON(payload)
        try throwAgentErrorIfPresent(payload)
        try AgentResponseDecoder.peerPlacementAcknowledgement(
            payload,
            peerID: peerID,
            placement: placement
        )
    }

    func revokePeer(peerID: String) throws -> AgentStatusResponse {
        try validatePeerID(peerID)
        return try requestStatus(
            AgentCommand(command: "revoke_peer", peerID: peerID),
            deadlineSeconds: Self.defaultReplyDeadlineSeconds
        )
    }

    func sendFiles(paths: [String]) throws -> QueuedTransferReference {
        try Self.validateSelectedPaths(paths)
        let payload = try requestData(
            AgentCommand(command: "send_files", paths: paths),
            deadlineSeconds: TransferCommandDeadline.admissionSeconds
        )
        try AgentResponseDecoder.validateStrictJSON(payload)
        try throwAgentErrorIfPresent(payload)
        return try AgentResponseDecoder.transferAdmission(payload)
    }

    func listTransfers() throws -> TransferSnapshot {
        let payload = try requestData(
            AgentCommand.simple("list_transfers"),
            deadlineSeconds: TransferCommandDeadline.statusSeconds
        )
        try AgentResponseDecoder.validateStrictJSON(payload)
        try throwAgentErrorIfPresent(payload)
        return try AgentResponseDecoder.transferSnapshot(payload)
    }

    func cancelTransfer(transferID: String) throws -> TransferSnapshot {
        guard TransferSummary.isCanonicalNonNilUUID(transferID) else {
            throw AgentClientError.unsafeValue
        }
        let payload = try requestData(
            AgentCommand(command: "cancel_transfer", transferID: transferID),
            deadlineSeconds: TransferCommandDeadline.statusSeconds
        )
        try AgentResponseDecoder.validateStrictJSON(payload)
        try throwAgentErrorIfPresent(payload)
        return try AgentResponseDecoder.transferSnapshot(payload)
    }

    func updateStatus() throws -> UpdateStatusSnapshot {
        try AgentResponseDecoder.updateStatus(
            request(AgentCommand.simple("get_update_status"))
        )
    }

    func checkForUpdate() throws -> UpdateStatusSnapshot {
        try AgentResponseDecoder.updateStatus(
            request(AgentCommand.simple("check_for_update"))
        )
    }

    func decideUpdate(offerID: String, accepted: Bool) throws -> UpdateStatusSnapshot {
        let canonicalOfferID = try AgentResponseDecoder.validateCanonicalOfferID(offerID)
        let status = try AgentResponseDecoder.updateStatus(
            request(AgentCommand.updateDecision(
                offerID: canonicalOfferID,
                accepted: accepted
            ))
        )
        if let returnedOfferID = status.offerID, returnedOfferID != canonicalOfferID {
            throw AgentClientError.invalidResponse
        }
        return status
    }

    static func validateSelectedPaths(_ paths: [String]) throws {
        guard !paths.isEmpty, paths.count <= maximumSelectedPaths else {
            throw AgentClientError.unsafeValue
        }
        for path in paths {
            guard !path.isEmpty,
                  path.utf8.count <= maximumSelectedPathBytes,
                  !path.utf8.contains(0),
                  NSString(string: path).isAbsolutePath
            else {
                throw AgentClientError.unsafeValue
            }
        }
    }

    private func requestStatus(
        _ command: AgentCommand,
        deadlineSeconds: Int
    ) throws -> AgentStatusResponse {
        let payload = try requestData(command, deadlineSeconds: deadlineSeconds)
        try AgentResponseDecoder.validateStrictJSON(payload)
        try throwAgentErrorIfPresent(payload)
        return try AgentResponseDecoder.status(payload)
    }

    private func validatePeerID(_ peerID: String) throws {
        guard !peerID.isEmpty,
              peerID.utf8.count <= AgentResponseDecoder.maximumPeerIDBytes,
              !containsControlCharacter(peerID)
        else {
            throw AgentClientError.unsafeValue
        }
    }

    private func request(_ command: AgentCommand) throws -> AgentResponse {
        let response = try requestData(command, deadlineSeconds: Self.defaultReplyDeadlineSeconds)
        try AgentResponseDecoder.validateStrictJSON(response)
        try throwAgentErrorIfPresent(response)
        let decoded = try JSONDecoder().decode(AgentResponse.self, from: response)
        return decoded
    }

    private func requestData(_ command: AgentCommand, deadlineSeconds: Int) throws -> Data {
        let payload = try JSONEncoder().encode(command)
        guard !payload.isEmpty, payload.count <= Self.maximumMessageSize else {
            throw AgentClientError.requestTooLarge
        }

        #if NODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC
        return try requestOverDevelopmentSocket(payload, deadlineSeconds: deadlineSeconds)
        #else
        return try requestOverSignedXpc(payload, deadlineSeconds: deadlineSeconds)
        #endif
    }

    private func throwAgentErrorIfPresent(_ payload: Data) throws {
        if let error = try AgentResponseDecoder.agentError(payload) {
            throw error
        }
    }

    #if !NODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC
    private func requestOverSignedXpc(_ payload: Data, deadlineSeconds: Int) throws -> Data {
        let configuration = try AgentXpcConfiguration.load()
        let connection = xpc_connection_create_mach_service(
            configuration.serviceName,
            nil,
            0
        )
        let requirementStatus = xpc_connection_set_peer_code_signing_requirement(
            connection,
            configuration.peerCodeSigningRequirement
        )
        guard requirementStatus == 0 else {
            // XPC requires every created connection to be activated before its
            // final reference is released, including fail-closed setup paths.
            xpc_connection_set_event_handler(connection) { _ in }
            xpc_connection_activate(connection)
            xpc_connection_cancel(connection)
            throw AgentClientError.agentUnavailable
        }

        let waiter = XpcReplyWaiter()
        xpc_connection_set_event_handler(connection) { event in
            if xpc_get_type(event) == XPC_TYPE_ERROR {
                waiter.finish(.failure(.agentUnavailable))
            }
        }
        xpc_connection_activate(connection)
        defer { xpc_connection_cancel(connection) }

        let message = xpc_dictionary_create(nil, nil, 0)
        payload.withUnsafeBytes { bytes in
            xpc_dictionary_set_data(message, "frame", bytes.baseAddress, bytes.count)
        }
        xpc_connection_send_message_with_reply(connection, message, nil) { reply in
            waiter.finish(Self.decodeXpcReply(reply))
        }

        guard let result = waiter.wait(seconds: deadlineSeconds) else {
            throw AgentClientError.agentUnavailable
        }
        return try result.get()
    }

    private nonisolated static func decodeXpcReply(
        _ reply: xpc_object_t
    ) -> Result<Data, AgentClientError> {
        guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY,
              xpc_dictionary_get_count(reply) == 1
        else {
            return .failure(.agentUnavailable)
        }
        var length = 0
        guard let bytes = xpc_dictionary_get_data(reply, "frame", &length), length > 0 else {
            return .failure(.invalidResponse)
        }
        guard length <= maximumMessageSize else { return .failure(.messageTooLarge) }
        return .success(Data(bytes: bytes, count: length))
    }
    #else
    private func requestOverDevelopmentSocket(_ payload: Data, deadlineSeconds: Int) throws -> Data {
        let socketPath = try defaultSocketPath()
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw AgentClientError.system(errno)
        }
        defer { close(descriptor) }
        try Self.setCloseOnExec(descriptor)
        var timeout = timeval(tv_sec: deadlineSeconds, tv_usec: 0)
        guard setsockopt(
            descriptor,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        ) == 0,
        setsockopt(
            descriptor,
            SOL_SOCKET,
            SO_SNDTIMEO,
            &timeout,
            socklen_t(MemoryLayout<timeval>.size)
        ) == 0 else {
            throw AgentClientError.system(errno)
        }

        do {
            try connect(descriptor: descriptor, path: socketPath)
        } catch AgentClientError.system(let code) where code == ENOENT || code == ECONNREFUSED {
            throw AgentClientError.agentUnavailable
        }

        var length = UInt32(payload.count).bigEndian
        try withUnsafeBytes(of: &length) { try writeAll(descriptor, bytes: $0) }
        try payload.withUnsafeBytes { try writeAll(descriptor, bytes: $0) }

        var responseLength: UInt32 = 0
        try withUnsafeMutableBytes(of: &responseLength) { try readAll(descriptor, bytes: $0) }
        let count = Int(UInt32(bigEndian: responseLength))
        guard count > 0, count <= Self.maximumMessageSize else {
            throw AgentClientError.messageTooLarge
        }
        var response = Data(count: count)
        try response.withUnsafeMutableBytes { try readAll(descriptor, bytes: $0) }
        return response
    }

    private func defaultSocketPath() throws -> String {
        Self.socketPath()
    }

    static func socketPath(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> String {
        #if NODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC
        if let override = environment["NODAVO_IPC_PATH"], !override.isEmpty {
            return override
        }
        #endif
        return homeDirectory
            .appending(path: "Library/Application Support/Nodavo/agent.sock")
            .path
    }

    static func setCloseOnExec(_ descriptor: Int32) throws {
        let flags = Darwin.fcntl(descriptor, F_GETFD)
        guard flags >= 0 else {
            throw AgentClientError.system(errno)
        }
        guard Darwin.fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0 else {
            throw AgentClientError.system(errno)
        }
    }

    private func connect(descriptor: Int32, path: String) throws {
        let pathBytes = Array(path.utf8CString)
        var address = sockaddr_un()
        guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw AgentClientError.unsafePath
        }
        address.sun_family = sa_family_t(AF_UNIX)

        // SAFETY: sun_path is a fixed-size C character array. The UTF-8 string
        // includes one trailing NUL, was size-checked above, and the address is
        // used only for the duration of this synchronous connect call.
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.initializeMemory(as: UInt8.self, repeating: 0)
            destination.copyBytes(from: pathBytes.map(UInt8.init(bitPattern:)))
        }

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                Darwin.connect(
                    descriptor,
                    socketAddress,
                    socklen_t(MemoryLayout<sockaddr_un>.size)
                )
            }
        }
        guard result == 0 else {
            throw AgentClientError.system(errno)
        }
    }

    private func writeAll(_ descriptor: Int32, bytes: UnsafeRawBufferPointer) throws {
        var offset = 0
        while offset < bytes.count {
            let written = Darwin.write(
                descriptor,
                bytes.baseAddress?.advanced(by: offset),
                bytes.count - offset
            )
            if written < 0, errno == EINTR { continue }
            guard written > 0 else { throw AgentClientError.system(errno) }
            offset += written
        }
    }

    private func readAll(_ descriptor: Int32, bytes: UnsafeMutableRawBufferPointer) throws {
        var offset = 0
        while offset < bytes.count {
            let readCount = Darwin.read(
                descriptor,
                bytes.baseAddress?.advanced(by: offset),
                bytes.count - offset
            )
            if readCount < 0, errno == EINTR { continue }
            guard readCount > 0 else { throw AgentClientError.agentUnavailable }
            offset += readCount
        }
    }
    #endif
}

private func containsControlCharacter(_ value: String) -> Bool {
    value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
}
