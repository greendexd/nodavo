import Darwin
import Foundation

enum AgentClientError: Error {
    case agentUnavailable
    case unsafePath
    case unsafeValue
    case messageTooLarge
    case invalidResponse
    case agent(code: String, message: String)
    case system(Int32)
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
    let capabilities: [String]?
    let paths: [String]?
    let ttlMs: UInt32?
    let offerID: String?

    enum CodingKeys: String, CodingKey {
        case command
        case endpoint
        case pairingID = "pairing_id"
        case accepted
        case peerID = "peer_id"
        case capability
        case enabled
        case capabilities
        case paths
        case ttlMs = "ttl_ms"
        case offerID = "offer_id"
    }

    init(
        command: String,
        endpoint: String? = nil,
        pairingID: String? = nil,
        accepted: Bool? = nil,
        peerID: String? = nil,
        capability: String? = nil,
        enabled: Bool? = nil,
        capabilities: [String]? = nil,
        paths: [String]? = nil,
        ttlMs: UInt32? = nil,
        offerID: String? = nil
    ) {
        self.command = command
        self.endpoint = endpoint
        self.pairingID = pairingID
        self.accepted = accepted
        self.peerID = peerID
        self.capability = capability
        self.enabled = enabled
        self.capabilities = capabilities
        self.paths = paths
        self.ttlMs = ttlMs
        self.offerID = offerID
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

    enum CodingKeys: String, CodingKey {
        case peerID = "peer_id"
        case displayName = "display_name"
        case state
        case localGrants = "local_grants"
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
    let peers: [AgentPeerResponse]?
    let transferID: String?
    let message: String?
    let offerID: String?
    let version: String?
    let receivedBytes: UInt64?
    let totalBytes: UInt64?
    let failure: String?

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
        case peers
        case transferID = "transfer_id"
        case message
        case offerID = "offer_id"
        case version
        case receivedBytes = "received_bytes"
        case totalBytes = "total_bytes"
        case failure
    }
}

struct AgentStatusResponse {
    let phase: String
    let connectedPeer: String?
    let inputOwner: String
    let focusState: String
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

struct TrustedPeerSummary: Identifiable, Equatable {
    let peerID: String
    let displayName: String
    var state: TrustedPeerState
    var localGrants: Set<PairingCapability>

    var id: String { peerID }

    var redactedID: String {
        String(peerID.prefix(8)) + "…"
    }
}

struct QueuedTransferReference: Equatable {
    let redactedID: String
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

    static func trustedPeers(_ response: AgentResponse) throws -> [TrustedPeerSummary] {
        guard response.event == "trusted_peers", let peers = response.peers,
              peers.count <= maximumTrustedPeers,
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
                localGrants: Set(peer.localGrants)
            )
        }
    }

    static func transferReference(_ response: AgentResponse) throws -> QueuedTransferReference {
        guard response.event == "transfer_queued",
              let transferID = response.transferID,
              transferID.utf8.count == 36,
              UUID(uuidString: transferID) != nil
        else {
            throw AgentClientError.invalidResponse
        }
        return QueuedTransferReference(redactedID: String(transferID.prefix(8)) + "…")
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
    private let maximumMessageSize = 64 * 1024
    private let maximumEndpointBytes = 512
    static let maximumSelectedPaths = 32
    static let maximumSelectedPathBytes = 4 * 1024

    func status() throws -> AgentStatusResponse {
        try decodeStatus(request(AgentCommand.simple("get_status")))
    }

    func emergencyStop() throws -> AgentStatusResponse {
        try decodeStatus(request(AgentCommand.simple("emergency_stop")))
    }

    func requestRemoteFocus(ttlMs: UInt32 = 5_000) throws -> AgentStatusResponse {
        guard (1_000 ... 30_000).contains(ttlMs) else {
            throw AgentClientError.unsafeValue
        }
        return try decodeStatus(request(AgentCommand(
            command: "request_remote_focus",
            ttlMs: ttlMs
        )))
    }

    func releaseFocus() throws -> AgentStatusResponse {
        try decodeStatus(request(AgentCommand.simple("release_focus")))
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
        try AgentResponseDecoder.trustedPeers(request(AgentCommand.simple("list_trusted_peers")))
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

    func revokePeer(peerID: String) throws -> AgentStatusResponse {
        try validatePeerID(peerID)
        return try decodeStatus(request(AgentCommand(command: "revoke_peer", peerID: peerID)))
    }

    func sendFiles(paths: [String]) throws -> QueuedTransferReference {
        try Self.validateSelectedPaths(paths)
        return try AgentResponseDecoder.transferReference(
            request(AgentCommand(command: "send_files", paths: paths))
        )
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

    private func decodeStatus(_ response: AgentResponse) throws -> AgentStatusResponse {
        let validPhases = ["starting", "ready", "pairing", "connected", "stopping"]
        let validFocusStates = ["local", "controlling_peer", "controlled_by_peer"]
        let focusState = response.focusState ?? "local"
        guard response.event == "status",
              let phase = response.phase,
              validPhases.contains(phase),
              let inputOwner = response.inputOwner,
              inputOwner == "local" || inputOwner == "remote",
              validFocusStates.contains(focusState),
              response.connectedPeer?.utf8.count ?? 0 <= 256,
              response.connectedPeer.map(containsControlCharacter) != true
        else {
            throw AgentClientError.invalidResponse
        }
        return AgentStatusResponse(
            phase: phase,
            connectedPeer: response.connectedPeer,
            inputOwner: inputOwner,
            focusState: focusState
        )
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
        let socketPath = try defaultSocketPath()
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw AgentClientError.system(errno)
        }
        defer { close(descriptor) }

        do {
            try connect(descriptor: descriptor, path: socketPath)
        } catch AgentClientError.system(let code) where code == ENOENT || code == ECONNREFUSED {
            throw AgentClientError.agentUnavailable
        }

        let payload = try JSONEncoder().encode(command)
        guard payload.count <= maximumMessageSize else {
            throw AgentClientError.messageTooLarge
        }
        var length = UInt32(payload.count).bigEndian
        try withUnsafeBytes(of: &length) { try writeAll(descriptor, bytes: $0) }
        try payload.withUnsafeBytes { try writeAll(descriptor, bytes: $0) }

        var responseLength: UInt32 = 0
        try withUnsafeMutableBytes(of: &responseLength) { try readAll(descriptor, bytes: $0) }
        let count = Int(UInt32(bigEndian: responseLength))
        guard count <= maximumMessageSize else {
            throw AgentClientError.messageTooLarge
        }
        var response = Data(count: count)
        try response.withUnsafeMutableBytes { try readAll(descriptor, bytes: $0) }
        let decoded = try JSONDecoder().decode(AgentResponse.self, from: response)
        if decoded.event == "error" {
            guard let code = decoded.code,
                  let message = decoded.message,
                  code.utf8.count <= 64,
                  message.utf8.count <= 512
            else {
                throw AgentClientError.invalidResponse
            }
            throw AgentClientError.agent(code: code, message: message)
        }
        return decoded
    }

    private func defaultSocketPath() throws -> String {
        if let override = ProcessInfo.processInfo.environment["NODAVO_IPC_PATH"], !override.isEmpty {
            return override
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appending(path: "Library/Application Support/Nodavo/agent.sock")
            .path
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
}

private func containsControlCharacter(_ value: String) -> Bool {
    value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
}
