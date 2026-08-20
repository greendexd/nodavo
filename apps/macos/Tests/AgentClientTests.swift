import Foundation
import Darwin
import Security
import Testing
@testable import NodavoMac

#if NODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC
@Test func localSocketDescriptorIsClosedAcrossExec() throws {
    let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
    #expect(descriptor >= 0)
    defer { close(descriptor) }

    try AgentClient.setCloseOnExec(descriptor)

    let flags = Darwin.fcntl(descriptor, F_GETFD)
    #expect(flags >= 0)
    #expect(flags & FD_CLOEXEC == FD_CLOEXEC)
}
#endif

@Test func releaseXpcConfigurationBindsExactAgentIdentity() throws {
    #if !NODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC
    let configuration = try AgentXpcConfiguration.load(infoDictionary: [
        "NodavoAgentMachService": "dev.nodavo.agent.ipc",
        "NodavoAppleTeamIdentifier": "ABCDE12345",
    ])
    #expect(configuration.serviceName == "dev.nodavo.agent.ipc")
    #expect(configuration.peerCodeSigningRequirement.contains("identifier \"dev.nodavo.agent\""))
    #expect(configuration.peerCodeSigningRequirement.contains("ABCDE12345.dev.nodavo.agent"))
    #expect(configuration.peerCodeSigningRequirement.contains("get-task-allow\"] absent"))

    var requirement: SecRequirement?
    let status = SecRequirementCreateWithString(
        configuration.peerCodeSigningRequirement as CFString,
        SecCSFlags(),
        &requirement
    )
    #expect(status == errSecSuccess)
    #expect(requirement != nil)
    #endif
}

@Test func releaseXpcConfigurationRejectsWrongServiceOrTeam() {
    #if !NODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC
    #expect(throws: AgentClientError.self) {
        try AgentXpcConfiguration.load(infoDictionary: [
            "NodavoAgentMachService": "dev.attacker.agent.ipc",
            "NodavoAppleTeamIdentifier": "ABCDE12345",
        ])
    }
    #expect(throws: AgentClientError.self) {
        try AgentXpcConfiguration.load(infoDictionary: [
            "NodavoAgentMachService": "dev.nodavo.agent.ipc",
            "NodavoAppleTeamIdentifier": "DEVELOPMENT",
        ])
    }
    #endif
}

@Test func trustedPeerDecoderAcceptsBoundedPublicSummary() throws {
    let data = Data(#"""
    {
        "event":"trusted_peers",
        "peers":[{
            "peer_id":"0123456789abcdef",
            "display_name":"Office Mac",
            "state":"active",
            "local_grants":["input","files"],
            "placement":"right"
        }]
    }
    """#.utf8)

    let peers = try AgentResponseDecoder.trustedPeers(data)

    #expect(peers.count == 1)
    #expect(peers[0].displayName == "Office Mac")
    #expect(peers[0].state == .active)
    #expect(peers[0].localGrants == [.input, .files])
    #expect(peers[0].placement == .right)
    #expect(peers[0].redactedID == "01234567…")
}

@Test func trustedPeerDecoderRejectsMoreThanThirtyTwoSummaries() throws {
    let peer = [
        "peer_id": "0123456789abcdef",
        "display_name": "Peer",
        "state": "active",
        "local_grants": [],
        "placement": "disabled",
    ] as [String: Any]
    let payload: [String: Any] = [
        "event": "trusted_peers",
        "peers": Array(repeating: peer, count: 33),
    ]
    let data = try JSONSerialization.data(withJSONObject: payload)

    #expect(throws: AgentClientError.self) {
        try AgentResponseDecoder.trustedPeers(data)
    }
}

@Test func trustedPeerDecoderRejectsDuplicateGrants() throws {
    let data = Data(#"""
    {
        "event":"trusted_peers",
        "peers":[{
            "peer_id":"0123456789abcdef",
            "display_name":"Peer",
            "state":"active",
            "local_grants":["files","files"],
            "placement":"disabled"
        }]
    }
    """#.utf8)
    #expect(throws: AgentClientError.self) {
        try AgentResponseDecoder.trustedPeers(data)
    }
}

@Test func trustedPeerDecoderRejectsDuplicateIdentifiers() throws {
    let peer: [String: Any] = [
        "peer_id": "0123456789abcdef",
        "display_name": "Peer",
        "state": "active",
        "local_grants": [],
        "placement": "left",
    ]
    let data = try JSONSerialization.data(withJSONObject: [
            "event": "trusted_peers",
            "peers": [peer, peer],
        ])

    #expect(throws: AgentClientError.self) {
        try AgentResponseDecoder.trustedPeers(data)
    }
}

@Test func trustedPeerDecoderRequiresExactPlacementAndObjectShapes() throws {
    for placement in PeerPlacement.allCases {
        let data = Data(#"{"event":"trusted_peers","peers":[{"peer_id":"peer","display_name":"Peer","state":"active","local_grants":[],"placement":"\#(placement.rawValue)"}]}"#.utf8)
        #expect(try AgentResponseDecoder.trustedPeers(data).first?.placement == placement)
    }

    for invalid in [
        #"{"event":"trusted_peers","peers":[{"peer_id":"peer","display_name":"Peer","state":"active","local_grants":[]}]}"#,
        #"{"event":"trusted_peers","peers":[{"peer_id":"peer","display_name":"Peer","state":"active","local_grants":[],"placement":"diagonal"}]}"#,
        #"{"event":"trusted_peers","peers":[{"peer_id":"peer","display_name":"Peer","state":"active","local_grants":[],"placement":"left","display_id":7}]}"#,
        #"{"event":"trusted_peers","peers":[],"revision":1}"#,
        #"{"event":"trusted_peers","peers":[{"peer_id":"peer","display_name":"Peer","state":"active","local_grants":[],"placement":"left","placement":"right"}]}"#,
        #"{"event":"trusted_peers","peers":[{"peer_id":"peer","display_name":"Peer","state":"active","local_grants":[],"placement":"left","place\u006dent":"right"}]}"#,
    ] {
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.trustedPeers(Data(invalid.utf8))
        }
    }
}

@Test func peerPlacementCommandAndAcknowledgementAreExact() throws {
    let command = AgentCommand(
        command: "set_peer_placement",
        peerID: "peer-1",
        placement: .above
    )
    let object = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(command)) as? [String: Any]
    )
    #expect(object.count == 3)
    #expect(object["command"] as? String == "set_peer_placement")
    #expect(object["peer_id"] as? String == "peer-1")
    #expect(object["placement"] as? String == "above")

    let valid = Data(
        #"{"event":"peer_placement_changed","peer_id":"peer-1","placement":"above"}"#.utf8
    )
    try AgentResponseDecoder.peerPlacementAcknowledgement(
        valid,
        peerID: "peer-1",
        placement: .above
    )

    for invalid in [
        #"{"event":"peer_placement_changed","peer_id":"peer-2","placement":"above"}"#,
        #"{"event":"peer_placement_changed","peer_id":"peer-1","placement":"below"}"#,
        #"{"event":"peer_placement_changed","peer_id":"peer-1"}"#,
        #"{"event":"peer_placement_changed","peer_id":"peer-1","placement":"diagonal"}"#,
        #"{"event":"peer_placement_changed","peer_id":"peer-1","placement":"above","session_id":"private"}"#,
        #"{"event":"peer_placement_changed","peer_id":"peer-1","placement":"above","placement":"below"}"#,
    ] {
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.peerPlacementAcknowledgement(
                Data(invalid.utf8),
                peerID: "peer-1",
                placement: .above
            )
        }
    }
}

@Test func placementMutationWaitsForExactAckOrAuthoritativeReconciliation() throws {
    var owner = PeerPlacementMutationOwner()
    let revokedCandidate = owner.begin(
        peerID: "revoked-peer",
        currentPlacement: .disabled,
        requestedPlacement: .left,
        eligible: false
    )
    #expect(revokedCandidate == nil)
    let unchangedCandidate = owner.begin(
        peerID: "peer-1",
        currentPlacement: .right,
        requestedPlacement: .right,
        eligible: true
    )
    #expect(unchangedCandidate == nil)
    let firstCandidate = owner.begin(
        peerID: "peer-1",
        currentPlacement: .disabled,
        requestedPlacement: .right,
        eligible: true
    )
    let first = try #require(firstCandidate)
    let busyCandidate = owner.begin(
        peerID: "peer-2",
        currentPlacement: .disabled,
        requestedPlacement: .above,
        eligible: true
    )
    #expect(busyCandidate == nil)
    let wrongPeerAccepted = owner.acceptAcknowledgement(
        generation: first,
        peerID: "peer-2",
        placement: .right
    )
    #expect(!wrongPeerAccepted)
    let wrongPlacementAccepted = owner.acceptAcknowledgement(
        generation: first,
        peerID: "peer-1",
        placement: .left
    )
    #expect(!wrongPlacementAccepted)
    #expect(owner.isActive)
    let markedAmbiguous = owner.markAmbiguous(generation: first, peerID: "peer-1")
    #expect(markedAmbiguous)
    let duplicateAmbiguity = owner.markAmbiguous(generation: first, peerID: "peer-1")
    #expect(!duplicateAmbiguity)
    let lateAcknowledgementAccepted = owner.acceptAcknowledgement(
        generation: first,
        peerID: "peer-1",
        placement: .right
    )
    #expect(!lateAcknowledgementAccepted)
    let reconciled = owner.finishReconciliation(generation: first, peerID: "peer-1")
    #expect(reconciled)
    #expect(!owner.isActive)

    let secondCandidate = owner.begin(
        peerID: "peer-1",
        currentPlacement: .left,
        requestedPlacement: .below,
        eligible: true
    )
    let second = try #require(secondCandidate)
    #expect(second != first)
    let staleReconciliation = owner.finishReconciliation(generation: first, peerID: "peer-1")
    #expect(!staleReconciliation)
    let exactAcknowledgement = owner.acceptAcknowledgement(
        generation: second,
        peerID: "peer-1",
        placement: .below
    )
    #expect(exactAcknowledgement)
}

@Test func placementMutationClassifiesOnlyDefiniteRejectionAsRetryableByUser() {
    #expect(
        PeerPlacementMutationFailureDisposition.classify(
            AgentClientError.agent(code: "peer_not_found", message: "missing")
        ) == .rejected
    )
    #expect(
        PeerPlacementMutationFailureDisposition.classify(
            AgentClientError.agent(code: "storage_unavailable", message: "not persisted")
        ) == .rejected
    )
    #expect(
        PeerPlacementMutationFailureDisposition.classify(
            AgentClientError.agent(code: "placement_apply_failed", message: "persisted")
        ) == .outcomeUnknown
    )
    #expect(
        PeerPlacementMutationFailureDisposition.classify(
            AgentClientError.agent(code: "unexpected", message: "unknown")
        ) == .outcomeUnknown
    )
    #expect(
        PeerPlacementMutationFailureDisposition.classify(AgentClientError.unsafeValue)
            == .rejected
    )
    #expect(
        PeerPlacementMutationFailureDisposition.classify(AgentClientError.invalidResponse)
            == .outcomeUnknown
    )
    #expect(
        PeerPlacementMutationFailureDisposition.classify(AgentClientError.agentUnavailable)
            == .outcomeUnknown
    )
}

@Test func focusReducerOwnsOneBoundedGenerationAndNeverAdmitsRepeatClicks() {
    let ready = FocusActionContext(
        hasConnectedPeer: true,
        isConnectedPhase: true,
        isInputReady: true,
        isLocalTopologyAvailable: true,
        isSessionTopologyReady: true
    )
    var state = FocusControlState(
        authority: .local,
        phase: .idle,
        notice: .none,
        generation: 7,
        context: ready
    )
    #expect(FocusControlReducer.canAcquire(state))

    for blocked in [
        FocusActionContext(
            hasConnectedPeer: false,
            isConnectedPhase: true,
            isInputReady: true,
            isLocalTopologyAvailable: true,
            isSessionTopologyReady: true
        ),
        FocusActionContext(
            hasConnectedPeer: true,
            isConnectedPhase: false,
            isInputReady: true,
            isLocalTopologyAvailable: true,
            isSessionTopologyReady: true
        ),
        FocusActionContext(
            hasConnectedPeer: true,
            isConnectedPhase: true,
            isInputReady: false,
            isLocalTopologyAvailable: true,
            isSessionTopologyReady: true
        ),
        FocusActionContext(
            hasConnectedPeer: true,
            isConnectedPhase: true,
            isInputReady: true,
            isLocalTopologyAvailable: false,
            isSessionTopologyReady: true
        ),
        FocusActionContext(
            hasConnectedPeer: true,
            isConnectedPhase: true,
            isInputReady: true,
            isLocalTopologyAvailable: true,
            isSessionTopologyReady: false
        ),
    ] {
        var candidate = state
        candidate.context = blocked
        #expect(!FocusControlReducer.canAcquire(candidate))
    }

    state = FocusControlReducer.beginAcquire(state, generation: 8)
    #expect(state.phase == .acquireInFlight)
    #expect(state.authority == .local)
    #expect(!FocusControlReducer.canAcquire(state))
    let repeated = FocusControlReducer.beginAcquire(state, generation: 9)
    #expect(repeated == state)
    #expect(repeated.generation == 8)
    #expect(FocusControlReducer.expireOperation(state, generation: 7) == state)
    let expired = FocusControlReducer.expireOperation(state, generation: 8)
    #expect(expired.phase == .outcomeUnknown)
    #expect(expired.authority == .unknown)

    state = FocusControlReducer.applyMutationStatus(
        state,
        generation: 8,
        authority: .local,
        context: ready
    )
    #expect(state.phase == .acquireLeaseWindow)
    #expect(FocusControlReducer.isProgressVisible(state))
    #expect(
        FocusControlReducer.markAcquireLeaseWindowElapsed(state, generation: 7) == state
    )
    state = FocusControlReducer.markAcquireLeaseWindowElapsed(state, generation: 8)
    #expect(state.phase == .acquireReconciliation)
    state = FocusControlReducer.applyReconciledStatus(
        state,
        generation: 8,
        authority: .controllingPeer,
        context: ready
    )
    #expect(state.phase == .idle)
    #expect(state.authority == .controllingPeer)
    #expect(FocusControlReducer.canRelease(state))
}

@Test func focusReducerLocksAmbiguityUntilExplicitStatusAndEmergencySupersedesLateReplies() {
    let ready = FocusActionContext(
        hasConnectedPeer: true,
        isConnectedPhase: true,
        isInputReady: true,
        isLocalTopologyAvailable: true,
        isSessionTopologyReady: true
    )
    var state = FocusControlState(
        authority: .local,
        phase: .idle,
        notice: .none,
        generation: 10,
        context: ready
    )
    state = FocusControlReducer.beginAcquire(state, generation: 11)
    state = FocusControlReducer.markAmbiguousMutation(state, generation: 11)
    #expect(state.phase == .acquireLeaseWindow)
    state = FocusControlReducer.failReconciliation(state, generation: 11)
    #expect(state.phase == .outcomeUnknown)
    #expect(state.authority == .unknown)
    #expect(!FocusControlReducer.canAcquire(state))
    #expect(!FocusControlReducer.canRelease(state))

    let repeatedAcquire = FocusControlReducer.beginAcquire(state, generation: 12)
    let repeatedRelease = FocusControlReducer.beginRelease(state, generation: 12)
    #expect(repeatedAcquire == state)
    #expect(repeatedRelease == state)

    state = FocusControlReducer.beginStatusRefresh(state, generation: 12)
    #expect(state.phase == .statusReconciliation)
    state = FocusControlReducer.applyReconciledStatus(
        state,
        generation: 12,
        authority: .local,
        context: ready
    )
    #expect(state.phase == .idle)
    #expect(FocusControlReducer.canAcquire(state))

    state = FocusControlReducer.beginAcquire(state, generation: 13)
    state = FocusControlReducer.beginEmergency(state, generation: 14)
    let stale = FocusControlReducer.applyMutationStatus(
        state,
        generation: 13,
        authority: .controllingPeer,
        context: ready
    )
    #expect(stale == state)
    #expect(stale.phase == .emergencyInFlight)
    state = FocusControlReducer.applyMutationStatus(
        state,
        generation: 14,
        authority: .local,
        context: ready
    )
    #expect(state.phase == .idle)
    #expect(state.authority == .local)

    state.authority = .controlledByPeer
    state.context = .unavailable
    #expect(FocusControlReducer.canRelease(state))
    state = FocusControlReducer.beginRelease(state, generation: 15)
    state = FocusControlReducer.applyMutationStatus(
        state,
        generation: 15,
        authority: .local,
        context: ready
    )
    #expect(state.phase == .idle)
    #expect(state.authority == .local)
}

@Test func focusContractUsesFixedLeaseSeparateDeadlinesAndOnlyExactRejection() throws {
    #expect(FocusCommandContract.acquireLeaseMilliseconds == 5_000)
    #expect(FocusCommandContract.mutationDeadlineSeconds == 15)
    #expect(FocusCommandContract.reconciliationDeadlineSeconds == 8)
    #expect(FocusCommandContract.maximumSequentialOperationSeconds == 28)
    #expect(
        FocusCommandContract.maximumSequentialOperationSeconds
            <= FocusCommandContract.overallOperationDeadlineSeconds
    )

    let acquire = AgentCommand(
        command: "request_remote_focus",
        ttlMs: FocusCommandContract.acquireLeaseMilliseconds
    )
    let acquireObject = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(acquire)) as? [String: Any]
    )
    #expect(acquireObject.count == 2)
    #expect(acquireObject["command"] as? String == "request_remote_focus")
    #expect(acquireObject["ttl_ms"] as? Int == 5_000)

    let releaseObject = try #require(
        JSONSerialization.jsonObject(
            with: JSONEncoder().encode(AgentCommand.simple("release_focus"))
        ) as? [String: Any]
    )
    #expect(releaseObject.count == 1)
    #expect(releaseObject["command"] as? String == "release_focus")

    #expect(
        FocusMutationFailureDisposition.classify(
            AgentClientError.agent(code: "focus_rejected", message: "rejected")
        ) == .rejected
    )
    for ambiguous: AgentClientError in [
        .agent(code: "not_connected", message: "not connected"),
        .agent(code: "unexpected", message: "unexpected"),
        .agentUnavailable,
        .invalidResponse,
        .system(1),
        .unsafeValue,
    ] {
        #expect(FocusMutationFailureDisposition.classify(ambiguous) == .outcomeUnknown)
    }
}

@Test func focusStatusAndAgentErrorDecodersRequireExactDuplicateFreeEnvelopes() throws {
    let validStatus = Data(#"{"event":"status","phase":"connected","connected_peer":"peer","input_owner":"local","focus_state":"local","readiness":{"accessibility":"granted","input":"ready","local_topology":"available","session_topology":"ready"}}"#.utf8)
    let status = try AgentResponseDecoder.status(validStatus)
    #expect(status.phase == "connected")
    #expect(status.connectedPeer == "peer")
    #expect(status.focusState == "local")

    for invalid in [
        #"{"event":"status","phase":"connected","connected_peer":"peer","input_owner":"local","readiness":{"accessibility":"granted","input":"ready","local_topology":"available","session_topology":"ready"}}"#,
        #"{"event":"status","phase":"connected","connected_peer":"peer","input_owner":"local","focus_state":"future","readiness":{"accessibility":"granted","input":"ready","local_topology":"available","session_topology":"ready"}}"#,
        #"{"event":"status","phase":"connected","connected_peer":"peer","input_owner":"local","focus_state":"local","readiness":{"accessibility":"granted","input":"ready","local_topology":"available","session_topology":"ready"},"private":"secret"}"#,
        #"{"event":"status","phase":"connected","connected_peer":"peer","input_owner":"local","focus_state":"local","focus_state":"controlled_by_peer","readiness":{"accessibility":"granted","input":"ready","local_topology":"available","session_topology":"ready"}}"#,
        #"{"event":"status","phase":"connected","connected_peer":"peer","input_owner":"local","focus_state":"local","focus_\u0073tate":"controlled_by_peer","readiness":{"accessibility":"granted","input":"ready","local_topology":"available","session_topology":"ready"}}"#,
    ] {
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.status(Data(invalid.utf8))
        }
    }

    let exactError = Data(
        #"{"event":"error","code":"focus_rejected","message":"focus lease rejected"}"#.utf8
    )
    let candidate = try AgentResponseDecoder.agentError(exactError)
    let decoded = try #require(candidate)
    guard case let AgentClientError.agent(code, _) = decoded else {
        Issue.record("exact error did not decode as an agent error")
        return
    }
    #expect(code == "focus_rejected")

    for malformed in [
        #"{"event":"error","code":"focus_rejected"}"#,
        #"{"event":"error","code":"focus_rejected","message":"rejected","detail":"private"}"#,
        #"{"event":"error","code":"focus_rejected","code":"not_connected","message":"rejected"}"#,
        #"{"event":"error","code":"focus_rejected","c\u006fde":"not_connected","message":"rejected"}"#,
        #"{"event":"error","code":"unknown_error","message":"rejected"}"#,
    ] {
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.agentError(Data(malformed.utf8))
        }
    }
}

@Test func transferReferenceIsValidatedAndImmediatelyRedacted() throws {
    let data = Data(#"""
    {
        "event":"transfer_queued",
        "transfer_id":"123e4567-e89b-12d3-a456-426614174000"
    }
    """#.utf8)
    let reference = try AgentResponseDecoder.transferAdmission(data)
    #expect(reference.transferID == "123e4567-e89b-12d3-a456-426614174000")
    #expect(reference.redactedID == "••••••••-14174000")

    for invalid in [
        #"{"event":"transfer_queued","transfer_id":"123E4567-E89B-12D3-A456-426614174000"}"#,
        #"{"event":"transfer_queued","transfer_id":"00000000-0000-0000-0000-000000000000"}"#,
        #"{"event":"transfer_queued","transfer_id":"123e4567-e89b-12d3-a456-426614174000","path":"/private"}"#,
    ] {
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.transferAdmission(Data(invalid.utf8))
        }
    }
}

@Test func receiveDestinationErrorIsStrictAndHasAContentFreePresentation() throws {
    let payload = Data(
        #"{"event":"error","code":"receive_destination_unavailable","message":"the receive destination is unavailable"}"#.utf8
    )
    let decoded = try #require(try AgentResponseDecoder.agentError(payload))
    #expect(ReceiveDestinationFailurePresentation.matches(decoded))
    #expect(!ReceiveDestinationFailurePresentation.matches(
        AgentClientError.agent(code: "storage_unavailable", message: "unavailable")
    ))
    #expect(!ReceiveDestinationFailurePresentation.matches(AgentClientError.invalidResponse))

    #if NODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC
    #expect(
        ReceiveDestinationFailurePresentation.pairingLocalizationKey
            == "pairing_receive_destination_unavailable_development"
    )
    #expect(
        ReceiveDestinationFailurePresentation.grantLocalizationKey
            == "trusted_devices_receive_destination_unavailable_development"
    )
    #else
    #expect(
        ReceiveDestinationFailurePresentation.pairingLocalizationKey
            == "pairing_receive_destination_unavailable"
    )
    #expect(
        ReceiveDestinationFailurePresentation.grantLocalizationKey
            == "trusted_devices_receive_destination_unavailable"
    )
    #endif
}

@Test func transferAdmissionRejectsRawDuplicateKeysIncludingEscapedAliases() {
    for payload in [
        #"{"event":"transfer_queued","event":"transfer_queued","transfer_id":"123e4567-e89b-12d3-a456-426614174000"}"#,
        #"{"event":"transfer_queued","transfer_id":"123e4567-e89b-12d3-a456-426614174000","transfer_\u0069d":"123e4567-e89b-12d3-a456-426614174000"}"#,
    ] {
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.transferAdmission(Data(payload.utf8))
        }
    }
}

@Test func selectedPathsMustBeAbsoluteAndBounded() throws {
    try AgentClient.validateSelectedPaths(["/Users/example/report.pdf"])

    #expect(throws: AgentClientError.self) {
        try AgentClient.validateSelectedPaths(["relative/report.pdf"])
    }
    #expect(throws: AgentClientError.self) {
        try AgentClient.validateSelectedPaths(
            Array(repeating: "/Users/example/report.pdf", count: 33)
        )
    }
}

@Test func updateOfferDecoderAcceptsCanonicalBoundedMetadata() throws {
    let response = try decodeAgentResponse(#"""
    {
        "event":"update_status",
        "phase":"offer_available",
        "offer_id":"123e4567-e89b-12d3-a456-426614174000",
        "version":"1.2.3-beta.1+build.7",
        "total_bytes":2097152
    }
    """#)

    let status = try AgentResponseDecoder.updateStatus(response)
    #expect(status.phase == .offerAvailable)
    #expect(status.offerID == "123e4567-e89b-12d3-a456-426614174000")
    #expect(status.version == "1.2.3-beta.1+build.7")
    #expect(status.receivedBytes == nil)
    #expect(status.totalBytes == 2_097_152)
    #expect(status.failure == nil)
}

@Test func updateProgressDecoderRequiresConsistentBoundedCounters() throws {
    let valid = try decodeAgentResponse(#"""
    {
        "event":"update_status",
        "phase":"downloading",
        "offer_id":"123e4567-e89b-12d3-a456-426614174000",
        "version":"2.0.0",
        "received_bytes":1048576,
        "total_bytes":2097152
    }
    """#)
    let status = try AgentResponseDecoder.updateStatus(valid)
    #expect(status.receivedBytes == 1_048_576)
    #expect(status.totalBytes == 2_097_152)

    for invalid in [
        #"{"event":"update_status","phase":"downloading","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"2.0.0","received_bytes":1}"#,
        #"{"event":"update_status","phase":"downloading","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"2.0.0","received_bytes":3,"total_bytes":2}"#,
        #"{"event":"update_status","phase":"downloading","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"2.0.0","received_bytes":0,"total_bytes":0}"#,
        #"{"event":"update_status","phase":"offer_available","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"2.0.0","received_bytes":1,"total_bytes":2}"#,
        #"{"event":"update_status","phase":"downloading","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"2.0.0","received_bytes":0,"total_bytes":17179869185}"#,
    ] {
        let response = try decodeAgentResponse(invalid)
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.updateStatus(response)
        }
    }
}

@Test func updateDecoderRejectsNoncanonicalOfferAndMalformedVersion() throws {
    for invalid in [
        #"{"event":"update_status","phase":"offer_available","offer_id":"123E4567-E89B-12D3-A456-426614174000","version":"1.0.0","total_bytes":2}"#,
        #"{"event":"update_status","phase":"offer_available","offer_id":"not-a-uuid","version":"1.0.0","total_bytes":2}"#,
        #"{"event":"update_status","phase":"offer_available","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"01.0.0","total_bytes":2}"#,
        #"{"event":"update_status","phase":"offer_available","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"1.0.0-01","total_bytes":2}"#,
        #"{"event":"update_status","phase":"offer_available","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"1.0","total_bytes":2}"#,
        #"{"event":"update_status","phase":"offer_available","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"1.0.0+","total_bytes":2}"#,
        #"{"event":"update_status","phase":"offer_available","offer_id":"123e4567-e89b-12d3-a456-426614174000","total_bytes":2}"#,
    ] {
        let response = try decodeAgentResponse(invalid)
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.updateStatus(response)
        }
    }
}

@Test func updateDecoderMirrorsEveryPhaseShapeInvariant() throws {
    let validPayloads = [
        #"{"event":"update_status","phase":"idle"}"#,
        #"{"event":"update_status","phase":"checking"}"#,
        #"{"event":"update_status","phase":"up_to_date"}"#,
        #"{"event":"update_status","phase":"declined"}"#,
        #"{"event":"update_status","phase":"consent_recorded","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"1.0.0","total_bytes":8}"#,
        #"{"event":"update_status","phase":"download_paused","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"1.0.0","received_bytes":3,"total_bytes":8}"#,
        #"{"event":"update_status","phase":"verified_staged","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"1.0.0","received_bytes":8,"total_bytes":8}"#,
        #"{"event":"update_status","phase":"unavailable","failure":"not_configured"}"#,
    ]
    for payload in validPayloads {
        _ = try AgentResponseDecoder.updateStatus(decodeAgentResponse(payload))
    }

    let invalidPayloads = [
        #"{"event":"update_status","phase":"idle","version":"1.0.0"}"#,
        #"{"event":"update_status","phase":"declined","offer_id":"123e4567-e89b-12d3-a456-426614174000"}"#,
        #"{"event":"update_status","phase":"offer_available","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"1.0.0"}"#,
        #"{"event":"update_status","phase":"consent_recorded","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"1.0.0","received_bytes":0,"total_bytes":8}"#,
        #"{"event":"update_status","phase":"verified_staged","offer_id":"123e4567-e89b-12d3-a456-426614174000","version":"1.0.0","received_bytes":7,"total_bytes":8}"#,
        #"{"event":"update_status","phase":"unavailable"}"#,
        #"{"event":"update_status","phase":"failed","failure":"internal","version":"1.0.0"}"#,
    ]
    for payload in invalidPayloads {
        let response = try decodeAgentResponse(payload)
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.updateStatus(response)
        }
    }
}

@Test func upToDateIsAnEmptySuccessfulSnapshot() throws {
    let response = try decodeAgentResponse(
        #"{"event":"update_status","phase":"up_to_date"}"#
    )
    let status = try AgentResponseDecoder.updateStatus(response)

    #expect(status.phase == .upToDate)
    #expect(status.offerID == nil)
    #expect(status.version == nil)
    #expect(status.receivedBytes == nil)
    #expect(status.totalBytes == nil)
    #expect(status.failure == nil)

    let invalid = try decodeAgentResponse(
        #"{"event":"update_status","phase":"up_to_date","failure":"internal"}"#
    )
    #expect(throws: AgentClientError.self) {
        try AgentResponseDecoder.updateStatus(invalid)
    }
}

@Test func updateDecoderAllowsOnlyDocumentedPhasesAndFailureCodes() throws {
    let failed = try decodeAgentResponse(#"""
    {
        "event":"update_status",
        "phase":"failed",
        "failure":"verification"
    }
    """#)
    #expect(try AgentResponseDecoder.updateStatus(failed).failure == .verification)

    for invalid in [
        #"{"event":"update_status","phase":"installing"}"#,
        #"{"event":"update_status","phase":"failed","failure":"signature"}"#,
        #"{"event":"update_status","phase":"idle","failure":"network"}"#,
    ] {
        let response = try decodeAgentResponse(invalid)
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.updateStatus(response)
        }
    }
}

@Test func updateDecisionCommandBindsExactOfferAndDecision() throws {
    let command = AgentCommand.updateDecision(
        offerID: "123e4567-e89b-12d3-a456-426614174000",
        accepted: true
    )
    let object = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(command)) as? [String: Any]
    )

    #expect(object["command"] as? String == "decide_update")
    #expect(object["offer_id"] as? String == "123e4567-e89b-12d3-a456-426614174000")
    #expect(object["accepted"] as? Bool == true)
}

@Test func updateReadCommandsUseStableWireNames() throws {
    for expected in ["get_update_status", "check_for_update"] {
        let object = try #require(
            JSONSerialization.jsonObject(
                with: JSONEncoder().encode(AgentCommand.simple(expected))
            ) as? [String: Any]
        )
        #expect(object["command"] as? String == expected)
    }
}

@Test func updateVersionTextHasAHardByteBound() throws {
    let payload: [String: Any] = [
        "event": "update_status",
        "phase": "offer_available",
        "offer_id": "123e4567-e89b-12d3-a456-426614174000",
        "version": String(repeating: "1", count: 129),
        "total_bytes": 8,
    ]
    let response = try JSONDecoder().decode(
        AgentResponse.self,
        from: JSONSerialization.data(withJSONObject: payload)
    )
    #expect(throws: AgentClientError.self) {
        try AgentResponseDecoder.updateStatus(response)
    }
}

@Test func updateDecisionPolicyAllowsResumeButNotPausedDecline() {
    #expect(UpdatePhase.offerAvailable.acceptsPositiveDecision)
    #expect(UpdatePhase.offerAvailable.acceptsDecline)
    #expect(UpdatePhase.downloadPaused.acceptsPositiveDecision)
    #expect(!UpdatePhase.downloadPaused.acceptsDecline)
    #expect(!UpdatePhase.downloading.acceptsPositiveDecision)
    #expect(!UpdatePhase.verifiedStaged.acceptsPositiveDecision)
}

@Test func automaticUpdatePollingHasExactStartAndStopPhases() {
    #expect(UpdatePhase.consentRecorded.requiresAutomaticPolling)
    #expect(UpdatePhase.downloading.requiresAutomaticPolling)
    for phase in UpdatePhase.allCases where
        phase != .consentRecorded && phase != .downloading
    {
        #expect(!phase.requiresAutomaticPolling)
    }
}

@Test func automaticUpdatePollingHasOnlyOneGenerationOwner() throws {
    var owner = UpdatePollingOwner()
    let firstCandidate = owner.begin(for: .consentRecorded)
    let first = try #require(firstCandidate)
    #expect(owner.owns(first))
    let duplicate = owner.begin(for: .downloading)
    #expect(duplicate == nil)

    let firstFinished = owner.finish(first)
    #expect(firstFinished)
    #expect(!owner.owns(first))
    let secondCandidate = owner.begin(for: .downloading)
    let second = try #require(secondCandidate)
    #expect(second != first)
    #expect(owner.owns(second))

    owner.stop()
    #expect(!owner.owns(second))
    #expect(!owner.isActive)
    let stoppedPhase = owner.begin(for: .downloadPaused)
    #expect(stoppedPhase == nil)
}

@Test func readinessDecoderAcceptsEveryKnownEnumValue() throws {
    for accessibility in AccessibilityReadiness.allCases {
        for input in InputReadiness.allCases {
            for localTopology in LocalTopologyReadiness.allCases {
                for sessionTopology in SessionTopologyReadiness.allCases {
                    let response = try readinessStatusResponse(
                        accessibility: accessibility.rawValue,
                        input: input.rawValue,
                        localTopology: localTopology.rawValue,
                        sessionTopology: sessionTopology.rawValue
                    )
                    let status = try AgentResponseDecoder.status(response)
                    #expect(status.readiness.accessibility == accessibility)
                    #expect(status.readiness.input == input)
                    #expect(status.readiness.localTopology == localTopology)
                    #expect(status.readiness.sessionTopology == sessionTopology)
                }
            }
        }
    }
}

@Test func readinessDecoderRejectsMissingMalformedAndUnexpectedFields() throws {
    let invalidPayloads = [
        #"{"event":"status","phase":"ready","input_owner":"local"}"#,
        #"{"event":"status","phase":"ready","input_owner":"local","readiness":null}"#,
        #"{"event":"status","phase":"ready","input_owner":"local","readiness":"granted"}"#,
        #"{"event":"status","phase":"ready","input_owner":"local","readiness":{"accessibility":"unknown","input":"ready","local_topology":"available","session_topology":"ready"}}"#,
        #"{"event":"status","phase":"ready","input_owner":"local","readiness":{"accessibility":"granted","input":"ready","local_topology":"available","session_topology":"ready","pairing_code":"123456"}}"#,
        #"{"event":"status","phase":"ready","input_owner":"local","readiness":{"accessibility":"granted","input":"ready","local_topology":"available"}}"#,
    ]

    for payload in invalidPayloads {
        #expect(throws: AgentClientError.self) {
            try AgentResponseDecoder.status(Data(payload.utf8))
        }
    }
}

@Test func accessibilityPermissionCommandUsesExactWireName() throws {
    let object = try #require(
        JSONSerialization.jsonObject(
            with: JSONEncoder().encode(AgentCommand.simple("request_accessibility_permission"))
        ) as? [String: Any]
    )
    #expect(object.count == 1)
    #expect(object["command"] as? String == "request_accessibility_permission")
}

@Test func accessibilityPromptResponseDoesNotImplyGrantedPermission() throws {
    let response = try readinessStatusResponse(
        accessibility: AccessibilityReadiness.actionRequired.rawValue,
        input: InputReadiness.blockedByPermission.rawValue,
        localTopology: LocalTopologyReadiness.available.rawValue,
        sessionTopology: SessionTopologyReadiness.notConnected.rawValue
    )
    let status = try AgentResponseDecoder.status(response)
    #expect(status.readiness.accessibility == .actionRequired)
    #expect(status.readiness.accessibility != .granted)
    #expect(ReadinessRequestPolicy.allowsAccessibilityPrompt(for: status.readiness))
}

@Test func readinessRequestGenerationKeepsTheNewestResponseOwner() throws {
    var owner = ReadinessRequestOwner()
    let first = owner.begin()
    let second = owner.begin()
    #expect(second != first)
    let staleFinished = owner.finish(first)
    #expect(!staleFinished)
    #expect(owner.isRequestInProgress)
    let latestFinished = owner.finish(second)
    #expect(latestFinished)
    #expect(!owner.isRequestInProgress)
}

@Test func readinessPromptPolicyOnlyAllowsActionRequired() {
    for accessibility in AccessibilityReadiness.allCases {
        let readiness = AgentReadiness(
            accessibility: accessibility,
            input: .ready,
            localTopology: .available,
            sessionTopology: .notConnected
        )
        #expect(
            ReadinessRequestPolicy.allowsAccessibilityPrompt(for: readiness)
                == (accessibility == .actionRequired)
        )
    }
}

@Test func emergencyStatusApplicationReplacesCachedReadinessWithoutInferringGrant() throws {
    let cached = AgentReadiness(
        accessibility: .granted,
        input: .ready,
        localTopology: .available,
        sessionTopology: .ready
    )
    let response = try AgentResponseDecoder.status(readinessStatusResponse(
        accessibility: AccessibilityReadiness.actionRequired.rawValue,
        input: InputReadiness.blockedByPermission.rawValue,
        localTopology: LocalTopologyReadiness.available.rawValue,
        sessionTopology: SessionTopologyReadiness.notConnected.rawValue
    ))

    let applied = AuthoritativeAgentStatus(response)
    #expect(applied.readiness != cached)
    #expect(applied.readiness == response.readiness)
    #expect(applied.readiness.accessibility == .actionRequired)
    #expect(applied.readiness.accessibility != .granted)
    #expect(applied.readiness.sessionTopology == .notConnected)
}

private func readinessStatusResponse(
    accessibility: String,
    input: String,
    localTopology: String,
    sessionTopology: String
) throws -> Data {
    Data("""
    {"event":"status","phase":"ready","connected_peer":null,"input_owner":"local","focus_state":"local","readiness":{"accessibility":"\(accessibility)","input":"\(input)","local_topology":"\(localTopology)","session_topology":"\(sessionTopology)"}}
    """.utf8)
}

private func decodeAgentResponse(_ json: String) throws -> AgentResponse {
    try JSONDecoder().decode(AgentResponse.self, from: Data(json.utf8))
}
