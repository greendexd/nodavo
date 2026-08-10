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
            "local_grants":["input","files"]
        }]
    }
    """#.utf8)

    let response = try JSONDecoder().decode(AgentResponse.self, from: data)
    let peers = try AgentResponseDecoder.trustedPeers(response)

    #expect(peers.count == 1)
    #expect(peers[0].displayName == "Office Mac")
    #expect(peers[0].state == .active)
    #expect(peers[0].localGrants == [.input, .files])
    #expect(peers[0].redactedID == "01234567…")
}

@Test func trustedPeerDecoderRejectsMoreThanThirtyTwoSummaries() throws {
    let peer = [
        "peer_id": "0123456789abcdef",
        "display_name": "Peer",
        "state": "active",
        "local_grants": [],
    ] as [String: Any]
    let payload: [String: Any] = [
        "event": "trusted_peers",
        "peers": Array(repeating: peer, count: 33),
    ]
    let response = try JSONDecoder().decode(
        AgentResponse.self,
        from: JSONSerialization.data(withJSONObject: payload)
    )

    #expect(throws: AgentClientError.self) {
        try AgentResponseDecoder.trustedPeers(response)
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
            "local_grants":["files","files"]
        }]
    }
    """#.utf8)
    let response = try JSONDecoder().decode(AgentResponse.self, from: data)

    #expect(throws: AgentClientError.self) {
        try AgentResponseDecoder.trustedPeers(response)
    }
}

@Test func trustedPeerDecoderRejectsDuplicateIdentifiers() throws {
    let peer: [String: Any] = [
        "peer_id": "0123456789abcdef",
        "display_name": "Peer",
        "state": "active",
        "local_grants": [],
    ]
    let response = try JSONDecoder().decode(
        AgentResponse.self,
        from: JSONSerialization.data(withJSONObject: [
            "event": "trusted_peers",
            "peers": [peer, peer],
        ])
    )

    #expect(throws: AgentClientError.self) {
        try AgentResponseDecoder.trustedPeers(response)
    }
}

@Test func transferReferenceIsValidatedAndImmediatelyRedacted() throws {
    let data = Data(#"""
    {
        "event":"transfer_queued",
        "transfer_id":"123e4567-e89b-12d3-a456-426614174000"
    }
    """#.utf8)
    let response = try JSONDecoder().decode(AgentResponse.self, from: data)

    #expect(
        try AgentResponseDecoder.transferReference(response)
            == QueuedTransferReference(redactedID: "123e4567…")
    )
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

private func decodeAgentResponse(_ json: String) throws -> AgentResponse {
    try JSONDecoder().decode(AgentResponse.self, from: Data(json.utf8))
}
