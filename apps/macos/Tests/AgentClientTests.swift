import Foundation
import Testing
@testable import NodavoMac

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
