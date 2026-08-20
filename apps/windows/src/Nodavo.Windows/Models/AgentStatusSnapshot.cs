namespace Nodavo.Windows.Models;

internal sealed record AgentStatusSnapshot(
    string Phase,
    string? ConnectedPeer,
    string InputOwner,
    string FocusState,
    AgentReadinessSnapshot Readiness);

internal sealed record AgentReadinessSnapshot(
    string Accessibility,
    string Input,
    string LocalTopology,
    string SessionTopology);

internal sealed record PairingCodeSnapshot(
    string PairingId,
    string PeerName,
    string Code);

internal sealed record PairingResultSnapshot(
    string PairingId,
    bool Paired);

internal sealed record TrustedPeerSnapshot(
    string PeerId,
    string DisplayName,
    string State,
    IReadOnlySet<string> LocalGrants,
    PeerPlacement Placement)
{
    internal bool HasGrant(string capability) => LocalGrants.Contains(capability);
}

internal sealed record CapabilityChangeSnapshot(
    string PeerId,
    string Capability,
    bool Enabled);

internal sealed record PeerPlacementChangeSnapshot(
    string PeerId,
    PeerPlacement Placement);

internal sealed record TransferQueuedSnapshot(string RedactedTransferId);
