namespace Nodavo.Windows.Models;

internal sealed record AgentStatusSnapshot(
    string Phase,
    string? ConnectedPeer,
    string InputOwner);

internal sealed record PairingCodeSnapshot(
    string PairingId,
    string PeerName,
    string Code);

internal sealed record PairingResultSnapshot(
    string PairingId,
    bool Paired);
