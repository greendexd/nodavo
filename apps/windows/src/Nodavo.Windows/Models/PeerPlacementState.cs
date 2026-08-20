namespace Nodavo.Windows.Models;

internal enum PeerPlacement
{
    Disabled,
    Left,
    Right,
    Above,
    Below,
}

internal enum PeerPlacementOperationPhase
{
    Idle,
    MutationInFlight,
    ReconciliationInFlight,
    OutcomeUnknown,
}

internal sealed record PeerPlacementControlState(
    string? PeerId,
    PeerPlacement AuthoritativePlacement,
    PeerPlacement? PendingPlacement,
    bool IsActive,
    PeerPlacementOperationPhase Phase,
    long Generation)
{
    internal static PeerPlacementControlState Initial { get; } = new(
        null,
        PeerPlacement.Disabled,
        null,
        false,
        PeerPlacementOperationPhase.Idle,
        0);
}

internal static class PeerPlacementReducer
{
    internal static PeerPlacementControlState SelectAuthoritativePeer(
        string peerId,
        PeerPlacement placement,
        bool isActive,
        bool outcomeUnknown,
        long generation) =>
        new(
            peerId,
            placement,
            null,
            isActive,
            outcomeUnknown
                ? PeerPlacementOperationPhase.OutcomeUnknown
                : PeerPlacementOperationPhase.Idle,
            generation);

    internal static bool CanMutate(
        PeerPlacementControlState state,
        PeerPlacement proposedPlacement) =>
        state.PeerId is not null &&
        state.IsActive &&
        state.Phase == PeerPlacementOperationPhase.Idle &&
        proposedPlacement != state.AuthoritativePlacement;

    internal static PeerPlacementControlState BeginMutation(
        PeerPlacementControlState state,
        long generation,
        PeerPlacement proposedPlacement) =>
        CanMutate(state, proposedPlacement)
            ? state with
            {
                PendingPlacement = proposedPlacement,
                Phase = PeerPlacementOperationPhase.MutationInFlight,
                Generation = generation,
            }
            : state;

    internal static PeerPlacementControlState ApplyExactAcknowledgement(
        PeerPlacementControlState state,
        long generation,
        string peerId,
        PeerPlacement placement)
    {
        if (generation != state.Generation ||
            state.Phase != PeerPlacementOperationPhase.MutationInFlight ||
            state.PeerId != peerId ||
            state.PendingPlacement != placement)
        {
            return state;
        }

        return state with
        {
            AuthoritativePlacement = placement,
            PendingPlacement = null,
            Phase = PeerPlacementOperationPhase.Idle,
        };
    }

    internal static PeerPlacementControlState MarkAmbiguous(
        PeerPlacementControlState state,
        long generation) =>
        generation == state.Generation &&
        state.Phase == PeerPlacementOperationPhase.MutationInFlight
            ? state with { Phase = PeerPlacementOperationPhase.OutcomeUnknown }
            : state;

    internal static PeerPlacementControlState BeginReconciliation(
        PeerPlacementControlState state,
        long generation) =>
        generation == state.Generation &&
        state.Phase == PeerPlacementOperationPhase.OutcomeUnknown
            ? state with { Phase = PeerPlacementOperationPhase.ReconciliationInFlight }
            : state;

    internal static PeerPlacementControlState ApplyAuthoritativeReconciliation(
        PeerPlacementControlState state,
        long generation,
        string peerId,
        PeerPlacement placement,
        bool isActive)
    {
        if (generation != state.Generation ||
            state.Phase != PeerPlacementOperationPhase.ReconciliationInFlight ||
            state.PeerId != peerId)
        {
            return state;
        }

        return state with
        {
            AuthoritativePlacement = placement,
            PendingPlacement = null,
            IsActive = isActive,
            Phase = PeerPlacementOperationPhase.Idle,
        };
    }

    internal static PeerPlacementControlState FailReconciliation(
        PeerPlacementControlState state,
        long generation) =>
        generation == state.Generation &&
        state.Phase == PeerPlacementOperationPhase.ReconciliationInFlight
            ? state with { Phase = PeerPlacementOperationPhase.OutcomeUnknown }
            : state;
}

internal static class PeerPlacementWire
{
    internal static string Encode(PeerPlacement placement) => placement switch
    {
        PeerPlacement.Disabled => "disabled",
        PeerPlacement.Left => "left",
        PeerPlacement.Right => "right",
        PeerPlacement.Above => "above",
        PeerPlacement.Below => "below",
        _ => throw new InvalidDataException("Invalid peer placement."),
    };

    internal static PeerPlacement Decode(string placement) => placement switch
    {
        "disabled" => PeerPlacement.Disabled,
        "left" => PeerPlacement.Left,
        "right" => PeerPlacement.Right,
        "above" => PeerPlacement.Above,
        "below" => PeerPlacement.Below,
        _ => throw new InvalidDataException("Invalid peer placement."),
    };
}
