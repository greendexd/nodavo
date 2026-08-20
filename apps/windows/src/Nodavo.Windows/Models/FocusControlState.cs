namespace Nodavo.Windows.Models;

internal enum FocusAuthority
{
    Unknown,
    Local,
    ControllingPeer,
    ControlledByPeer,
}

internal enum FocusOperationPhase
{
    Idle,
    AcquireInFlight,
    AcquireLeaseWindow,
    AcquireReconciliation,
    ReleaseInFlight,
    ReleaseReconciliation,
    EmergencyInFlight,
    StatusReconciliation,
    OutcomeUnknown,
}

internal enum FocusNotice
{
    None,
    Rejected,
    StatusUnavailable,
}

internal sealed record FocusActionContext(
    bool HasConnectedPeer,
    bool IsConnectedPhase,
    bool IsInputReady,
    bool IsLocalTopologyAvailable,
    bool IsSessionTopologyReady)
{
    internal static FocusActionContext Unavailable { get; } = new(false, false, false, false, false);
}

internal sealed record FocusControlState(
    FocusAuthority Authority,
    FocusOperationPhase Phase,
    FocusNotice Notice,
    long Generation,
    FocusActionContext Context)
{
    internal static FocusControlState Initial { get; } = new(
        FocusAuthority.Unknown,
        FocusOperationPhase.Idle,
        FocusNotice.StatusUnavailable,
        0,
        FocusActionContext.Unavailable);
}

internal static class FocusControlReducer
{
    // This is the complete fixed lease requested by the Windows shell. A local
    // acquisition response or an ambiguous response remains locked for this
    // whole window before one status-only reconciliation is admitted.
    internal const int AcquireLeaseMilliseconds = 5_000;

    internal static bool CanAcquire(FocusControlState state) =>
        state.Phase == FocusOperationPhase.Idle &&
        state.Authority == FocusAuthority.Local &&
        state.Context.HasConnectedPeer &&
        state.Context.IsConnectedPhase &&
        state.Context.IsInputReady &&
        state.Context.IsLocalTopologyAvailable &&
        state.Context.IsSessionTopologyReady;

    // Returning input is a safety action. Once an exact status says focus is
    // nonlocal, readiness/topology guards must not prevent an explicit release.
    internal static bool CanRelease(FocusControlState state) =>
        state.Phase == FocusOperationPhase.Idle &&
        state.Authority is FocusAuthority.ControllingPeer or FocusAuthority.ControlledByPeer;

    internal static bool IsProgressVisible(FocusControlState state) => state.Phase is
        FocusOperationPhase.AcquireInFlight or
        FocusOperationPhase.AcquireLeaseWindow or
        FocusOperationPhase.AcquireReconciliation or
        FocusOperationPhase.ReleaseInFlight or
        FocusOperationPhase.ReleaseReconciliation or
        FocusOperationPhase.EmergencyInFlight or
        FocusOperationPhase.StatusReconciliation;

    internal static FocusControlState BeginStatusRefresh(FocusControlState state, long generation)
    {
        if (state.Phase is not FocusOperationPhase.Idle and not FocusOperationPhase.OutcomeUnknown)
        {
            return state;
        }

        return state with
        {
            Phase = state.Phase == FocusOperationPhase.OutcomeUnknown
                ? FocusOperationPhase.StatusReconciliation
                : FocusOperationPhase.Idle,
            Notice = FocusNotice.None,
            Generation = generation,
        };
    }

    internal static FocusControlState BeginAcquire(FocusControlState state, long generation) =>
        CanAcquire(state)
            ? state with
            {
                Phase = FocusOperationPhase.AcquireInFlight,
                Notice = FocusNotice.None,
                Generation = generation,
            }
            : state;

    internal static FocusControlState BeginRelease(FocusControlState state, long generation) =>
        CanRelease(state)
            ? state with
            {
                Phase = FocusOperationPhase.ReleaseInFlight,
                Notice = FocusNotice.None,
                Generation = generation,
            }
            : state;

    // Emergency is deliberately unconditional and replaces the generation of
    // any stale refresh/focus operation without claiming local ownership.
    internal static FocusControlState BeginEmergency(FocusControlState state, long generation) =>
        state with
        {
            Phase = FocusOperationPhase.EmergencyInFlight,
            Notice = FocusNotice.None,
            Generation = generation,
        };

    internal static FocusControlState ApplyMutationStatus(
        FocusControlState state,
        long generation,
        FocusAuthority authority,
        FocusActionContext context)
    {
        if (generation != state.Generation)
        {
            return state;
        }

        return state.Phase switch
        {
            FocusOperationPhase.AcquireInFlight when authority == FocusAuthority.Local =>
                state with
                {
                    Authority = authority,
                    Context = context,
                    Phase = FocusOperationPhase.AcquireLeaseWindow,
                    Notice = FocusNotice.None,
                },
            FocusOperationPhase.AcquireInFlight => IdleWithStatus(state, authority, context),
            FocusOperationPhase.ReleaseInFlight when authority == FocusAuthority.Local =>
                IdleWithStatus(state, authority, context),
            FocusOperationPhase.ReleaseInFlight => state with
            {
                Authority = authority,
                Context = context,
                Phase = FocusOperationPhase.ReleaseReconciliation,
                Notice = FocusNotice.None,
            },
            FocusOperationPhase.EmergencyInFlight => IdleWithStatus(state, authority, context),
            _ => state,
        };
    }

    internal static FocusControlState ApplyReconciledStatus(
        FocusControlState state,
        long generation,
        FocusAuthority authority,
        FocusActionContext context)
    {
        if (generation != state.Generation || state.Phase is not (
            FocusOperationPhase.AcquireReconciliation or
            FocusOperationPhase.ReleaseReconciliation or
            FocusOperationPhase.StatusReconciliation))
        {
            return state;
        }

        return IdleWithStatus(state, authority, context);
    }

    internal static FocusControlState ApplyOrdinaryStatus(
        FocusControlState state,
        long generation,
        FocusAuthority authority,
        FocusActionContext context)
    {
        if (generation != state.Generation || state.Phase != FocusOperationPhase.Idle)
        {
            return state;
        }

        return IdleWithStatus(state, authority, context);
    }

    internal static FocusControlState MarkAmbiguousMutation(
        FocusControlState state,
        long generation)
    {
        if (generation != state.Generation)
        {
            return state;
        }

        return state.Phase switch
        {
            FocusOperationPhase.AcquireInFlight => state with
            {
                Phase = FocusOperationPhase.AcquireLeaseWindow,
                Notice = FocusNotice.None,
            },
            FocusOperationPhase.ReleaseInFlight => state with
            {
                Phase = FocusOperationPhase.ReleaseReconciliation,
                Notice = FocusNotice.None,
            },
            FocusOperationPhase.EmergencyInFlight => UnknownOutcome(state),
            _ => state,
        };
    }

    internal static FocusControlState MarkAcquireLeaseWindowElapsed(
        FocusControlState state,
        long generation) =>
        generation == state.Generation && state.Phase == FocusOperationPhase.AcquireLeaseWindow
            ? state with { Phase = FocusOperationPhase.AcquireReconciliation }
            : state;

    internal static FocusControlState RejectMutation(
        FocusControlState state,
        long generation) =>
        generation == state.Generation && state.Phase is (
            FocusOperationPhase.AcquireInFlight or FocusOperationPhase.ReleaseInFlight)
            ? state with
            {
                Phase = FocusOperationPhase.Idle,
                Notice = FocusNotice.Rejected,
            }
            : state;

    internal static FocusControlState FailStatus(FocusControlState state, long generation)
    {
        if (generation != state.Generation)
        {
            return state;
        }

        return state.Phase == FocusOperationPhase.StatusReconciliation
            ? UnknownOutcome(state)
            : state with
            {
                Authority = FocusAuthority.Unknown,
                Phase = FocusOperationPhase.Idle,
                Notice = FocusNotice.StatusUnavailable,
                Context = FocusActionContext.Unavailable,
            };
    }

    internal static FocusControlState FailReconciliation(
        FocusControlState state,
        long generation) =>
        generation == state.Generation && state.Phase is (
            FocusOperationPhase.AcquireLeaseWindow or
            FocusOperationPhase.AcquireReconciliation or
            FocusOperationPhase.ReleaseReconciliation or
            FocusOperationPhase.StatusReconciliation)
            ? UnknownOutcome(state)
            : state;

    private static FocusControlState IdleWithStatus(
        FocusControlState state,
        FocusAuthority authority,
        FocusActionContext context) => state with
        {
            Authority = authority,
            Phase = FocusOperationPhase.Idle,
            Notice = FocusNotice.None,
            Context = context,
        };

    private static FocusControlState UnknownOutcome(FocusControlState state) => state with
    {
        Authority = FocusAuthority.Unknown,
        Phase = FocusOperationPhase.OutcomeUnknown,
        Notice = FocusNotice.None,
        Context = FocusActionContext.Unavailable,
    };
}
