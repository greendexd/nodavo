using Nodavo.Windows.Models;
using Nodavo.Windows.Services;

namespace Nodavo.Windows.ViewModels;

internal sealed record TransferRowState(TransferSnapshot Snapshot, long FirstSeenOrder);

internal sealed record TransferPollSchedule(
    bool IsLoaded,
    bool LoopRunning,
    bool ForcedRefreshPending)
{
    internal static TransferPollSchedule Empty { get; } = new(false, false, false);
}

internal static class TransferPollLifecycle
{
    internal static TransferPollSchedule Load(TransferPollSchedule schedule) =>
        schedule with { IsLoaded = true, ForcedRefreshPending = true };

    internal static TransferPollSchedule Unload(TransferPollSchedule schedule) =>
        schedule with { IsLoaded = false, ForcedRefreshPending = false };

    internal static TransferPollSchedule RequestForcedRefresh(TransferPollSchedule schedule) =>
        schedule.IsLoaded ? schedule with { ForcedRefreshPending = true } : schedule;

    internal static TransferPollSchedule TryStart(
        TransferPollSchedule schedule,
        bool hasPollingWork,
        out bool shouldStart)
    {
        shouldStart = schedule.IsLoaded && !schedule.LoopRunning &&
            (schedule.ForcedRefreshPending || hasPollingWork);
        return shouldStart
            ? schedule with { LoopRunning = true, ForcedRefreshPending = false }
            : schedule;
    }

    internal static (TransferPollSchedule Schedule, bool WasPending) TakeForcedRefresh(
        TransferPollSchedule schedule)
    {
        bool wasPending = schedule.IsLoaded && schedule.ForcedRefreshPending;
        return (schedule with { ForcedRefreshPending = false }, wasPending);
    }

    internal static TransferPollSchedule CompleteLoop(TransferPollSchedule schedule) =>
        schedule with { LoopRunning = false };
}

internal sealed record TransfersState(
    long Generation,
    bool IsLoaded,
    string? InstanceId,
    ulong Revision,
    bool Truncated,
    bool IsStale,
    IReadOnlyList<TransferRowState> Rows,
    string? CancelOwnerId,
    bool CancelInFlight,
    bool CancelOutcomeUnknown,
    bool AdmissionReconciliationPending,
    int AdmissionReconciliationAttemptsRemaining)
{
    internal static TransfersState Empty { get; } = new(
        0,
        false,
        null,
        0,
        false,
        false,
        [],
        null,
        false,
        false,
        false,
        0);

    internal bool HasPollingWork =>
        IsLoaded && (Rows.Any(row => !row.Snapshot.IsTerminal) || CancelOwnerId is not null ||
            AdmissionReconciliationPending && AdmissionReconciliationAttemptsRemaining > 0);
}

internal static class TransfersViewModel
{
    internal const int MaximumAdmissionReconciliationAttempts = 5;

    internal static TransfersState Start(TransfersState state) =>
        state with { Generation = state.Generation + 1, IsLoaded = true };

    internal static TransfersState Stop(TransfersState state) =>
        state with
        {
            Generation = state.Generation + 1,
            IsLoaded = false,
            CancelInFlight = false,
        };

    internal static TransfersState ApplySnapshot(
        TransfersState state,
        TransferListSnapshot snapshot,
        long generation)
    {
        if (!state.IsLoaded || state.Generation != generation)
        {
            return state;
        }

        bool replacedInstance = state.InstanceId is not null &&
            !string.Equals(state.InstanceId, snapshot.InstanceId, StringComparison.Ordinal);
        if (!replacedInstance && state.InstanceId is not null && snapshot.Revision < state.Revision)
        {
            return state;
        }
        if (!replacedInstance && state.InstanceId is not null && snapshot.Revision == state.Revision)
        {
            string? equalCancelOwner = state.CancelOwnerId;
            bool equalCancelInFlight = state.CancelInFlight;
            bool equalCancelUnknown = state.CancelOutcomeUnknown;
            if (equalCancelOwner is not null)
            {
                TransferSnapshot? owner = snapshot.Transfers.FirstOrDefault(
                    transfer => transfer.TransferId == equalCancelOwner);
                if (owner is null && !snapshot.Truncated ||
                    owner is not null &&
                    (owner.IsTerminal || owner.Phase == TransferPhase.CancelRequested))
                {
                    equalCancelOwner = null;
                    equalCancelUnknown = false;
                }
            }
            return state with
            {
                Truncated = snapshot.Truncated,
                IsStale = false,
                CancelOwnerId = equalCancelOwner,
                CancelInFlight = equalCancelInFlight,
                CancelOutcomeUnknown = equalCancelUnknown,
                AdmissionReconciliationPending = false,
                AdmissionReconciliationAttemptsRemaining = 0,
            };
        }

        IReadOnlyList<TransferRowState> previous = replacedInstance ? [] : state.Rows;
        long nextOrder = previous.Count == 0 ? 0 : previous.Max(row => row.FirstSeenOrder) + 1;
        var previousById = previous.ToDictionary(row => row.Snapshot.TransferId, StringComparer.Ordinal);
        var merged = new List<TransferRowState>(TransferSnapshotDecoder.MaximumTransfers);
        var incomingIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (TransferSnapshot transfer in snapshot.Transfers)
        {
            incomingIds.Add(transfer.TransferId);
            long order = previousById.TryGetValue(transfer.TransferId, out TransferRowState? old)
                ? old.FirstSeenOrder
                : nextOrder++;
            merged.Add(new TransferRowState(transfer, order));
        }

        if (!replacedInstance)
        {
            foreach (TransferRowState recent in previous
                .Where(row =>
                    !incomingIds.Contains(row.Snapshot.TransferId) &&
                    (snapshot.Truncated || row.Snapshot.IsTerminal))
                .OrderBy(row => row.FirstSeenOrder))
            {
                if (merged.Count == TransferSnapshotDecoder.MaximumTransfers)
                {
                    break;
                }
                merged.Add(recent);
            }
        }
        merged.Sort((left, right) => left.FirstSeenOrder.CompareTo(right.FirstSeenOrder));

        string? cancelOwner = replacedInstance ? null : state.CancelOwnerId;
        bool cancelInFlight = replacedInstance ? false : state.CancelInFlight;
        bool cancelUnknown = replacedInstance ? false : state.CancelOutcomeUnknown;
        if (cancelOwner is not null)
        {
            TransferSnapshot? owner = merged
                .Select(row => row.Snapshot)
                .FirstOrDefault(transfer => transfer.TransferId == cancelOwner);
            if (owner is null && !snapshot.Truncated ||
                owner is not null && (owner.IsTerminal || owner.Phase == TransferPhase.CancelRequested))
            {
                cancelOwner = null;
                cancelInFlight = false;
                cancelUnknown = false;
            }
        }

        return state with
        {
            InstanceId = snapshot.InstanceId,
            Revision = snapshot.Revision,
            Truncated = snapshot.Truncated,
            IsStale = false,
            Rows = merged,
            CancelOwnerId = cancelOwner,
            CancelInFlight = cancelInFlight,
            CancelOutcomeUnknown = cancelUnknown,
            AdmissionReconciliationPending = false,
            AdmissionReconciliationAttemptsRemaining = 0,
        };
    }

    internal static bool IsAuthoritativeSnapshot(
        TransfersState state,
        TransferListSnapshot snapshot,
        long generation) =>
        state.IsLoaded && state.Generation == generation &&
        (state.InstanceId is null ||
            !string.Equals(state.InstanceId, snapshot.InstanceId, StringComparison.Ordinal) ||
            snapshot.Revision >= state.Revision);

    internal static TransfersState BeginAdmissionReconciliation(TransfersState state) =>
        state with
        {
            AdmissionReconciliationPending = true,
            AdmissionReconciliationAttemptsRemaining =
                MaximumAdmissionReconciliationAttempts,
        };

    internal static TransfersState RestartAdmissionReconciliation(TransfersState state) =>
        state.IsLoaded && state.AdmissionReconciliationPending
            ? state with
            {
                AdmissionReconciliationAttemptsRemaining =
                    MaximumAdmissionReconciliationAttempts,
            }
            : state;

    internal static TransfersState MarkPollFailure(TransfersState state, long generation)
    {
        if (!state.IsLoaded || state.Generation != generation)
        {
            return state;
        }
        int attempts = state.AdmissionReconciliationPending
            ? Math.Max(0, state.AdmissionReconciliationAttemptsRemaining - 1)
            : 0;
        return state with
        {
            IsStale = true,
            AdmissionReconciliationAttemptsRemaining = attempts,
        };
    }

    internal static TransfersState CompleteCancelSnapshot(
        TransfersState state,
        TransferListSnapshot snapshot,
        string transferId,
        long generation)
    {
        TransfersState applied = ApplySnapshot(state, snapshot, generation);
        if (ReferenceEquals(applied, state))
        {
            return OwnsCancel(state, transferId, generation)
                ? state with
                {
                    CancelInFlight = false,
                    CancelOutcomeUnknown = true,
                    IsStale = true,
                }
                : state;
        }
        if (applied.Generation != generation ||
            applied.CancelOwnerId != transferId)
        {
            return applied;
        }
        return applied with
        {
            CancelInFlight = false,
            CancelOutcomeUnknown = true,
        };
    }

    internal static bool CanCancel(TransfersState state, string transferId)
    {
        TransferSnapshot? transfer = state.Rows
            .Select(row => row.Snapshot)
            .FirstOrDefault(row => row.TransferId == transferId);
        return state.IsLoaded && transfer is { Cancellable: true, IsTerminal: false } &&
            !state.CancelInFlight &&
            (state.CancelOwnerId is null || state.CancelOwnerId == transferId);
    }

    internal static TransfersState BeginCancel(TransfersState state, string transferId)
    {
        if (!CanCancel(state, transferId))
        {
            return state;
        }
        return state with
        {
            CancelOwnerId = transferId,
            CancelInFlight = true,
            CancelOutcomeUnknown = false,
        };
    }

    internal static TransfersState RejectCancel(
        TransfersState state,
        string transferId,
        long generation)
    {
        if (!OwnsCancel(state, transferId, generation))
        {
            return state;
        }
        return state with
        {
            CancelOwnerId = null,
            CancelInFlight = false,
            CancelOutcomeUnknown = false,
        };
    }

    internal static TransfersState MarkCancelOutcomeUnknown(
        TransfersState state,
        string transferId,
        long generation)
    {
        if (!OwnsCancel(state, transferId, generation))
        {
            return state;
        }
        return state with { CancelInFlight = false, CancelOutcomeUnknown = true, IsStale = true };
    }

    private static bool OwnsCancel(TransfersState state, string transferId, long generation) =>
        state.IsLoaded && state.Generation == generation && state.CancelOwnerId == transferId;
}
