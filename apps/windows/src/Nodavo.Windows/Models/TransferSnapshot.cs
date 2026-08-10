namespace Nodavo.Windows.Models;

internal enum TransferDirection
{
    Inbound,
    Outbound,
}

internal enum TransferPhase
{
    Preparing,
    Queued,
    Transferring,
    Paused,
    Finalizing,
    CancelRequested,
    Completed,
    Cancelled,
    Failed,
}

internal enum TransferFailure
{
    AdmissionFailed,
    SourceUnavailable,
    AuthorizationRevoked,
    TransportFailed,
    CleanupFailed,
    Internal,
}

internal sealed record TransferSnapshot(
    string TransferId,
    string RedactedTransferId,
    TransferDirection Direction,
    TransferPhase Phase,
    ulong? ProcessedBytes,
    ulong? TotalBytes,
    bool Cancellable,
    TransferFailure? Failure)
{
    internal bool IsTerminal =>
        Phase is TransferPhase.Completed or TransferPhase.Cancelled or TransferPhase.Failed;
}

internal sealed record TransferListSnapshot(
    string InstanceId,
    ulong Revision,
    bool Truncated,
    IReadOnlyList<TransferSnapshot> Transfers);
