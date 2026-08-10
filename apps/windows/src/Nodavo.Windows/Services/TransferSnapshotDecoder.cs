using System.Text.Json;
using Nodavo.Windows.Models;

namespace Nodavo.Windows.Services;

internal static class TransferSnapshotDecoder
{
    internal const int MaximumTransfers = 160;
    internal const ulong MaximumTransferBytes = 10UL * 1024 * 1024 * 1024;
    private const string InvalidResponse = "Invalid transfer snapshot response.";
    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal)
    {
        "event",
        "instance_id",
        "revision",
        "truncated",
        "transfers",
    };
    private static readonly HashSet<string> TransferFields = new(StringComparer.Ordinal)
    {
        "transfer_id",
        "direction",
        "phase",
        "processed_bytes",
        "total_bytes",
        "cancellable",
        "failure",
    };

    internal static TransferListSnapshot DecodeTransfers(byte[] payload)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(payload, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 6,
            });
            JsonElement root = document.RootElement;
            RequireExactObject(root, RootFields);
            if (ReadRequiredString(root, "event") != "transfers")
            {
                throw new InvalidDataException();
            }

            string instanceId = ReadCanonicalIdentifier(root, "instance_id");
            ulong revision = ReadRequiredUInt64(root, "revision");
            if (revision == 0 ||
                !root.TryGetProperty("truncated", out JsonElement truncatedElement) ||
                truncatedElement.ValueKind is not JsonValueKind.True and not JsonValueKind.False ||
                !root.TryGetProperty("transfers", out JsonElement transfersElement) ||
                transfersElement.ValueKind != JsonValueKind.Array ||
                transfersElement.GetArrayLength() > MaximumTransfers)
            {
                throw new InvalidDataException();
            }

            var transferIds = new HashSet<string>(StringComparer.Ordinal);
            var transfers = new List<TransferSnapshot>(transfersElement.GetArrayLength());
            foreach (JsonElement transferElement in transfersElement.EnumerateArray())
            {
                TransferSnapshot transfer = DecodeTransfer(transferElement);
                if (!transferIds.Add(transfer.TransferId))
                {
                    throw new InvalidDataException();
                }
                transfers.Add(transfer);
            }

            return new TransferListSnapshot(
                instanceId,
                revision,
                truncatedElement.GetBoolean(),
                transfers);
        }
        catch (Exception exception) when (
            exception is JsonException or InvalidDataException or FormatException or
            OverflowException)
        {
            throw new InvalidDataException(InvalidResponse);
        }
    }

    private static TransferSnapshot DecodeTransfer(JsonElement element)
    {
        RequireExactObject(element, TransferFields);
        string transferId = ReadCanonicalIdentifier(element, "transfer_id");
        TransferDirection direction = ReadRequiredString(element, "direction") switch
        {
            "inbound" => TransferDirection.Inbound,
            "outbound" => TransferDirection.Outbound,
            _ => throw new InvalidDataException(),
        };
        TransferPhase phase = ReadRequiredString(element, "phase") switch
        {
            "preparing" => TransferPhase.Preparing,
            "queued" => TransferPhase.Queued,
            "transferring" => TransferPhase.Transferring,
            "paused" => TransferPhase.Paused,
            "finalizing" => TransferPhase.Finalizing,
            "cancel_requested" => TransferPhase.CancelRequested,
            "completed" => TransferPhase.Completed,
            "cancelled" => TransferPhase.Cancelled,
            "failed" => TransferPhase.Failed,
            _ => throw new InvalidDataException(),
        };
        ulong? processedBytes = ReadNullableUInt64(element, "processed_bytes");
        ulong? totalBytes = ReadNullableUInt64(element, "total_bytes");
        bool countersMayBeNull = phase is TransferPhase.Preparing or
            TransferPhase.CancelRequested or TransferPhase.Cancelled or TransferPhase.Failed;
        if (processedBytes.HasValue != totalBytes.HasValue ||
            (!processedBytes.HasValue && !countersMayBeNull) ||
            totalBytes > MaximumTransferBytes || processedBytes > totalBytes ||
            (phase == TransferPhase.Completed && processedBytes != totalBytes))
        {
            throw new InvalidDataException();
        }

        if (!element.TryGetProperty("cancellable", out JsonElement cancellableElement) ||
            cancellableElement.ValueKind is not JsonValueKind.True and not JsonValueKind.False)
        {
            throw new InvalidDataException();
        }
        bool cancellable = cancellableElement.GetBoolean();
        if ((phase is TransferPhase.CancelRequested or TransferPhase.Completed or
            TransferPhase.Cancelled or TransferPhase.Failed) && cancellable)
        {
            throw new InvalidDataException();
        }

        TransferFailure? failure = ReadFailure(element, phase);
        return new TransferSnapshot(
            transferId,
            $"••••••••-{transferId[^8..]}",
            direction,
            phase,
            processedBytes,
            totalBytes,
            cancellable,
            failure);
    }

    private static TransferFailure? ReadFailure(JsonElement element, TransferPhase phase)
    {
        JsonElement failureElement = element.GetProperty("failure");
        if (phase != TransferPhase.Failed)
        {
            if (failureElement.ValueKind != JsonValueKind.Null)
            {
                throw new InvalidDataException();
            }
            return null;
        }
        if (failureElement.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException();
        }
        return failureElement.GetString() switch
        {
            "admission_failed" => TransferFailure.AdmissionFailed,
            "source_unavailable" => TransferFailure.SourceUnavailable,
            "authorization_revoked" => TransferFailure.AuthorizationRevoked,
            "transport_failed" => TransferFailure.TransportFailed,
            "cleanup_failed" => TransferFailure.CleanupFailed,
            "internal" => TransferFailure.Internal,
            _ => throw new InvalidDataException(),
        };
    }

    private static void RequireExactObject(JsonElement element, IReadOnlySet<string> fields)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException();
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!fields.Contains(property.Name) || !seen.Add(property.Name))
            {
                throw new InvalidDataException();
            }
        }
        if (seen.Count != fields.Count)
        {
            throw new InvalidDataException();
        }
    }

    private static string ReadCanonicalIdentifier(JsonElement element, string property)
    {
        string value = ReadRequiredString(element, property);
        if (!Guid.TryParseExact(value, "D", out Guid parsed) || parsed == Guid.Empty ||
            !string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal))
        {
            throw new InvalidDataException();
        }
        return value;
    }

    private static string ReadRequiredString(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String || value.GetString() is not { } text)
        {
            throw new InvalidDataException();
        }
        return text;
    }

    private static ulong ReadRequiredUInt64(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out JsonElement value) ||
            value.ValueKind != JsonValueKind.Number || !value.TryGetUInt64(out ulong number))
        {
            throw new InvalidDataException();
        }
        return number;
    }

    private static ulong? ReadNullableUInt64(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out JsonElement value))
        {
            throw new InvalidDataException();
        }
        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetUInt64(out ulong number))
        {
            throw new InvalidDataException();
        }
        return number;
    }
}
