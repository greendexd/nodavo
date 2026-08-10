using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Nodavo.Windows.Models;

namespace Nodavo.Windows.Services;

internal sealed class AgentClient : IAgentReadinessProbe
{
    private const int MaximumMessageSize = 64 * 1024;
    private const int MaximumEndpointLength = 512;
    private const int MaximumIdentifierLength = 256;
    private const int MaximumErrorMessageLength = 1024;
    private const int MaximumTrustedPeers = 32;
    private const int MaximumSelectedPaths = 32;
    private const int MaximumSelectedPathBytes = 4 * 1024;
    private static readonly HashSet<string> AllowedPairingCapabilities = new(StringComparer.Ordinal)
    {
        "input",
        "clipboard_read",
        "clipboard_write",
        "files",
    };
    private static readonly HashSet<string> AllowedAgentErrorCodes = new(StringComparer.Ordinal)
    {
        "busy",
        "invalid_endpoint",
        "discovery_unavailable",
        "pairing_timed_out",
        "reconnect_failed",
        "pairing_not_found",
        "already_confirmed",
        "peer_not_found",
        "storage_unavailable",
        "grant_epoch_exhausted",
        "pairing_failed",
        "not_connected",
        "focus_rejected",
        "safety_recovery_failed",
        "transfer_failed",
    };
    // The agent may use its full three-second platform-readiness probe budget.
    // Leave additional time for pipe connection, mutual authentication, IPC, and scheduling.
    private static readonly TimeSpan StatusRequestTimeout = TimeSpan.FromSeconds(8);
    // Emergency stop may use the server's full twenty-second fail-closed safety window.
    // Keep this independent from ordinary status polling and leave transport margin.
    private static readonly TimeSpan EmergencyRequestTimeout = TimeSpan.FromSeconds(25);
    // The agent may spend two sequential five-second safety windows applying a grant.
    private static readonly TimeSpan MutationRequestTimeout = TimeSpan.FromSeconds(15);
    // The agent owns a five-minute bounded preparation window after command delivery.
    private static readonly TimeSpan TransferRequestTimeout = TimeSpan.FromMinutes(5.25);
    private static readonly TimeSpan PairingRequestTimeout = TimeSpan.FromMinutes(2.2);
    private readonly string _pipeName;

    internal AgentClient()
        : this(CreateCurrentUserPipeName())
    {
    }

    internal AgentClient(string pipeName)
    {
        if (string.IsNullOrWhiteSpace(pipeName) || pipeName.Length > 240 ||
            pipeName.Contains('\\') || pipeName.Contains('/'))
        {
            throw new ArgumentException("Unsafe Nodavo pipe name.", nameof(pipeName));
        }

        _pipeName = pipeName;
    }

    internal Task<AgentStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken = default) =>
        RequestAsync(
            new CommandEnvelope("get_status"),
            StatusRequestTimeout,
            AgentStatusDecoder.DecodeStatus,
            cancellationToken);

    async Task<bool> IAgentReadinessProbe.IsAgentReachableAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            _ = await GetStatusAsync(cancellationToken);
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or IOException or InvalidDataException or
            JsonException or InvalidOperationException or AgentProtocolException)
        {
            return false;
        }
    }

    internal Task<AgentStatusSnapshot> EmergencyStopAsync(
        CancellationToken cancellationToken = default) =>
        RequestAsync(
            new CommandEnvelope("emergency_stop"),
            EmergencyRequestTimeout,
            AgentStatusDecoder.DecodeStatus,
            cancellationToken);

    internal Task<PairingCodeSnapshot> BeginPairingAsync(
        string endpoint,
        IReadOnlyCollection<string> capabilities,
        CancellationToken cancellationToken = default)
    {
        ValidateText(endpoint, MaximumEndpointLength, "pairing endpoint");
        if (endpoint.StartsWith("reconnect:", StringComparison.Ordinal) ||
            endpoint.StartsWith("reconnect-listen:", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Reconnect requires the trusted-device flow.");
        }
        if (capabilities.Count > AllowedPairingCapabilities.Count ||
            capabilities.Distinct(StringComparer.Ordinal).Count() != capabilities.Count ||
            capabilities.Any(capability => !AllowedPairingCapabilities.Contains(capability)))
        {
            throw new InvalidDataException("Invalid pairing capabilities.");
        }
        return RequestAsync(
            new BeginPairingEnvelope(
                "begin_pairing",
                endpoint,
                capabilities.OrderBy(capability => capability, StringComparer.Ordinal).ToArray()),
            PairingRequestTimeout,
            DecodePairingCode,
            cancellationToken);
    }

    internal Task<PairingResultSnapshot> ConfirmPairingAsync(
        string pairingId,
        bool accepted,
        CancellationToken cancellationToken = default)
    {
        ValidateText(pairingId, MaximumIdentifierLength, "pairing identifier");
        return RequestAsync(
            new ConfirmPairingEnvelope("confirm_pairing", pairingId, accepted),
            PairingRequestTimeout,
            DecodePairingResult,
            cancellationToken);
    }

    internal Task<IReadOnlyList<TrustedPeerSnapshot>> ListTrustedPeersAsync(
        CancellationToken cancellationToken = default) =>
        RequestAsync(
            new CommandEnvelope("list_trusted_peers"),
            StatusRequestTimeout,
            DecodeTrustedPeers,
            cancellationToken);

    internal Task<CapabilityChangeSnapshot> SetCapabilityAsync(
        string peerId,
        string capability,
        bool enabled,
        CancellationToken cancellationToken = default)
    {
        ValidateText(peerId, MaximumIdentifierLength, "peer identifier");
        ValidateCapability(capability);
        return RequestAsync(
            new SetCapabilityEnvelope("set_capability", peerId, capability, enabled),
            MutationRequestTimeout,
            DecodeCapabilityChanged,
            cancellationToken);
    }

    internal Task<AgentStatusSnapshot> RevokePeerAsync(
        string peerId,
        CancellationToken cancellationToken = default)
    {
        ValidateText(peerId, MaximumIdentifierLength, "peer identifier");
        return RequestAsync(
            new RevokePeerEnvelope("revoke_peer", peerId),
            MutationRequestTimeout,
            AgentStatusDecoder.DecodeStatus,
            cancellationToken);
    }

    internal Task<TransferQueuedSnapshot> SendFilesAsync(
        IReadOnlyCollection<string> paths,
        CancellationToken cancellationToken = default)
    {
        string[] selectedPaths = ValidateSelectedPaths(paths);
        return RequestAsync(
            new SendFilesEnvelope("send_files", selectedPaths),
            TransferRequestTimeout,
            DecodeTransferQueued,
            cancellationToken);
    }

    internal static string[] ValidateSelectedPaths(IReadOnlyCollection<string> paths)
    {
        if (paths.Count is 0 or > MaximumSelectedPaths)
        {
            throw new InvalidDataException("Select between one and 32 files or folders.");
        }

        var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var validated = new List<string>(paths.Count);
        foreach (string path in paths)
        {
            if (string.IsNullOrEmpty(path) || path.Any(char.IsControl) ||
                Encoding.UTF8.GetByteCount(path) > MaximumSelectedPathBytes ||
                !Path.IsPathFullyQualified(path) || !unique.Add(path))
            {
                throw new InvalidDataException("Unsafe or duplicate selected path.");
            }
            validated.Add(path);
        }
        return validated.ToArray();
    }

    private async Task<TResult> RequestAsync<TRequest, TResult>(
        TRequest request,
        TimeSpan timeout,
        Func<byte[], TResult> decode,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);

        await using var pipe = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
            TokenImpersonationLevel.Identification);

        await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
        using AuthenticatedAgentServer server = AgentServerAuthenticator.Authenticate(pipe);
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(request);
        await WriteFrameAsync(pipe, payload, deadline.Token).ConfigureAwait(false);
        server.Revalidate();
        byte[] response = await ReadFrameAsync(pipe, deadline.Token).ConfigureAwait(false);
        server.Revalidate();
        return decode(response);
    }

    private static async Task WriteFrameAsync(
        Stream stream,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        if (payload.Length > MaximumMessageSize)
        {
            throw new InvalidDataException("Local IPC request exceeds the Nodavo limit.");
        }

        byte[] header = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(header, checked((uint)payload.Length));
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        byte[] header = new byte[sizeof(uint)];
        await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false);

        uint encodedLength = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (encodedLength > MaximumMessageSize)
        {
            throw new InvalidDataException("Local IPC response exceeds the Nodavo limit.");
        }

        byte[] payload = new byte[checked((int)encodedLength)];
        await ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        return payload;
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int count = await stream.ReadAsync(destination[offset..], cancellationToken)
                .ConfigureAwait(false);
            if (count == 0)
            {
                throw new EndOfStreamException("The Nodavo agent closed local IPC.");
            }
            offset += count;
        }
    }

    private static PairingCodeSnapshot DecodePairingCode(byte[] payload)
    {
        using JsonDocument document = ParseResponse(payload);
        JsonElement root = document.RootElement;
        RequireEvent(root, "pairing_code");
        string pairingId = ReadRequiredText(root, "pairing_id", MaximumIdentifierLength);
        string peerName = ReadRequiredText(root, "peer_name", MaximumIdentifierLength);
        string code = ReadRequiredText(root, "code", 6);
        if (code.Length != 6 || code.Any(character => character is < '0' or > '9'))
        {
            throw new InvalidDataException("Invalid pairing code.");
        }
        return new PairingCodeSnapshot(pairingId, peerName, code);
    }

    private static PairingResultSnapshot DecodePairingResult(byte[] payload)
    {
        using JsonDocument document = ParseResponse(payload);
        JsonElement root = document.RootElement;
        RequireEvent(root, "pairing_finished");
        string pairingId = ReadRequiredText(root, "pairing_id", MaximumIdentifierLength);
        if (!root.TryGetProperty("paired", out JsonElement paired) ||
            paired.ValueKind is not JsonValueKind.True and not JsonValueKind.False)
        {
            throw new InvalidDataException("Invalid pairing result.");
        }
        return new PairingResultSnapshot(pairingId, paired.GetBoolean());
    }

    private static IReadOnlyList<TrustedPeerSnapshot> DecodeTrustedPeers(byte[] payload)
    {
        using JsonDocument document = ParseResponse(payload);
        JsonElement root = document.RootElement;
        RequireEvent(root, "trusted_peers");
        if (!root.TryGetProperty("peers", out JsonElement peers) ||
            peers.ValueKind != JsonValueKind.Array || peers.GetArrayLength() > MaximumTrustedPeers)
        {
            throw new InvalidDataException("Invalid trusted-peer list.");
        }

        var decoded = new List<TrustedPeerSnapshot>(peers.GetArrayLength());
        var peerIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement peer in peers.EnumerateArray())
        {
            if (peer.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("Invalid trusted peer.");
            }
            string peerId = ReadRequiredText(peer, "peer_id", MaximumIdentifierLength);
            string displayName = ReadRequiredText(peer, "display_name", MaximumIdentifierLength);
            string state = ReadRequiredEnum(peer, "state", "active", "revoked");
            if (!peerIds.Add(peerId) ||
                !peer.TryGetProperty("local_grants", out JsonElement grants) ||
                grants.ValueKind != JsonValueKind.Array ||
                grants.GetArrayLength() > AllowedPairingCapabilities.Count)
            {
                throw new InvalidDataException("Invalid trusted peer.");
            }

            var localGrants = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonElement grant in grants.EnumerateArray())
            {
                if (grant.ValueKind != JsonValueKind.String || grant.GetString() is not { } capability)
                {
                    throw new InvalidDataException("Invalid trusted-peer capability.");
                }
                ValidateCapability(capability);
                if (!localGrants.Add(capability))
                {
                    throw new InvalidDataException("Duplicate trusted-peer capability.");
                }
            }
            decoded.Add(new TrustedPeerSnapshot(peerId, displayName, state, localGrants));
        }
        return decoded;
    }

    private static CapabilityChangeSnapshot DecodeCapabilityChanged(byte[] payload)
    {
        using JsonDocument document = ParseResponse(payload);
        JsonElement root = document.RootElement;
        RequireEvent(root, "capability_changed");
        string peerId = ReadRequiredText(root, "peer_id", MaximumIdentifierLength);
        string capability = ReadRequiredText(root, "capability", 32);
        ValidateCapability(capability);
        if (!root.TryGetProperty("enabled", out JsonElement enabled) ||
            enabled.ValueKind is not JsonValueKind.True and not JsonValueKind.False)
        {
            throw new InvalidDataException("Invalid capability acknowledgement.");
        }
        return new CapabilityChangeSnapshot(peerId, capability, enabled.GetBoolean());
    }

    private static TransferQueuedSnapshot DecodeTransferQueued(byte[] payload)
    {
        using JsonDocument document = ParseResponse(payload);
        JsonElement root = document.RootElement;
        RequireEvent(root, "transfer_queued");
        string transferId = ReadRequiredText(root, "transfer_id", 36);
        if (!Guid.TryParseExact(transferId, "D", out Guid parsed) || parsed == Guid.Empty)
        {
            throw new InvalidDataException("Invalid transfer acknowledgement.");
        }
        string canonical = parsed.ToString("D");
        return new TransferQueuedSnapshot($"••••••••-{canonical[^8..]}");
    }

    private static JsonDocument ParseResponse(byte[] payload) =>
        JsonDocument.Parse(payload, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 8,
        });

    private static void RequireEvent(JsonElement root, string expected)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("event", out JsonElement eventName) ||
            eventName.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException("Unexpected local IPC event.");
        }

        string? actual = eventName.GetString();
        if (actual == "error")
        {
            string code = ReadRequiredText(root, "code", 128);
            _ = ReadRequiredText(root, "message", MaximumErrorMessageLength);
            if (!AllowedAgentErrorCodes.Contains(code))
            {
                throw new InvalidDataException("Unknown local IPC error code.");
            }
            throw new AgentProtocolException(code);
        }
        if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Unexpected local IPC event.");
        }
    }

    private static string ReadRequiredText(JsonElement root, string property, int maximumLength)
    {
        if (!root.TryGetProperty(property, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String ||
            value.GetString() is not { } text)
        {
            throw new InvalidDataException($"Invalid local IPC field: {property}.");
        }
        ValidateText(text, maximumLength, property);
        return text;
    }

    private static void ValidateText(string text, int maximumLength, string field)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > maximumLength ||
            !string.Equals(text, text.Trim(), StringComparison.Ordinal) || text.Any(char.IsControl))
        {
            throw new InvalidDataException($"Invalid local IPC field: {field}.");
        }
    }

    private static void ValidateCapability(string capability)
    {
        if (!AllowedPairingCapabilities.Contains(capability))
        {
            throw new InvalidDataException("Invalid capability.");
        }
    }

    private static string ReadRequiredEnum(
        JsonElement root,
        string property,
        params string[] allowed)
    {
        if (!root.TryGetProperty(property, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String ||
            value.GetString() is not { } text ||
            !allowed.Contains(text, StringComparer.Ordinal))
        {
            throw new InvalidDataException($"Invalid local IPC field: {property}.");
        }
        return text;
    }

    private static string CreateCurrentUserPipeName()
    {
        string? sid = WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrEmpty(sid))
        {
            throw new InvalidOperationException("The current Windows user SID is unavailable.");
        }
        return $"nodavo-agent-{sid}";
    }

    private sealed record CommandEnvelope(
        [property: JsonPropertyName("command")] string Command);

    private sealed record BeginPairingEnvelope(
        [property: JsonPropertyName("command")] string Command,
        [property: JsonPropertyName("endpoint")] string Endpoint,
        [property: JsonPropertyName("capabilities")] string[] Capabilities);

    private sealed record ConfirmPairingEnvelope(
        [property: JsonPropertyName("command")] string Command,
        [property: JsonPropertyName("pairing_id")] string PairingId,
        [property: JsonPropertyName("accepted")] bool Accepted);

    private sealed record SetCapabilityEnvelope(
        [property: JsonPropertyName("command")] string Command,
        [property: JsonPropertyName("peer_id")] string PeerId,
        [property: JsonPropertyName("capability")] string Capability,
        [property: JsonPropertyName("enabled")] bool Enabled);

    private sealed record RevokePeerEnvelope(
        [property: JsonPropertyName("command")] string Command,
        [property: JsonPropertyName("peer_id")] string PeerId);

    private sealed record SendFilesEnvelope(
        [property: JsonPropertyName("command")] string Command,
        [property: JsonPropertyName("paths")] string[] Paths);
}

internal sealed class AgentProtocolException(string code)
    : Exception("The Nodavo agent rejected the request.")
{
    internal string Code { get; } = code;
}
