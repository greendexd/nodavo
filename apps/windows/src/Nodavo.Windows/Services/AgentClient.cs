using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Nodavo.Windows.Models;

namespace Nodavo.Windows.Services;

internal sealed class AgentClient
{
    private const int MaximumMessageSize = 64 * 1024;
    private const int MaximumEndpointLength = 512;
    private const int MaximumIdentifierLength = 256;
    private static readonly HashSet<string> AllowedPairingCapabilities = new(StringComparer.Ordinal)
    {
        "input",
        "clipboard_read",
        "clipboard_write",
        "files",
    };
    private static readonly TimeSpan StatusRequestTimeout = TimeSpan.FromSeconds(3);
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
            DecodeStatus,
            cancellationToken);

    internal Task<AgentStatusSnapshot> EmergencyStopAsync(
        CancellationToken cancellationToken = default) =>
        RequestAsync(
            new CommandEnvelope("emergency_stop"),
            StatusRequestTimeout,
            DecodeStatus,
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
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(request);
        await WriteFrameAsync(pipe, payload, deadline.Token).ConfigureAwait(false);
        byte[] response = await ReadFrameAsync(pipe, deadline.Token).ConfigureAwait(false);
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

    private static AgentStatusSnapshot DecodeStatus(byte[] payload)
    {
        using JsonDocument document = ParseResponse(payload);
        JsonElement root = document.RootElement;
        RequireEvent(root, "status");

        string phase = ReadRequiredEnum(root, "phase", "starting", "ready", "pairing", "connected", "stopping");
        string inputOwner = ReadRequiredEnum(root, "input_owner", "local", "remote");
        string? connectedPeer = null;
        if (root.TryGetProperty("connected_peer", out JsonElement peer) &&
            peer.ValueKind != JsonValueKind.Null)
        {
            connectedPeer = peer.GetString();
            if (connectedPeer is null || connectedPeer.Length is 0 or > 256 ||
                connectedPeer.Any(char.IsControl))
            {
                throw new InvalidDataException("Invalid peer display name.");
            }
        }

        return new AgentStatusSnapshot(phase, connectedPeer, inputOwner);
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
}

internal sealed class AgentProtocolException(string code)
    : InvalidDataException("The Nodavo agent rejected the request.")
{
    internal string Code { get; } = code;
}
