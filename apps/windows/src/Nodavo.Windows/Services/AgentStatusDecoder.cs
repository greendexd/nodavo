using System.Text.Json;
using Nodavo.Windows.Models;

namespace Nodavo.Windows.Services;

internal static class AgentStatusDecoder
{
    internal static AgentStatusSnapshot DecodeStatus(byte[] payload)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(payload, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8,
            });
            JsonElement root = document.RootElement;
            RequireExactStatusFields(root);
            RequireEvent(root, "status");

            string phase = ReadRequiredEnum(
                root,
                "phase",
                "starting",
                "ready",
                "pairing",
                "connected",
                "stopping");
            string inputOwner = ReadRequiredEnum(root, "input_owner", "local", "remote");
            string focusState = ReadRequiredEnum(
                root,
                "focus_state",
                "local",
                "controlling_peer",
                "controlled_by_peer");
            string? connectedPeer = ReadOptionalPeer(root);
            AgentReadinessSnapshot readiness = DecodeReadiness(root);

            return new AgentStatusSnapshot(phase, connectedPeer, inputOwner, focusState, readiness);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Invalid agent status response.", exception);
        }
    }

    private static AgentReadinessSnapshot DecodeReadiness(JsonElement root)
    {
        if (!root.TryGetProperty("readiness", out JsonElement readiness) ||
            readiness.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("Invalid agent status response.");
        }
        RequireExactReadinessFields(readiness);

        string accessibility = ReadRequiredEnum(
            readiness,
            "accessibility",
            "granted",
            "action_required",
            "not_applicable",
            "unavailable");
        // Windows has no accessibility consent flow. A different platform value is a
        // contract mismatch, not a request to show an accessibility action.
        if (accessibility != "not_applicable")
        {
            throw new InvalidDataException("Invalid agent status response.");
        }

        string input = ReadRequiredEnum(
            readiness,
            "input",
            "ready",
            "blocked_by_permission",
            "blocked_by_desktop",
            "unavailable");
        string localTopology = ReadRequiredEnum(readiness, "local_topology", "available", "unavailable");
        string sessionTopology = ReadRequiredEnum(
            readiness,
            "session_topology",
            "not_connected",
            "synchronizing",
            "ready");
        return new AgentReadinessSnapshot(accessibility, input, localTopology, sessionTopology);
    }

    private static void RequireExactReadinessFields(JsonElement readiness)
    {
        var fields = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in readiness.EnumerateObject())
        {
            if (!fields.Add(property.Name) || property.Name is not (
                "accessibility" or "input" or "local_topology" or "session_topology"))
            {
                throw new InvalidDataException("Invalid agent status response.");
            }
        }

        if (fields.Count != 4)
        {
            throw new InvalidDataException("Invalid agent status response.");
        }
    }

    private static void RequireExactStatusFields(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("Invalid agent status response.");
        }

        var fields = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (property.Name is not (
                    "event" or
                    "phase" or
                    "connected_peer" or
                    "input_owner" or
                    "focus_state" or
                    "readiness") ||
                !fields.Add(property.Name))
            {
                throw new InvalidDataException("Invalid agent status response.");
            }
        }
        if (fields.Count != 6)
        {
            throw new InvalidDataException("Invalid agent status response.");
        }
    }

    private static string? ReadOptionalPeer(JsonElement root)
    {
        if (!root.TryGetProperty("connected_peer", out JsonElement peer) ||
            peer.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (peer.ValueKind != JsonValueKind.String || peer.GetString() is not { } text ||
            text.Length is 0 or > 256 || text.Any(char.IsControl))
        {
            throw new InvalidDataException("Invalid agent status response.");
        }
        return text;
    }

    private static void RequireEvent(JsonElement root, string expected)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("event", out JsonElement eventName) ||
            eventName.ValueKind != JsonValueKind.String ||
            !string.Equals(eventName.GetString(), expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Invalid agent status response.");
        }
    }

    private static string ReadRequiredEnum(JsonElement root, string property, params string[] allowed)
    {
        if (!root.TryGetProperty(property, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String || value.GetString() is not { } text ||
            !allowed.Contains(text, StringComparer.Ordinal))
        {
            throw new InvalidDataException("Invalid agent status response.");
        }
        return text;
    }
}
