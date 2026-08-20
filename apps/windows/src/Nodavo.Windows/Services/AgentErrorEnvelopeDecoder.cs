using System.Text.Json;

namespace Nodavo.Windows.Services;

internal static class AgentErrorEnvelopeDecoder
{
    internal static bool TryDecode(
        JsonElement root,
        IReadOnlySet<string> allowedCodes,
        int maximumMessageLength,
        out string code)
    {
        code = string.Empty;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("event", out JsonElement eventName) ||
            eventName.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException("Unexpected local IPC event.");
        }
        if (!string.Equals(eventName.GetString(), "error", StringComparison.Ordinal))
        {
            return false;
        }

        RequireExactFields(root);
        code = ReadRequiredText(root, "code", 128);
        _ = ReadRequiredText(root, "message", maximumMessageLength);
        if (!allowedCodes.Contains(code))
        {
            throw new InvalidDataException("Unknown local IPC error code.");
        }
        return true;
    }

    private static void RequireExactFields(JsonElement root)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (property.Name is not ("event" or "code" or "message") ||
                !seen.Add(property.Name))
            {
                throw new InvalidDataException("Invalid local IPC error envelope.");
            }
        }
        if (seen.Count != 3)
        {
            throw new InvalidDataException("Invalid local IPC error envelope.");
        }
    }

    private static string ReadRequiredText(
        JsonElement root,
        string property,
        int maximumLength)
    {
        if (!root.TryGetProperty(property, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String ||
            value.GetString() is not { } text ||
            string.IsNullOrWhiteSpace(text) ||
            text.Length > maximumLength ||
            !string.Equals(text, text.Trim(), StringComparison.Ordinal) ||
            text.Any(char.IsControl))
        {
            throw new InvalidDataException("Invalid local IPC error envelope.");
        }
        return text;
    }
}
