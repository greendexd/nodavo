using System.Reflection;
using System.Text;

namespace Nodavo.Windows.Models;

internal enum AgentServerAuthMode
{
    Development,
    Release,
}

internal sealed record AgentServerAuthPolicy(
    AgentServerAuthMode Mode,
    string PackageName,
    string Publisher,
    string PackageFamilyName,
    string ApplicationUserModelId,
    string RelativeExecutable,
    byte[] SignerCertificateSha256)
{
    private const string DevelopmentPackageName = "dev.nodavo.Nodavo.Development";
    private const string DevelopmentPublisher = "CN=Nodavo Development Only";
    private const string ReleasePackageName = "dev.nodavo.Nodavo";
    private const string ExpectedApplicationId = "App";
    private const string ExpectedRelativeExecutable = "agent\\nodavo-agent.exe";
    private const int Sha256Length = 32;

    private static readonly string[] RequiredMetadataKeys =
    [
        "Nodavo.AgentServerAuth.Mode",
        "Nodavo.AgentServerAuth.PackageNameBase64",
        "Nodavo.AgentServerAuth.PublisherBase64",
        "Nodavo.AgentServerAuth.PackageFamilyNameBase64",
        "Nodavo.AgentServerAuth.ApplicationUserModelIdBase64",
        "Nodavo.AgentServerAuth.RelativeExecutableBase64",
        "Nodavo.AgentServerAuth.SignerCertificateSha256",
    ];

    internal string ApplicationId => ExpectedApplicationId;

    internal static AgentServerAuthPolicy LoadCompiled()
    {
        var metadata = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (AssemblyMetadataAttribute attribute in
                 typeof(AgentServerAuthPolicy).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>())
        {
            if (!attribute.Key.StartsWith("Nodavo.AgentServerAuth.", StringComparison.Ordinal))
            {
                continue;
            }
            if (!metadata.TryAdd(attribute.Key, attribute.Value ?? string.Empty))
            {
                throw new InvalidOperationException(
                    "The Windows agent authentication policy is inconsistent.");
            }
        }
        return FromMetadata(metadata);
    }

    internal static AgentServerAuthPolicy FromMetadata(
        IReadOnlyDictionary<string, string> metadata)
    {
        if (metadata.Count != RequiredMetadataKeys.Length ||
            RequiredMetadataKeys.Any(key => !metadata.ContainsKey(key)))
        {
            throw new InvalidOperationException(
                "The Windows agent authentication policy is not configured.");
        }

        AgentServerAuthMode mode = Required(metadata, RequiredMetadataKeys[0]) switch
        {
            "development" => AgentServerAuthMode.Development,
            "release" => AgentServerAuthMode.Release,
            _ => throw new InvalidOperationException(
                "The Windows agent authentication policy mode is invalid."),
        };

        string packageName = Decode(Required(metadata, RequiredMetadataKeys[1]), 50);
        string publisher = Decode(Required(metadata, RequiredMetadataKeys[2]), 8192);
        string packageFamilyName = Decode(Required(metadata, RequiredMetadataKeys[3]), 64);
        string applicationUserModelId = Decode(Required(metadata, RequiredMetadataKeys[4]), 130);
        string relativeExecutable = Decode(Required(metadata, RequiredMetadataKeys[5]), 64);
        byte[] signerSha256 = DecodeSha256(Required(metadata, RequiredMetadataKeys[6]));

        if (mode == AgentServerAuthMode.Development &&
            (packageName != DevelopmentPackageName || publisher != DevelopmentPublisher))
        {
            throw new InvalidOperationException(
                "The Windows development agent authentication policy is invalid.");
        }
        if (mode == AgentServerAuthMode.Release && packageName != ReleasePackageName)
        {
            throw new InvalidOperationException(
                "The Windows release agent authentication policy is invalid.");
        }
        if (!IsPackageName(packageName) || !IsPublisher(publisher) ||
            !IsPackageFamilyName(packageFamilyName) ||
            applicationUserModelId != $"{packageFamilyName}!{ExpectedApplicationId}" ||
            relativeExecutable != ExpectedRelativeExecutable)
        {
            throw new InvalidOperationException(
                "The Windows agent authentication policy identity is invalid.");
        }

        return new AgentServerAuthPolicy(
            mode,
            packageName,
            publisher,
            packageFamilyName,
            applicationUserModelId,
            relativeExecutable,
            signerSha256);
    }

    private static string Required(
        IReadOnlyDictionary<string, string> metadata,
        string key)
    {
        string value = metadata[key];
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(
                "The Windows agent authentication policy is incomplete.");
        }
        return value;
    }

    private static string Decode(string encoded, int maximumCharacters)
    {
        try
        {
            byte[] bytes = Convert.FromBase64String(encoded);
            string value = new UTF8Encoding(false, true).GetString(bytes);
            if (value.Length is 0 || value.Length > maximumCharacters ||
                value.Contains('\0') || value.Any(char.IsControl))
            {
                throw new InvalidOperationException();
            }
            return value;
        }
        catch (Exception exception) when (
            exception is FormatException or DecoderFallbackException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                "The Windows agent authentication policy encoding is invalid.");
        }
    }

    private static byte[] DecodeSha256(string encoded)
    {
        if (encoded.Length != Sha256Length * 2)
        {
            throw new InvalidOperationException(
                "The Windows agent signer policy is invalid.");
        }

        try
        {
            byte[] digest = Convert.FromHexString(encoded);
            if (digest.Length != Sha256Length || digest.All(value => value == 0))
            {
                throw new InvalidOperationException();
            }
            return digest;
        }
        catch (Exception exception) when (
            exception is FormatException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                "The Windows agent signer policy is invalid.");
        }
    }

    private static bool IsPackageName(string value) =>
        value.Length is >= 3 and <= 50 &&
        !value.EndsWith(".", StringComparison.Ordinal) &&
        value.All(character =>
            character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-');

    private static bool IsPublisher(string value) =>
        value.StartsWith("CN=", StringComparison.Ordinal) && value.Length <= 8192;

    private static bool IsPackageFamilyName(string value) =>
        value.Length is >= 3 and <= 64 &&
        value.Count(character => character == '_') == 1 &&
        value.All(character =>
            character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_');

    public override string ToString() => "AgentServerAuthPolicy { redacted }";
}
