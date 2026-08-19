#requires -Version 7.4

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText',
    '',
    Justification = 'Release CI supplies a protected environment value which is immediately converted and cleared.'
)]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 65535)]
    [int] $BuildNumber,

    [switch] $Development,

    [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WinTrustErrorSuccess = 0
$WinTrustCertificateUntrustedRoot = -2146762487 # CERT_E_UNTRUSTEDROOT (0x800B0109)

function Fail([string] $Message) {
    throw "package-windows: $Message"
}

function Get-RequiredCommand([string] $Name) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        Fail "required command is unavailable: $Name"
    }
    return $command.Source
}

function Invoke-Native([string] $FilePath, [string[]] $Arguments) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "command failed with exit code $LASTEXITCODE`: $FilePath"
    }
}

function Get-PackageFamilyName([string] $PackageName, [string] $Publisher) {
    if ($null -eq ('Nodavo.WindowsPackaging.PackageIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Nodavo.WindowsPackaging
{
    public static class PackageIdentity
    {
        private const int ErrorSuccess = 0;
        private const int ErrorInsufficientBuffer = 122;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
        private struct PackageId
        {
            public uint reserved;
            public uint processorArchitecture;
            public ulong version;
            [MarshalAs(UnmanagedType.LPWStr)] public string name;
            [MarshalAs(UnmanagedType.LPWStr)] public string publisher;
            public IntPtr resourceId;
            public IntPtr publisherId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern int PackageFamilyNameFromId(
            ref PackageId packageId,
            ref uint packageFamilyNameLength,
            StringBuilder packageFamilyName);

        public static string Derive(string name, string publisher)
        {
            var id = new PackageId
            {
                name = name,
                publisher = publisher,
                resourceId = IntPtr.Zero,
                publisherId = IntPtr.Zero,
            };
            uint length = 0;
            int status = PackageFamilyNameFromId(ref id, ref length, null);
            if (status != ErrorInsufficientBuffer || length < 2 || length > 65)
            {
                throw new InvalidOperationException(
                    "PackageFamilyNameFromId sizing failed");
            }
            var output = new StringBuilder(checked((int)length));
            status = PackageFamilyNameFromId(ref id, ref length, output);
            if (status != ErrorSuccess)
            {
                throw new InvalidOperationException(
                    "PackageFamilyNameFromId derivation failed");
            }
            return output.ToString();
        }
    }
}
'@
    }
    return [Nodavo.WindowsPackaging.PackageIdentity]::Derive(
        $PackageName,
        $Publisher
    )
}

function Get-CertificateSha256(
    [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
) {
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Certificate.RawData)
    ).ToLowerInvariant()
}

function ConvertTo-Utf8Base64([string] $Value) {
    if ([string]::IsNullOrEmpty($Value)) {
        Fail "compile-time authentication policy values must not be empty"
    }
    return [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false, $true).GetBytes($Value)
    )
}

function Assert-CompiledAgentServerAuthMetadata(
    [string] $Path,
    [System.Collections.IDictionary] $ExpectedMetadata
) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Fail "compiled Windows UI assembly is missing: $Path"
    }

    if ($null -eq ('Nodavo.WindowsPackaging.CompiledAssemblyMetadata' -as [type])) {
        Add-Type -AssemblyName System.Reflection.Metadata
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace Nodavo.WindowsPackaging
{
    public static class CompiledAssemblyMetadata
    {
        public static string[] Read(string path)
        {
            var entries = new List<string>();
            using (var stream = File.OpenRead(path))
            using (var peReader = new PEReader(stream))
            {
                if (!peReader.HasMetadata)
                {
                    throw new InvalidDataException("file has no managed metadata");
                }

                MetadataReader reader = peReader.GetMetadataReader();
                AssemblyDefinition assembly = reader.GetAssemblyDefinition();
                foreach (CustomAttributeHandle handle in assembly.GetCustomAttributes())
                {
                    CustomAttribute attribute = reader.GetCustomAttribute(handle);
                    if (!IsAssemblyMetadataAttribute(reader, attribute.Constructor))
                    {
                        continue;
                    }

                    BlobReader value = reader.GetBlobReader(attribute.Value);
                    if (value.ReadUInt16() != 1)
                    {
                        throw new InvalidDataException(
                            "AssemblyMetadataAttribute has an invalid prolog");
                    }
                    string key = value.ReadSerializedString();
                    string metadataValue = value.ReadSerializedString();
                    if (key == null || metadataValue == null ||
                        value.ReadUInt16() != 0 || value.RemainingBytes != 0)
                    {
                        throw new InvalidDataException(
                            "AssemblyMetadataAttribute has an invalid value");
                    }
                    entries.Add(key + "\0" + metadataValue);
                }
            }
            return entries.ToArray();
        }

        private static bool IsAssemblyMetadataAttribute(
            MetadataReader reader,
            EntityHandle constructorHandle)
        {
            if (constructorHandle.Kind != HandleKind.MemberReference)
            {
                return false;
            }
            MemberReference constructor = reader.GetMemberReference(
                (MemberReferenceHandle)constructorHandle);
            if (reader.GetString(constructor.Name) != ".ctor" ||
                constructor.Parent.Kind != HandleKind.TypeReference)
            {
                return false;
            }
            TypeReference type = reader.GetTypeReference(
                (TypeReferenceHandle)constructor.Parent);
            return reader.GetString(type.Namespace) == "System.Reflection" &&
                reader.GetString(type.Name) == "AssemblyMetadataAttribute";
        }
    }
}
'@
    }

    try {
        $encodedEntries = @(
            [Nodavo.WindowsPackaging.CompiledAssemblyMetadata]::Read($Path)
        )
    }
    catch {
        Fail "cannot inspect compiled Windows UI authentication policy: $($_.Exception.Message)"
    }

    $actualMetadata = [Collections.Generic.Dictionary[string, string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($encodedEntry in $encodedEntries) {
        $separator = $encodedEntry.IndexOf([char] 0)
        if ($separator -lt 1) {
            Fail "compiled Windows UI authentication policy metadata is malformed"
        }
        $key = $encodedEntry.Substring(0, $separator)
        if (-not $key.StartsWith('Nodavo.AgentServerAuth.', [StringComparison]::Ordinal)) {
            continue
        }
        $value = $encodedEntry.Substring($separator + 1)
        if (-not $actualMetadata.TryAdd($key, $value)) {
            Fail "compiled Windows UI authentication policy contains duplicate metadata: $key"
        }
    }

    if ($actualMetadata.Count -ne $ExpectedMetadata.Count) {
        Fail "compiled Windows UI authentication policy has missing or extra metadata"
    }
    foreach ($entry in $ExpectedMetadata.GetEnumerator()) {
        $actualValue = $null
        if (-not $actualMetadata.TryGetValue([string] $entry.Key, [ref] $actualValue) -or
            $actualValue -cne [string] $entry.Value) {
            Fail "compiled Windows UI authentication policy metadata mismatch: $($entry.Key)"
        }
    }
}

function Find-WindowsSdkTool([string] $FileName) {
    $command = Get-Command $FileName -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    $sdkBin = Join-Path $programFilesX86 'Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $sdkBin -PathType Container)) {
        Fail "Windows SDK tools directory was not found: $sdkBin"
    }

    $candidate = Get-ChildItem -LiteralPath $sdkBin -Directory |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName "x64\$FileName" } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        Fail "Windows SDK tool was not found: $FileName"
    }
    return $candidate
}

function ConvertTo-XmlEscapedText([string] $Value) {
    return [System.Security.SecurityElement]::Escape($Value)
}

function Write-RenderedManifest(
    [string] $TemplatePath,
    [string] $DestinationPath,
    [string] $PackageIdentity,
    [string] $Publisher,
    [string] $PackageVersion,
    [string] $Architecture,
    [string] $DisplayName,
    [string] $PublisherDisplayName,
    [string] $Description
) {
    $rendered = [IO.File]::ReadAllText($TemplatePath)
    $replacements = [ordered]@{
        '@PACKAGE_IDENTITY@'       = ConvertTo-XmlEscapedText $PackageIdentity
        '@PUBLISHER@'              = ConvertTo-XmlEscapedText $Publisher
        '@PACKAGE_VERSION@'        = ConvertTo-XmlEscapedText $PackageVersion
        '@ARCHITECTURE@'           = ConvertTo-XmlEscapedText $Architecture
        '@DISPLAY_NAME@'           = ConvertTo-XmlEscapedText $DisplayName
        '@PUBLISHER_DISPLAY_NAME@' = ConvertTo-XmlEscapedText $PublisherDisplayName
        '@DESCRIPTION@'            = ConvertTo-XmlEscapedText $Description
    }
    foreach ($entry in $replacements.GetEnumerator()) {
        $rendered = $rendered.Replace($entry.Key, $entry.Value)
    }
    if ($rendered.Contains('@')) {
        Fail "unresolved token remains in rendered package manifest"
    }
    [IO.File]::WriteAllText(
        $DestinationPath,
        $rendered,
        [Text.UTF8Encoding]::new($false)
    )
}

function Get-PeMachine([string] $Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            Fail "file is not a PE executable: $Path"
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 6)) {
            Fail "PE header offset is invalid: $Path"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            Fail "PE signature is invalid: $Path"
        }
        return $reader.ReadUInt16()
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-PeArchitecture([string] $Path, [string] $Architecture) {
    $expected = switch ($Architecture) {
        'x64' { 0x8664 }
        'arm64' { 0xAA64 }
        default { Fail "unsupported PE architecture: $Architecture" }
    }
    $actual = Get-PeMachine $Path
    if ($actual -ne $expected) {
        Fail ("PE architecture mismatch for {0}: expected 0x{1:X4}, got 0x{2:X4}" -f `
            $Path, $expected, $actual)
    }
}

function Assert-CodeSigningCertificate(
    [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
    [string] $ExpectedPublisher,
    [Security.Cryptography.X509Certificates.X509Certificate2Collection] $CertificateBundle,
    [string[]] $AllowedChainThumbprints,
    [bool] $RequirePrivateKey
) {
    if ($RequirePrivateKey -and -not $Certificate.HasPrivateKey) {
        Fail "release signing certificate has no private key"
    }
    if (-not $RequirePrivateKey -and $Certificate.HasPrivateKey) {
        Fail "public release certificate input must not contain a private key"
    }
    if ($Certificate.Subject -cne $ExpectedPublisher) {
        Fail "certificate subject must exactly match WINDOWS_PACKAGE_PUBLISHER"
    }
    if ($Certificate.Subject -ceq $Certificate.Issuer) {
        Fail "release signing certificate must not be self-signed"
    }
    $now = [DateTime]::UtcNow
    if ($Certificate.NotBefore.ToUniversalTime() -gt $now) {
        Fail "release signing certificate is not valid yet"
    }
    if ($Certificate.NotAfter.ToUniversalTime() -le $now) {
        Fail "release signing certificate has expired"
    }

    $hasCodeSigningEku = $false
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($usage in $extension.EnhancedKeyUsages) {
                if ($usage.Value -eq '1.3.6.1.5.5.7.3.3') {
                    $hasCodeSigningEku = $true
                }
            }
        }
    }
    if (-not $hasCodeSigningEku) {
        Fail "release signing certificate lacks the Code Signing EKU"
    }

    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] -and
            $extension.CertificateAuthority) {
            Fail "release signing certificate must be an end-entity certificate, not a CA"
        }
    }

    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode =
            [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag =
            [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags =
            [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.TrustMode =
            [Security.Cryptography.X509Certificates.X509ChainTrustMode]::System
        $chain.ChainPolicy.DisableCertificateDownloads = $false
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(30)
        $chain.ChainPolicy.ApplicationPolicy.Add(
            [Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')
        ) | Out-Null
        foreach ($extraCertificate in $CertificateBundle) {
            if ($extraCertificate.Thumbprint -cne $Certificate.Thumbprint) {
                $chain.ChainPolicy.ExtraStore.Add($extraCertificate) | Out-Null
            }
        }
        if (-not $chain.Build($Certificate)) {
            $statuses = @($chain.ChainStatus |
                ForEach-Object { [string] $_.Status } |
                Sort-Object -Unique)
            $statusText = if ($statuses.Count -eq 0) { 'unknown chain error' } else { $statuses -join ', ' }
            Fail "release signing certificate failed online revocation/chain validation: $statusText"
        }
        if ($chain.ChainElements.Count -lt 2) {
            Fail "release signing certificate chain does not contain an issuer"
        }

        $issuerThumbprint = $chain.ChainElements[1].Certificate.Thumbprint.ToUpperInvariant()
        $rootThumbprint = $chain.ChainElements[
            $chain.ChainElements.Count - 1
        ].Certificate.Thumbprint.ToUpperInvariant()
        if ($issuerThumbprint -notin $AllowedChainThumbprints -and
            $rootThumbprint -notin $AllowedChainThumbprints) {
            Fail "release signing chain root or immediate issuer is not in WINDOWS_SIGNING_CHAIN_ALLOWLIST"
        }
    }
    finally {
        $chain.Dispose()
    }
}

function ConvertTo-ChainAllowlist([string] $Value) {
    $normalized = @()
    foreach ($entry in @($Value -split '[,;]')) {
        $thumbprint = $entry.Trim().ToUpperInvariant()
        if ($thumbprint -notmatch '^[0-9A-F]{40}$') {
            Fail "WINDOWS_SIGNING_CHAIN_ALLOWLIST must contain comma- or semicolon-separated 40-hex thumbprints"
        }
        if ($thumbprint -notin $normalized) {
            $normalized += $thumbprint
        }
    }
    if ($normalized.Count -eq 0) {
        Fail "WINDOWS_SIGNING_CHAIN_ALLOWLIST must contain at least one thumbprint"
    }
    return $normalized
}

function Get-WinTrustSignatureStatus([string] $Path, [bool] $HashOnly) {
    $winTrustType = 'Nodavo.WindowsPackaging.WinTrust' -as [type]
    if ($null -eq $winTrustType) {
        $compiledTypes = @(Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Nodavo.WindowsPackaging
{
    public static class WinTrust
    {
        public const int ErrorSuccess = 0;
        public const int CertificateUntrustedRoot = unchecked((int)0x800B0109);

        private const uint WtdUiNone = 2;
        private const uint WtdRevokeNone = 0;
        private const uint WtdChoiceFile = 1;
        private const uint WtdStateActionIgnore = 0;
        private const uint WtdRevocationCheckNone = 0x00000010;
        private const uint WtdHashOnlyFlag = 0x00000200;
        private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustFileInfo
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustData
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSipClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(
            IntPtr hwnd,
            ref Guid actionId,
            IntPtr trustData);

        public static int VerifyEmbeddedSignature(string filePath, bool hashOnly)
        {
            var fileInfo = new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };
            IntPtr fileInfoPointer = Marshal.AllocHGlobal(
                Marshal.SizeOf<WinTrustFileInfo>());
            IntPtr trustDataPointer = IntPtr.Zero;
            bool fileInfoMarshaled = false;
            try
            {
                Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
                fileInfoMarshaled = true;
                var trustData = new WinTrustData
                {
                    cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                    dwUIChoice = WtdUiNone,
                    fdwRevocationChecks = WtdRevokeNone,
                    dwUnionChoice = WtdChoiceFile,
                    pFile = fileInfoPointer,
                    dwStateAction = WtdStateActionIgnore,
                    dwProvFlags = WtdRevocationCheckNone |
                        WtdCacheOnlyUrlRetrieval |
                        (hashOnly ? WtdHashOnlyFlag : 0),
                };
                trustDataPointer = Marshal.AllocHGlobal(
                    Marshal.SizeOf<WinTrustData>());
                Marshal.StructureToPtr(trustData, trustDataPointer, false);

                var actionId = new Guid(
                    "00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
                return WinVerifyTrust(
                    new IntPtr(-1),
                    ref actionId,
                    trustDataPointer);
            }
            finally
            {
                if (trustDataPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(trustDataPointer);
                }
                if (fileInfoMarshaled)
                {
                    Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
                }
                Marshal.FreeHGlobal(fileInfoPointer);
            }
        }
    }
}
'@ -PassThru)
        $winTrustType = $compiledTypes | Where-Object {
            $_.FullName -ceq 'Nodavo.WindowsPackaging.WinTrust'
        } | Select-Object -First 1
    }
    if ($null -eq $winTrustType) {
        Fail "WinVerifyTrust helper type did not load"
    }
    $method = $winTrustType.GetMethod(
        'VerifyEmbeddedSignature',
        [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Static
    )
    if ($null -eq $method) {
        Fail "WinVerifyTrust helper method did not load"
    }
    return [int] $method.Invoke($null, [object[]] @($Path, $HashOnly))
}

function Get-AppxSignedCms([string] $BundlePath) {
    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    $archive = [IO.Compression.ZipFile]::OpenRead($BundlePath)
    try {
        $signatureEntries = @($archive.Entries | Where-Object {
            $_.FullName -ieq 'AppxSignature.p7x'
        })
        if ($signatureEntries.Count -ne 1) {
            Fail "development package must contain exactly one AppxSignature.p7x"
        }

        $stream = $signatureEntries[0].Open()
        try {
            $buffer = [IO.MemoryStream]::new()
            try {
                $stream.CopyTo($buffer)
                $signatureBytes = $buffer.ToArray()
            }
            finally {
                $buffer.Dispose()
            }
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $archive.Dispose()
    }

    if ($signatureBytes.Length -le 4 -or
        $signatureBytes[0] -ne 0x50 -or
        $signatureBytes[1] -ne 0x4B -or
        $signatureBytes[2] -ne 0x43 -or
        $signatureBytes[3] -ne 0x58) {
        Fail "development AppxSignature.p7x has an invalid PKCX header"
    }
    $cmsBytes = [byte[]]::new($signatureBytes.Length - 4)
    [Array]::Copy($signatureBytes, 4, $cmsBytes, 0, $cmsBytes.Length)
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
    try {
        $cms.Decode($cmsBytes)
        if ($cms.Detached) {
            Fail "development package signature must not be detached"
        }
        $cms.CheckSignature($true)
    }
    catch {
        Fail "development PKCS#7 signature verification failed: $($_.Exception.Message)"
    }
    return $cms
}

function Assert-DevelopmentSignature(
    [string] $BundlePath,
    [Security.Cryptography.X509Certificates.X509Certificate2] $ExpectedCertificate
) {
    # WinVerifyTrust's Authenticode provider validates the package subject. The
    # normal policy call must fail for one reason only: the freshly generated
    # self-signed root was intentionally not installed into a trust store.
    $trustStatus = Get-WinTrustSignatureStatus $BundlePath $false
    if ($trustStatus -ne $WinTrustCertificateUntrustedRoot) {
        $statusHex = '0x{0:X8}' -f ($trustStatus -band 0xFFFFFFFFL)
        Fail "development Authenticode policy returned unexpected status: $statusHex"
    }

    # WTD_HASH_ONLY_FLAG separates subject-integrity validation from Windows
    # certificate-store trust. CMS verification below then proves that the
    # validated subject was signed by the exact generated certificate.
    $hashStatus = Get-WinTrustSignatureStatus $BundlePath $true
    if ($hashStatus -ne $WinTrustErrorSuccess) {
        $statusHex = '0x{0:X8}' -f ($hashStatus -band 0xFFFFFFFFL)
        Fail "development Authenticode hash verification failed: $statusHex"
    }

    $cms = Get-AppxSignedCms $BundlePath
    if ($cms.SignerInfos.Count -ne 1) {
        Fail "development package must contain exactly one PKCS#7 signer"
    }
    $signer = $cms.SignerInfos[0]
    if ($signer.CounterSignerInfos.Count -ne 0) {
        Fail "development package must not contain a countersignature"
    }
    $signerCertificate = $signer.Certificate
    if ($null -eq $signerCertificate -or
        [Convert]::ToHexString($signerCertificate.RawData) -cne
            [Convert]::ToHexString($ExpectedCertificate.RawData)) {
        Fail "development package signer is not the exact generated certificate"
    }

    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode =
            [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags =
            [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.TrustMode =
            [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        $chain.ChainPolicy.ApplicationPolicy.Add(
            [Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')
        ) | Out-Null
        $chain.ChainPolicy.CustomTrustStore.Add($ExpectedCertificate) | Out-Null
        if (-not $chain.Build($signerCertificate)) {
            $statuses = @($chain.ChainStatus |
                ForEach-Object { [string] $_.Status } |
                Sort-Object -Unique)
            $statusText = if ($statuses.Count -eq 0) {
                'unknown chain error'
            }
            else {
                $statuses -join ', '
            }
            Fail "development signer failed custom-root validation: $statusText"
        }
        if ($chain.ChainElements.Count -ne 1 -or
            [Convert]::ToHexString($chain.ChainElements[0].Certificate.RawData) -cne
                [Convert]::ToHexString($ExpectedCertificate.RawData)) {
            Fail "development signer chain is not the exact generated self-signed certificate"
        }
    }
    finally {
        $chain.Dispose()
    }
}

function Assert-AuthenticodeSignature(
    [string] $Path,
    [Security.Cryptography.X509Certificates.X509Certificate2] $ExpectedCertificate,
    [bool] $IsDevelopment
) {
    $expectedTrustStatus = if ($IsDevelopment) {
        $WinTrustCertificateUntrustedRoot
    }
    else {
        $WinTrustErrorSuccess
    }
    if ((Get-WinTrustSignatureStatus $Path $false) -ne $expectedTrustStatus) {
        Fail "Windows executable Authenticode policy status does not match the selected package mode"
    }
    $hashStatus = Get-WinTrustSignatureStatus $Path $true
    if ($hashStatus -ne $WinTrustErrorSuccess) {
        Fail "Windows executable Authenticode subject-integrity verification failed"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($null -eq $signature.SignerCertificate -or
        [Convert]::ToHexString($signature.SignerCertificate.RawData) -cne
            [Convert]::ToHexString($ExpectedCertificate.RawData)) {
        Fail "Windows executable signer is not the exact certificate embedded in the agent policy"
    }
}

function Assert-PackageContent(
    [string] $BundlePath,
    [string] $MakeAppxPath,
    [string] $InspectionRoot,
    [string] $ExpectedIdentity,
    [string] $ExpectedPublisher,
    [string] $ExpectedVersion,
    [string] $ExpectedDisplayName,
    [string] $ExpectedPackageFamilyName,
    [string] $ExpectedApplicationId,
    [string] $ExpectedExecutable,
    [string] $ExpectedAgentExecutable,
    [string] $ExpectedStartupTaskId,
    [System.Collections.IDictionary] $ExpectedAgentServerAuthMetadata,
    [Security.Cryptography.X509Certificates.X509Certificate2] $ExpectedUiSigner,
    [bool] $IsDevelopment
) {
    if (Test-Path -LiteralPath $InspectionRoot) {
        Remove-Item -LiteralPath $InspectionRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $InspectionRoot | Out-Null
    Invoke-Native $MakeAppxPath @('unbundle', '/p', $BundlePath, '/d', $InspectionRoot, '/o')

    $packages = @(Get-ChildItem -LiteralPath $InspectionRoot -File -Filter '*.msix')
    if ($packages.Count -ne 2) {
        Fail "bundle must contain exactly two architecture packages"
    }

    $seen = @{}
    foreach ($package in $packages) {
        $expanded = Join-Path $InspectionRoot $package.BaseName
        Invoke-Native $MakeAppxPath @('unpack', '/p', $package.FullName, '/d', $expanded, '/o')
        $manifestPath = Join-Path $expanded 'AppxManifest.xml'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            Fail "package does not contain AppxManifest.xml"
        }
        [xml] $manifest = Get-Content -LiteralPath $manifestPath -Raw
        $identity = $manifest.Package.Identity
        if ($identity.Name -cne $ExpectedIdentity -or
            $identity.Publisher -cne $ExpectedPublisher -or
            $identity.Version -cne $ExpectedVersion) {
            Fail "package identity does not match the requested release identity"
        }
        if ((Get-PackageFamilyName $identity.Name $identity.Publisher) -cne
            $ExpectedPackageFamilyName) {
            Fail "package family name does not match the embedded agent policy"
        }
        $architecture = [string] $identity.ProcessorArchitecture
        if ($architecture -notin @('x64', 'arm64') -or $seen.ContainsKey($architecture)) {
            Fail "bundle has a missing, duplicate, or unsupported architecture"
        }
        $seen[$architecture] = $true

        $applications = @($manifest.SelectNodes("//*[local-name()='Application']"))
        if ($applications.Count -ne 1) {
            Fail "package must contain exactly one application declaration"
        }
        $application = $applications[0]
        if ($application.Id -cne $ExpectedApplicationId -or
            $application.Executable -cne $ExpectedExecutable) {
            Fail "package application identity/executable does not match the embedded agent policy"
        }
        $runtimeBehavior = $application.GetAttribute(
            'RuntimeBehavior',
            'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'
        )
        $trustLevel = $application.GetAttribute(
            'TrustLevel',
            'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'
        )
        if ($runtimeBehavior -cne 'packagedClassicApp' -or $trustLevel -cne 'mediumIL') {
            Fail "application must be a packagedClassicApp at mediumIL"
        }

        $foundationNamespace = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10'
        $desktopNamespace = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10'
        $extensionContainers = @($application.ChildNodes | Where-Object {
            $_.NodeType -eq [Xml.XmlNodeType]::Element -and
            $_.NamespaceURI -ceq $foundationNamespace -and $_.LocalName -ceq 'Extensions'
        })
        if ($extensionContainers.Count -ne 1) {
            Fail "application must contain exactly one extension container"
        }
        $extensions = @($extensionContainers[0].ChildNodes | Where-Object {
            $_.NodeType -eq [Xml.XmlNodeType]::Element
        })
        if ($extensions.Count -ne 1) {
            Fail "package must contain exactly one application extension"
        }
        $startupExtension = $extensions[0]
        if ($startupExtension.Attributes.Count -ne 3 -or
            $startupExtension.NamespaceURI -cne $desktopNamespace -or
            $startupExtension.LocalName -cne 'Extension' -or
            $startupExtension.GetAttribute('Category') -cne 'windows.startupTask' -or
            $startupExtension.GetAttribute('Executable') -cne $ExpectedAgentExecutable -or
            $startupExtension.GetAttribute('EntryPoint') -cne 'Windows.FullTrustApplication') {
            Fail "startup extension must target the exact bundled per-user agent"
        }
        $startupTasks = @($startupExtension.ChildNodes | Where-Object {
            $_.NodeType -eq [Xml.XmlNodeType]::Element
        })
        if ($startupTasks.Count -ne 1 -or
            $startupTasks[0].Attributes.Count -ne 3 -or
            $startupTasks[0].NamespaceURI -cne $desktopNamespace -or
            $startupTasks[0].LocalName -cne 'StartupTask' -or
            $startupTasks[0].GetAttribute('TaskId') -cne $ExpectedStartupTaskId -or
            $startupTasks[0].GetAttribute('Enabled') -cne 'false' -or
            $startupTasks[0].GetAttribute('DisplayName') -cne
                'ms-resource:StartupTaskDisplayName') {
            Fail "startup task must be exact, user-configurable, and disabled by default"
        }
        if (@($manifest.SelectNodes("//*[local-name()='FullTrustProcess']")).Count -ne 0 -or
            @($manifest.SelectNodes("//*[@*[local-name()='ImmediateRegistration']]")).Count -ne 0) {
            Fail "unsupported full-trust launcher or non-user-configurable startup is forbidden"
        }

        $propertyDisplayNames = @($manifest.SelectNodes(
            "/*[local-name()='Package']/*[local-name()='Properties']/*[local-name()='DisplayName']"
        ))
        $visualElements = @($manifest.SelectNodes("//*[local-name()='VisualElements']"))
        if ($propertyDisplayNames.Count -ne 1 -or
            $propertyDisplayNames[0].InnerText -cne $ExpectedDisplayName -or
            $visualElements.Count -ne 1 -or
            $visualElements[0].GetAttribute('DisplayName') -cne $ExpectedDisplayName) {
            Fail "package display names do not exactly match the selected identity"
        }

        $capabilityContainers = @($manifest.SelectNodes(
            "/*[local-name()='Package']/*[local-name()='Capabilities']"
        ))
        if ($capabilityContainers.Count -ne 1) {
            Fail "package must contain exactly one capability declaration container"
        }
        $capabilityElements = @($capabilityContainers[0].ChildNodes | Where-Object {
            $_.NodeType -eq [Xml.XmlNodeType]::Element
        })
        $restrictedNamespace =
            'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities'
        $actualCapabilities = @($capabilityElements | ForEach-Object {
            '{0}|{1}|{2}' -f $_.NamespaceURI, $_.LocalName, $_.GetAttribute('Name')
        } | Sort-Object)
        $expectedCapabilities = @(
            "$foundationNamespace|Capability|privateNetworkClientServer",
            "$restrictedNamespace|Capability|runFullTrust"
        ) | Sort-Object
        $capabilityDifference = @(Compare-Object `
            -ReferenceObject $expectedCapabilities `
            -DifferenceObject $actualCapabilities)
        if ($actualCapabilities.Count -ne 2 -or $capabilityDifference.Count -ne 0) {
            Fail "package capability multiset must be exactly privateNetworkClientServer and runFullTrust"
        }
        $allCapabilityDeclarations = @($manifest.SelectNodes(
            "//*[local-name()='Capability' or local-name()='DeviceCapability']"
        ))
        if ($allCapabilityDeclarations.Count -ne 2) {
            Fail "DeviceCapability or out-of-container capability declarations are forbidden"
        }
        if (@($capabilityElements | Where-Object {
            $_.LocalName -ne 'Capability'
        }).Count -ne 0) {
            Fail "custom capability elements are forbidden"
        }
        $expectedCapabilityNames = @(
            'privateNetworkClientServer',
            'runFullTrust'
        )
        $capabilityNames = @($capabilityElements | ForEach-Object {
            $_.GetAttribute('Name')
        })
        if (@(Compare-Object `
            -ReferenceObject ($expectedCapabilityNames | Sort-Object) `
            -DifferenceObject ($capabilityNames | Sort-Object)).Count -ne 0) {
            Fail "unexpected package capability name"
        }
        if (@($manifest.SelectNodes("//*[local-name()='Service']")).Count -ne 0) {
            Fail "Windows services are forbidden in the Nodavo 1.0 package"
        }

        $uiPath = Join-Path $expanded 'Nodavo.Windows.exe'
        $uiAssemblyPath = Join-Path $expanded 'Nodavo.Windows.dll'
        $agentPath = Join-Path $expanded 'agent\nodavo-agent.exe'
        if (-not (Test-Path -LiteralPath $uiPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $uiAssemblyPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $agentPath -PathType Leaf)) {
            Fail "package is missing the UI assembly, UI executable, or per-user session agent"
        }
        Assert-PeArchitecture $uiPath $architecture
        Assert-PeArchitecture $agentPath $architecture
        Assert-CompiledAgentServerAuthMetadata `
            $uiAssemblyPath `
            $ExpectedAgentServerAuthMetadata
        Assert-AuthenticodeSignature $uiPath $ExpectedUiSigner $IsDevelopment
        Assert-AuthenticodeSignature $agentPath $ExpectedUiSigner $IsDevelopment

        $developmentMarker = Join-Path $expanded 'DEVELOPMENT-NOT-FOR-DISTRIBUTION.txt'
        $developmentMarkerRu = Join-Path $expanded 'DEVELOPMENT-NOT-FOR-DISTRIBUTION.ru.txt'
        if ($IsDevelopment -and -not (Test-Path -LiteralPath $developmentMarker -PathType Leaf)) {
            Fail "development package is missing its in-package distribution warning"
        }
        if ($IsDevelopment -and -not (Test-Path -LiteralPath $developmentMarkerRu -PathType Leaf)) {
            Fail "development package is missing its Russian in-package distribution warning"
        }
        if (-not $IsDevelopment -and (Test-Path -LiteralPath $developmentMarker)) {
            Fail "release package contains a development marker"
        }
        if (-not $IsDevelopment -and (Test-Path -LiteralPath $developmentMarkerRu)) {
            Fail "release package contains a development marker"
        }

        $secretFiles = @(Get-ChildItem -LiteralPath $expanded -Recurse -File | Where-Object {
            $_.Extension -in @('.pfx', '.p12', '.pem', '.key')
        })
        if ($secretFiles.Count -ne 0) {
            Fail "package contains a private-key file"
        }
    }
    if (-not $seen.ContainsKey('x64') -or -not $seen.ContainsKey('arm64')) {
        Fail "bundle must contain both x64 and ARM64 packages"
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Fail "this script must run on Windows with the Windows SDK installed"
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot 'target\windows-packages'
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$projectPath = Join-Path $repositoryRoot 'apps\windows\src\Nodavo.Windows\Nodavo.Windows.csproj'
$solutionPath = Join-Path $repositoryRoot 'apps\windows\Nodavo.Windows.sln'
$manifestTemplate = Join-Path $repositoryRoot 'apps\windows\packaging\AppxManifest.xml.in'
$identityPath = Join-Path $repositoryRoot 'apps\windows\packaging\identity.json'
$developmentWarningPath = Join-Path $repositoryRoot `
    'apps\windows\packaging\DEVELOPMENT-NOT-FOR-DISTRIBUTION.txt'
$developmentWarningRuPath = Join-Path $repositoryRoot `
    'apps\windows\packaging\DEVELOPMENT-NOT-FOR-DISTRIBUTION.ru.txt'
foreach ($requiredPath in @(
    $projectPath,
    $solutionPath,
    $manifestTemplate,
    $identityPath,
    $developmentWarningPath,
    $developmentWarningRuPath
)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        Fail "required packaging input is missing: $requiredPath"
    }
}

$versionParts = @($Version.Split('.') | ForEach-Object { [int] $_ })
foreach ($part in $versionParts) {
    if ($part -lt 0 -or $part -gt 65535) {
        Fail "each version component must be between 0 and 65535"
    }
}
$packageVersion = "$Version.$BuildNumber"
$mode = if ($Development) { 'development' } else { 'release' }
$identityConfiguration = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
if ($identityConfiguration.schemaVersion -ne 1) {
    Fail "unsupported Windows package identity configuration"
}
$agentExecutable = [string] $identityConfiguration.lifecycle.agentExecutable
$startupTaskId = [string] $identityConfiguration.lifecycle.startupTaskId
if ($agentExecutable -cne 'agent\nodavo-agent.exe' -or
    $startupTaskId -cne 'NodavoAgentStartup') {
    Fail "Windows lifecycle policy requires the exact bundled agent and startup task ID"
}

$releasePfxPath = $null
$releaseCertificatePath = $null
$releasePfxPassword = $null
$timestampUrl = $null
$releaseAllowedChainThumbprints = @()
$releaseCertificateBundle = $null
$releaseCertificate = $null
$releaseImportedThumbprints = @()
$releaseSignerThumbprint = $null
$developmentCertificate = $null
$packagingCompleted = $false

if ($Development) {
    $packageIdentity = [string] $identityConfiguration.development.packageIdentityName
    $publisher = [string] $identityConfiguration.development.publisher
    $applicationId = [string] $identityConfiguration.development.applicationId
    $executable = [string] $identityConfiguration.development.executable
    $publisherDisplayName = [string] $identityConfiguration.development.publisherDisplayName
    $displayName = [string] $identityConfiguration.development.displayName
    $description = [string] $identityConfiguration.development.description
}
else {
    $packageIdentity = [string] $identityConfiguration.release.packageIdentityName
    $applicationId = [string] $identityConfiguration.release.applicationId
    $executable = [string] $identityConfiguration.release.executable
    $displayName = [string] $identityConfiguration.release.displayName
    $description = [string] $identityConfiguration.release.description
    $publisher = [Environment]::GetEnvironmentVariable('WINDOWS_PACKAGE_PUBLISHER')
    $expectedPackageFamilyName = [Environment]::GetEnvironmentVariable(
        'WINDOWS_PACKAGE_FAMILY_NAME'
    )
    $publisherDisplayName = [Environment]::GetEnvironmentVariable('WINDOWS_PUBLISHER_DISPLAY_NAME')
    $releasePfxPath = [Environment]::GetEnvironmentVariable('WINDOWS_SIGNING_PFX')
    $releaseCertificatePath = [Environment]::GetEnvironmentVariable(
        'WINDOWS_SIGNING_CERTIFICATE'
    )
    $releasePfxPasswordPlain = [Environment]::GetEnvironmentVariable('WINDOWS_SIGNING_PFX_PASSWORD')
    $releasePfxPasswordMissing = [string]::IsNullOrWhiteSpace($releasePfxPasswordPlain)
    try {
        if (-not $releasePfxPasswordMissing) {
            $releasePfxPassword = ConvertTo-SecureString `
                $releasePfxPasswordPlain -AsPlainText -Force
        }
    }
    finally {
        $releasePfxPasswordPlain = $null
        [Environment]::SetEnvironmentVariable(
            'WINDOWS_SIGNING_PFX_PASSWORD',
            $null,
            [EnvironmentVariableTarget]::Process
        )
        Remove-Item -LiteralPath 'Env:\WINDOWS_SIGNING_PFX_PASSWORD' `
            -Force -ErrorAction SilentlyContinue
    }
    $timestampUrl = [Environment]::GetEnvironmentVariable('WINDOWS_TIMESTAMP_URL')
    $chainAllowlist = [Environment]::GetEnvironmentVariable(
        'WINDOWS_SIGNING_CHAIN_ALLOWLIST'
    )
    $missing = @()
    foreach ($entry in ([ordered]@{
        WINDOWS_PACKAGE_PUBLISHER = $publisher
        WINDOWS_PACKAGE_FAMILY_NAME = $expectedPackageFamilyName
        WINDOWS_PUBLISHER_DISPLAY_NAME = $publisherDisplayName
        WINDOWS_SIGNING_PFX = $releasePfxPath
        WINDOWS_SIGNING_CERTIFICATE = $releaseCertificatePath
        WINDOWS_TIMESTAMP_URL = $timestampUrl
        WINDOWS_SIGNING_CHAIN_ALLOWLIST = $chainAllowlist
    }).GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace([string] $entry.Value)) {
            $missing += $entry.Key
        }
    }
    if ($releasePfxPasswordMissing) {
        $missing += 'WINDOWS_SIGNING_PFX_PASSWORD'
    }
    if ($missing.Count -ne 0) {
        Fail ("release mode refuses to run without: " + ($missing -join ', '))
    }
    $releaseAllowedChainThumbprints = @(ConvertTo-ChainAllowlist $chainAllowlist)
    $chainAllowlist = $null
    $releasePfxPath = [IO.Path]::GetFullPath($releasePfxPath)
    if (-not (Test-Path -LiteralPath $releasePfxPath -PathType Leaf)) {
        Fail "WINDOWS_SIGNING_PFX does not point to a file"
    }
    $releaseCertificatePath = [IO.Path]::GetFullPath($releaseCertificatePath)
    if (-not (Test-Path -LiteralPath $releaseCertificatePath -PathType Leaf)) {
        Fail "WINDOWS_SIGNING_CERTIFICATE does not point to a file"
    }
    if (-not [Uri]::IsWellFormedUriString($timestampUrl, [UriKind]::Absolute) -or
        -not $timestampUrl.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        Fail "WINDOWS_TIMESTAMP_URL must be an absolute HTTPS URL"
    }
}

if ($packageIdentity -notmatch '^[A-Za-z0-9.-]{3,50}$' -or
    $packageIdentity.EndsWith('.', [StringComparison]::Ordinal)) {
    Fail "configured package identity name is invalid"
}
foreach ($value in @($publisher, $publisherDisplayName, $displayName, $description)) {
    if ([string]::IsNullOrWhiteSpace($value)) {
        Fail "package identity metadata contains an empty value"
    }
}
if ($applicationId -cne 'App' -or $executable -cne 'Nodavo.Windows.exe') {
    Fail "Windows package policy requires exact App / Nodavo.Windows.exe identity"
}
$packageFamilyName = Get-PackageFamilyName $packageIdentity $publisher
if ($Development) {
    if ($packageIdentity -cne 'dev.nodavo.Nodavo.Development' -or
        $publisher -cne 'CN=Nodavo Development Only') {
        Fail "development package identity does not match the isolated compile-time policy"
    }
}
elseif ($packageIdentity -cne 'dev.nodavo.Nodavo' -or
    $packageFamilyName -cne $expectedPackageFamilyName) {
    Fail "release package identity/PFN does not match WINDOWS_PACKAGE_FAMILY_NAME"
}
$applicationUserModelId = "$packageFamilyName!$applicationId"
$rustAuthFeature = if ($Development) {
    'windows-ui-auth-development'
}
else {
    'windows-ui-auth-release'
}

$cargo = Get-RequiredCommand 'cargo.exe'
foreach ($rustTarget in @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')) {
    $agentFeatureTree = & $cargo @(
        'tree', '--locked', '--manifest-path', (Join-Path $repositoryRoot 'Cargo.toml'),
        '-e', 'features', '-p', 'nodavo-agent',
        '--no-default-features', '--features', $rustAuthFeature,
        '--target', $rustTarget
    )
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect the exact nodavo-agent Cargo feature tree for $rustTarget."
    }
    if (($agentFeatureTree -join "`n").IndexOf(
            'nodavo-update feature "supervisor-host"',
            [StringComparison]::Ordinal) -ge 0) {
        throw 'nodavo-agent must not enable the supervisor-only update reducer feature.'
    }
}
$rustup = Get-RequiredCommand 'rustup.exe'
$dotnet = Get-RequiredCommand 'dotnet.exe'
$makeAppx = Find-WindowsSdkTool 'makeappx.exe'
$signTool = Find-WindowsSdkTool 'signtool.exe'

$artifactRoot = Join-Path $OutputDirectory "$packageVersion-$mode"
$workRoot = Join-Path $repositoryRoot "target\package-windows\$packageVersion-$mode-$PID"
$artifactComparable = $artifactRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
$workComparable = $workRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if ($artifactComparable.StartsWith($workComparable, [StringComparison]::OrdinalIgnoreCase) -or
    $workComparable.StartsWith($artifactComparable, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "artifact and private work directories must not overlap"
}
if (Test-Path -LiteralPath $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null

try {
    if ($Development) {
        $developmentCertificate = New-SelfSignedCertificate `
            -Type Custom `
            -Subject $publisher `
            -FriendlyName "Nodavo Development Package $packageVersion" `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -KeyAlgorithm RSA `
            -KeyLength 3072 `
            -HashAlgorithm SHA256 `
            -KeyUsage DigitalSignature `
            -NotAfter ([DateTime]::UtcNow.AddDays(30)) `
            -TextExtension @(
                '2.5.29.37={text}1.3.6.1.5.5.7.3.3',
                '2.5.29.19={text}'
            )
        $embeddedSignerCertificate = $developmentCertificate
    }
    else {
        $releaseCertificate =
            [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $releaseCertificatePath
            )
        $releaseCertificateBundle =
            [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $releaseCertificateBundle.Add($releaseCertificate) | Out-Null
        Assert-CodeSigningCertificate `
            $releaseCertificate `
            $publisher `
            $releaseCertificateBundle `
            $releaseAllowedChainThumbprints `
            $false
        $releaseSignerThumbprint = $releaseCertificate.Thumbprint.ToUpperInvariant()
        $embeddedSignerCertificate =
            [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $releaseCertificate.RawData
            )
        foreach ($certificate in $releaseCertificateBundle) {
            $certificate.Dispose()
        }
        $releaseCertificateBundle = $null
        $releaseCertificate = $null
        [Environment]::SetEnvironmentVariable(
            'WINDOWS_SIGNING_PFX',
            $null,
            [EnvironmentVariableTarget]::Process
        )
        Remove-Item -LiteralPath 'Env:\WINDOWS_SIGNING_PFX' `
            -Force -ErrorAction SilentlyContinue
        [Environment]::SetEnvironmentVariable(
            'WINDOWS_SIGNING_CERTIFICATE',
            $null,
            [EnvironmentVariableTarget]::Process
        )
        Remove-Item -LiteralPath 'Env:\WINDOWS_SIGNING_CERTIFICATE' `
            -Force -ErrorAction SilentlyContinue
    }

    $signerCertificateSha256 = Get-CertificateSha256 $embeddedSignerCertificate
    $agentServerAuthPackageNameBase64 = ConvertTo-Utf8Base64 $packageIdentity
    $agentServerAuthPublisherBase64 = ConvertTo-Utf8Base64 $publisher
    $agentServerAuthPackageFamilyNameBase64 = ConvertTo-Utf8Base64 $packageFamilyName
    $agentServerAuthApplicationUserModelIdBase64 = ConvertTo-Utf8Base64 `
        $applicationUserModelId
    $agentServerAuthRelativeExecutableBase64 = ConvertTo-Utf8Base64 $agentExecutable
    $agentServerAuthMetadata = [ordered]@{
        'Nodavo.AgentServerAuth.Mode' = $mode
        'Nodavo.AgentServerAuth.PackageNameBase64' = $agentServerAuthPackageNameBase64
        'Nodavo.AgentServerAuth.PublisherBase64' = $agentServerAuthPublisherBase64
        'Nodavo.AgentServerAuth.PackageFamilyNameBase64' = `
            $agentServerAuthPackageFamilyNameBase64
        'Nodavo.AgentServerAuth.ApplicationUserModelIdBase64' = `
            $agentServerAuthApplicationUserModelIdBase64
        'Nodavo.AgentServerAuth.RelativeExecutableBase64' = `
            $agentServerAuthRelativeExecutableBase64
        'Nodavo.AgentServerAuth.SignerCertificateSha256' = $signerCertificateSha256
    }
    $agentServerAuthMsBuildProperties = @(
        "-p:NodavoAgentServerAuthMode=$mode",
        "-p:NodavoAgentServerAuthPackageNameBase64=$agentServerAuthPackageNameBase64",
        "-p:NodavoAgentServerAuthPublisherBase64=$agentServerAuthPublisherBase64",
        "-p:NodavoAgentServerAuthPackageFamilyNameBase64=$agentServerAuthPackageFamilyNameBase64",
        "-p:NodavoAgentServerAuthApplicationUserModelIdBase64=$agentServerAuthApplicationUserModelIdBase64",
        "-p:NodavoAgentServerAuthRelativeExecutableBase64=$agentServerAuthRelativeExecutableBase64",
        "-p:NodavoAgentServerAuthSignerCertificateSha256=$signerCertificateSha256"
    )
    [Environment]::SetEnvironmentVariable(
        'NODAVO_WINDOWS_AUTH_SIGNER_CERT_SHA256',
        $signerCertificateSha256,
        [EnvironmentVariableTarget]::Process
    )
    [Environment]::SetEnvironmentVariable(
        'NODAVO_WINDOWS_AUTH_PACKAGE_FAMILY_NAME',
        $packageFamilyName,
        [EnvironmentVariableTarget]::Process
    )
    [Environment]::SetEnvironmentVariable(
        'NODAVO_WINDOWS_AUTH_PUBLISHER',
        $publisher,
        [EnvironmentVariableTarget]::Process
    )

    $bundleInput = Join-Path $workRoot 'bundle-input'
    $rustOutputRoot = Join-Path $workRoot 'rust-target'
    New-Item -ItemType Directory -Path $bundleInput | Out-Null
    New-Item -ItemType Directory -Path $rustOutputRoot | Out-Null
    $architectures = @(
        [pscustomobject]@{ Platform = 'x64'; Architecture = 'x64'; Rid = 'win-x64'; RustTarget = 'x86_64-pc-windows-msvc' },
        [pscustomobject]@{ Platform = 'ARM64'; Architecture = 'arm64'; Rid = 'win-arm64'; RustTarget = 'aarch64-pc-windows-msvc' }
    )
    $stagedTargets = @()

    foreach ($target in $architectures) {
        $publishRoot = Join-Path $workRoot "publish-$($target.Architecture)"
        $stageRoot = Join-Path $workRoot "stage-$($target.Architecture)"
        New-Item -ItemType Directory -Path $publishRoot | Out-Null
        New-Item -ItemType Directory -Path $stageRoot | Out-Null

        Invoke-Native $rustup @('target', 'add', $target.RustTarget)
        Invoke-Native $cargo @(
            'build', '--locked', '--release', '-p', 'nodavo-agent',
            '--no-default-features',
            '--features', $rustAuthFeature,
            '--target', $target.RustTarget,
            '--target-dir', $rustOutputRoot
        )
        $restoreArguments = @(
            'restore', $solutionPath,
            "-p:Platform=$($target.Platform)",
            "-p:RuntimeIdentifier=$($target.Rid)",
            '-p:NodavoPackageMode=Unpackaged',
            '-p:WindowsPackageType=None',
            '-p:SelfContained=true',
            '-p:WindowsAppSDKSelfContained=true',
            '-p:PublishTrimmed=false',
            '-p:PublishSingleFile=false'
        ) + $agentServerAuthMsBuildProperties
        Invoke-Native $dotnet $restoreArguments
        $publishArguments = @(
            'publish', $projectPath, '--no-restore',
            '--configuration', 'Release',
            "-p:Platform=$($target.Platform)",
            "-p:RuntimeIdentifier=$($target.Rid)",
            '-p:NodavoPackageMode=Unpackaged',
            '-p:WindowsPackageType=None',
            '-p:SelfContained=true',
            '-p:WindowsAppSDKSelfContained=true',
            '-p:PublishTrimmed=false',
            '-p:PublishSingleFile=false',
            "-p:PublishDir=$publishRoot"
        ) + $agentServerAuthMsBuildProperties
        Invoke-Native $dotnet $publishArguments
        Assert-CompiledAgentServerAuthMetadata `
            (Join-Path $publishRoot 'Nodavo.Windows.dll') `
            $agentServerAuthMetadata
        Copy-Item -Path (Join-Path $publishRoot '*') -Destination $stageRoot -Recurse -Force

        $agentSource = Join-Path $rustOutputRoot `
            "$($target.RustTarget)\release\nodavo-agent.exe"
        $agentDirectory = Join-Path $stageRoot 'agent'
        New-Item -ItemType Directory -Path $agentDirectory | Out-Null
        Copy-Item -LiteralPath $agentSource `
            -Destination (Join-Path $agentDirectory 'nodavo-agent.exe') -Force

        Get-ChildItem -LiteralPath $stageRoot -Recurse -File -Filter '*.pdb' |
            Remove-Item -Force
        $projectManifestCopy = Join-Path $stageRoot 'Package.appxmanifest'
        if (Test-Path -LiteralPath $projectManifestCopy) {
            Remove-Item -LiteralPath $projectManifestCopy -Force
        }
        $uiPath = Join-Path $stageRoot 'Nodavo.Windows.exe'
        $agentPath = Join-Path $stageRoot 'agent\nodavo-agent.exe'
        Assert-PeArchitecture $uiPath $target.Architecture
        Assert-PeArchitecture $agentPath $target.Architecture
        if ($target.Architecture -ceq 'x64') {
            $selfCheck = @(& $agentPath '--self-check')
            if ($LASTEXITCODE -ne 0 -or $selfCheck.Count -ne 1 -or
                $selfCheck[0] -cne
                    "nodavo-agent: core runtime available; windows-ui-auth=$mode") {
                Fail "Windows agent compile-time authentication policy self-check failed"
            }
        }
        $stagedTargets += [pscustomobject]@{
            Architecture = $target.Architecture
            StageRoot = $stageRoot
            UiPath = $uiPath
            AgentPath = $agentPath
        }
    }

    if (-not $Development) {
        $releaseCertificateBundle =
            [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $releaseCertificateBundle.Import(
            $releasePfxPath,
            $releasePfxPassword,
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        )
        $privateKeyCertificates = @($releaseCertificateBundle | Where-Object {
            $_.HasPrivateKey
        })
        if ($privateKeyCertificates.Count -ne 1) {
            Fail "release PFX changed after policy compilation"
        }
        $releaseCertificate = $privateKeyCertificates[0]
        Assert-CodeSigningCertificate `
            $releaseCertificate `
            $publisher `
            $releaseCertificateBundle `
            $releaseAllowedChainThumbprints `
            $true
        if ($releaseCertificate.Thumbprint.ToUpperInvariant() -cne $releaseSignerThumbprint -or
            [Convert]::ToHexString($releaseCertificate.RawData) -cne
                [Convert]::ToHexString($embeddedSignerCertificate.RawData)) {
            Fail "release signer changed after policy compilation"
        }
        $candidateReleaseImportThumbprints = @($releaseCertificateBundle |
            ForEach-Object { $_.Thumbprint.ToUpperInvariant() } |
            Sort-Object -Unique)
        foreach ($thumbprint in $candidateReleaseImportThumbprints) {
            if (Test-Path -LiteralPath "Cert:\CurrentUser\My\$thumbprint") {
                Fail "release PFX certificate already exists in CurrentUser/My"
            }
        }
        # Cleanup ownership starts only after every preexistence check passes.
        # Assign before import so a provider failure after a partial import is
        # still cleaned by the exact, prevalidated PFX thumbprint set.
        $releaseImportedThumbprints = $candidateReleaseImportThumbprints
        $importedCertificates = @(Import-PfxCertificate `
            -FilePath $releasePfxPath `
            -Password $releasePfxPassword `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -Exportable:$false)
        $importedSigningLeaves = @($importedCertificates | Where-Object {
            $_.Thumbprint.ToUpperInvariant() -ceq $releaseSignerThumbprint -and $_.HasPrivateKey
        })
        if ($importedSigningLeaves.Count -ne 1) {
            Fail "release PFX import did not produce exactly one expected signing leaf"
        }
    }

    foreach ($staged in $stagedTargets) {
        $uiPath = $staged.UiPath
        $agentPath = $staged.AgentPath
        foreach ($executablePath in @($uiPath, $agentPath)) {
            if ($Development) {
                Invoke-Native $signTool @(
                    'sign', '/v', '/fd', 'SHA256',
                    '/sha1', $developmentCertificate.Thumbprint,
                    '/s', 'My', $executablePath
                )
            }
            else {
                Invoke-Native $signTool @(
                    'sign', '/v', '/fd', 'SHA256',
                    '/sha1', $releaseSignerThumbprint,
                    '/s', 'My',
                    '/tr', $timestampUrl,
                    '/td', 'SHA256',
                    '/d', 'Nodavo',
                    $executablePath
                )
                Invoke-Native $signTool @(
                    'verify', '/pa', '/all', '/v', '/tw', $executablePath
                )
            }
            Assert-AuthenticodeSignature `
                $executablePath `
                $embeddedSignerCertificate `
                ([bool] $Development)
        }

        if ($Development) {
            Copy-Item -LiteralPath $developmentWarningPath -Destination $staged.StageRoot
            Copy-Item -LiteralPath $developmentWarningRuPath -Destination $staged.StageRoot
        }
        Write-RenderedManifest `
            $manifestTemplate `
            (Join-Path $staged.StageRoot 'AppxManifest.xml') `
            $packageIdentity `
            $publisher `
            $packageVersion `
            $staged.Architecture `
            $displayName `
            $publisherDisplayName `
            $description

        $packagePath = Join-Path $bundleInput `
            "Nodavo-$packageVersion-$($staged.Architecture).msix"
        Invoke-Native $makeAppx @('pack', '/d', $staged.StageRoot, '/p', $packagePath, '/o')
    }

    $bundleName = if ($Development) {
        "Nodavo-$packageVersion-DEVELOPMENT-NOT-FOR-DISTRIBUTION.msixbundle"
    }
    else {
        "Nodavo-$packageVersion.msixbundle"
    }
    $bundlePath = Join-Path $artifactRoot $bundleName
    Invoke-Native $makeAppx @(
        'bundle', '/d', $bundleInput, '/p', $bundlePath, '/bv', $packageVersion, '/o'
    )

    Assert-PackageContent `
        $bundlePath `
        $makeAppx `
        (Join-Path $workRoot 'unsigned-inspection') `
        $packageIdentity `
        $publisher `
        $packageVersion `
        $displayName `
        $packageFamilyName `
        $applicationId `
        $executable `
        $agentExecutable `
        $startupTaskId `
        $agentServerAuthMetadata `
        $embeddedSignerCertificate `
        ([bool] $Development)

    if ($Development) {
        $certificatePath = Join-Path $artifactRoot `
            'Nodavo-DEVELOPMENT-NOT-FOR-DISTRIBUTION.cer'
        Export-Certificate -Cert $developmentCertificate -FilePath $certificatePath -Force | Out-Null
        Invoke-Native $signTool @(
            'sign', '/v', '/fd', 'SHA256',
            '/sha1', $developmentCertificate.Thumbprint,
            '/s', 'My', $bundlePath
        )

        # Verify the package hash through WinVerifyTrust, then verify and bind
        # the PKCS#7 signer to an in-memory custom-root chain. Development CI
        # never mutates TrustedPeople or Root stores.
        Assert-DevelopmentSignature $bundlePath $developmentCertificate

        Copy-Item -LiteralPath $developmentWarningPath -Destination $artifactRoot
        Copy-Item -LiteralPath $developmentWarningRuPath -Destination $artifactRoot
    }
    else {
        Invoke-Native $signTool @(
            'sign', '/v', '/fd', 'SHA256',
            '/sha1', $releaseCertificate.Thumbprint,
            '/s', 'My',
            '/tr', $timestampUrl,
            '/td', 'SHA256',
            '/d', 'Nodavo',
            $bundlePath
        )
        Invoke-Native $signTool @('verify', '/pa', '/all', '/v', '/tw', $bundlePath)
    }

    Assert-PackageContent `
        $bundlePath `
        $makeAppx `
        (Join-Path $workRoot 'inspection') `
        $packageIdentity `
        $publisher `
        $packageVersion `
        $displayName `
        $packageFamilyName `
        $applicationId `
        $executable `
        $agentExecutable `
        $startupTaskId `
        $agentServerAuthMetadata `
        $embeddedSignerCertificate `
        ([bool] $Development)

    $hash = (Get-FileHash -LiteralPath $bundlePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        "$bundlePath.sha256",
        "$hash  $bundleName`r`n",
        [Text.UTF8Encoding]::new($false)
    )
    $metadata = [ordered]@{
        schemaVersion = 1
        product = 'Nodavo'
        mode = $mode
        version = $Version
        buildNumber = $BuildNumber
        packageVersion = $packageVersion
        packageIdentityName = $packageIdentity
        packageFamilyName = $packageFamilyName
        applicationUserModelId = $applicationUserModelId
        executable = $executable
        agentExecutable = $agentExecutable
        startupTaskId = $startupTaskId
        publisher = $publisher
        signerCertificateSha256 = $signerCertificateSha256
        architectures = @('x64', 'arm64')
        artifact = $bundleName
        sha256 = $hash
        signed = $true
        signatureKind = if ($Development) { 'self-signed-development' } else { 'authenticode-release' }
        timestampRequired = -not [bool] $Development
        signerThumbprint = if ($Development) {
            $developmentCertificate.Thumbprint
        }
        else {
            $releaseCertificate.Thumbprint
        }
    }
    $metadata | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $artifactRoot 'package-metadata.json') -Encoding utf8

    $packagingCompleted = $true
    Write-Output "Windows package completed: $artifactRoot"
    if ($Development) {
        Write-Warning 'Development artifact is self-signed and NOT FOR DISTRIBUTION.'
    }
}
finally {
    foreach ($name in @(
        'NODAVO_WINDOWS_AUTH_SIGNER_CERT_SHA256',
        'NODAVO_WINDOWS_AUTH_PACKAGE_FAMILY_NAME',
        'NODAVO_WINDOWS_AUTH_PUBLISHER',
        'WINDOWS_SIGNING_PFX',
        'WINDOWS_SIGNING_CERTIFICATE'
    )) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $null,
            [EnvironmentVariableTarget]::Process
        )
        Remove-Item -LiteralPath "Env:\$name" -Force -ErrorAction SilentlyContinue
    }
    $releaseStoreCleanupError = $null
    $developmentStoreCleanupError = $null
    if ($releaseImportedThumbprints.Count -ne 0) {
        try {
            foreach ($thumbprint in $releaseImportedThumbprints) {
                $certificatePath = "Cert:\CurrentUser\My\$thumbprint"
                Remove-Item -LiteralPath $certificatePath -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $certificatePath) {
                    throw "exact imported certificate remains in CurrentUser/My"
                }
            }
        }
        catch {
            $releaseStoreCleanupError = $_
        }
    }
    if ($null -ne $developmentCertificate) {
        $personalPath = "Cert:\CurrentUser\My\$($developmentCertificate.Thumbprint)"
        try {
            Remove-Item -LiteralPath $personalPath -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $personalPath) {
                throw 'certificate remains in CurrentUser/My'
            }
        }
        catch {
            $developmentStoreCleanupError = $_
        }
    }
    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
    if (-not $packagingCompleted -and (Test-Path -LiteralPath $artifactRoot)) {
        Remove-Item -LiteralPath $artifactRoot -Recurse -Force
    }
    if ($null -ne $releaseCertificateBundle) {
        foreach ($certificate in $releaseCertificateBundle) {
            $certificate.Dispose()
        }
    }
    if ($null -ne $releasePfxPassword) {
        $releasePfxPassword.Dispose()
    }
    if ($null -ne $releaseStoreCleanupError) {
        Fail "release certificate-store cleanup failed; signing runner must be discarded"
    }
    if ($null -ne $developmentStoreCleanupError) {
        Fail "development certificate-store cleanup failed; signing runner must be discarded"
    }
}
