using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Nodavo.Windows.Models;
using Windows.ApplicationModel;

namespace Nodavo.Windows.Services;

internal sealed class AgentServerAuthenticationException : UnauthorizedAccessException
{
    internal AgentServerAuthenticationException()
        : base("The local Nodavo agent could not be authenticated.")
    {
    }
}

internal sealed class AuthenticatedAgentServer : IDisposable
{
    private readonly SafePipeHandle _pipe;
    private readonly SafeProcessHandle _process;
    private readonly SafeAccessTokenHandle _token;
    private readonly SafeFileHandle _imageFile;
    private readonly uint _processId;
    private readonly ulong _creationTime;
    private readonly NativeTokenIdentity _clientTokenIdentity;
    private readonly NativeTokenIdentity _serverTokenIdentity;
    private readonly NativeServerIdentity _serverIdentity;
    private bool _disposed;

    internal AuthenticatedAgentServer(
        SafePipeHandle pipe,
        SafeProcessHandle process,
        SafeAccessTokenHandle token,
        SafeFileHandle imageFile,
        uint processId,
        ulong creationTime,
        NativeTokenIdentity clientTokenIdentity,
        NativeTokenIdentity serverTokenIdentity,
        NativeServerIdentity serverIdentity)
    {
        _pipe = pipe;
        _process = process;
        _token = token;
        _imageFile = imageFile;
        _processId = processId;
        _creationTime = creationTime;
        _clientTokenIdentity = clientTokenIdentity;
        _serverTokenIdentity = serverTokenIdentity;
        _serverIdentity = serverIdentity;
    }

    internal void Revalidate()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(AuthenticatedAgentServer));
        }

        try
        {
            if (AgentServerNative.GetPipeServerProcessId(_pipe) != _processId ||
                AgentServerNative.GetProcessId(_process) != _processId ||
                AgentServerNative.GetProcessCreationTime(_process) != _creationTime ||
                !AgentServerNative.IsProcessLive(_process))
            {
                throw new AgentServerAuthenticationException();
            }

            NativeTokenIdentity retained = AgentServerNative.ReadTokenIdentity(_token);
            if (!retained.Equals(_serverTokenIdentity))
            {
                throw new AgentServerAuthenticationException();
            }

            using SafeAccessTokenHandle currentToken = AgentServerNative.OpenProcessToken(_process);
            NativeTokenIdentity current = AgentServerNative.ReadTokenIdentity(currentToken);
            NativeTokenIdentity client = AgentServerNative.ReadCurrentProcessTokenIdentity();
            if (!current.Equals(_serverTokenIdentity) || !client.Equals(_clientTokenIdentity) ||
                !AgentServerNative.HasSameLogonIdentity(client, current) ||
                AgentServerNative.GetProcessSessionId(_processId) != current.SessionId)
            {
                throw new AgentServerAuthenticationException();
            }

            NativeServerIdentity identity = AgentServerNative.ReadServerIdentity(
                _process,
                _serverIdentity.Policy,
                _serverIdentity.ClientPackage);
            if (!identity.Equals(_serverIdentity))
            {
                throw new AgentServerAuthenticationException();
            }
            AgentServerNative.ValidateRetainedImage(
                _imageFile,
                _process,
                _serverIdentity.ImagePath);

            if (AgentServerNative.GetPipeServerProcessId(_pipe) != _processId ||
                !AgentServerNative.IsProcessLive(_process))
            {
                throw new AgentServerAuthenticationException();
            }
        }
        catch (AgentServerAuthenticationException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new AgentServerAuthenticationException();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _imageFile.Dispose();
        _token.Dispose();
        _process.Dispose();
    }

    public override string ToString() => "AuthenticatedAgentServer { redacted }";
}

internal static class AgentServerAuthenticator
{
    internal static AuthenticatedAgentServer Authenticate(NamedPipeClientStream pipe)
    {
        SafeProcessHandle? process = null;
        SafeAccessTokenHandle? token = null;
        SafeFileHandle? imageFile = null;
        try
        {
            AgentServerAuthPolicy policy = AgentServerAuthPolicy.LoadCompiled();
            NativeClientPackage clientPackage = AgentServerNative.ReadCurrentClientPackage(policy);
            NativeTokenIdentity clientToken = AgentServerNative.ReadCurrentProcessTokenIdentity();

            uint pipeProcessId = AgentServerNative.GetPipeServerProcessId(pipe.SafePipeHandle);
            process = AgentServerNative.OpenProcess(pipeProcessId);
            if (AgentServerNative.GetProcessId(process) != pipeProcessId)
            {
                throw new AgentServerAuthenticationException();
            }

            ulong creationTime = AgentServerNative.GetProcessCreationTime(process);
            token = AgentServerNative.OpenProcessToken(process);
            NativeTokenIdentity serverToken = AgentServerNative.ReadTokenIdentity(token);
            if (!AgentServerNative.HasSameLogonIdentity(clientToken, serverToken) ||
                AgentServerNative.GetProcessSessionId(pipeProcessId) != serverToken.SessionId)
            {
                throw new AgentServerAuthenticationException();
            }

            NativeServerIdentity identity = AgentServerNative.ReadServerIdentity(
                process,
                policy,
                clientPackage);
            imageFile = AgentServerNative.OpenAndValidateImage(process, identity.ImagePath);
            AgentServerNative.VerifyAuthenticode(
                imageFile,
                identity.ImagePath,
                policy.SignerCertificateSha256,
                policy.Mode == AgentServerAuthMode.Release);

            if (AgentServerNative.GetPipeServerProcessId(pipe.SafePipeHandle) != pipeProcessId ||
                !AgentServerNative.IsProcessLive(process))
            {
                throw new AgentServerAuthenticationException();
            }

            var guard = new AuthenticatedAgentServer(
                pipe.SafePipeHandle,
                process,
                token,
                imageFile,
                pipeProcessId,
                creationTime,
                clientToken,
                serverToken,
                identity);
            process = null;
            token = null;
            imageFile = null;
            return guard;
        }
        catch (AgentServerAuthenticationException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new AgentServerAuthenticationException();
        }
        finally
        {
            imageFile?.Dispose();
            token?.Dispose();
            process?.Dispose();
        }
    }
}

internal sealed class NativeClientPackage : IEquatable<NativeClientPackage>
{
    internal NativeClientPackage(
        string fullName,
        string familyName,
        string installedPath,
        string publisherId)
    {
        FullName = fullName;
        FamilyName = familyName;
        InstalledPath = installedPath;
        PublisherId = publisherId;
    }

    internal string FullName { get; }
    internal string FamilyName { get; }
    internal string InstalledPath { get; }
    internal string PublisherId { get; }

    public bool Equals(NativeClientPackage? other) =>
        other is not null && FullName == other.FullName && FamilyName == other.FamilyName &&
        StringComparer.OrdinalIgnoreCase.Equals(InstalledPath, other.InstalledPath) &&
        PublisherId == other.PublisherId;

    public override bool Equals(object? obj) => Equals(obj as NativeClientPackage);
    public override int GetHashCode() => HashCode.Combine(FullName, FamilyName, PublisherId);
    public override string ToString() => "NativeClientPackage { redacted }";
}

internal sealed class NativeServerIdentity : IEquatable<NativeServerIdentity>
{
    internal NativeServerIdentity(
        AgentServerAuthPolicy policy,
        NativeClientPackage clientPackage,
        string imagePath)
    {
        Policy = policy;
        ClientPackage = clientPackage;
        ImagePath = imagePath;
    }

    internal AgentServerAuthPolicy Policy { get; }
    internal NativeClientPackage ClientPackage { get; }
    internal string ImagePath { get; }

    public bool Equals(NativeServerIdentity? other) =>
        other is not null && Policy == other.Policy && ClientPackage.Equals(other.ClientPackage) &&
        StringComparer.OrdinalIgnoreCase.Equals(ImagePath, other.ImagePath);

    public override bool Equals(object? obj) => Equals(obj as NativeServerIdentity);
    public override int GetHashCode() => StringComparer.OrdinalIgnoreCase.GetHashCode(ImagePath);
    public override string ToString() => "NativeServerIdentity { redacted }";
}

internal sealed class NativeTokenIdentity : IEquatable<NativeTokenIdentity>
{
    internal NativeTokenIdentity(
        string userSid,
        uint sessionId,
        NativeLuid tokenId,
        NativeLuid authenticationId,
        NativeLuid modifiedId)
    {
        UserSid = userSid;
        SessionId = sessionId;
        TokenId = tokenId;
        AuthenticationId = authenticationId;
        ModifiedId = modifiedId;
    }

    internal string UserSid { get; }
    internal uint SessionId { get; }
    internal NativeLuid TokenId { get; }
    internal NativeLuid AuthenticationId { get; }
    internal NativeLuid ModifiedId { get; }

    public bool Equals(NativeTokenIdentity? other) =>
        other is not null && UserSid == other.UserSid && SessionId == other.SessionId &&
        TokenId == other.TokenId && AuthenticationId == other.AuthenticationId &&
        ModifiedId == other.ModifiedId;

    public override bool Equals(object? obj) => Equals(obj as NativeTokenIdentity);
    public override int GetHashCode() => HashCode.Combine(UserSid, SessionId, TokenId);
    public override string ToString() => "NativeTokenIdentity { redacted }";
}

internal readonly record struct NativeLuid(uint LowPart, int HighPart)
{
    public override string ToString() => "NativeLuid { redacted }";
}

internal static class AgentServerNative
{
    private const uint ProcessSynchronize = 0x00100000;
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint TokenQuery = 0x0008;
    private const uint WaitTimeout = 0x00000102;
    private const uint ErrorInsufficientBuffer = 122;
    private const int ErrorSuccess = 0;
    private const uint PackagePathTypeInstall = 0;
    private const uint MaximumTokenBytes = 64 * 1024;
    private const int MaximumWindowsPath = 32_767;
    private const int MaximumCertificateBytes = 1024 * 1024;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int FileAttributeTagInfo = 9;
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckNone = 0x00000010;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    private const uint WtdDisableMd2Md4 = 0x00002000;
    private const uint SgnrTypeTimestamp = 16;
    private const uint MaximumProviderChain = 32;

    private static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    internal static uint GetPipeServerProcessId(SafePipeHandle pipe)
    {
        if (pipe.IsInvalid || !NativeMethods.GetNamedPipeServerProcessId(pipe, out uint processId) ||
            processId == 0)
        {
            throw new AgentServerAuthenticationException();
        }
        return processId;
    }

    internal static SafeProcessHandle OpenProcess(uint processId)
    {
        SafeProcessHandle process = NativeMethods.OpenProcess(
            ProcessQueryLimitedInformation | ProcessSynchronize,
            false,
            processId);
        if (process.IsInvalid)
        {
            process.Dispose();
            throw new AgentServerAuthenticationException();
        }
        return process;
    }

    internal static uint GetProcessId(SafeProcessHandle process)
    {
        uint processId = NativeMethods.GetProcessId(process);
        if (processId == 0)
        {
            throw new AgentServerAuthenticationException();
        }
        return processId;
    }

    internal static ulong GetProcessCreationTime(SafeProcessHandle process)
    {
        if (!NativeMethods.GetProcessTimes(
                process,
                out NativeFileTime creation,
                out _,
                out _,
                out _))
        {
            throw new AgentServerAuthenticationException();
        }
        return ((ulong)creation.HighDateTime << 32) | creation.LowDateTime;
    }

    internal static bool IsProcessLive(SafeProcessHandle process) =>
        NativeMethods.WaitForSingleObject(process, 0) == WaitTimeout;

    internal static SafeAccessTokenHandle OpenProcessToken(SafeProcessHandle process)
    {
        if (!NativeMethods.OpenProcessToken(process, TokenQuery, out SafeAccessTokenHandle token) ||
            token.IsInvalid)
        {
            token?.Dispose();
            throw new AgentServerAuthenticationException();
        }
        return token;
    }

    internal static NativeTokenIdentity ReadCurrentProcessTokenIdentity()
    {
        if (!NativeMethods.OpenCurrentProcessToken(
                NativeMethods.GetCurrentProcess(),
                TokenQuery,
                out SafeAccessTokenHandle token) || token.IsInvalid)
        {
            token?.Dispose();
            throw new AgentServerAuthenticationException();
        }
        using (token)
        {
            return ReadTokenIdentity(token);
        }
    }

    internal static NativeTokenIdentity ReadTokenIdentity(SafeAccessTokenHandle token)
    {
        using NativeBuffer user = QueryToken(token, TokenInformationClass.TokenUser);
        NativeTokenUser tokenUser = Marshal.PtrToStructure<NativeTokenUser>(user.Pointer);
        uint sidLength = NativeMethods.GetLengthSid(tokenUser.User.Sid);
        if (tokenUser.User.Sid == IntPtr.Zero || sidLength is 0 or > 256)
        {
            throw new AgentServerAuthenticationException();
        }
        string? sid = new System.Security.Principal.SecurityIdentifier(
            tokenUser.User.Sid).Value;
        if (string.IsNullOrEmpty(sid) || sid.Length > 256)
        {
            throw new AgentServerAuthenticationException();
        }

        using NativeBuffer session = QueryToken(token, TokenInformationClass.TokenSessionId);
        if (session.Size != sizeof(uint))
        {
            throw new AgentServerAuthenticationException();
        }
        uint sessionId = unchecked((uint)Marshal.ReadInt32(session.Pointer));

        using NativeBuffer statistics = QueryToken(token, TokenInformationClass.TokenStatistics);
        if (statistics.Size < Marshal.SizeOf<NativeTokenStatistics>())
        {
            throw new AgentServerAuthenticationException();
        }
        NativeTokenStatistics value =
            Marshal.PtrToStructure<NativeTokenStatistics>(statistics.Pointer);
        return new NativeTokenIdentity(
            sid,
            sessionId,
            new NativeLuid(value.TokenId.LowPart, value.TokenId.HighPart),
            new NativeLuid(value.AuthenticationId.LowPart, value.AuthenticationId.HighPart),
            new NativeLuid(value.ModifiedId.LowPart, value.ModifiedId.HighPart));
    }

    internal static bool HasSameLogonIdentity(
        NativeTokenIdentity client,
        NativeTokenIdentity server) =>
        client.SessionId != 0 && client.UserSid == server.UserSid &&
        client.SessionId == server.SessionId &&
        client.AuthenticationId == server.AuthenticationId;

    internal static uint GetProcessSessionId(uint processId)
    {
        if (!NativeMethods.ProcessIdToSessionId(processId, out uint sessionId) || sessionId == 0)
        {
            throw new AgentServerAuthenticationException();
        }
        return sessionId;
    }

    internal static NativeClientPackage ReadCurrentClientPackage(AgentServerAuthPolicy policy)
    {
        Package package = Package.Current;
        string packageName = package.Id.Name;
        string publisher = package.Id.Publisher;
        string fullName = package.Id.FullName;
        string familyName = package.Id.FamilyName;
        string publisherId = package.Id.PublisherId;
        string installedPath = NormalizePath(package.InstalledLocation.Path);
        string currentAumid = QueryCurrentApplicationUserModelId();

        if (packageName != policy.PackageName || publisher != policy.Publisher ||
            familyName != policy.PackageFamilyName ||
            familyName != $"{packageName}_{publisherId}" ||
            currentAumid != policy.ApplicationUserModelId ||
            string.IsNullOrEmpty(fullName) || fullName.Length > 127 ||
            string.IsNullOrEmpty(publisherId) || publisherId.Length > 13)
        {
            throw new AgentServerAuthenticationException();
        }

        string packagePath = NormalizePath(QueryPackageInstallPath(fullName));
        if (!StringComparer.OrdinalIgnoreCase.Equals(installedPath, packagePath))
        {
            throw new AgentServerAuthenticationException();
        }
        return new NativeClientPackage(fullName, familyName, installedPath, publisherId);
    }

    internal static NativeServerIdentity ReadServerIdentity(
        SafeProcessHandle process,
        AgentServerAuthPolicy policy,
        NativeClientPackage clientPackage)
    {
        string imagePath = NormalizePath(QueryProcessImagePath(process));
        string expectedImage = NormalizePath(
            Path.Combine(clientPackage.InstalledPath, policy.RelativeExecutable));
        string relative = Path.GetRelativePath(clientPackage.InstalledPath, expectedImage);

        if (!StringComparer.OrdinalIgnoreCase.Equals(relative, policy.RelativeExecutable) ||
            !StringComparer.OrdinalIgnoreCase.Equals(imagePath, expectedImage))
        {
            throw new AgentServerAuthenticationException();
        }

        return new NativeServerIdentity(
            policy,
            clientPackage,
            imagePath);
    }

    internal static SafeFileHandle OpenAndValidateImage(
        SafeProcessHandle process,
        string imagePath)
    {
        SafeFileHandle imageFile = NativeMethods.CreateFile(
            imagePath,
            GenericRead,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileAttributeNormal | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (imageFile.IsInvalid)
        {
            imageFile.Dispose();
            throw new AgentServerAuthenticationException();
        }
        try
        {
            ValidateRetainedImage(imageFile, process, imagePath);
            return imageFile;
        }
        catch
        {
            imageFile.Dispose();
            throw;
        }
    }

    internal static void ValidateRetainedImage(
        SafeFileHandle imageFile,
        SafeProcessHandle process,
        string imagePath)
    {
        if (imageFile.IsInvalid || !NativeMethods.GetFileInformationByHandleEx(
                imageFile,
                FileAttributeTagInfo,
                out NativeFileAttributeTagInfo attributes,
                (uint)Marshal.SizeOf<NativeFileAttributeTagInfo>()) ||
            (attributes.FileAttributes & (FileAttributeDirectory | FileAttributeReparsePoint)) != 0)
        {
            throw new AgentServerAuthenticationException();
        }
        string retainedPath = NormalizePath(QueryFinalFilePath(imageFile));
        string currentProcessPath = NormalizePath(QueryProcessImagePath(process));
        if (!StringComparer.OrdinalIgnoreCase.Equals(retainedPath, imagePath) ||
            !StringComparer.OrdinalIgnoreCase.Equals(currentProcessPath, imagePath))
        {
            throw new AgentServerAuthenticationException();
        }
    }

    internal static void VerifyAuthenticode(
        SafeFileHandle imageFile,
        string imagePath,
        byte[] expectedCertificateSha256,
        bool requireTimestamp)
    {
        bool handleAdded = false;
        IntPtr pathPointer = IntPtr.Zero;
        IntPtr fileInfoPointer = IntPtr.Zero;
        try
        {
            imageFile.DangerousAddRef(ref handleAdded);
            pathPointer = Marshal.StringToHGlobalUni(imagePath);
            var fileInfo = new NativeWinTrustFileInfo
            {
                StructureSize = (uint)Marshal.SizeOf<NativeWinTrustFileInfo>(),
                FilePath = pathPointer,
                FileHandle = imageFile.DangerousGetHandle(),
                KnownSubject = IntPtr.Zero,
            };
            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeWinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            var data = new NativeWinTrustData
            {
                StructureSize = (uint)Marshal.SizeOf<NativeWinTrustData>(),
                UiChoice = WtdUiNone,
                RevocationChecks = WtdRevokeNone,
                UnionChoice = WtdChoiceFile,
                FileInfo = fileInfoPointer,
                StateAction = WtdStateActionVerify,
                ProviderFlags = WtdRevocationCheckNone |
                    WtdCacheOnlyUrlRetrieval |
                    WtdDisableMd2Md4,
                UiContext = 0,
            };
            Guid action = WinTrustActionGenericVerifyV2;
            int status = NativeMethods.WinVerifyTrust(
                new IntPtr(-1),
                ref action,
                ref data);
            try
            {
                if (status != ErrorSuccess || data.StateData == IntPtr.Zero)
                {
                    throw new AgentServerAuthenticationException();
                }
                ValidateProviderEvidence(
                    data.StateData,
                    expectedCertificateSha256,
                    requireTimestamp);
            }
            finally
            {
                data.StateAction = WtdStateActionClose;
                int closeStatus = NativeMethods.WinVerifyTrust(
                    new IntPtr(-1),
                    ref action,
                    ref data);
                if (closeStatus != ErrorSuccess)
                {
                    throw new AgentServerAuthenticationException();
                }
            }
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(fileInfoPointer);
            }
            if (pathPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pathPointer);
            }
            if (handleAdded)
            {
                imageFile.DangerousRelease();
            }
        }
    }

    private static void ValidateProviderEvidence(
        IntPtr stateData,
        byte[] expectedCertificateSha256,
        bool requireTimestamp)
    {
        IntPtr provider = NativeMethods.WTHelperProvDataFromStateData(stateData);
        IntPtr signerPointer = NativeMethods.WTHelperGetProvSignerFromChain(
            provider,
            0,
            false,
            0);
        if (provider == IntPtr.Zero || signerPointer == IntPtr.Zero)
        {
            throw new AgentServerAuthenticationException();
        }
        NativeCryptProviderSigner signer =
            Marshal.PtrToStructure<NativeCryptProviderSigner>(signerPointer);
        if (signer.StructureSize < Marshal.SizeOf<NativeCryptProviderSigner>() ||
            signer.Error != ErrorSuccess || signer.CertificateChainCount is 0 or > MaximumProviderChain)
        {
            throw new AgentServerAuthenticationException();
        }
        IntPtr providerCertificatePointer =
            NativeMethods.WTHelperGetProvCertFromChain(signerPointer, 0);
        byte[] digest = HashProviderCertificate(providerCertificatePointer);
        if (!CryptographicOperations.FixedTimeEquals(digest, expectedCertificateSha256))
        {
            throw new AgentServerAuthenticationException();
        }

        if (!requireTimestamp)
        {
            return;
        }
        if (signer.CounterSignerCount != 1)
        {
            throw new AgentServerAuthenticationException();
        }
        IntPtr timestampPointer = NativeMethods.WTHelperGetProvSignerFromChain(
            provider,
            0,
            true,
            0);
        if (timestampPointer == IntPtr.Zero)
        {
            throw new AgentServerAuthenticationException();
        }
        NativeCryptProviderSigner timestamp =
            Marshal.PtrToStructure<NativeCryptProviderSigner>(timestampPointer);
        if (timestamp.StructureSize < Marshal.SizeOf<NativeCryptProviderSigner>() ||
            timestamp.SignerType != SgnrTypeTimestamp || timestamp.Error != ErrorSuccess ||
            timestamp.CertificateChainCount is 0 or > MaximumProviderChain ||
            (timestamp.VerifyAsOf.LowDateTime == 0 && timestamp.VerifyAsOf.HighDateTime == 0))
        {
            throw new AgentServerAuthenticationException();
        }
        _ = HashProviderCertificate(
            NativeMethods.WTHelperGetProvCertFromChain(timestampPointer, 0));
    }

    private static byte[] HashProviderCertificate(IntPtr providerCertificatePointer)
    {
        if (providerCertificatePointer == IntPtr.Zero)
        {
            throw new AgentServerAuthenticationException();
        }
        NativeCryptProviderCertificate providerCertificate =
            Marshal.PtrToStructure<NativeCryptProviderCertificate>(providerCertificatePointer);
        if (providerCertificate.StructureSize < Marshal.SizeOf<NativeCryptProviderCertificate>() ||
            providerCertificate.Error != ErrorSuccess || providerCertificate.Certificate == IntPtr.Zero)
        {
            throw new AgentServerAuthenticationException();
        }
        NativeCertificateContext certificate =
            Marshal.PtrToStructure<NativeCertificateContext>(providerCertificate.Certificate);
        if (certificate.EncodedCertificate == IntPtr.Zero ||
            certificate.EncodedCertificateSize is 0 or > MaximumCertificateBytes)
        {
            throw new AgentServerAuthenticationException();
        }
        byte[] encoded = new byte[checked((int)certificate.EncodedCertificateSize)];
        Marshal.Copy(certificate.EncodedCertificate, encoded, 0, encoded.Length);
        return SHA256.HashData(encoded);
    }

    private static NativeBuffer QueryToken(
        SafeAccessTokenHandle token,
        TokenInformationClass informationClass)
    {
        _ = NativeMethods.GetTokenInformation(
            token,
            informationClass,
            IntPtr.Zero,
            0,
            out uint required);
        if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer ||
            required == 0 || required > MaximumTokenBytes)
        {
            throw new AgentServerAuthenticationException();
        }
        var output = new NativeBuffer(required);
        if (!NativeMethods.GetTokenInformation(
                token,
                informationClass,
                output.Pointer,
                required,
                out uint returned) || returned != required)
        {
            output.Dispose();
            throw new AgentServerAuthenticationException();
        }
        return output;
    }

    private static string QueryCurrentApplicationUserModelId() =>
        QueryAppModelString(
            130,
            (ref uint length, StringBuilder? output) =>
                NativeMethods.GetCurrentApplicationUserModelId(ref length, output));

    private static string QueryPackageInstallPath(string fullName) =>
        QueryAppModelString(
            MaximumWindowsPath + 1,
            (ref uint length, StringBuilder? output) =>
                NativeMethods.GetPackagePathByFullName2(
                    fullName,
                    PackagePathTypeInstall,
                    ref length,
                    output));

    private static string QueryAppModelString(
        int maximumUnitsIncludingNull,
        AppModelQuery query)
    {
        uint required = 0;
        if (query(ref required, null) != unchecked((int)ErrorInsufficientBuffer) ||
            required < 2 || required > maximumUnitsIncludingNull)
        {
            throw new AgentServerAuthenticationException();
        }
        var output = new StringBuilder(checked((int)required));
        uint supplied = required;
        if (query(ref supplied, output) != ErrorSuccess || supplied != required)
        {
            throw new AgentServerAuthenticationException();
        }
        string value = output.ToString();
        if (value.Length != supplied - 1 || value.Contains('\0'))
        {
            throw new AgentServerAuthenticationException();
        }
        return value;
    }

    private static string QueryProcessImagePath(SafeProcessHandle process)
    {
        var output = new StringBuilder(MaximumWindowsPath + 1);
        uint length = (uint)output.Capacity;
        if (!NativeMethods.QueryFullProcessImageName(process, 0, output, ref length) ||
            length == 0 || length >= output.Capacity || output.Length != length)
        {
            throw new AgentServerAuthenticationException();
        }
        return output.ToString();
    }

    private static string QueryFinalFilePath(SafeFileHandle file)
    {
        var output = new StringBuilder(MaximumWindowsPath + 1);
        uint length = NativeMethods.GetFinalPathNameByHandle(
            file,
            output,
            (uint)output.Capacity,
            0);
        if (length == 0 || length >= output.Capacity || output.Length != length)
        {
            throw new AgentServerAuthenticationException();
        }
        return output.ToString();
    }

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaximumWindowsPath ||
            value.Contains('\0'))
        {
            throw new AgentServerAuthenticationException();
        }
        string path = value;
        if (path.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
        {
            path = "\\\\" + path[8..];
        }
        else if (path.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase))
        {
            path = path[4..];
        }
        string normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (normalized.Length is 0 or > MaximumWindowsPath)
        {
            throw new AgentServerAuthenticationException();
        }
        return normalized;
    }

    private delegate int AppModelQuery(ref uint length, StringBuilder? output);

    private sealed class NativeBuffer : IDisposable
    {
        internal NativeBuffer(uint size)
        {
            Size = size;
            Pointer = Marshal.AllocHGlobal(checked((int)size));
        }

        internal IntPtr Pointer { get; }
        internal uint Size { get; }

        public void Dispose() => Marshal.FreeHGlobal(Pointer);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        internal uint LowDateTime;
        internal uint HighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeLuidValue
    {
        internal uint LowPart;
        internal int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeSidAndAttributes
    {
        internal IntPtr Sid;
        internal uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeTokenUser
    {
        internal NativeSidAndAttributes User;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeTokenStatistics
    {
        internal NativeLuidValue TokenId;
        internal NativeLuidValue AuthenticationId;
        internal long ExpirationTime;
        internal uint TokenType;
        internal uint ImpersonationLevel;
        internal uint DynamicCharged;
        internal uint DynamicAvailable;
        internal uint GroupCount;
        internal uint PrivilegeCount;
        internal NativeLuidValue ModifiedId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileAttributeTagInfo
    {
        internal uint FileAttributes;
        internal uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeWinTrustFileInfo
    {
        internal uint StructureSize;
        internal IntPtr FilePath;
        internal IntPtr FileHandle;
        internal IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeWinTrustData
    {
        internal uint StructureSize;
        internal IntPtr PolicyCallbackData;
        internal IntPtr SipClientData;
        internal uint UiChoice;
        internal uint RevocationChecks;
        internal uint UnionChoice;
        internal IntPtr FileInfo;
        internal uint StateAction;
        internal IntPtr StateData;
        internal IntPtr UrlReference;
        internal uint ProviderFlags;
        internal uint UiContext;
        internal IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCryptProviderSigner
    {
        internal uint StructureSize;
        internal NativeFileTime VerifyAsOf;
        internal uint CertificateChainCount;
        internal IntPtr CertificateChain;
        internal uint SignerType;
        internal IntPtr Signer;
        internal uint Error;
        internal uint CounterSignerCount;
        internal IntPtr CounterSigners;
        internal IntPtr ChainContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCryptProviderCertificate
    {
        internal uint StructureSize;
        internal IntPtr Certificate;
        [MarshalAs(UnmanagedType.Bool)] internal bool Commercial;
        [MarshalAs(UnmanagedType.Bool)] internal bool TrustedRoot;
        [MarshalAs(UnmanagedType.Bool)] internal bool SelfSigned;
        [MarshalAs(UnmanagedType.Bool)] internal bool TestCertificate;
        internal uint RevokedReason;
        internal uint Confidence;
        internal uint Error;
        internal IntPtr TrustListContext;
        [MarshalAs(UnmanagedType.Bool)] internal bool TrustListSignerCertificate;
        internal IntPtr CtlContext;
        internal uint CtlError;
        [MarshalAs(UnmanagedType.Bool)] internal bool IsCyclic;
        internal IntPtr ChainElement;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCertificateContext
    {
        internal uint EncodingType;
        internal IntPtr EncodedCertificate;
        internal uint EncodedCertificateSize;
        internal IntPtr CertificateInfo;
        internal IntPtr CertificateStore;
    }

    private enum TokenInformationClass
    {
        TokenUser = 1,
        TokenSessionId = 12,
        TokenStatistics = 10,
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetNamedPipeServerProcessId(
            SafePipeHandle pipe,
            out uint serverProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            uint processId);

        [DllImport("kernel32.dll")]
        internal static extern uint GetProcessId(SafeProcessHandle process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetProcessTimes(
            SafeProcessHandle process,
            out NativeFileTime creationTime,
            out NativeFileTime exitTime,
            out NativeFileTime kernelTime,
            out NativeFileTime userTime);

        [DllImport("kernel32.dll")]
        internal static extern uint WaitForSingleObject(
            SafeProcessHandle handle,
            uint milliseconds);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenProcessToken(
            SafeProcessHandle process,
            uint desiredAccess,
            out SafeAccessTokenHandle token);

        [DllImport("advapi32.dll", EntryPoint = "OpenProcessToken", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenCurrentProcessToken(
            IntPtr process,
            uint desiredAccess,
            out SafeAccessTokenHandle token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetTokenInformation(
            SafeAccessTokenHandle token,
            TokenInformationClass informationClass,
            IntPtr tokenInformation,
            uint tokenInformationLength,
            out uint returnLength);

        [DllImport("advapi32.dll")]
        internal static extern uint GetLengthSid(IntPtr sid);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ProcessIdToSessionId(
            uint processId,
            out uint sessionId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern int GetCurrentApplicationUserModelId(
            ref uint applicationUserModelIdLength,
            StringBuilder? applicationUserModelId);

        [DllImport("kernelbase.dll", CharSet = CharSet.Unicode)]
        internal static extern int GetPackagePathByFullName2(
            string packageFullName,
            uint packagePathType,
            ref uint pathLength,
            StringBuilder? path);

        [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryFullProcessImageName(
            SafeProcessHandle process,
            uint flags,
            StringBuilder executableName,
            ref uint size);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            int informationClass,
            out NativeFileAttributeTagInfo fileInformation,
            uint bufferSize);

        [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetFinalPathNameByHandle(
            SafeFileHandle file,
            StringBuilder filePath,
            uint filePathLength,
            uint flags);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        internal static extern int WinVerifyTrust(
            IntPtr window,
            ref Guid action,
            ref NativeWinTrustData trustData);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        internal static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        internal static extern IntPtr WTHelperGetProvSignerFromChain(
            IntPtr providerData,
            uint signerIndex,
            [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
            uint counterSignerIndex);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        internal static extern IntPtr WTHelperGetProvCertFromChain(
            IntPtr providerSigner,
            uint certificateIndex);
    }
}
