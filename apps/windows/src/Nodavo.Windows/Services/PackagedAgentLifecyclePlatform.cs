using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Windows.ApplicationModel;
using Windows.Foundation.Metadata;
using Nodavo.Windows.Models;

namespace Nodavo.Windows.Services;

internal sealed class PackagedAgentLifecyclePlatform : IAgentLifecyclePlatform
{
    internal const string StartupTaskId = "NodavoAgentStartup";
    internal const string AgentRelativePath = @"agent\nodavo-agent.exe";
    private const int MaximumWindowsPathLength = 32_767;
    private static readonly TimeSpan PlatformApiDeadline = TimeSpan.FromSeconds(5);

    public Task<AgentLaunchRequestResult> LaunchAgentAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        AgentLaunchRequestResult resolution = ResolveAgentPath(out string? agentPath);
        if (resolution != AgentLaunchRequestResult.Requested || agentPath is null)
        {
            return Task.FromResult(resolution);
        }

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = agentPath,
                WorkingDirectory = Path.GetDirectoryName(agentPath)!,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using Process? process = Process.Start(startInfo);
            return Task.FromResult(
                process is null
                    ? AgentLaunchRequestResult.Failed
                    : AgentLaunchRequestResult.Requested);
        }
        catch (Exception exception) when (
            exception is Win32Exception or InvalidOperationException or IOException or
            UnauthorizedAccessException)
        {
            return Task.FromResult(AgentLaunchRequestResult.Failed);
        }
    }

    public async Task<StartupRegistrationState> GetStartupStateAsync(
        CancellationToken cancellationToken)
    {
        StartupTask? task = await GetStartupTaskAsync(cancellationToken);
        return task is null ? StartupRegistrationState.Unavailable : MapStartupState(task.State);
    }

    public async Task<StartupRegistrationState> SetStartupEnabledAsync(
        bool enabled,
        CancellationToken cancellationToken)
    {
        StartupTask? task = await GetStartupTaskAsync(cancellationToken);
        if (task is null)
        {
            return StartupRegistrationState.Unavailable;
        }

        StartupRegistrationState current = MapStartupState(task.State);
        try
        {
            if (enabled)
            {
                if (current != StartupRegistrationState.Disabled)
                {
                    return current;
                }
                using var deadline =
                    CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                deadline.CancelAfter(PlatformApiDeadline);
                StartupTaskState result =
                    await task.RequestEnableAsync().AsTask(deadline.Token);
                return MapStartupState(result);
            }

            if (current != StartupRegistrationState.Enabled)
            {
                return current;
            }
            task.Disable();
            cancellationToken.ThrowIfCancellationRequested();
            return MapStartupState(task.State);
        }
        catch (Exception exception) when (
            !cancellationToken.IsCancellationRequested && IsExpectedPlatformFailure(exception))
        {
            return StartupRegistrationState.Unavailable;
        }
    }

    private static async Task<StartupTask?> GetStartupTaskAsync(
        CancellationToken cancellationToken)
    {
        if (!ApiInformation.IsApiContractPresent(
                "Windows.ApplicationModel.StartupTaskContract",
                1,
                0))
        {
            return null;
        }

        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(PlatformApiDeadline);
            return await StartupTask.GetAsync(StartupTaskId).AsTask(deadline.Token);
        }
        catch (Exception exception) when (
            !cancellationToken.IsCancellationRequested && IsExpectedPlatformFailure(exception))
        {
            return null;
        }
    }

    private static AgentLaunchRequestResult ResolveAgentPath(out string? agentPath)
    {
        agentPath = null;
        string packageRoot;
        try
        {
            packageRoot = Package.Current.InstalledLocation.Path;
        }
        catch (Exception exception) when (
            exception is COMException or InvalidOperationException or UnauthorizedAccessException)
        {
            return AgentLaunchRequestResult.Unsupported;
        }

        if (string.IsNullOrWhiteSpace(packageRoot) ||
            packageRoot.Length > MaximumWindowsPathLength ||
            !Path.IsPathFullyQualified(packageRoot))
        {
            return AgentLaunchRequestResult.Unsupported;
        }

        try
        {
            string canonicalRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(packageRoot));
            string candidate = Path.GetFullPath(Path.Combine(canonicalRoot, AgentRelativePath));
            string relative = Path.GetRelativePath(canonicalRoot, candidate);
            if (candidate.Length > MaximumWindowsPathLength ||
                !string.Equals(relative, AgentRelativePath, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(Path.GetFileName(candidate), "nodavo-agent.exe", StringComparison.Ordinal) ||
                !File.Exists(candidate))
            {
                return AgentLaunchRequestResult.Failed;
            }

            FileAttributes attributes = File.GetAttributes(candidate);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint |
                               FileAttributes.Device)) != 0)
            {
                return AgentLaunchRequestResult.Failed;
            }

            agentPath = candidate;
            return AgentLaunchRequestResult.Requested;
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or NotSupportedException or
            UnauthorizedAccessException)
        {
            return AgentLaunchRequestResult.Failed;
        }
    }

    private static StartupRegistrationState MapStartupState(StartupTaskState state) => state switch
    {
        StartupTaskState.Disabled => StartupRegistrationState.Disabled,
        StartupTaskState.DisabledByUser => StartupRegistrationState.DisabledByUser,
        StartupTaskState.Enabled => StartupRegistrationState.Enabled,
        StartupTaskState.DisabledByPolicy => StartupRegistrationState.DisabledByPolicy,
        StartupTaskState.EnabledByPolicy => StartupRegistrationState.EnabledByPolicy,
        _ => StartupRegistrationState.Unavailable,
    };

    private static bool IsExpectedPlatformFailure(Exception exception) =>
        exception is COMException or InvalidOperationException or ArgumentException or
        UnauthorizedAccessException or TaskCanceledException;
}
