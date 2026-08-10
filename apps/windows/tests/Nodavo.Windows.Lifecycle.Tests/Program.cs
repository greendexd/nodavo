using System.Diagnostics;
using System.Text;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;

await LifecycleTests.RunAllAsync();

internal static class LifecycleTests
{
    internal static async Task RunAllAsync()
    {
        AgentServerAuthPolicyAcceptsExactDevelopmentAndRelease();
        AgentServerAuthPolicyRejectsIncompleteOrAlteredMetadata();
        StartupReducerCoversEveryState();
        LaunchReducerIsFailClosed();
        await ConcurrentStartsLaunchOnlyOnceAsync();
        await MissingAgentReachesBoundedTimeoutAsync();
        await ExternalCancellationPreventsLaunchAsync();
        Console.WriteLine(
            "Windows agent auth policy, lifecycle reducer, race, and timeout tests passed.");
    }

    private static void AgentServerAuthPolicyAcceptsExactDevelopmentAndRelease()
    {
        IReadOnlyDictionary<string, string> development = AuthMetadata(
            "development",
            "dev.nodavo.Nodavo.Development",
            "CN=Nodavo Development Only",
            "dev.nodavo.Nodavo.Development_1234567890abc",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        AgentServerAuthPolicy developmentPolicy = AgentServerAuthPolicy.FromMetadata(development);
        Assert(
            developmentPolicy.Mode == AgentServerAuthMode.Development,
            "exact development policy must be accepted");
        Assert(
            developmentPolicy.PackageName == "dev.nodavo.Nodavo.Development" &&
            developmentPolicy.Publisher == "CN=Nodavo Development Only" &&
            developmentPolicy.PackageFamilyName ==
                "dev.nodavo.Nodavo.Development_1234567890abc" &&
            developmentPolicy.ApplicationUserModelId ==
                "dev.nodavo.Nodavo.Development_1234567890abc!App" &&
            developmentPolicy.ApplicationId == "App" &&
            developmentPolicy.RelativeExecutable == @"agent\nodavo-agent.exe",
            "development policy identity must remain exact");

        IReadOnlyDictionary<string, string> release = AuthMetadata(
            "release",
            "dev.nodavo.Nodavo",
            "CN=Nodavo Release Publisher",
            "dev.nodavo.Nodavo_abcdefghijklm",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        AgentServerAuthPolicy releasePolicy = AgentServerAuthPolicy.FromMetadata(release);
        Assert(
            releasePolicy.Mode == AgentServerAuthMode.Release,
            "exact release policy must be accepted");
        Assert(
            releasePolicy.PackageName == "dev.nodavo.Nodavo" &&
            releasePolicy.Publisher == "CN=Nodavo Release Publisher" &&
            releasePolicy.PackageFamilyName == "dev.nodavo.Nodavo_abcdefghijklm" &&
            releasePolicy.ApplicationUserModelId ==
                "dev.nodavo.Nodavo_abcdefghijklm!App" &&
            releasePolicy.RelativeExecutable == @"agent\nodavo-agent.exe",
            "release policy identity must remain exact");
    }

    private static void AgentServerAuthPolicyRejectsIncompleteOrAlteredMetadata()
    {
        Dictionary<string, string> exact = AuthMetadata(
            "development",
            "dev.nodavo.Nodavo.Development",
            "CN=Nodavo Development Only",
            "dev.nodavo.Nodavo.Development_1234567890abc",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        AssertRejected(
            Mutate(exact, metadata => metadata.Remove("Nodavo.AgentServerAuth.Mode")),
            "missing metadata must be rejected");
        AssertRejected(
            Mutate(exact, metadata => metadata.Add("Nodavo.AgentServerAuth.Unexpected", "x")),
            "extra metadata must be rejected");
        AssertRejected(
            Mutate(exact, metadata =>
                metadata["Nodavo.AgentServerAuth.PublisherBase64"] = "%%%"),
            "malformed base64 must be rejected");
        AssertRejected(
            Mutate(exact, metadata =>
                metadata["Nodavo.AgentServerAuth.Mode"] = "Development"),
            "wrong mode must be rejected");
        AssertRejected(
            Mutate(exact, metadata =>
                metadata["Nodavo.AgentServerAuth.PackageNameBase64"] =
                    Encode("dev.nodavo.Nodavo")),
            "wrong development package name must be rejected");
        AssertRejected(
            Mutate(exact, metadata =>
                metadata["Nodavo.AgentServerAuth.PublisherBase64"] =
                    Encode("CN=Nodavo Release Publisher")),
            "wrong development publisher must be rejected");
        AssertRejected(
            Mutate(exact, metadata =>
                metadata["Nodavo.AgentServerAuth.PackageFamilyNameBase64"] =
                    Encode("dev.nodavo.Nodavo.Development_wrongpublisher")),
            "wrong package family name must be rejected");
        AssertRejected(
            Mutate(exact, metadata =>
                metadata["Nodavo.AgentServerAuth.ApplicationUserModelIdBase64"] =
                    Encode("dev.nodavo.Nodavo.Development_1234567890abc!Other")),
            "wrong application user model ID must be rejected");
        AssertRejected(
            Mutate(exact, metadata =>
                metadata["Nodavo.AgentServerAuth.RelativeExecutableBase64"] =
                    Encode(@"agent\other.exe")),
            "wrong agent executable must be rejected");
        AssertRejected(
            Mutate(exact, metadata =>
                metadata["Nodavo.AgentServerAuth.SignerCertificateSha256"] =
                    new string('0', 64)),
            "wrong signer hash must be rejected");
    }

    private static Dictionary<string, string> AuthMetadata(
        string mode,
        string packageName,
        string publisher,
        string packageFamilyName,
        string signerCertificateSha256) =>
        new(StringComparer.Ordinal)
        {
            ["Nodavo.AgentServerAuth.Mode"] = mode,
            ["Nodavo.AgentServerAuth.PackageNameBase64"] = Encode(packageName),
            ["Nodavo.AgentServerAuth.PublisherBase64"] = Encode(publisher),
            ["Nodavo.AgentServerAuth.PackageFamilyNameBase64"] = Encode(packageFamilyName),
            ["Nodavo.AgentServerAuth.ApplicationUserModelIdBase64"] =
                Encode($"{packageFamilyName}!App"),
            ["Nodavo.AgentServerAuth.RelativeExecutableBase64"] =
                Encode(@"agent\nodavo-agent.exe"),
            ["Nodavo.AgentServerAuth.SignerCertificateSha256"] = signerCertificateSha256,
        };

    private static Dictionary<string, string> Mutate(
        IReadOnlyDictionary<string, string> source,
        Action<Dictionary<string, string>> mutation)
    {
        var changed = new Dictionary<string, string>(source, StringComparer.Ordinal);
        mutation(changed);
        return changed;
    }

    private static void AssertRejected(
        IReadOnlyDictionary<string, string> metadata,
        string message)
    {
        try
        {
            _ = AgentServerAuthPolicy.FromMetadata(metadata);
        }
        catch (InvalidOperationException)
        {
            return;
        }
        throw new InvalidOperationException(message);
    }

    private static string Encode(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private static void StartupReducerCoversEveryState()
    {
        AssertStartup(
            StartupRegistrationState.Disabled,
            false,
            true,
            StartupChangeAction.Enable,
            StartupRecoveryKind.None);
        AssertStartup(
            StartupRegistrationState.Enabled,
            true,
            true,
            StartupChangeAction.Disable,
            StartupRecoveryKind.None);
        AssertStartup(
            StartupRegistrationState.DisabledByUser,
            false,
            false,
            StartupChangeAction.None,
            StartupRecoveryKind.EnableInWindowsSettings);
        AssertStartup(
            StartupRegistrationState.DisabledByPolicy,
            false,
            false,
            StartupChangeAction.None,
            StartupRecoveryKind.ContactAdministrator);
        AssertStartup(
            StartupRegistrationState.EnabledByPolicy,
            true,
            false,
            StartupChangeAction.None,
            StartupRecoveryKind.ContactAdministrator);
        AssertStartup(
            StartupRegistrationState.Unavailable,
            false,
            false,
            StartupChangeAction.None,
            StartupRecoveryKind.UnsupportedOrMissing);
        AssertStartup(
            StartupRegistrationState.Unknown,
            false,
            false,
            StartupChangeAction.None,
            StartupRecoveryKind.None);
    }

    private static void LaunchReducerIsFailClosed()
    {
        Assert(
            AgentLifecycleReducer.ReduceLaunch(AgentLaunchOutcome.Started) == AgentRunState.Running,
            "started launch must become running");
        Assert(
            AgentLifecycleReducer.ReduceLaunch(AgentLaunchOutcome.AlreadyRunning) ==
                AgentRunState.Running,
            "existing agent must remain running");
        Assert(
            AgentLifecycleReducer.ReduceLaunch(AgentLaunchOutcome.TimedOut) == AgentRunState.TimedOut,
            "timeout must not be reported as running");
        Assert(
            AgentLifecycleReducer.ReduceLaunch(AgentLaunchOutcome.Unsupported) ==
                AgentRunState.Unsupported,
            "unsupported launch must remain unavailable");
        Assert(
            AgentLifecycleReducer.ReduceLaunch(AgentLaunchOutcome.Failed) == AgentRunState.Failed,
            "failed launch must remain failed");
    }

    private static async Task ConcurrentStartsLaunchOnlyOnceAsync()
    {
        var fixture = new LaunchFixture(becomesReachable: true);
        var coordinator = new AgentLifecycleCoordinator(
            fixture,
            fixture,
            TimeSpan.FromSeconds(1),
            TimeSpan.FromMilliseconds(5));

        Task<AgentLaunchOutcome> first = coordinator.EnsureAgentRunningAsync();
        Task<AgentLaunchOutcome> second = coordinator.EnsureAgentRunningAsync();
        AgentLaunchOutcome[] outcomes = await Task.WhenAll(first, second);

        Assert(fixture.LaunchCount == 1, "serialized concurrent starts must launch exactly once");
        Assert(outcomes.Contains(AgentLaunchOutcome.Started), "one caller must observe the launch");
        Assert(
            outcomes.Contains(AgentLaunchOutcome.AlreadyRunning),
            "the waiting caller must observe the existing agent");
    }

    private static async Task MissingAgentReachesBoundedTimeoutAsync()
    {
        var fixture = new LaunchFixture(becomesReachable: false);
        var coordinator = new AgentLifecycleCoordinator(
            fixture,
            fixture,
            TimeSpan.FromMilliseconds(60),
            TimeSpan.FromMilliseconds(5));
        var stopwatch = Stopwatch.StartNew();

        AgentLaunchOutcome outcome = await coordinator.EnsureAgentRunningAsync();

        stopwatch.Stop();
        Assert(outcome == AgentLaunchOutcome.TimedOut, "missing agent must report timeout");
        Assert(fixture.LaunchCount == 1, "timeout path must never retry process launch");
        Assert(stopwatch.Elapsed < TimeSpan.FromSeconds(2), "timeout must remain bounded");
    }

    private static async Task ExternalCancellationPreventsLaunchAsync()
    {
        var fixture = new LaunchFixture(becomesReachable: false);
        var coordinator = new AgentLifecycleCoordinator(
            fixture,
            fixture,
            TimeSpan.FromSeconds(1),
            TimeSpan.FromMilliseconds(5));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        try
        {
            _ = await coordinator.EnsureAgentRunningAsync(cancellation.Token);
            throw new InvalidOperationException("external cancellation must propagate");
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            Assert(fixture.LaunchCount == 0, "cancelled request must not launch or retry");
        }
    }

    private static void AssertStartup(
        StartupRegistrationState state,
        bool isEnabled,
        bool canChange,
        StartupChangeAction action,
        StartupRecoveryKind recovery)
    {
        StartupControlState actual = AgentLifecycleReducer.ReduceStartup(state);
        Assert(actual.IsEnabled == isEnabled, $"unexpected enabled state for {state}");
        Assert(actual.CanChange == canChange, $"unexpected mutability for {state}");
        Assert(actual.Action == action, $"unexpected action for {state}");
        Assert(actual.Recovery == recovery, $"unexpected recovery for {state}");
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class LaunchFixture : IAgentReadinessProbe, IAgentLifecyclePlatform
    {
        private readonly bool _becomesReachable;
        private int _launchCount;

        internal LaunchFixture(bool becomesReachable)
        {
            _becomesReachable = becomesReachable;
        }

        internal int LaunchCount => Volatile.Read(ref _launchCount);

        public Task<bool> IsAgentReachableAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_becomesReachable && LaunchCount != 0);
        }

        public Task<AgentLaunchRequestResult> LaunchAgentAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref _launchCount);
            return Task.FromResult(AgentLaunchRequestResult.Requested);
        }

        public Task<StartupRegistrationState> GetStartupStateAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult(StartupRegistrationState.Disabled);

        public Task<StartupRegistrationState> SetStartupEnabledAsync(
            bool enabled,
            CancellationToken cancellationToken) =>
            Task.FromResult(
                enabled ? StartupRegistrationState.Enabled : StartupRegistrationState.Disabled);
    }
}
