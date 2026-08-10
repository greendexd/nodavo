using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;

await LifecycleTests.RunAllAsync();

internal static class LifecycleTests
{
    internal static async Task RunAllAsync()
    {
        AgentServerAuthPolicyAcceptsExactDevelopmentAndRelease();
        AgentServerAuthPolicyRejectsIncompleteOrAlteredMetadata();
        StatusReadinessDecoderIsStrictAndRedacted();
        ReadinessReducerKeepsSignalsIndependent();
        ClientDeadlinesExceedServerBudgetsAndRemainDistinct();
        OverviewXamlHasBilingualReadinessResourcesAndNoAccessibilityAction();
        StartupReducerCoversEveryState();
        LaunchReducerIsFailClosed();
        await ConcurrentStartsLaunchOnlyOnceAsync();
        await MissingAgentReachesBoundedTimeoutAsync();
        await ExternalCancellationPreventsLaunchAsync();
        Console.WriteLine(
            "Windows agent status, readiness, lifecycle, race, and timeout tests passed.");
    }

    private static void StatusReadinessDecoderIsStrictAndRedacted()
    {
        AgentStatusSnapshot snapshot = DecodeStatus(
            """
            {"event":"status","phase":"ready","input_owner":"local","readiness":{"accessibility":"not_applicable","input":"blocked_by_desktop","local_topology":"available","session_topology":"synchronizing"}}
            """);
        Assert(snapshot.Readiness.Accessibility == "not_applicable", "Windows accessibility must be not applicable");
        Assert(snapshot.Readiness.Input == "blocked_by_desktop", "input readiness must decode exactly");
        Assert(snapshot.Readiness.LocalTopology == "available", "local topology must decode exactly");
        Assert(snapshot.Readiness.SessionTopology == "synchronizing", "session topology must decode exactly");

        AssertStatusRejected(
            """
            {"event":"status","phase":"ready","input_owner":"local","readiness":{"accessibility":"not_applicable","input":"ready","local_topology":"available"}}
            """,
            "missing readiness fields must fail closed",
            "not_applicable");
        AssertStatusRejected(
            """
            {"event":"status","phase":"ready","input_owner":"local","readiness":{"accessibility":"not_applicable","input":"ready","local_topology":"available","session_topology":"ready","peer_secret":"do-not-expose"}}
            """,
            "unknown readiness fields must fail closed",
            "do-not-expose");
        AssertStatusRejected(
            """
            {"event":"status","phase":"ready","input_owner":"local","readiness":{"accessibility":"not_applicable","input":"future_input_state","local_topology":"available","session_topology":"ready"}}
            """,
            "unknown readiness values must fail closed",
            "future_input_state");
        AssertStatusRejected(
            """
            {"event":"status","phase":"ready","input_owner":"local","readiness":{"accessibility":"granted","input":"ready","local_topology":"available","session_topology":"ready"}}
            """,
            "Windows must reject a non-applicable accessibility state",
            "granted");
        AssertStatusRejected(
            """
            {"event":"status","phase":"ready","input_owner":"local","readiness":{"accessibility":"not_applicable","input":"ready","local_topology":"available","session_topology":"ready"}
            """,
            "malformed status JSON must fail closed",
            "session_topology");
    }

    private static void ReadinessReducerKeepsSignalsIndependent()
    {
        AgentReadinessPresentation desktopBlocked = AgentReadinessReducer.Reduce(
            new AgentReadinessSnapshot(
                "not_applicable",
                "blocked_by_desktop",
                "available",
                "not_connected"));
        Assert(
            desktopBlocked.InputEnvironment == InputEnvironmentState.BlockedByDesktop &&
            desktopBlocked.InputGuidance == InputEnvironmentGuidance.RefreshAfterNormalDesktop,
            "desktop blocking must use only normal-desktop refresh guidance");
        Assert(
            desktopBlocked.LocalDisplays == LocalDisplaysState.Available &&
            desktopBlocked.PeerTopology == PeerTopologyState.NotConnected,
            "local displays available must not imply that peer topology is ready");

        AgentReadinessPresentation synchronizing = AgentReadinessReducer.Reduce(
            new AgentReadinessSnapshot(
                "not_applicable",
                "ready",
                "unavailable",
                "synchronizing"));
        Assert(
            synchronizing.InputEnvironment == InputEnvironmentState.Ready &&
            synchronizing.LocalDisplays == LocalDisplaysState.Unavailable &&
            synchronizing.PeerTopology == PeerTopologyState.Synchronizing,
            "input, displays, and peer topology must remain separate signals");
    }

    private static void ClientDeadlinesExceedServerBudgetsAndRemainDistinct()
    {
        const int serverReadinessBudgetSeconds = 3;
        const int serverEmergencyBudgetSeconds = 20;
        string repository = FindRepositoryRoot();
        string client = File.ReadAllText(Path.Combine(
            repository,
            "apps/windows/src/Nodavo.Windows/Services/AgentClient.cs"));
        Match statusTimeout = Regex.Match(
            client,
            @"StatusRequestTimeout\s*=\s*TimeSpan\.FromSeconds\((\d+)\)");
        Match emergencyTimeout = Regex.Match(
            client,
            @"EmergencyRequestTimeout\s*=\s*TimeSpan\.FromSeconds\((\d+)\)");
        Assert(
            statusTimeout.Success && emergencyTimeout.Success,
            "status and emergency client timeouts must remain explicit and statically testable");
        int statusSeconds = int.Parse(statusTimeout.Groups[1].Value);
        int emergencySeconds = int.Parse(emergencyTimeout.Groups[1].Value);
        Assert(
            statusSeconds > serverReadinessBudgetSeconds,
            "status and lifecycle readiness must outlive the server's three-second probe budget");
        Assert(
            emergencySeconds > serverEmergencyBudgetSeconds && emergencySeconds != statusSeconds,
            "emergency stop must have a distinct deadline beyond the server's twenty-second safety budget");
        Assert(
            Regex.IsMatch(
                client,
                @"CommandEnvelope\(\""get_status\""\),\s*StatusRequestTimeout") &&
            Regex.IsMatch(
                client,
                @"CommandEnvelope\(\""emergency_stop\""\),\s*EmergencyRequestTimeout"),
            "get-status and emergency-stop must use their dedicated client deadlines");
    }

    private static void OverviewXamlHasBilingualReadinessResourcesAndNoAccessibilityAction()
    {
        string repository = FindRepositoryRoot();
        string overview = Path.Combine(
            repository,
            "apps/windows/src/Nodavo.Windows/Views/OverviewView.xaml");
        string xaml = File.ReadAllText(overview);
        Assert(
            xaml.Contains("AgentReachabilityText", StringComparison.Ordinal) &&
            xaml.Contains("InputEnvironmentText", StringComparison.Ordinal) &&
            xaml.Contains("LocalDisplaysText", StringComparison.Ordinal) &&
            xaml.Contains("PeerTopologyText", StringComparison.Ordinal),
            "overview must present the four independent readiness signals");
        Assert(
            xaml.Contains("StatusText", StringComparison.Ordinal) &&
            xaml.Contains("PeerText", StringComparison.Ordinal) &&
            xaml.Contains("InputOwnerText", StringComparison.Ordinal),
            "overview must retain session status, connected peer, and input owner");
        string viewModel = File.ReadAllText(Path.Combine(
            repository,
            "apps/windows/src/Nodavo.Windows/ViewModels/AgentViewModel.cs"));
        int unavailableStart = viewModel.IndexOf(
            "private Task SetUnavailableAsync",
            StringComparison.Ordinal);
        int checkingStart = viewModel.IndexOf("private void SetChecking", StringComparison.Ordinal);
        Assert(
            unavailableStart >= 0 && checkingStart > unavailableStart,
            "view model must centralize the status failure transition");
        string unavailableTransition = viewModel[unavailableStart..checkingStart];
        Assert(
            unavailableTransition.Contains(
                "PeerText = _resources.GetString(\"NoPeer\")",
                StringComparison.Ordinal) &&
            unavailableTransition.Contains(
                "InputOwnerText = _resources.GetString(\"InputOwnerLocal\")",
                StringComparison.Ordinal),
            "failed refresh and emergency operations must clear stale peer and input owner state");
        Assert(
            !xaml.Contains("RequestAccessibility", StringComparison.Ordinal) &&
            !xaml.Contains("request_accessibility", StringComparison.Ordinal),
            "Windows overview must not expose an accessibility request action");

        HashSet<string> english = ReadResourceNames(
            Path.Combine(repository, "apps/windows/src/Nodavo.Windows/Strings/en-US/Resources.resw"));
        HashSet<string> russian = ReadResourceNames(
            Path.Combine(repository, "apps/windows/src/Nodavo.Windows/Strings/ru-RU/Resources.resw"));
        foreach (Match uid in Regex.Matches(xaml, "x:Uid=\\\"([^\\\"]+)\\\""))
        {
            string resourcePrefix = $"{uid.Groups[1].Value}.";
            Assert(
                english.Any(name => name.StartsWith(resourcePrefix, StringComparison.Ordinal)),
                $"missing English XAML resource: {resourcePrefix}");
            Assert(
                russian.Any(name => name.StartsWith(resourcePrefix, StringComparison.Ordinal)),
                $"missing Russian XAML resource: {resourcePrefix}");
        }
    }

    private static AgentStatusSnapshot DecodeStatus(string json) =>
        AgentStatusDecoder.DecodeStatus(Encoding.UTF8.GetBytes(json));

    private static void AssertStatusRejected(string json, string message, string redactedDetail)
    {
        try
        {
            _ = DecodeStatus(json);
        }
        catch (InvalidDataException exception)
        {
            Assert(
                exception.Message == "Invalid agent status response." &&
                !exception.Message.Contains(redactedDetail, StringComparison.Ordinal),
                "invalid status details must be redacted");
            return;
        }
        throw new InvalidOperationException(message);
    }

    private static HashSet<string> ReadResourceNames(string path) =>
        XDocument.Load(path)
            .Root!
            .Elements("data")
            .Select(element => element.Attribute("name")?.Value)
            .OfType<string>()
            .ToHashSet(StringComparer.Ordinal);

    private static string FindRepositoryRoot()
    {
        foreach (string startingPath in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            for (DirectoryInfo? directory = new(startingPath); directory is not null;
                 directory = directory.Parent)
            {
                if (File.Exists(Path.Combine(
                    directory.FullName,
                    "apps/windows/src/Nodavo.Windows/Views/OverviewView.xaml")))
                {
                    return directory.FullName;
                }
            }
        }
        throw new InvalidOperationException("Unable to locate the Nodavo repository root.");
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
