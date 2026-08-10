using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;
using Nodavo.Windows.ViewModels;

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
        TransferSnapshotDecoderAcceptsOnlyExactBoundedWireData();
        TransferSnapshotDecoderRejectsPrivateAndMalformedDataGenerically();
        TransferReducerGuardsInstanceRevisionGenerationAndCancelOwnership();
        TransferAdmissionReconciliationIsBoundedAndNeverResends();
        TransferPollLifecycleQueuesRefreshAcrossReload();
        TransferUiHasPollingProgressPrivacyAndAccessibilityAuthority();
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

    private static void TransferSnapshotDecoderAcceptsOnlyExactBoundedWireData()
    {
        const string instanceId = "11111111-1111-1111-1111-111111111111";
        const string transferId = "22222222-2222-2222-2222-222222222222";
        TransferListSnapshot preparing = DecodeTransfers(
            TransferEnvelope(
                instanceId,
                1,
                false,
                TransferRow(transferId, "outbound", "preparing", "null", "null", true, "null")));
        Assert(preparing.InstanceId == instanceId && preparing.Revision == 1,
            "transfer instance and revision must decode exactly");
        Assert(preparing.Transfers.Count == 1 &&
            preparing.Transfers[0].RedactedTransferId == "••••••••-22222222" &&
            !preparing.Transfers[0].RedactedTransferId.Contains(transferId, StringComparison.Ordinal),
            "the decoder must expose only the required redacted transfer ID");

        TransferListSnapshot zero = DecodeTransfers(
            TransferEnvelope(
                instanceId,
                2,
                false,
                TransferRow(transferId, "inbound", "transferring", "0", "0", true, "null")));
        Assert(zero.Transfers[0].ProcessedBytes == 0 && zero.Transfers[0].TotalBytes == 0 &&
            !zero.Transfers[0].IsTerminal,
            "zero-byte nonterminal progress must remain an explicit nonterminal state");

        foreach (string failure in new[]
        {
            "admission_failed",
            "source_unavailable",
            "authorization_revoked",
            "transport_failed",
            "cleanup_failed",
            "internal",
        })
        {
            TransferListSnapshot failed = DecodeTransfers(
                TransferEnvelope(
                    instanceId,
                    3,
                    false,
                    TransferRow(transferId, "inbound", "failed", "null", "null", false,
                        $"\"{failure}\"")));
            Assert(failed.Transfers[0].Failure.HasValue,
                $"bounded failure value must decode: {failure}");
        }

        TransferListSnapshot completed = DecodeTransfers(
            TransferEnvelope(
                instanceId,
                4,
                true,
                TransferRow(transferId, "outbound", "completed", "0", "0", false, "null")));
        Assert(completed.Truncated && completed.Transfers[0].IsTerminal,
            "zero-byte completion must remain explicitly terminal and preserve truncation");

        TransferListSnapshot preManifestCancelled = DecodeTransfers(
            TransferEnvelope(
                instanceId,
                5,
                false,
                TransferRow(transferId, "outbound", "cancelled", "null", "null", false, "null")));
        Assert(preManifestCancelled.Transfers[0].IsTerminal &&
            !preManifestCancelled.Transfers[0].ProcessedBytes.HasValue,
            "pre-manifest cancellation may carry two null counters");

        TransferListSnapshot manifestedFailure = DecodeTransfers(
            TransferEnvelope(
                instanceId,
                6,
                false,
                TransferRow(transferId, "outbound", "failed", "4", "9", false,
                    "\"internal\"")));
        Assert(manifestedFailure.Transfers[0].Failure == TransferFailure.Internal &&
            manifestedFailure.Transfers[0].ProcessedBytes == 4,
            "manifested terminal failure may preserve bounded byte counters");
    }

    private static void TransferSnapshotDecoderRejectsPrivateAndMalformedDataGenerically()
    {
        const string instanceId = "11111111-1111-1111-1111-111111111111";
        const string transferId = "22222222-2222-2222-2222-222222222222";
        const string casedInstanceId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        const string casedTransferId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        string validRow = TransferRow(
            transferId,
            "outbound",
            "transferring",
            "5",
            "10",
            true,
            "null");
        var rejected = new List<(string Json, string Detail)>
        {
            (TransferEnvelope(instanceId, 0, false, validRow), transferId),
            (TransferEnvelope(casedInstanceId.ToUpperInvariant(), 1, false, validRow), casedInstanceId),
            (TransferEnvelope(Guid.Empty.ToString("D"), 1, false, validRow), instanceId),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(casedTransferId.ToUpperInvariant(), "outbound", "transferring", "5", "10", true, "null")), casedTransferId),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(Guid.Empty.ToString("D"), "outbound", "transferring", "5", "10", true, "null")), transferId),
            (TransferEnvelope(instanceId, 1, false, validRow + "," + validRow), transferId),
            (TransferEnvelope(instanceId, 1, false,
                validRow[..^1] + ",\"private_path\":\"C:\\\\private.txt\"}"), "private.txt"),
            (TransferEnvelope(instanceId, 1, false,
                validRow.Replace("\"phase\":\"transferring\"", "\"phase\":\"transferring\",\"phase\":\"paused\"")), "paused"),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "sideways", "transferring", "5", "10", true, "null")), "sideways"),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "future_phase", "5", "10", true, "null")), "future_phase"),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "transferring", "null", "null", true, "null")), transferId),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "preparing", "null", "10", true, "null")), transferId),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "cancel_requested", "5", "10", true, "null")), transferId),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "transferring", "11", "10", true, "null")), transferId),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "transferring", "0", "10737418241", true, "null")), transferId),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "completed", "9", "10", false, "null")), transferId),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "completed", "10", "10", true, "null")), transferId),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "transferring", "5", "10", true, "\"transport_failed\"")), "transport_failed"),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "failed", "null", "null", false, "null")), transferId),
            (TransferEnvelope(instanceId, 1, false,
                TransferRow(transferId, "outbound", "failed", "null", "null", false, "\"future_failure\"")), "future_failure"),
            ($"{{\"event\":\"transfers\",\"instance_id\":\"{instanceId}\",\"revision\":1,\"truncated\":false,\"transfers\":[],\"peer_name\":\"private-peer\"}}", "private-peer"),
            ("{", transferId),
        };

        string maximumRows = string.Join(",", Enumerable.Range(1, 161).Select(index =>
            TransferRow(
                $"00000000-0000-0000-0000-{index:000000000000}",
                "outbound",
                "queued",
                "0",
                "1",
                true,
                "null")));
        rejected.Add((TransferEnvelope(instanceId, 1, false, maximumRows), transferId));

        for (int caseIndex = 0; caseIndex < rejected.Count; caseIndex++)
        {
            (string json, string detail) = rejected[caseIndex];
            AssertTransferRejected(json, detail, caseIndex);
        }
    }

    private static void TransferReducerGuardsInstanceRevisionGenerationAndCancelOwnership()
    {
        const string firstInstance = "11111111-1111-1111-1111-111111111111";
        const string secondInstance = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        const string firstTransfer = "22222222-2222-2222-2222-222222222222";
        const string secondTransfer = "33333333-3333-3333-3333-333333333333";
        TransfersState state = TransfersViewModel.Start(TransfersState.Empty);
        long generation = state.Generation;
        state = TransfersViewModel.ApplySnapshot(
            state,
            Snapshot(firstInstance, 5, false,
                Transfer(firstTransfer, TransferPhase.Transferring, true, 4, 8),
                Transfer(secondTransfer, TransferPhase.Transferring, true, 1, 8)),
            generation);
        Assert(state.Rows.Count == 2 && state.HasPollingWork,
            "a current transfer snapshot must start bounded polling work");

        TransfersState stale = TransfersViewModel.MarkPollFailure(state, generation);
        Assert(stale.IsStale && stale.Rows.Count == 2,
            "poll failure must preserve authoritative rows and mark them stale");
        TransfersState lower = TransfersViewModel.ApplySnapshot(
            stale,
            Snapshot(firstInstance, 4, false),
            generation);
        Assert(ReferenceEquals(lower, stale), "lower revisions must be ignored without clearing rows");
        TransfersState wrongGeneration = TransfersViewModel.ApplySnapshot(
            stale,
            Snapshot(firstInstance, 6, false),
            generation + 1);
        Assert(ReferenceEquals(wrongGeneration, stale),
            "late poll generations must not mutate transfer state");

        TransfersState ambiguous = TransfersViewModel.BeginCancel(stale, firstTransfer);
        ambiguous = TransfersViewModel.MarkCancelOutcomeUnknown(
            ambiguous,
            firstTransfer,
            generation);
        TransfersState truncatedEqual = TransfersViewModel.ApplySnapshot(
            ambiguous,
            Snapshot(firstInstance, 5, true,
                Transfer(secondTransfer, TransferPhase.Transferring, true, 7, 8)),
            generation);
        Assert(!truncatedEqual.IsStale && truncatedEqual.CancelOwnerId == firstTransfer &&
            truncatedEqual.CancelOutcomeUnknown,
            "equal fresh truncated revisions clear stale state without inferring an omitted cancel owner");
        TransfersState exactEqual = TransfersViewModel.ApplySnapshot(
            ambiguous,
            Snapshot(firstInstance, 5, false,
                Transfer(firstTransfer, TransferPhase.Paused, true, 7, 8),
                Transfer(secondTransfer, TransferPhase.Transferring, true, 7, 8)),
            generation);
        Assert(!exactEqual.IsStale && exactEqual.CancelOwnerId == firstTransfer &&
            exactEqual.CancelOutcomeUnknown &&
            TransfersViewModel.CanCancel(exactEqual, firstTransfer) &&
            !TransfersViewModel.CanCancel(exactEqual, secondTransfer) &&
            ReferenceEquals(exactEqual.Rows, ambiguous.Rows) &&
            exactEqual.Rows[0].Snapshot.Phase == TransferPhase.Transferring &&
            exactEqual.Rows[0].Snapshot.ProcessedBytes == 4,
            "equal revisions must retain row payload and same-ID authority while the owner remains active");
        TransfersState terminalEqual = TransfersViewModel.ApplySnapshot(
            ambiguous,
            Snapshot(firstInstance, 5, false,
                Transfer(firstTransfer, TransferPhase.CancelRequested, false, 0, 0),
                Transfer(secondTransfer, TransferPhase.Transferring, true, 7, 8)),
            generation);
        Assert(terminalEqual.CancelOwnerId is null && !terminalEqual.CancelOutcomeUnknown &&
            ReferenceEquals(terminalEqual.Rows, ambiguous.Rows),
            "equal revisions may reconcile only exact cancel-requested or terminal owner evidence");
        TransfersState absentEqual = TransfersViewModel.ApplySnapshot(
            ambiguous,
            Snapshot(firstInstance, 5, false,
                Transfer(secondTransfer, TransferPhase.Transferring, true, 7, 8)),
            generation);
        Assert(absentEqual.CancelOwnerId is null && !absentEqual.CancelOutcomeUnknown,
            "an untruncated equal revision may reconcile an owner that is authoritatively absent");

        TransfersState acceptedWithoutPhase = TransfersViewModel.CompleteCancelSnapshot(
            TransfersViewModel.BeginCancel(state, firstTransfer),
            Snapshot(firstInstance, 6, false,
                Transfer(firstTransfer, TransferPhase.Transferring, true, 5, 8),
                Transfer(secondTransfer, TransferPhase.Transferring, true, 2, 8)),
            firstTransfer,
            generation);
        Assert(acceptedWithoutPhase.CancelOwnerId == firstTransfer &&
            acceptedWithoutPhase.CancelOutcomeUnknown &&
            TransfersViewModel.CanCancel(acceptedWithoutPhase, firstTransfer) &&
            !TransfersViewModel.CanCancel(acceptedWithoutPhase, secondTransfer),
            "a successful cancel response without phase evidence must keep global ownership on the same ID");
        TransfersState deterministicallyRejected = TransfersViewModel.RejectCancel(
            acceptedWithoutPhase,
            firstTransfer,
            generation);
        Assert(deterministicallyRejected.CancelOwnerId is null &&
            !deterministicallyRejected.CancelOutcomeUnknown,
            "an explicit deterministic agent rejection may release cancel ownership");

        state = TransfersViewModel.BeginCancel(state, firstTransfer);
        Assert(state.CancelOwnerId == firstTransfer && state.CancelInFlight &&
            !TransfersViewModel.CanCancel(state, secondTransfer),
            "only one transfer row may own a cancellation mutation");
        state = TransfersViewModel.MarkCancelOutcomeUnknown(state, firstTransfer, generation);
        Assert(state.CancelOutcomeUnknown && TransfersViewModel.CanCancel(state, firstTransfer) &&
            !TransfersViewModel.CanCancel(state, secondTransfer),
            "ambiguous cancellation may retry only the same transfer ID");

        state = TransfersViewModel.ApplySnapshot(
            state,
            Snapshot(firstInstance, 6, true,
                Transfer(secondTransfer, TransferPhase.Transferring, true, 2, 8)),
            generation);
        Assert(state.CancelOwnerId == firstTransfer,
            "truncated snapshots must not infer that an omitted cancel owner disappeared");
        state = TransfersViewModel.ApplySnapshot(
            state,
            Snapshot(firstInstance, 7, false,
                Transfer(firstTransfer, TransferPhase.Cancelled, false, 4, 8),
                Transfer(secondTransfer, TransferPhase.Completed, false, 8, 8)),
            generation);
        Assert(state.CancelOwnerId is null && !state.HasPollingWork,
            "terminal phases must reconcile cancellation and stop polling");

        state = TransfersViewModel.ApplySnapshot(
            state,
            Snapshot(firstInstance, 8, false),
            generation);
        Assert(state.Rows.Count == 2 && state.Rows.All(row => row.Snapshot.IsTerminal),
            "terminal rows observed in this agent session must remain recent in-memory rows");
        state = TransfersViewModel.ApplySnapshot(
            state,
            Snapshot(secondInstance, 1, false),
            generation);
        Assert(state.InstanceId == secondInstance && state.Rows.Count == 0 && state.Revision == 1,
            "a new agent instance must clear prior in-session rows and accept its lower revision");

        TransfersState stopped = TransfersViewModel.Stop(state);
        TransfersState late = TransfersViewModel.ApplySnapshot(
            stopped,
            Snapshot(secondInstance, 2, false,
                Transfer(firstTransfer, TransferPhase.Completed, false, 8, 8)),
            generation);
        Assert(ReferenceEquals(late, stopped),
            "unload generation changes must reject late poll results");
    }

    private static void TransferAdmissionReconciliationIsBoundedAndNeverResends()
    {
        TransfersState state = TransfersViewModel.Start(TransfersState.Empty);
        long generation = state.Generation;
        state = TransfersViewModel.BeginAdmissionReconciliation(state);
        Assert(state.AdmissionReconciliationPending &&
            state.AdmissionReconciliationAttemptsRemaining ==
                TransfersViewModel.MaximumAdmissionReconciliationAttempts &&
            state.HasPollingWork,
            "local admission must create bounded authoritative-list polling even with no rows");

        for (int attempt = 1;
             attempt < TransfersViewModel.MaximumAdmissionReconciliationAttempts;
             attempt++)
        {
            state = TransfersViewModel.MarkPollFailure(state, generation);
            Assert(state.HasPollingWork,
                "a transient or explicit protocol list failure must continue bounded admission polling");
        }
        state = TransfersViewModel.MarkPollFailure(state, generation);
        Assert(state.AdmissionReconciliationPending &&
            state.AdmissionReconciliationAttemptsRemaining == 0 && !state.HasPollingWork,
            "automatic admission reconciliation must stop after its exact bounded attempt count");

        state = TransfersViewModel.RestartAdmissionReconciliation(state);
        Assert(state.AdmissionReconciliationAttemptsRemaining ==
                TransfersViewModel.MaximumAdmissionReconciliationAttempts && state.HasPollingWork,
            "explicit Refresh transfers must start another bounded reconciliation window");
        TransferListSnapshot authoritative = Snapshot(
            "11111111-1111-1111-1111-111111111111",
            1,
            false);
        Assert(TransfersViewModel.IsAuthoritativeSnapshot(state, authoritative, generation),
            "the first valid instance snapshot must be authoritative");
        state = TransfersViewModel.ApplySnapshot(state, authoritative, generation);
        Assert(!state.AdmissionReconciliationPending &&
            state.AdmissionReconciliationAttemptsRemaining == 0,
            "an authoritative list must end pending-admission reconciliation");
    }

    private static void TransferPollLifecycleQueuesRefreshAcrossReload()
    {
        TransferPollSchedule schedule = TransferPollLifecycle.Load(TransferPollSchedule.Empty);
        Assert(schedule.IsLoaded && schedule.ForcedRefreshPending,
            "load must owe one authoritative refresh");
        schedule = TransferPollLifecycle.TryStart(schedule, false, out bool started);
        Assert(started && schedule.LoopRunning && !schedule.ForcedRefreshPending,
            "the load refresh must start even without previously known rows");

        schedule = TransferPollLifecycle.RequestForcedRefresh(schedule);
        schedule = TransferPollLifecycle.TryStart(schedule, false, out bool overlapped);
        Assert(!overlapped && schedule.LoopRunning && schedule.ForcedRefreshPending,
            "a forced refresh during a loop must queue without overlapping it");
        (TransferPollSchedule consumedSchedule, bool consumed) =
            TransferPollLifecycle.TakeForcedRefresh(schedule);
        schedule = consumedSchedule;
        Assert(consumed && schedule.LoopRunning && !schedule.ForcedRefreshPending,
            "the active sequential loop must consume an owed follow-up refresh");

        schedule = TransferPollLifecycle.RequestForcedRefresh(schedule);
        schedule = TransferPollLifecycle.Unload(schedule);
        schedule = TransferPollLifecycle.Load(schedule);
        schedule = TransferPollLifecycle.TryStart(schedule, false, out bool racedStart);
        Assert(!racedStart && schedule.LoopRunning && schedule.ForcedRefreshPending,
            "rapid unload/reload must retain the new load refresh while the old loop winds down");
        schedule = TransferPollLifecycle.CompleteLoop(schedule);
        schedule = TransferPollLifecycle.TryStart(schedule, false, out bool restarted);
        Assert(restarted && schedule.LoopRunning && !schedule.ForcedRefreshPending,
            "old-loop completion must release and start the queued reload refresh");

        schedule = TransferPollLifecycle.Unload(schedule);
        schedule = TransferPollLifecycle.RequestForcedRefresh(schedule);
        Assert(!schedule.ForcedRefreshPending,
            "refresh requests while unloaded must not create background polling");
    }

    private static void TransferUiHasPollingProgressPrivacyAndAccessibilityAuthority()
    {
        string repository = FindRepositoryRoot();
        string client = File.ReadAllText(Path.Combine(
            repository,
            "apps/windows/src/Nodavo.Windows/Services/AgentClient.cs"));
        string view = File.ReadAllText(Path.Combine(
            repository,
            "apps/windows/src/Nodavo.Windows/Views/TransfersView.xaml.cs"));
        string xaml = File.ReadAllText(Path.Combine(
            repository,
            "apps/windows/src/Nodavo.Windows/Views/TransfersView.xaml"));
        Match listTimeout = Regex.Match(
            client,
            @"TransferListRequestTimeout\s*=\s*TimeSpan\.FromSeconds\((\d+)\)");
        Match cancelTimeout = Regex.Match(
            client,
            @"TransferCancelRequestTimeout\s*=\s*TimeSpan\.FromSeconds\((\d+)\)");
        Assert(listTimeout.Success && cancelTimeout.Success &&
            listTimeout.Groups[1].Value == "8" && cancelTimeout.Groups[1].Value == "8",
            "list and cancel must retain dedicated eight-second deadlines");
        Assert(client.Contains("CommandEnvelope(\"list_transfers\")", StringComparison.Ordinal) &&
            client.Contains("CancelTransferEnvelope(\"cancel_transfer\", transferId)", StringComparison.Ordinal),
            "the client must bind the exact list and cancel wire commands");
        Assert(view.Contains("TimeSpan.FromSeconds(1)", StringComparison.Ordinal) &&
            view.Contains("SemaphoreSlim _transferRequestGate = new(1, 1)", StringComparison.Ordinal) &&
            view.Contains("TransfersViewModel.Stop", StringComparison.Ordinal) &&
            view.Contains("IsCurrentTransferGeneration", StringComparison.Ordinal) &&
            view.Contains("TransferPollLifecycle.RequestForcedRefresh", StringComparison.Ordinal) &&
            view.Contains("ObservePollCompletionAsync", StringComparison.Ordinal),
            "polling must be sequential, approximately one second, unload-cancellable, and generation guarded");
        Assert(view.Contains("AgentProtocolException", StringComparison.Ordinal) &&
            view.Contains("TransfersViewModel.MarkPollFailure", StringComparison.Ordinal),
            "explicit list errors must preserve rows as stale and remain in bounded polling");
        Assert(view.Contains("BeginAdmissionReconciliation", StringComparison.Ordinal) &&
            view.Contains("RestartAdmissionReconciliation", StringComparison.Ordinal) &&
            Regex.Matches(view, @"_client\.SendFilesAsync\(").Count == 1,
            "admission reconciliation must be bounded status-only work without blind resend paths");
        Assert(view.Contains("zeroByteNonterminal", StringComparison.Ordinal) &&
            view.Contains("(!snapshot.TotalBytes.HasValue || zeroByteNonterminal)", StringComparison.Ordinal),
            "zero-byte nonterminal progress must remain indeterminate until a terminal phase");
        Assert(view.Contains("completedZeroBytes ? 1", StringComparison.Ordinal) &&
            view.Contains("TransferProgressCompleteZero", StringComparison.Ordinal),
            "completed zero-byte progress must expose a determinate native 100 percent value");
        Assert(!view.Contains(".Focus(", StringComparison.Ordinal) &&
            !view.Contains("peer", StringComparison.OrdinalIgnoreCase),
            "transfer updates must not force focus or display peer information");
        Assert(xaml.Contains("<ProgressBar", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.Name=\"{Binding ProgressAutomationName}\"", StringComparison.Ordinal) &&
            xaml.Contains("AutomationProperties.Name=\"{Binding CancelAutomationName}\"", StringComparison.Ordinal) &&
            xaml.Contains("Text=\"{Binding DirectionPhaseText}\"", StringComparison.Ordinal),
            "transfer rows need native progress/cancel controls and textual direction/phase authority");
    }

    private static TransferListSnapshot DecodeTransfers(string json) =>
        TransferSnapshotDecoder.DecodeTransfers(Encoding.UTF8.GetBytes(json));

    private static void AssertTransferRejected(
        string json,
        string privateDetail,
        int caseIndex)
    {
        try
        {
            _ = DecodeTransfers(json);
        }
        catch (InvalidDataException exception)
        {
            Assert(exception.Message == "Invalid transfer snapshot response." &&
                !exception.Message.Contains(privateDetail, StringComparison.Ordinal),
                "transfer decoder errors must be generic and redact private or malformed data");
            return;
        }
        throw new InvalidOperationException(
            $"malformed transfer response case {caseIndex} must fail closed");
    }

    private static string TransferEnvelope(
        string instanceId,
        ulong revision,
        bool truncated,
        string rows) =>
        $"{{\"event\":\"transfers\",\"instance_id\":\"{instanceId}\",\"revision\":{revision},\"truncated\":{truncated.ToString().ToLowerInvariant()},\"transfers\":[{rows}]}}";

    private static string TransferRow(
        string transferId,
        string direction,
        string phase,
        string processedBytes,
        string totalBytes,
        bool cancellable,
        string failure) =>
        $"{{\"transfer_id\":\"{transferId}\",\"direction\":\"{direction}\",\"phase\":\"{phase}\",\"processed_bytes\":{processedBytes},\"total_bytes\":{totalBytes},\"cancellable\":{cancellable.ToString().ToLowerInvariant()},\"failure\":{failure}}}";

    private static TransferListSnapshot Snapshot(
        string instanceId,
        ulong revision,
        bool truncated,
        params TransferSnapshot[] transfers) =>
        new(instanceId, revision, truncated, transfers);

    private static TransferSnapshot Transfer(
        string id,
        TransferPhase phase,
        bool cancellable,
        ulong processed,
        ulong total)
    {
        bool countersAreNull = phase is TransferPhase.Preparing or
            TransferPhase.CancelRequested or TransferPhase.Cancelled or TransferPhase.Failed;
        return new TransferSnapshot(
            id,
            $"••••••••-{id[^8..]}",
            TransferDirection.Outbound,
            phase,
            countersAreNull ? null : processed,
            countersAreNull ? null : total,
            cancellable,
            phase == TransferPhase.Failed ? TransferFailure.Internal : null);
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
