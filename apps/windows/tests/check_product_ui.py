#!/usr/bin/env python3
"""Static, cross-host safety checks for the pre-alpha Windows product UI."""

from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[3]
APP = ROOT / "apps/windows/src/Nodavo.Windows"


def resource_keys(language: str) -> set[str]:
    path = APP / f"Strings/{language}/Resources.resw"
    root = ElementTree.parse(path).getroot()
    names = [node.attrib["name"] for node in root.findall("data")]
    assert len(names) == len(set(names)), f"duplicate {language} resource key"
    return set(names)


english = resource_keys("en-US")
russian = resource_keys("ru-RU")
assert english == russian, "English and Russian Windows resources differ"

for path in APP.rglob("*.xaml"):
    ElementTree.parse(path)
    for uid in re.findall(r'x:Uid="([^"]+)"', path.read_text(encoding="utf-8")):
        assert any(key == uid or key.startswith(uid + ".") for key in english), (
            f"missing resource for {path.relative_to(ROOT)}: {uid}"
        )

for path in APP.rglob("*.cs"):
    source = path.read_text(encoding="utf-8")
    for key in re.findall(r'GetString\("([^"]+)"\)', source):
        assert key in english, f"missing resource for {path.relative_to(ROOT)}: {key}"

client = (APP / "Services/AgentClient.cs").read_text(encoding="utf-8")
server_authenticator = (
    APP / "Services/AgentServerAuthenticator.cs"
).read_text(encoding="utf-8")
devices = (APP / "Views/DevicesView.xaml.cs").read_text(encoding="utf-8")
layout = (APP / "Views/LayoutView.xaml.cs").read_text(encoding="utf-8")
layout_xaml = (APP / "Views/LayoutView.xaml").read_text(encoding="utf-8")
placement_reducer = (
    APP / "Models/PeerPlacementState.cs"
).read_text(encoding="utf-8")
transfers = (APP / "Views/TransfersView.xaml.cs").read_text(encoding="utf-8")
transfers_xaml = (APP / "Views/TransfersView.xaml").read_text(encoding="utf-8")
transfer_model = (APP / "Models/TransferSnapshot.cs").read_text(encoding="utf-8")
transfer_decoder = (
    APP / "Services/TransferSnapshotDecoder.cs"
).read_text(encoding="utf-8")
transfer_reducer = (
    APP / "ViewModels/TransfersViewModel.cs"
).read_text(encoding="utf-8")
overview_xaml = (APP / "Views/OverviewView.xaml").read_text(encoding="utf-8")
settings_xaml = (APP / "Views/SettingsView.xaml").read_text(encoding="utf-8")
agent_view_model = (APP / "ViewModels/AgentViewModel.cs").read_text(encoding="utf-8")
focus_reducer = (APP / "Models/FocusControlState.cs").read_text(encoding="utf-8")
status_decoder = (APP / "Services/AgentStatusDecoder.cs").read_text(encoding="utf-8")
error_decoder = (APP / "Services/AgentErrorEnvelopeDecoder.cs").read_text(
    encoding="utf-8"
)
rust_runtime = (ROOT / "crates/nodavo-agent/src/runtime.rs").read_text(encoding="utf-8")
agent_main = (ROOT / "crates/nodavo-agent/src/main.rs").read_text(encoding="utf-8")
windows_agent_platform = (
    ROOT / "crates/nodavo-agent/src/windows/platform.rs"
).read_text(encoding="utf-8")
windows_platform = (
    ROOT / "crates/nodavo-platform-windows/src/windows/mod.rs"
).read_text(encoding="utf-8")
windows_ffi = (
    ROOT / "crates/nodavo-platform-windows/src/windows/ffi.rs"
).read_text(encoding="utf-8")
windows_platform_production = windows_platform.rsplit("#[cfg(test)]", 1)[0]
package_script = (ROOT / "scripts/package-windows.ps1").read_text(encoding="utf-8")
packaging_workflow = (
    ROOT / ".github/workflows/windows-packaging.yml"
).read_text(encoding="utf-8")
project_file = ElementTree.parse(APP / "Nodavo.Windows.csproj").getroot()
manifest_template_path = ROOT / "apps/windows/packaging/AppxManifest.xml.in"
manifest_template = ElementTree.parse(manifest_template_path).getroot()
manifest_source = manifest_template_path.read_text(encoding="utf-8")
lifecycle_platform = (
    APP / "Services/PackagedAgentLifecyclePlatform.cs"
).read_text(encoding="utf-8")
lifecycle_coordinator = (
    APP / "Services/AgentLifecycleCoordinator.cs"
).read_text(encoding="utf-8")
identity = json.loads(
    (ROOT / "apps/windows/packaging/identity.json").read_text(encoding="utf-8")
)

dynamic_resource_prefixes = set(
    re.findall(
        r'(?:ShowStatus|ShowTrustedStatus)\("([^"]+)"',
        devices + transfers + layout,
    )
)
dynamic_resource_prefixes.update(("TrustedRevokeReconciling", "TrustedRevokeVerifying"))
for prefix in dynamic_resource_prefixes:
    assert prefix + "Title" in english, f"missing dynamic title resource: {prefix}"
    assert prefix + "Message" in english, f"missing dynamic message resource: {prefix}"

lifecycle_resources = {
    "StartupTaskDisplayName",
    "LifecycleAgentChecking",
    "LifecycleAgentStopped",
    "LifecycleAgentStarting",
    "LifecycleAgentRunning",
    "LifecycleAgentTimedOut",
    "LifecycleAgentUnsupported",
    "LifecycleAgentFailed",
    "LifecycleNoRecovery",
    "LifecycleAgentStoppedHelp",
    "LifecycleAgentTimedOutHelp",
    "LifecycleAgentUnsupportedHelp",
    "LifecycleAgentFailedHelp",
    "StartupChecking",
    "StartupDisabled",
    "StartupDisabledByUser",
    "StartupDisabledByPolicy",
    "StartupEnabled",
    "StartupEnabledByPolicy",
    "StartupUnavailable",
    "StartupCheckingHelp",
    "StartupDisabledHelp",
    "StartupDisabledByUserHelp",
    "StartupDisabledByPolicyHelp",
    "StartupEnabledHelp",
    "StartupEnabledByPolicyHelp",
    "StartupUnavailableHelp",
    "StartupEnableAction",
    "StartupDisableAction",
    "StartupManagedAction",
}
assert lifecycle_resources <= english, "missing lifecycle localization resources"

focus_resources = {
    "FocusLabel.Text",
    "FocusAcquireButton.Content",
    "FocusReleaseButton.Content",
    "FocusStateLocal",
    "FocusStateControllingPeer",
    "FocusStateControlledByPeer",
    "FocusStateUnavailable",
    "FocusGuidanceReady",
    "FocusGuidanceConnectPeer",
    "FocusGuidanceWaitForReadiness",
    "FocusGuidanceControllingPeer",
    "FocusGuidanceControlledByPeer",
    "FocusGuidanceAcquiring",
    "FocusGuidanceAcquireLeaseWindow",
    "FocusGuidanceReleasing",
    "FocusGuidanceReconciling",
    "FocusGuidanceEmergency",
    "FocusGuidanceOutcomeUnknown",
    "FocusGuidanceRejected",
    "FocusGuidanceStatusUnavailable",
}
assert focus_resources <= english, "missing manual-focus localization resources"

placement_resources = {
    "LayoutPlacementDisabled",
    "LayoutPlacementLeft",
    "LayoutPlacementRight",
    "LayoutPlacementAbove",
    "LayoutPlacementBelow",
    "LayoutPeerRevokedDisplay",
    "LayoutLoadingTitle",
    "LayoutLoadingMessage",
    "LayoutLoadedTitle",
    "LayoutLoadedMessage",
    "LayoutEmptyTitle",
    "LayoutEmptyMessage",
    "LayoutTimeoutTitle",
    "LayoutTimeoutMessage",
    "LayoutFailedTitle",
    "LayoutFailedMessage",
    "LayoutReadyTitle",
    "LayoutReadyMessage",
    "LayoutSavingTitle",
    "LayoutSavingMessage",
    "LayoutSavedTitle",
    "LayoutSavedMessage",
    "LayoutReconcilingTitle",
    "LayoutReconcilingMessage",
    "LayoutReconciledAppliedTitle",
    "LayoutReconciledAppliedMessage",
    "LayoutReconciledNotAppliedTitle",
    "LayoutReconciledNotAppliedMessage",
    "LayoutPeerMissingTitle",
    "LayoutPeerMissingMessage",
    "LayoutPeerRevokedTitle",
    "LayoutPeerRevokedMessage",
    "LayoutOutcomeUnknownTitle",
    "LayoutOutcomeUnknownMessage",
}
assert placement_resources <= english, "missing peer-placement localization resources"

receive_destination_resources = {
    "PairingReceiveDestinationUnavailable",
    "TrustedReceiveDestinationUnavailableTitle",
    "TrustedReceiveDestinationUnavailableMessage",
    "TransferReceiveDestination.Text",
}
assert receive_destination_resources <= english
assert client.count('"receive_destination_unavailable"') == 1
assert 'ReceiveDestinationUnavailableCode = "receive_destination_unavailable"' in devices
assert "exception.Code == ReceiveDestinationUnavailableCode" in devices
assert devices.count("PairingProtocolFailureKey(exception,") == 2
assert "TrustedReceiveDestinationUnavailable" in devices
assert "PairingReceiveDestinationUnavailable" in devices

assert "TransferReceiveDestination.Text" in english
assert "Downloads/Nodavo" in ElementTree.parse(
    APP / "Strings/en-US/Resources.resw"
).find(".//data[@name='TransferReceiveDestination.Text']/value").text
assert "Downloads/Nodavo" in ElementTree.parse(
    APP / "Strings/ru-RU/Resources.resw"
).find(".//data[@name='TransferReceiveDestination.Text']/value").text
assert "never opened automatically" in ElementTree.parse(
    APP / "Strings/en-US/Resources.resw"
).find(".//data[@name='TransferReceiveDestination.Text']/value").text

mutation_seconds = float(
    re.search(
        r"MutationRequestTimeout\s*=\s*TimeSpan\.FromSeconds\(([0-9.]+)\)", client
    ).group(1)
)
transfer_minutes = float(
    re.search(
        r"TransferRequestTimeout\s*=\s*TimeSpan\.FromMinutes\(([0-9.]+)\)", client
    ).group(1)
)
transfer_list_seconds = float(
    re.search(
        r"TransferListRequestTimeout\s*=\s*TimeSpan\.FromSeconds\(([0-9.]+)\)",
        client,
    ).group(1)
)
transfer_cancel_seconds = float(
    re.search(
        r"TransferCancelRequestTimeout\s*=\s*TimeSpan\.FromSeconds\(([0-9.]+)\)",
        client,
    ).group(1)
)
assert mutation_seconds > 10, "UI mutation deadline must exceed two agent 5s waits"
placement_mutation_seconds = float(
    re.search(
        r"PlacementMutationRequestTimeout\s*=\s*TimeSpan\.FromSeconds\(([0-9.]+)\)",
        client,
    ).group(1)
)
assert placement_mutation_seconds > 10
assert "PlacementMutationRequestTimeout" != "MutationRequestTimeout"
assert transfer_minutes * 60 > 305, "UI transfer deadline must exceed agent 5s + 5min waits"
assert transfer_list_seconds == 8
assert transfer_cancel_seconds == 8
assert "TransferListRequestTimeout" != "TransferCancelRequestTimeout"
assert "Duration::from_secs(5)" in rust_runtime

focus_acquire_seconds = float(
    re.search(
        r"FocusAcquireRequestTimeout\s*=\s*TimeSpan\.FromSeconds\(([0-9.]+)\)",
        client,
    ).group(1)
)
focus_release_seconds = float(
    re.search(
        r"FocusReleaseRequestTimeout\s*=\s*TimeSpan\.FromSeconds\(([0-9.]+)\)",
        client,
    ).group(1)
)
assert focus_acquire_seconds == 15
assert focus_release_seconds == 15
assert "RemoteFocusLeaseMilliseconds = 5_000" in client
assert re.search(r'RequestRemoteFocusEnvelope\(\s*"request_remote_focus"', client)
assert 'CommandEnvelope("release_focus")' in client
assert client.count("DecodeStatusResponse,") == 5
assert 'RequireEvent(document.RootElement, "status")' in client
assert "return AgentStatusDecoder.DecodeStatus(payload);" in client
assert 'ReadRequiredEnum(\n                root,\n                "focus_state"' in status_decoder
assert "RequireExactStatusFields(root);" in status_decoder
for exact_status_field in (
    '"event"',
    '"phase"',
    '"connected_peer"',
    '"input_owner"',
    '"focus_state"',
    '"readiness"',
):
    assert exact_status_field in status_decoder
assert "if (fields.Count != 6)" in status_decoder
for exact_focus_state in ("local", "controlling_peer", "controlled_by_peer"):
    assert f'"{exact_focus_state}"' in status_decoder

for guard in (
    "state.Context.HasConnectedPeer",
    "state.Context.IsConnectedPhase",
    "state.Context.IsInputReady",
    "state.Context.IsLocalTopologyAvailable",
    "state.Context.IsSessionTopologyReady",
):
    assert guard in focus_reducer, f"missing focus acquisition guard: {guard}"
assert "state.Authority == FocusAuthority.Local" in focus_reducer
assert "FocusAuthority.ControllingPeer or FocusAuthority.ControlledByPeer" in focus_reducer
assert "AcquireLeaseMilliseconds = 5_000" in focus_reducer
assert "generation != state.Generation" in focus_reducer
assert "FocusOperationPhase.OutcomeUnknown" in focus_reducer
assert agent_view_model.count("_client.RequestRemoteFocusAsync(") == 1
assert agent_view_model.count("_client.ReleaseFocusAsync(") == 1
assert "FocusOperationDeadline = TimeSpan.FromSeconds(30)" in agent_view_model
assert "new CancellationTokenSource(FocusOperationDeadline)" in agent_view_model
assert "FocusControlReducer.AcquireLeaseMilliseconds),\n                cancellationToken" in (
    agent_view_model
)
assert "_focusOperationCancellation?.Cancel()" in agent_view_model
assert "FocusControlReducer.BeginEmergency" in agent_view_model
assert "FocusControlReducer.ApplyMutationStatus" in agent_view_model
assert "FocusControlReducer.ApplyReconciledStatus" in agent_view_model
assert agent_view_model.count(
    "FocusActionContext context = CreateFocusContext(status);"
) == 1
deterministic_rejection = re.search(
    r"private static bool IsDeterministicFocusRejection.*?;",
    agent_view_model,
    re.DOTALL,
).group(0)
assert 'exception.Code == "focus_rejected"' in deterministic_rejection
assert "not_connected" not in deterministic_rejection
for binding in (
    "FocusStateText",
    "CanRequestRemoteFocus",
    "CanReleaseFocus",
    "IsFocusOperationInProgress",
    "FocusGuidanceText",
):
    assert binding in overview_xaml, f"missing Overview focus binding: {binding}"

for exact_placement in ("disabled", "left", "right", "above", "below"):
    assert f'"{exact_placement}"' in client
    assert f'"{exact_placement}"' in placement_reducer
assert '"set_peer_placement"' in client
assert 'RequireEvent(root, "peer_placement_changed")' in client
assert 'RequireExactFields(root, "event", "peer_id", "placement")' in client
assert 'RequireExactFields(root, "event", "peers")' in client
assert '"local_grants",\n                "placement"' in client
assert "peerId != expectedPeerId || placement != expectedPlacement" in client
assert '"placement_apply_failed"' in client
assert layout.count("_client.SetPeerPlacementAsync(") == 1, (
    "layout must never blindly resend a placement mutation"
)
assert layout.count("_client.ListTrustedPeersAsync(") == 2, (
    "layout must use only initial/manual listing and status-only reconciliation"
)
assert "_unresolvedPeerIds.Add(peer.PeerId)" in layout
assert "_unresolvedPeerIds.Clear()" in layout
assert "PeerPlacementReducer.MarkAmbiguous" in layout
assert "PeerPlacementReducer.BeginReconciliation" in layout
assert "PeerPlacementReducer.FailReconciliation" in layout
assert 'SelectedPeer() is not { State: "active" } peer' in layout
assert "PlacementSelector.IsEnabled = !_requestInProgress && active && !unresolved" in layout
assert "PeerSelector.IsEnabled = !_requestInProgress" in layout
for control in (
    "PeerSelector",
    "PlacementSelector",
    "ApplyPlacementButton",
    "CurrentPlacementText",
    "LayoutProgress",
):
    assert control in layout_xaml, f"missing layout control: {control}"
assert "PeerPlacementOperationPhase.OutcomeUnknown" in placement_reducer
assert "state.PendingPlacement != placement" in placement_reducer
assert "state.PeerId != peerId" in placement_reducer
assert "proposedPlacement != state.AuthoritativePlacement" in placement_reducer

assert "_trustedRefreshGeneration" in devices
assert "_trustedMutationGeneration" in devices
assert "_trustedGeneration" not in devices
assert "_trustedRefreshPending" in devices
assert "_unresolvedPeerIds" in devices
assert "ReconcileCapabilityAsync" in devices
assert "ReconcileRevocationAsync" in devices
assert "_trustedMutationInProgress = false;" in devices
dialog_end = devices.index("await dialog.ShowAsync()")
mutation_start = devices.index("long mutation = ++_trustedMutationGeneration", dialog_end)
post_dialog_guard = devices[dialog_end:mutation_start]
assert "_trustedMutationInProgress" in post_dialog_guard
assert "_trustedRefreshInProgress" in post_dialog_guard
assert "currentPeer.PeerId != peer.PeerId" in post_dialog_guard
assert not re.search(
    r"catch\s*\(Exception exception\)\s*when\s*\(\s*"
    r"(?:generation|mutation)\s*==.*?&&\s*exception\s+is",
    devices,
    re.DOTALL,
), "stale-operation filters must not bypass expected exception handling"

assert "_outcomeUnknown = true;" in transfers
assert "!_outcomeUnknown" in transfers
assert "_outcomeUnknown\n            ? freshSelections" in transfers
assert "_sendInProgress = false;" in transfers
assert "TransferOutcomeUnknown" in transfers
assert "MaximumSelectedPaths = 32" in client
assert "MaximumSelectedPathBytes = 4 * 1024" in client
assert "AgentErrorEnvelopeDecoder.TryDecode(" in client
assert 'property.Name is not ("event" or "code" or "message")' in error_decoder
assert "if (seen.Count != 3)" in error_decoder
assert "!allowedCodes.Contains(code)" in error_decoder
assert "Invalid local IPC error envelope." in error_decoder
assert 'CommandEnvelope("list_transfers")' in client
assert 'CancelTransferEnvelope("cancel_transfer", transferId)' in client
assert "TransferListRequestTimeout" in client
assert "TransferCancelRequestTimeout" in client

assert "MaximumTransfers = 160" in transfer_decoder
assert "10UL * 1024 * 1024 * 1024" in transfer_decoder
assert "countersMayBeNull" in transfer_decoder
assert "TransferPhase.CancelRequested or TransferPhase.Cancelled or TransferPhase.Failed" in (
    transfer_decoder
)
assert "(!processedBytes.HasValue && !countersMayBeNull)" in transfer_decoder
assert 'ReadCanonicalIdentifier(root, "instance_id")' in transfer_decoder
assert 'ReadCanonicalIdentifier(element, "transfer_id")' in transfer_decoder
assert 'parsed.ToString("D")' in transfer_decoder
assert "parsed == Guid.Empty" in transfer_decoder
for exact_field in (
    '"event"',
    '"instance_id"',
    '"revision"',
    '"truncated"',
    '"transfers"',
    '"transfer_id"',
    '"direction"',
    '"phase"',
    '"processed_bytes"',
    '"total_bytes"',
    '"cancellable"',
    '"failure"',
):
    assert exact_field in transfer_decoder, f"missing exact transfer field: {exact_field}"
for failure in (
    "admission_failed",
    "source_unavailable",
    "authorization_revoked",
    "transport_failed",
    "cleanup_failed",
    "internal",
):
    assert f'"{failure}"' in transfer_decoder, f"missing bounded failure: {failure}"
assert 'InvalidResponse = "Invalid transfer snapshot response."' in transfer_decoder
assert "$\"••••••••-{transferId[^8..]}\"" in transfer_decoder
managed_tests = (
    ROOT / "apps/windows/tests/Nodavo.Windows.Lifecycle.Tests/Program.cs"
).read_text(encoding="utf-8")
assert 'casedInstanceId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"' in managed_tests
assert 'casedTransferId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"' in managed_tests
assert "caseIndex" in managed_tests
assert "public string TransferId" not in transfer_model + transfer_reducer + transfers

assert 'TimeSpan PollInterval = TimeSpan.FromSeconds(1)' in transfers
assert "SemaphoreSlim _transferRequestGate = new(1, 1)" in transfers
assert 'Loaded="TransfersView_Loaded"' in transfers_xaml
assert 'Unloaded="TransfersView_Unloaded"' in transfers_xaml
assert "TransfersViewModel.Stop(_transferState)" in transfers
assert "IsCurrentTransferGeneration" in transfers
assert "_transferState.HasPollingWork" in transfers
assert "TransferPollLifecycle.RequestForcedRefresh" in transfers
assert "TransferPollLifecycle.TakeForcedRefresh" in transfers
assert "TransferPollLifecycle.CompleteLoop" in transfers
assert "ObservePollCompletionAsync" in transfers
assert "BeginAdmissionReconciliation" in transfers
assert "RestartAdmissionReconciliation" in transfers
assert "AdmissionReconciliationAttemptsRemaining" in transfer_reducer
assert re.search(
    r"internal static class TransfersViewModel\s*\{\s*"
    r"internal const int MaximumAdmissionReconciliationAttempts = 5;",
    transfer_reducer,
), "admission attempt bound must be accessible to the reducer"
assert "string? equalCancelOwner =" in transfer_reducer
assert "bool equalCancelInFlight =" in transfer_reducer
assert "bool equalCancelUnknown =" in transfer_reducer
assert transfer_reducer.count("string? cancelOwner =") == 1, (
    "equal-revision locals must not shadow the main reducer locals"
)
assert transfers.count("_client.SendFilesAsync(") == 1, (
    "admission reconciliation must never create a blind resend path"
)
poll_catch = re.search(
    r"catch \(Exception exception\) when \(.*?AgentProtocolException.*?\)\s*\{\s*"
    r"_transferState = TransfersViewModel\.MarkPollFailure",
    transfers,
    re.DOTALL,
)
assert poll_catch, "explicit transfer-list errors must preserve stale rows"
assert "zeroByteNonterminal" in transfers
assert "(!snapshot.TotalBytes.HasValue || zeroByteNonterminal)" in transfers
assert "completedZeroBytes ? 1" in transfers
assert 'GetString("TransferProgressCompleteZero")' in transfers
assert ".Focus(" not in transfers
assert "Console." not in transfers
assert "Debug." not in transfers
assert "peer" not in transfers.lower()
assert "<ProgressBar" in transfers_xaml
assert 'AutomationProperties.Name="{Binding ProgressAutomationName}"' in transfers_xaml
assert 'AutomationProperties.Name="{Binding CancelAutomationName}"' in transfers_xaml
assert 'Text="{Binding DirectionPhaseText}"' in transfers_xaml
assert 'IsEnabled="{Binding CanCancel}"' in transfers_xaml
assert "TransferFeedStaleTitle" in english
assert "TransferFeedTruncatedTitle" in english
assert "TransferCancelUnknownTitle" in english
assert "TransferProgressCompleteZero" in english
assert "TransferAdmissionReconcilingTitle" in english
assert "TransferAdmissionUnresolvedTitle" in english

test_project = (
    ROOT / "apps/windows/tests/Nodavo.Windows.Lifecycle.Tests/"
    "Nodavo.Windows.Lifecycle.Tests.csproj"
).read_text(encoding="utf-8")
for linked_source in (
    "Models/PeerPlacementState.cs",
    "Models/TransferSnapshot.cs",
    "Services/TransferSnapshotDecoder.cs",
    "ViewModels/TransfersViewModel.cs",
):
    assert linked_source in test_project, f"pure transfer source is not linked: {linked_source}"

connect = client.index("await pipe.ConnectAsync(deadline.Token)")
authenticate_server = client.index(
    "AgentServerAuthenticator.Authenticate(pipe)", connect
)
write_request = client.index("await WriteFrameAsync(pipe, payload", authenticate_server)
pre_read_revalidation = client.index("server.Revalidate();", write_request)
read_response = client.index("await ReadFrameAsync(pipe", pre_read_revalidation)
post_read_revalidation = client.index("server.Revalidate();", read_response)
decode_response = client.index("return decode(response);", post_read_revalidation)
assert (
    connect
    < authenticate_server
    < write_request
    < pre_read_revalidation
    < read_response
    < post_read_revalidation
    < decode_response
), "named-pipe server authentication/revalidation ordering drifted"
for required_server_api in (
    "GetNamedPipeServerProcessId",
    "ProcessQueryLimitedInformation | ProcessSynchronize",
    "GetProcessTimes",
    "OpenProcessToken",
    "TokenStatistics",
    "WaitForSingleObject",
    "QueryFullProcessImageName",
    "FileFlagOpenReparsePoint",
    "GetFileInformationByHandleEx",
    "GetFinalPathNameByHandle",
    "WinVerifyTrust",
    "WTHelperGetProvSignerFromChain",
    "CryptographicOperations.FixedTimeEquals",
    "WtdStateActionClose",
):
    assert required_server_api in server_authenticator, (
        f"missing retained server-auth invariant: {required_server_api}"
    )
assert "Package.Current" in server_authenticator
assert 'Path.Combine(clientPackage.InstalledPath, policy.RelativeExecutable)' in (
    server_authenticator
)
assert "GetPackageFullName(" not in server_authenticator
assert "GetApplicationUserModelId(" not in server_authenticator
assert "Environment.GetEnvironmentVariable" not in server_authenticator
assert "serve_one_authorized_exchange" in agent_main
assert "await_framed_client_close(stream).await?" in agent_main
assert "CLOSE_ACK_TIMEOUT" in agent_main
assert "framed_connection_services_exactly_one_exchange" in agent_main
assert "framed_connection_rejects_a_second_queued_request" in agent_main

assert identity["development"]["packageIdentityName"] == (
    "dev.nodavo.Nodavo.Development"
)
assert identity["development"]["publisher"] == "CN=Nodavo Development Only"
for mode in ("development", "release"):
    assert identity[mode]["applicationId"] == "App"
    assert identity[mode]["executable"] == "Nodavo.Windows.exe"
assert identity["release"]["packageIdentityName"] == "dev.nodavo.Nodavo"
assert identity["lifecycle"] == {
    "agentExecutable": r"agent\nodavo-agent.exe",
    "startupTaskId": "NodavoAgentStartup",
}

expected_auth_attributes = {
    "Nodavo.AgentServerAuth.Mode": "$(NodavoAgentServerAuthMode)",
    "Nodavo.AgentServerAuth.PackageNameBase64": (
        "$(NodavoAgentServerAuthPackageNameBase64)"
    ),
    "Nodavo.AgentServerAuth.PublisherBase64": (
        "$(NodavoAgentServerAuthPublisherBase64)"
    ),
    "Nodavo.AgentServerAuth.PackageFamilyNameBase64": (
        "$(NodavoAgentServerAuthPackageFamilyNameBase64)"
    ),
    "Nodavo.AgentServerAuth.ApplicationUserModelIdBase64": (
        "$(NodavoAgentServerAuthApplicationUserModelIdBase64)"
    ),
    "Nodavo.AgentServerAuth.RelativeExecutableBase64": (
        "$(NodavoAgentServerAuthRelativeExecutableBase64)"
    ),
    "Nodavo.AgentServerAuth.SignerCertificateSha256": (
        "$(NodavoAgentServerAuthSignerCertificateSha256)"
    ),
}
auth_attributes: dict[str, str] = {}
for attribute in project_file.findall(".//AssemblyAttribute"):
    if attribute.attrib.get("Include") != "System.Reflection.AssemblyMetadataAttribute":
        continue
    key = attribute.findtext("_Parameter1")
    value = attribute.findtext("_Parameter2")
    assert key is not None and value is not None, "incomplete auth assembly metadata"
    assert key not in auth_attributes, f"duplicate auth assembly metadata: {key}"
    auth_attributes[key] = value
assert auth_attributes == expected_auth_attributes, "C# auth assembly metadata contract drifted"

foundation = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
desktop = "http://schemas.microsoft.com/appx/manifest/desktop/windows10"
applications = manifest_template.findall(f"{{{foundation}}}Applications")
assert len(applications) == 1
application_nodes = applications[0].findall(f"{{{foundation}}}Application")
assert len(application_nodes) == 1
extensions = application_nodes[0].findall(
    f"{{{foundation}}}Extensions/{{{desktop}}}Extension"
)
assert len(extensions) == 1, "manifest must declare exactly one desktop extension"
startup_extension = extensions[0]
assert startup_extension.attrib == {
    "Category": "windows.startupTask",
    "Executable": r"agent\nodavo-agent.exe",
    "EntryPoint": "Windows.FullTrustApplication",
}
startup_tasks = startup_extension.findall(f"{{{desktop}}}StartupTask")
assert len(startup_tasks) == 1
assert startup_tasks[0].attrib == {
    "TaskId": "NodavoAgentStartup",
    "Enabled": "false",
    "DisplayName": "ms-resource:StartupTaskDisplayName",
}
assert "fullTrustProcess" not in manifest_source
assert "ImmediateRegistration" not in manifest_source

restricted = (
    "http://schemas.microsoft.com/appx/manifest/"
    "foundation/windows10/restrictedcapabilities"
)
capability_containers = manifest_template.findall(f"{{{foundation}}}Capabilities")
assert len(capability_containers) == 1
declared_capabilities = [
    (node.tag, node.attrib)
    for node in list(capability_containers[0])
]
assert declared_capabilities == [
    (f"{{{foundation}}}Capability", {"Name": "privateNetworkClientServer"}),
    (f"{{{restricted}}}Capability", {"Name": "runFullTrust"}),
], "receive destination must not expand the package capability multiset"
for forbidden_capability in ("broadFileSystemAccess", "downloadsFolder"):
    assert forbidden_capability not in manifest_source
assert "capability multiset must be exactly privateNetworkClientServer and runFullTrust" in package_script

assert re.search(
    r"pub fn resolve_downloads_nodavo_directory\(\)\s*"
    r"-> Result<std::fs::File, WindowsPlatformError>",
    windows_platform,
), "Windows receive resolver must return only a retained owned handle"
for required_receive_boundary in (
    "SHGetKnownFolderPath",
    "FOLDERID_Downloads",
    "KF_FLAG_DEFAULT",
    "CoTaskWideString(value)",
    "create_private_receive_directory",
    "open_retained_update_directory",
    "open_retained_receive_directory",
    "validate_private_receive_handle",
    "FILE_ATTRIBUTE_REPARSE_POINT",
    'const RECEIVED_FILES_DIRECTORY_NAME: &str = "Nodavo"',
):
    assert required_receive_boundary in windows_platform + windows_ffi, (
        f"missing fixed Windows receive invariant: {required_receive_boundary}"
    )
assert "USERPROFILE" not in windows_platform_production + windows_ffi
assert 'var_os("HOME")' not in windows_platform_production + windows_ffi
assert "ReceiveRoot::from_retained_directory_handle(handle)" in windows_agent_platform
assert 'format!("O:{sid}D:P(A;OICI;FA;;;{sid})")' in windows_ffi
assert "create_private_update_directory(&lookup)" not in windows_platform
assert "validate_private_update_handle(&leaf)" not in windows_platform
assert "PathBuf" not in re.search(
    r"pub\(crate\) fn resolve_downloads_nodavo_directory\(\).*?\n}",
    windows_agent_platform,
    re.DOTALL,
).group(0), "agent bridge must not materialize or reopen the receive path"

assert "Package.Current.InstalledLocation.Path" in lifecycle_platform
assert 'AgentRelativePath = @"agent\\nodavo-agent.exe"' in lifecycle_platform
assert "UseShellExecute = false" in lifecycle_platform
assert "CreateNoWindow = true" in lifecycle_platform
assert "Process.Start(startInfo)" in lifecycle_platform
assert "ProcessStartInfo.Arguments" not in lifecycle_platform
assert "FullTrustProcessLauncher" not in lifecycle_platform
for forbidden in ("powershell", "cmd.exe", "schtasks", "currentversion\\run"):
    assert forbidden not in lifecycle_platform.lower()
assert "SemaphoreSlim _operationGate = new(1, 1)" in lifecycle_coordinator
assert lifecycle_coordinator.count("LaunchAgentAsync(cancellationToken)") == 1
assert "CancelAfter(_startDeadline)" in lifecycle_coordinator
emergency_button = re.search(
    r'<Button\s+x:Uid="EmergencyStopButton".*?/>', overview_xaml, re.DOTALL
).group(0)
assert "IsEnabled" not in emergency_button, "lifecycle state must not disable emergency stop"
settings_emergency_button = re.search(
    r'<Button\s+x:Uid="EmergencyStopButton".*?/>', settings_xaml, re.DOTALL
).group(0)
assert "IsEnabled" not in settings_emergency_button, (
    "focus/lifecycle state must not disable Settings emergency stop"
)
assert "FullTrustProcessLauncher" not in package_script
assert "windows.startupTask" in package_script
assert "ImmediateRegistration" in package_script
assert "Enabled') -cne 'false'" in package_script

package_build = packaging_workflow.index(
    "- name: Build and verify the development MSIX bundle"
)
installed_smoke = packaging_workflow.index(
    "- name: Install and inspect the exact development package"
)
package_upload = packaging_workflow.index(
    "- name: Upload development-only package evidence"
)
certificate_import = packaging_workflow.index("Import-Certificate", installed_smoke)
package_install = packaging_workflow.index("Add-AppxPackage", certificate_import)
manifest_inspection = packaging_workflow.index(
    "Get-AppxPackageManifest", package_install
)
agent_self_check = packaging_workflow.index("--self-check", manifest_inspection)
package_cleanup = packaging_workflow.index("Remove-AppxPackage", agent_self_check)
certificate_cleanup = packaging_workflow.index(
    "Remove-Item -LiteralPath $trustedCertificatePath", package_cleanup
)
assert (
    package_build
    < installed_smoke
    < certificate_import
    < package_install
    < manifest_inspection
    < agent_self_check
    < package_cleanup
    < certificate_cleanup
    < package_upload
), "installed-package smoke must run after build and clean up before upload"
assert "Cert:\\LocalMachine\\TrustedPeople" in packaging_workflow
assert "-allowunsigned" not in packaging_workflow.lower()
assert "windows-ui-auth=development" in packaging_workflow
assert "$applications[0].GetAttribute('Id') -cne 'App'" in packaging_workflow
assert "foundation:Extensions/desktop:Extension" in packaging_workflow
assert "$extensions[0].GetAttribute('Category')" in packaging_workflow
assert "'windows.startupTask'" in packaging_workflow
assert "$extensions[0].GetAttribute('EntryPoint')" in packaging_workflow
assert "'Windows.FullTrustApplication'" in packaging_workflow
assert "$startupTasks[0].GetAttribute('TaskId')" in packaging_workflow
assert "$startupTasks[0].GetAttribute('Enabled') -cne 'false'" in packaging_workflow
assert "$selfCheckProcess.WaitForExit(10000)" in packaging_workflow
assert "$selfCheckProcess.Kill($true)" in packaging_workflow
assert "$selfCheckProcess.WaitForExit(5000)" in packaging_workflow
assert "& $agent --self-check" not in packaging_workflow
assert "$primaryError = $_" in packaging_workflow
assert "$primaryError.Exception.Message" in packaging_workflow
assert "throw $primaryError" in packaging_workflow
assert "exact development package remains installed" in packaging_workflow
assert "exact development certificate remains trusted" in packaging_workflow

application_manifest = (APP / "app.manifest").read_text(encoding="utf-8")
assert 'requestedExecutionLevel level="asInvoker" uiAccess="false"' in application_manifest
assert "requireAdministrator" not in application_manifest

certificate_policy = package_script.index("$signerCertificateSha256 =")
metadata_properties = package_script.index(
    "$agentServerAuthMsBuildProperties =", certificate_policy
)
architecture_loop = package_script.index("foreach ($target in $architectures)")
executable_signing = package_script.index(
    "foreach ($executablePath in @($uiPath, $agentPath))", architecture_loop
)
package_pack = package_script.index("@('pack', '/d', $staged.StageRoot", architecture_loop)
release_import_candidates = package_script.index("$candidateReleaseImportThumbprints =")
release_preexistence_check = package_script.index(
    'Test-Path -LiteralPath "Cert:\\CurrentUser\\My\\$thumbprint"',
    release_import_candidates,
)
release_cleanup_ownership = package_script.index(
    "$releaseImportedThumbprints = $candidateReleaseImportThumbprints",
    release_preexistence_check,
)
release_private_import = package_script.index(
    "$importedCertificates = @(Import-PfxCertificate", release_cleanup_ownership
)
assert certificate_policy < architecture_loop, "signer pin must be embedded before Rust builds"
assert metadata_properties < architecture_loop, "C# server policy must be set before .NET builds"
assert "'--no-default-features'" in package_script
assert "'--features', $rustAuthFeature" in package_script
assert "& $cargo @(" in package_script
assert "$cargo.Source" not in package_script, (
    "Get-RequiredCommand already returns the cargo executable path"
)
assert "NODAVO_WINDOWS_AUTH_SIGNER_CERT_SHA256" in package_script
assert "NODAVO_WINDOWS_AUTH_PACKAGE_FAMILY_NAME" in package_script
assert "NODAVO_WINDOWS_AUTH_PUBLISHER" in package_script
assert "windows-ui-auth=$mode" in package_script
assert "Add-Type -TypeDefinition @'" in package_script
assert "'@ -PassThru" in package_script
assert "$winTrustType.GetMethod(" in package_script
assert "[Nodavo.WindowsPackaging.WinTrust]::" not in package_script, (
    "a helper type compiled inside a function must be invoked through its returned Type object"
)
for property_name in (
    "NodavoAgentServerAuthMode",
    "NodavoAgentServerAuthPackageNameBase64",
    "NodavoAgentServerAuthPublisherBase64",
    "NodavoAgentServerAuthPackageFamilyNameBase64",
    "NodavoAgentServerAuthApplicationUserModelIdBase64",
    "NodavoAgentServerAuthRelativeExecutableBase64",
    "NodavoAgentServerAuthSignerCertificateSha256",
):
    assert property_name in package_script, f"missing compile-time policy: {property_name}"
assert ") + $agentServerAuthMsBuildProperties" in package_script
assert package_script.count(") + $agentServerAuthMsBuildProperties") == 2
assert "Assert-CompiledAgentServerAuthMetadata" in package_script
assert "(Join-Path $publishRoot 'Nodavo.Windows.dll')" in package_script
assert "AgentPath = $agentPath" in package_script
assert executable_signing < package_pack, (
    "Windows UI and agent must be signed before MakeAppx packs them"
)
assert package_script.count(
    "Assert-AuthenticodeSignature $agentPath $ExpectedUiSigner $IsDevelopment"
) == 1, "unpacked agent signature must be verified"
assert package_script.count(
    "Assert-AuthenticodeSignature $uiPath $ExpectedUiSigner $IsDevelopment"
) == 1, "unpacked UI signature must be verified"
assert (
    release_import_candidates
    < release_preexistence_check
    < release_cleanup_ownership
    < release_private_import
), "release cleanup ownership must start only after all preexistence checks"
assert architecture_loop < release_private_import, (
    "release private key import must remain delayed until configured builds finish"
)

print(
    "Windows product UI static checks passed: resources, XML, deadlines, "
    "focus/trust/layout ownership and reconciliation, transfer polling/retry/progress, "
    "and package auth policy"
)
