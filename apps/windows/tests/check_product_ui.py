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
transfers = (APP / "Views/TransfersView.xaml.cs").read_text(encoding="utf-8")
overview_xaml = (APP / "Views/OverviewView.xaml").read_text(encoding="utf-8")
rust_runtime = (ROOT / "crates/nodavo-agent/src/runtime.rs").read_text(encoding="utf-8")
agent_main = (ROOT / "crates/nodavo-agent/src/main.rs").read_text(encoding="utf-8")
package_script = (ROOT / "scripts/package-windows.ps1").read_text(encoding="utf-8")
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
    re.findall(r'(?:ShowStatus|ShowTrustedStatus)\("([^"]+)"', devices + transfers)
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
assert mutation_seconds > 10, "UI mutation deadline must exceed two agent 5s waits"
assert transfer_minutes * 60 > 305, "UI transfer deadline must exceed agent 5s + 5min waits"
assert "Duration::from_secs(5)" in rust_runtime
assert "TRANSFER_PREPARATION_DEADLINE: Duration = Duration::from_mins(5)" in rust_runtime

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
assert 'ReadRequiredText(root, "message", MaximumErrorMessageLength)' in client
assert "AllowedAgentErrorCodes.Contains(code)" in client

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
assert "FullTrustProcessLauncher" not in package_script
assert "windows.startupTask" in package_script
assert "ImmediateRegistration" in package_script
assert "Enabled') -cne 'false'" in package_script

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
assert "NODAVO_WINDOWS_AUTH_SIGNER_CERT_SHA256" in package_script
assert "NODAVO_WINDOWS_AUTH_PACKAGE_FAMILY_NAME" in package_script
assert "NODAVO_WINDOWS_AUTH_PUBLISHER" in package_script
assert "windows-ui-auth=$mode" in package_script
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
    "trust ownership/reconciliation, transfer retry lockout, and package auth policy"
)
