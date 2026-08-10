#!/usr/bin/env python3
"""Static, cross-host safety checks for the pre-alpha Windows product UI."""

from __future__ import annotations

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
devices = (APP / "Views/DevicesView.xaml.cs").read_text(encoding="utf-8")
transfers = (APP / "Views/TransfersView.xaml.cs").read_text(encoding="utf-8")
rust_runtime = (ROOT / "crates/nodavo-agent/src/runtime.rs").read_text(encoding="utf-8")

dynamic_resource_prefixes = set(
    re.findall(r'(?:ShowStatus|ShowTrustedStatus)\("([^"]+)"', devices + transfers)
)
dynamic_resource_prefixes.update(("TrustedRevokeReconciling", "TrustedRevokeVerifying"))
for prefix in dynamic_resource_prefixes:
    assert prefix + "Title" in english, f"missing dynamic title resource: {prefix}"
    assert prefix + "Message" in english, f"missing dynamic message resource: {prefix}"

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

print(
    "Windows product UI static checks passed: resources, XML, deadlines, "
    "trust ownership/reconciliation, and transfer retry lockout"
)
