import AppKit
import SwiftUI

private enum ProductSection: String, CaseIterable, Identifiable {
    case overview
    case devices
    case layout
    case transfers
    case settings

    var id: Self { self }

    var title: LocalizedStringKey {
        LocalizedStringKey("section_\(rawValue)")
    }

    var symbol: String {
        switch self {
        case .overview: "rectangle.2.swap"
        case .devices: "desktopcomputer.and.macbook"
        case .layout: "square.grid.2x2"
        case .transfers: "arrow.left.arrow.right"
        case .settings: "gearshape"
        }
    }
}

struct MainWindow: View {
    @ObservedObject var model: AppModel
    @State private var selection: ProductSection? = .overview

    var body: some View {
        NavigationSplitView {
            List(ProductSection.allCases, selection: $selection) { section in
                Label(section.title, systemImage: section.symbol)
                    .tag(section)
            }
            .navigationTitle("product_name")
        } detail: {
            switch selection ?? .overview {
            case .overview:
                OverviewView(model: model)
            case .devices:
                DevicesView(model: model)
            case .layout:
                LayoutView(model: model)
            case .transfers:
                TransfersView(model: model)
            case .settings:
                SettingsView(model: model)
            }
        }
    }
}

private struct DevicesView: View {
    @ObservedObject var model: AppModel
    @State private var endpoint = ""
    @State private var allowInput = false
    @State private var allowClipboardRead = false
    @State private var allowClipboardWrite = false
    @State private var allowFiles = false
    @State private var peerPendingRevocation: TrustedPeerSummary?

    var body: some View {
        Form {
            Section("pairing_new_device") {
                Text("pairing_explanation")
                    .foregroundStyle(.secondary)

                Button("pairing_listen") {
                    model.listenForPairing(capabilities: selectedCapabilities)
                }
                .disabled(model.pairingIsBusy || model.pairingPrompt != nil)

                HStack {
                    TextField("pairing_endpoint_placeholder", text: $endpoint)
                        .textFieldStyle(.roundedBorder)
                        .disabled(model.pairingIsBusy || model.pairingPrompt != nil)
                    Button("pairing_connect") {
                        model.connectForPairing(
                            endpoint: endpoint,
                            capabilities: selectedCapabilities
                        )
                    }
                    .disabled(
                        endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            || model.pairingIsBusy
                            || model.pairingPrompt != nil
                    )
                }
                Text("pairing_endpoint_help")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("pairing_permissions") {
                Toggle("pairing_allow_input", isOn: $allowInput)
                Toggle("pairing_allow_clipboard_read", isOn: $allowClipboardRead)
                Toggle("pairing_allow_clipboard_write", isOn: $allowClipboardWrite)
                Toggle("pairing_allow_files", isOn: $allowFiles)
                Text("pairing_permissions_help")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .disabled(model.pairingIsBusy || model.pairingPrompt != nil)

            Section("pairing_status") {
                Label(model.pairingStatusText, systemImage: pairingSymbol)

                if let prompt = model.pairingPrompt {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("pairing_compare_instruction")
                            .font(.headline)
                        LabeledContent("peer", value: prompt.peerName)
                        Text(prompt.code)
                            .font(.system(size: 38, weight: .bold, design: .monospaced))
                            .tracking(6)
                            .textSelection(.enabled)
                            .accessibilityLabel(Text("pairing_code"))
                        HStack {
                            Button("pairing_codes_match") {
                                model.confirmPairing(accepted: true)
                            }
                            .buttonStyle(.borderedProminent)
                            Button("pairing_cancel", role: .destructive) {
                                model.confirmPairing(accepted: false)
                            }
                        }
                    }
                    .padding(.vertical, 6)
                } else if model.pairingState != .idle && !model.pairingIsBusy {
                    Button("pairing_reset") { model.resetPairingStatus() }
                }

                if model.pairingState == .waiting {
                    Button("emergency_stop", role: .destructive) {
                        model.emergencyStop()
                    }
                }
            }

            Section {
                if model.trustedPeersIsLoading && model.trustedPeers.isEmpty {
                    ProgressView("trusted_devices_loading")
                } else if model.trustedPeers.isEmpty {
                    Text("trusted_devices_empty")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.trustedPeers) { peer in
                        TrustedPeerView(
                            peer: peer,
                            isBusy: model.deviceOperationPeerIDs.contains(peer.peerID),
                            setCapability: { capability, enabled in
                                model.setCapability(
                                    peerID: peer.peerID,
                                    capability: capability,
                                    enabled: enabled
                                )
                            },
                            requestRevocation: {
                                peerPendingRevocation = peer
                            }
                        )
                    }
                }

                if let errorKey = model.devicesErrorKey {
                    Label(LocalizedStringKey(errorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            } header: {
                HStack {
                    Text("trusted_devices")
                    Spacer()
                    if model.trustedPeersIsLoading && !model.trustedPeers.isEmpty {
                        ProgressView()
                            .controlSize(.small)
                    }
                    Button("trusted_devices_refresh") {
                        model.refreshTrustedPeers()
                    }
                    .disabled(
                        model.trustedPeersIsLoading
                            || model.placementMutationInProgress
                            || !model.deviceOperationPeerIDs.isEmpty
                    )
                }
            }

            Section {
                Label("pairing_prealpha_notice", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("section_devices")
        .onAppear {
            if model.trustedPeersState == .idle {
                model.refreshTrustedPeers()
            }
        }
        .alert(
            "trusted_device_revoke_title",
            isPresented: Binding(
                get: { peerPendingRevocation != nil },
                set: { if !$0 { peerPendingRevocation = nil } }
            ),
            presenting: peerPendingRevocation
        ) { peer in
            Button("trusted_device_revoke_confirm", role: .destructive) {
                model.revokePeer(peerID: peer.peerID)
                peerPendingRevocation = nil
            }
            Button("cancel", role: .cancel) {
                peerPendingRevocation = nil
            }
        } message: { peer in
            Text(String.localizedStringWithFormat(
                String(localized: "trusted_device_revoke_message"),
                peer.displayName
            ))
        }
    }

    private var pairingSymbol: String {
        switch model.pairingState {
        case .idle: "circle.dashed"
        case .waiting, .confirming: "hourglass"
        case .comparing: "number"
        case .paired: "checkmark.shield"
        case .declined: "xmark.shield"
        case .failed: "exclamationmark.triangle"
        }
    }

    private var selectedCapabilities: [PairingCapability] {
        var capabilities = [PairingCapability]()
        if allowInput { capabilities.append(.input) }
        if allowClipboardRead { capabilities.append(.clipboardRead) }
        if allowClipboardWrite { capabilities.append(.clipboardWrite) }
        if allowFiles { capabilities.append(.files) }
        return capabilities
    }
}

private struct TrustedPeerView: View {
    let peer: TrustedPeerSummary
    let isBusy: Bool
    let setCapability: (PairingCapability, Bool) -> Void
    let requestRevocation: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(peer.displayName)
                        .font(.headline)
                        .lineLimit(1)
                    Text(peer.redactedID)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .accessibilityLabel(Text("trusted_device_redacted_id"))
                }
                Spacer()
                if isBusy {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityLabel(Text("trusted_device_saving"))
                }
                Label(peer.state.localizedKey, systemImage: peer.state.symbol)
                    .foregroundStyle(peer.state == .active ? .green : .secondary)
            }

            Text("trusted_device_local_grants")
                .font(.subheadline.weight(.semibold))

            ForEach(PairingCapability.allCases) { capability in
                Toggle(
                    capability.localizedKey,
                    isOn: Binding(
                        get: { peer.localGrants.contains(capability) },
                        set: { setCapability(capability, $0) }
                    )
                )
                .disabled(peer.state == .revoked || isBusy)
            }

            Button("trusted_device_revoke", role: .destructive, action: requestRevocation)
                .disabled(peer.state == .revoked || isBusy)
        }
        .padding(.vertical, 6)
    }
}

private extension PairingCapability {
    var localizedKey: LocalizedStringKey {
        switch self {
        case .input: "trusted_grant_input"
        case .clipboardRead: "trusted_grant_clipboard_read"
        case .clipboardWrite: "trusted_grant_clipboard_write"
        case .files: "trusted_grant_files"
        }
    }
}

private extension TrustedPeerState {
    var localizedKey: LocalizedStringKey {
        switch self {
        case .active: "trusted_device_active"
        case .revoked: "trusted_device_revoked"
        }
    }

    var symbol: String {
        switch self {
        case .active: "checkmark.shield.fill"
        case .revoked: "xmark.shield"
        }
    }
}

private struct LayoutView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Form {
            Section {
                if model.trustedPeersIsLoading && model.trustedPeers.isEmpty {
                    ProgressView("layout_loading")
                } else if model.trustedPeers.isEmpty {
                    Text("layout_no_devices")
                        .foregroundStyle(.secondary)
                } else {
                    Picker("layout_device", selection: selectedPeerBinding) {
                        ForEach(model.trustedPeers) { peer in
                            Text(peer.displayName).tag(peer.peerID)
                        }
                    }
                    .disabled(model.placementMutationInProgress)

                    if let peer = model.selectedLayoutPeer {
                        LabeledContent("layout_device_id", value: peer.redactedID)
                        Label(peer.state.localizedKey, systemImage: peer.state.symbol)
                            .foregroundStyle(peer.state == .active ? .green : .secondary)
                    }
                }
            } header: {
                HStack {
                    Text("layout_selected_device")
                    Spacer()
                    if model.trustedPeersIsLoading && !model.trustedPeers.isEmpty {
                        ProgressView()
                            .controlSize(.small)
                    }
                    Button("trusted_devices_refresh") {
                        model.refreshTrustedPeers()
                    }
                    .disabled(
                        model.trustedPeersIsLoading
                            || model.placementMutationInProgress
                            || !model.deviceOperationPeerIDs.isEmpty
                    )
                }
            }

            Section("layout_position") {
                Picker("layout_position", selection: placementBinding) {
                    ForEach(PeerPlacement.allCases) { placement in
                        Label(placement.localizedKey, systemImage: placement.symbol)
                            .tag(placement)
                    }
                }
                .pickerStyle(.radioGroup)
                .labelsHidden()
                .disabled(!model.layoutCanChangePlacement)

                if model.placementMutationInProgress {
                    ProgressView("layout_saving")
                }
                if model.selectedLayoutPeer?.state == .revoked {
                    Label("layout_revoked_help", systemImage: "xmark.shield")
                        .foregroundStyle(.secondary)
                } else if model.selectedLayoutPlacementOutcomeUnknown {
                    Label("layout_outcome_unknown_help", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
            }

            Section("layout_how_it_works") {
                Text("layout_explanation")
                    .foregroundStyle(.secondary)
                Text("layout_disabled_explanation")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let errorKey = model.layoutErrorKey {
                Section {
                    Label(LocalizedStringKey(errorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }

            Section {
                Label("layout_prealpha_notice", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("section_layout")
        .onAppear {
            if model.trustedPeersState == .idle {
                model.refreshTrustedPeers()
            }
        }
    }

    private var selectedPeerBinding: Binding<String> {
        Binding(
            get: { model.selectedLayoutPeerID ?? "" },
            set: { model.selectLayoutPeer($0) }
        )
    }

    private var placementBinding: Binding<PeerPlacement> {
        Binding(
            get: { model.selectedLayoutPeer?.placement ?? .disabled },
            set: { model.setSelectedPeerPlacement($0) }
        )
    }
}

private extension PeerPlacement {
    var localizedKey: LocalizedStringKey {
        switch self {
        case .disabled: "layout_placement_disabled"
        case .left: "layout_placement_left"
        case .right: "layout_placement_right"
        case .above: "layout_placement_above"
        case .below: "layout_placement_below"
        }
    }

    var symbol: String {
        switch self {
        case .disabled: "nosign"
        case .left: "arrow.left.square"
        case .right: "arrow.right.square"
        case .above: "arrow.up.square"
        case .below: "arrow.down.square"
        }
    }
}

private struct TransfersView: View {
    @ObservedObject var model: AppModel
    @State private var selectedPaths = [String]()

    var body: some View {
        Form {
            Section("transfer_selection") {
                Text("transfer_selection_help")
                    .foregroundStyle(.secondary)

                Button("transfer_choose") {
                    chooseFilesAndFolders()
                }
                .disabled(model.transferIsBusy)

                if !selectedPaths.isEmpty {
                    LabeledContent(
                        "transfer_selected",
                        value: String.localizedStringWithFormat(
                            String(localized: "transfer_selection_count"),
                            selectedPaths.count,
                            AgentClient.maximumSelectedPaths
                        )
                    )
                }

                Button("transfer_send_selected") {
                    model.sendFiles(paths: selectedPaths)
                }
                .buttonStyle(.borderedProminent)
                .disabled(
                    selectedPaths.isEmpty
                        || model.transferIsBusy
                        || model.transferSelectionRequiresFreshPicker
                        || model.connectedPeer == nil
                )

                if model.connectedPeer == nil {
                    Label("transfer_requires_connection", systemImage: "link.badge.plus")
                        .foregroundStyle(.secondary)
                }
            }

            Section("transfer_queue_status") {
                if model.transferIsBusy {
                    ProgressView("transfer_queueing")
                } else if let reference = model.queuedTransferReference {
                    Label("transfer_queued", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    LabeledContent("transfer_queued_id", value: reference.redactedID)
                } else {
                    Text("transfer_not_queued")
                        .foregroundStyle(.secondary)
                }

                if let errorKey = model.transferErrorKey {
                    Label(LocalizedStringKey(errorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }

            if !model.currentTransfers.isEmpty {
                Section("transfer_current") {
                    ForEach(model.currentTransfers) { transfer in
                        TransferRowView(
                            transfer: transfer,
                            cancellationInProgress: model.transferCancellationInProgress
                                .contains(transfer.transferID),
                            cancellationNeedsRetry: model.transferCancellationNeedsRetry
                                .contains(transfer.transferID),
                            cancellationBlocked: model.transferCancellationAuthority.transferID
                                .map { $0 != transfer.transferID } ?? false,
                            cancel: { model.cancelTransfer(transfer.transferID) }
                        )
                        .id(transfer.transferID)
                    }
                }
            }

            if !model.recentTransfers.isEmpty {
                Section("transfer_recent_session") {
                    ForEach(model.recentTransfers) { transfer in
                        TransferRowView(
                            transfer: transfer,
                            cancellationInProgress: false,
                            cancellationNeedsRetry: false,
                            cancellationBlocked: false,
                            cancel: {}
                        )
                        .id(transfer.transferID)
                    }
                }
            }

            if model.currentTransfers.isEmpty && model.recentTransfers.isEmpty {
                Section("transfer_progress") {
                    Text("transfer_progress_empty")
                        .foregroundStyle(.secondary)
                }
            }

            if model.transferProgressIsStale || model.transferSession.truncated {
                Section("transfer_progress") {
                    if model.transferProgressIsStale {
                        Label("transfer_progress_stale", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                        Button("transfer_progress_retry") {
                            model.retryTransferProgress()
                        }
                    }
                    if model.transferSession.truncated {
                        Label("transfer_progress_truncated", systemImage: "ellipsis.circle")
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Section("safety") {
                Button("emergency_stop", role: .destructive) { model.emergencyStop() }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("section_transfers")
        .onAppear {
            model.refresh()
            model.setTransfersVisible(true)
        }
        .onDisappear { model.setTransfersVisible(false) }
    }

    private func chooseFilesAndFolders() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "transfer_picker_title")
        panel.message = String(localized: "transfer_picker_message")
        panel.prompt = String(localized: "transfer_picker_confirm")
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.canCreateDirectories = false

        guard panel.runModal() == .OK else { return }
        let paths = panel.urls.map { $0.standardizedFileURL.path }
        guard paths.count <= AgentClient.maximumSelectedPaths else {
            selectedPaths.removeAll()
            model.rejectOversizedTransferSelection()
            return
        }
        selectedPaths = paths
        model.clearTransferFeedback()
    }
}

private struct TransferRowView: View {
    let transfer: TransferSummary
    let cancellationInProgress: Bool
    let cancellationNeedsRetry: Bool
    let cancellationBlocked: Bool
    let cancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Label(transfer.direction.localizedKey, systemImage: transfer.direction.symbol)
                    .font(.headline)
                Spacer()
                Text(transfer.phase.localizedKey)
                    .foregroundStyle(.secondary)
            }

            Text(transfer.redactedID)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .accessibilityLabel(Text("transfer_redacted_id"))
                .accessibilityValue(Text(transfer.redactedID))

            switch transfer.progressMode {
            case .determinate(let processed, let total):
                ProgressView(value: Double(processed), total: Double(total))
                    .accessibilityLabel(Text("transfer_progress_accessibility"))
                    .accessibilityValue(Text(bytesText))
            case .completedEmpty:
                ProgressView(value: 1, total: 1)
                    .accessibilityLabel(Text("transfer_progress_accessibility"))
                    .accessibilityValue(Text("transfer_progress_complete"))
            case .indeterminate:
                ProgressView()
                    .controlSize(.small)
                    .accessibilityLabel(Text("transfer_progress_accessibility"))
                    .accessibilityValue(Text(bytesText))
            case .hidden:
                EmptyView()
            }

            Text(bytesText)
                .font(.caption)
                .foregroundStyle(.secondary)

            if let failure = transfer.failure {
                Label(failure.localizedKey, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
            }

            if cancellationInProgress {
                ProgressView("transfer_cancelling")
                    .controlSize(.small)
            } else if !transfer.phase.isTerminal && transfer.cancellable {
                Button(cancellationNeedsRetry ? "transfer_cancel_retry" : "transfer_cancel") {
                    cancel()
                }
                .disabled(cancellationBlocked)
            }
        }
        .padding(.vertical, 5)
        .accessibilityElement(children: .contain)
    }

    private var bytesText: String {
        guard let processed = transfer.processedBytes, let total = transfer.totalBytes else {
            return transfer.direction == .outbound
                ? String(localized: "transfer_bytes_outbound_unavailable")
                : String(localized: "transfer_bytes_inbound_unavailable")
        }
        return String.localizedStringWithFormat(
            String(localized: transfer.direction == .outbound
                ? "transfer_bytes_outbound"
                : "transfer_bytes_inbound"),
            ByteCountFormatter.string(fromByteCount: Int64(processed), countStyle: .file),
            ByteCountFormatter.string(fromByteCount: Int64(total), countStyle: .file)
        )
    }
}

private extension TransferDirection {
    var localizedKey: LocalizedStringKey {
        switch self {
        case .inbound: "transfer_direction_inbound"
        case .outbound: "transfer_direction_outbound"
        }
    }

    var symbol: String {
        switch self {
        case .inbound: "arrow.down"
        case .outbound: "arrow.up"
        }
    }
}

private extension TransferPhase {
    var localizedKey: LocalizedStringKey {
        LocalizedStringKey("transfer_phase_\(rawValue)")
    }
}

private extension TransferFailure {
    var localizedKey: LocalizedStringKey {
        LocalizedStringKey("transfer_failure_\(rawValue)")
    }
}

private struct OverviewView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 14) {
                Image(systemName: model.statusSymbol)
                    .font(.system(size: 34))
                    .foregroundStyle(model.statusColor)
                VStack(alignment: .leading) {
                    Text("overview_title")
                        .font(.title2.bold())
                    Text(model.statusText)
                        .foregroundStyle(.secondary)
                }
            }

            GroupBox("connection") {
                LabeledContent("peer", value: model.connectedPeer ?? String(localized: "no_peer"))
                LabeledContent("input_owner", value: model.inputOwner)
                LabeledContent("focus_state") { Text(model.focusStatusText) }
            }

            ReadinessCard(model: model)

            HStack {
                Button("control_peer") { model.requestRemoteFocus() }
                    .disabled(!model.focusCanRequestRemote)
                Button("return_focus") { model.releaseFocus() }
                    .disabled(!model.focusCanRelease)
                Button("emergency_stop", role: .destructive) { model.emergencyStop() }
                if model.focusOperationInProgress {
                    ProgressView()
                        .controlSize(.small)
                }
            }

            if model.focusOutcomeUnknown {
                Label("focus_outcome_unknown", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }

            Spacer()

            Label("prealpha_notice", systemImage: "hammer")
                .foregroundStyle(.secondary)
        }
        .padding(28)
        .navigationTitle("section_overview")
    }
}

private struct SettingsView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Form {
            Section("privacy") {
                LabeledContent("telemetry", value: String(localized: "disabled"))
                LabeledContent("cloud_account", value: String(localized: "not_required"))
            }
            Section("agent_service") {
                LabeledContent("agent_registration") {
                    Text(model.agentRegistrationStatusText)
                }
                if model.agentRegistrationNeedsAttention {
                    Label("agent_registration_help", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
            }
            Section("readiness") {
                ReadinessCard(model: model)
            }
            Section("software_update") {
                Label(model.updateStatusText, systemImage: model.updateStatusSymbol)
                    .foregroundStyle(model.updateStatusColor)

                if let version = model.updateStatus.version {
                    LabeledContent("update_version", value: version)
                }

                if model.updateStatus.receivedBytes == nil,
                   let total = model.updateStatus.totalBytes {
                    LabeledContent(
                        "update_download_size",
                        value: ByteCountFormatter.string(
                            fromByteCount: Int64(total),
                            countStyle: .file
                        )
                    )
                }

                if let received = model.updateStatus.receivedBytes,
                   let total = model.updateStatus.totalBytes {
                    ProgressView(value: Double(received), total: Double(total))
                    Text(String.localizedStringWithFormat(
                        String(localized: "update_progress_format"),
                        ByteCountFormatter.string(
                            fromByteCount: Int64(received),
                            countStyle: .file
                        ),
                        ByteCountFormatter.string(
                            fromByteCount: Int64(total),
                            countStyle: .file
                        )
                    ))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                if model.updateOperationInProgress {
                    ProgressView("update_request_in_progress")
                }

                HStack {
                    Button("update_check") { model.checkForUpdate() }
                        .disabled(!model.updateCanCheck)
                    Button("update_refresh") { model.refreshUpdateStatus() }
                        .disabled(model.updateOperationInProgress)
                }

                if model.updateCanDecide {
                    HStack {
                        Button(
                            model.updateStatus.phase == .downloadPaused
                                ? "update_resume_download"
                                : "update_download_stage"
                        ) {
                            model.decideUpdate(accepted: true)
                        }
                        .buttonStyle(.borderedProminent)
                        if model.updateCanDecline {
                            Button("update_decline", role: .cancel) {
                                model.decideUpdate(accepted: false)
                            }
                        }
                    }
                }

                if model.updateStatus.phase == .verifiedStaged {
                    Label("update_staged_development_notice", systemImage: "hammer")
                        .foregroundStyle(.secondary)
                }

                if let failure = model.updateFailureText {
                    Label(failure, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }

                Text("update_privacy_notice")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("safety") {
                Button("emergency_stop", role: .destructive) { model.emergencyStop() }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("section_settings")
        .onAppear {
            model.refreshReadiness()
            model.refreshUpdateStatus()
        }
    }
}

private struct ReadinessCard: View {
    @ObservedObject var model: AppModel

    var body: some View {
        GroupBox("readiness") {
            VStack(alignment: .leading, spacing: 8) {
                LabeledContent("readiness_agent_reachable") {
                    Text(model.reachabilityText)
                }
                LabeledContent("readiness_accessibility") {
                    Text(model.readiness.accessibility.localizedKey)
                }
                LabeledContent("readiness_input") {
                    Text(model.readiness.input.localizedKey)
                }
                LabeledContent("readiness_local_displays") {
                    Text(model.readiness.localTopology.localizedKey)
                }
                LabeledContent("readiness_peer_topology") {
                    Text(model.readiness.sessionTopology.localizedKey)
                }

                if model.readinessRequestInProgress {
                    ProgressView("readiness_request_in_progress")
                        .controlSize(.small)
                }

                Button("refresh_status") {
                    model.refreshReadiness()
                }
                .disabled(model.readinessRequestInProgress)

                if model.readinessCanRequestAccessibilityPermission {
                    Text("readiness_accessibility_action_required_help")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("readiness_allow_accessibility") {
                        model.requestAccessibilityPermission()
                    }
                    .buttonStyle(.borderedProminent)
                    Text("readiness_accessibility_refresh_help")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if model.connectionState == .unavailable {
                    Label("agent_registration_help", systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        }
    }
}

private extension AppModel {
    var reachabilityText: LocalizedStringKey {
        switch connectionState {
        case .checking: "readiness_reachability_checking"
        case .ready, .connected: "readiness_reachability_reachable"
        case .unavailable, .failed: "readiness_reachability_unavailable"
        }
    }
}

private extension AccessibilityReadiness {
    var localizedKey: LocalizedStringKey {
        switch self {
        case .granted: "readiness_accessibility_granted"
        case .actionRequired: "readiness_accessibility_action_required"
        case .notApplicable: "readiness_accessibility_not_applicable"
        case .unavailable: "readiness_unavailable"
        }
    }
}

private extension InputReadiness {
    var localizedKey: LocalizedStringKey {
        switch self {
        case .ready: "readiness_input_ready"
        case .blockedByPermission: "readiness_input_blocked_by_permission"
        case .blockedByDesktop: "readiness_input_blocked_by_desktop"
        case .unavailable: "readiness_unavailable"
        }
    }
}

private extension LocalTopologyReadiness {
    var localizedKey: LocalizedStringKey {
        switch self {
        case .available: "readiness_local_topology_available"
        case .unavailable: "readiness_unavailable"
        }
    }
}

private extension SessionTopologyReadiness {
    var localizedKey: LocalizedStringKey {
        switch self {
        case .notConnected: "readiness_session_not_connected"
        case .synchronizing: "readiness_session_synchronizing"
        case .ready: "readiness_session_ready"
        }
    }
}
