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
                PlaceholderSection(
                    title: "section_layout",
                    symbol: "square.grid.2x2",
                    message: "layout_in_progress"
                )
            case .transfers:
                PlaceholderSection(
                    title: "section_transfers",
                    symbol: "arrow.left.arrow.right",
                    message: "transfers_in_progress"
                )
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

            Section("trusted_devices") {
                Text("trusted_devices_in_progress")
                    .foregroundStyle(.secondary)
            }

            Section {
                Label("pairing_prealpha_notice", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("section_devices")
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

            HStack {
                Button("refresh_status") { model.refresh() }
                Button("control_peer") { model.requestRemoteFocus() }
                    .disabled(model.connectedPeer == nil || model.focusState != "local")
                Button("return_focus") { model.releaseFocus() }
                    .disabled(model.connectedPeer == nil || model.focusState == "local")
                Button("emergency_stop", role: .destructive) { model.emergencyStop() }
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
            Section("safety") {
                Button("emergency_stop", role: .destructive) { model.emergencyStop() }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("section_settings")
    }
}

private struct PlaceholderSection: View {
    let title: LocalizedStringKey
    let symbol: String
    let message: LocalizedStringKey

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: symbol)
                .font(.system(size: 42))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.title2.bold())
            Text(message)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 380)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle(title)
    }
}
