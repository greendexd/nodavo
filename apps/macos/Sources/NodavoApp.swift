import SwiftUI

@main
struct NodavoApp: App {
    @StateObject private var model = AppModel()

    init() {
        BundledAgentRegistration.ensureRegistered()
    }

    var body: some Scene {
        MenuBarExtra("Nodavo", systemImage: model.menuBarSymbol) {
            MenuContent(model: model)
        }
        .menuBarExtraStyle(.window)

        Window("product_name", id: "main") {
            MainWindow(model: model)
        }
        .defaultSize(width: 760, height: 520)
    }
}

private struct MenuContent: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: model.statusSymbol)
                    .foregroundStyle(model.statusColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text("product_name")
                        .font(.headline)
                    Text(model.statusText)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Divider()

            if let peer = model.connectedPeer {
                Label(peer, systemImage: "desktopcomputer")
            } else {
                Text("no_peer")
                    .foregroundStyle(.secondary)
            }

            Button("open_nodavo") {
                openWindow(id: "main")
                NSApplication.shared.activate(ignoringOtherApps: true)
            }

            Button("refresh_status") {
                model.refresh()
            }
            .keyboardShortcut("r")

            Button("emergency_stop", role: .destructive) {
                model.emergencyStop()
            }
            .keyboardShortcut(.escape, modifiers: [.control, .option, .shift])

            Divider()

            Text("prealpha_notice")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Button("quit") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q")
        }
        .padding(14)
        .frame(width: 300)
        .task {
            model.refresh()
        }
    }
}
