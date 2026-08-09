// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "NodavoMacClipboardSpike",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "nodavo-macos-clipboard-spike", targets: ["NodavoMacClipboardSpike"])
    ],
    targets: [
        .executableTarget(
            name: "NodavoMacClipboardSpike",
            path: "Sources"
        )
    ]
)
