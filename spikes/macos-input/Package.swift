// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "NodavoMacInputSpike",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "nodavo-macos-input-spike", targets: ["NodavoMacInputSpike"])
    ],
    targets: [
        .executableTarget(
            name: "NodavoMacInputSpike",
            path: "Sources"
        )
    ]
)
