// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "NodavoMac",
    defaultLocalization: "en",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "Nodavo", targets: ["NodavoMac"])
    ],
    targets: [
        .executableTarget(
            name: "NodavoMac",
            path: "Sources",
            resources: [.process("Resources")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        )
    ]
)
