import AppKit
import Foundation

private enum Command: String {
    case inspect = "--inspect"
    case watch = "--watch"
    case roundTripPrivate = "--round-trip-private"
}

private func safeTypeName(_ type: NSPasteboard.PasteboardType) -> String {
    switch type {
    case .string: "text"
    case .html: "html"
    case .png: "png"
    case .tiff: "tiff"
    case .fileURL: "file-url"
    default: "other"
    }
}

private func inspect(_ pasteboard: NSPasteboard) {
    let categories = Set((pasteboard.types ?? []).map(safeTypeName)).sorted()
    print("revision=\(pasteboard.changeCount) categories=\(categories.joined(separator: ","))")
}

private func watchGeneralPasteboard() -> Never {
    let pasteboard = NSPasteboard.general
    var revision = pasteboard.changeCount
    inspect(pasteboard)
    print("watching pasteboard metadata; contents are never printed")
    while true {
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.25))
        if pasteboard.changeCount != revision {
            revision = pasteboard.changeCount
            inspect(pasteboard)
        }
    }
}

private func roundTripOnPrivatePasteboard() {
    let pasteboard = NSPasteboard(name: .init("dev.nodavo.m0.clipboard"))
    pasteboard.clearContents()
    guard pasteboard.setString("nodavo-m0-probe", forType: .string),
          pasteboard.string(forType: .string) == "nodavo-m0-probe"
    else {
        fputs("private pasteboard round trip failed\n", stderr)
        exit(4)
    }
    pasteboard.clearContents()
    print("private pasteboard round trip succeeded")
}

private let command = Command(rawValue: CommandLine.arguments.dropFirst().first ?? "")
switch command {
case .inspect:
    inspect(.general)
case .watch:
    watchGeneralPasteboard()
case .roundTripPrivate:
    roundTripOnPrivatePasteboard()
case nil:
    fputs(
        "usage: nodavo-macos-clipboard-spike --inspect | --watch | --round-trip-private\n",
        stderr
    )
    exit(2)
}
