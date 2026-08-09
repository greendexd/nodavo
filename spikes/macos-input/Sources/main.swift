import ApplicationServices
import CoreGraphics
import Foundation

private let nodavoSyntheticTag: Int64 = 0x4E_4F_44_41_56_4F

private enum Command: String {
    case checkPermission = "--check-permission"
    case requestPermission = "--request-permission"
    case monitor = "--monitor"
    case injectProbe = "--inject-probe"
}

private func accessibilityTrusted(prompt: Bool) -> Bool {
    let promptKey = "AXTrustedCheckOptionPrompt"
    return AXIsProcessTrustedWithOptions([promptKey: prompt] as CFDictionary)
}

private func printUsage() {
    print(
        """
        Nodavo macOS input feasibility spike

        USAGE:
          nodavo-macos-input-spike --check-permission
          nodavo-macos-input-spike --request-permission
          nodavo-macos-input-spike --monitor
          nodavo-macos-input-spike --inject-probe
        """
    )
}

private func eventBit(_ type: CGEventType) -> CGEventMask {
    CGEventMask(1) << type.rawValue
}

nonisolated(unsafe) private let eventTapCallback: CGEventTapCallBack = { _, type, event, _ in
    if event.getIntegerValueField(.eventSourceUserData) == nodavoSyntheticTag {
        return Unmanaged.passUnretained(event)
    }

    // Deliberately record event categories only. Key codes, pointer positions,
    // and typed content are not printed by this feasibility program.
    fputs("physical-event category=\(type.rawValue)\n", stderr)
    return Unmanaged.passUnretained(event)
}

private func monitorPhysicalInput() -> Never {
    guard accessibilityTrusted(prompt: false) else {
        fputs("Accessibility permission is required. Run --request-permission first.\n", stderr)
        exit(3)
    }

    let mask = [
        CGEventType.keyDown,
        .keyUp,
        .flagsChanged,
        .leftMouseDown,
        .leftMouseUp,
        .rightMouseDown,
        .rightMouseUp,
        .otherMouseDown,
        .otherMouseUp,
        .mouseMoved,
        .leftMouseDragged,
        .rightMouseDragged,
        .otherMouseDragged,
        .scrollWheel,
    ].reduce(CGEventMask(0)) { $0 | eventBit($1) }

    guard let eventTap = CGEvent.tapCreate(
        tap: .cgSessionEventTap,
        place: .headInsertEventTap,
        options: .listenOnly,
        eventsOfInterest: mask,
        callback: eventTapCallback,
        userInfo: nil
    ) else {
        fputs("Unable to create the session event tap.\n", stderr)
        exit(4)
    }

    let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, eventTap, 0)
    CFRunLoopAddSource(CFRunLoopGetCurrent(), source, .commonModes)
    CGEvent.tapEnable(tap: eventTap, enable: true)
    print("monitoring physical input categories; press Control-C to stop")
    CFRunLoopRun()
    exit(0)
}

private func injectTaggedProbe() {
    guard accessibilityTrusted(prompt: false) else {
        fputs("Accessibility permission is required. Run --request-permission first.\n", stderr)
        exit(3)
    }
    guard let source = CGEventSource(stateID: .privateState),
          let cursorProbe = CGEvent(source: source)
    else {
        fputs("Unable to create a CoreGraphics event source.\n", stderr)
        exit(4)
    }

    let current = cursorProbe.location
    guard let event = CGEvent(
        mouseEventSource: source,
        mouseType: .mouseMoved,
        mouseCursorPosition: current,
        mouseButton: .left
    ) else {
        fputs("Unable to create the synthetic probe event.\n", stderr)
        exit(4)
    }
    event.setIntegerValueField(.eventSourceUserData, value: nodavoSyntheticTag)
    event.post(tap: .cgSessionEventTap)
    print("posted a tagged no-motion probe event")
}

private let command = Command(rawValue: CommandLine.arguments.dropFirst().first ?? "")
switch command {
case .checkPermission:
    print(accessibilityTrusted(prompt: false) ? "trusted" : "not-trusted")
case .requestPermission:
    print(accessibilityTrusted(prompt: true) ? "trusted" : "permission-requested")
case .monitor:
    monitorPhysicalInput()
case .injectProbe:
    injectTaggedProbe()
case nil:
    printUsage()
    exit(2)
}
