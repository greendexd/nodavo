import Darwin
import Foundation

enum PassiveSmokeBuildContract {
    #if NODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC
    static let isCompiledIn = true
    #else
    static let isCompiledIn = false
    #endif
}

#if NODAVO_DEVELOPMENT_UNVERIFIED_LOCAL_IPC
protocol PassiveSmokeClient: Sendable {
    func status() async throws -> AgentStatusResponse
    func focusStatus() async throws -> AgentStatusResponse
    func listTrustedPeers() async throws -> [TrustedPeerSummary]
    func listTransfers() async throws -> TransferSnapshot
}

private struct ProductionPassiveSmokeClient: PassiveSmokeClient {
    private let client = AgentClient()

    func status() async throws -> AgentStatusResponse {
        try await client.status()
    }

    func focusStatus() async throws -> AgentStatusResponse {
        try await client.focusStatus()
    }

    func listTrustedPeers() async throws -> [TrustedPeerSummary] {
        try await client.listTrustedPeers()
    }

    func listTransfers() async throws -> TransferSnapshot {
        try await client.listTransfers()
    }
}

private final class PassiveSmokeWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var result: Bool?

    func finish(_ candidate: Bool) {
        lock.lock()
        defer { lock.unlock() }
        guard result == nil else { return }
        result = candidate
        semaphore.signal()
    }

    func wait(seconds: Int) -> Bool? {
        guard semaphore.wait(timeout: .now() + .seconds(seconds)) == .success else {
            return nil
        }
        lock.lock()
        defer { lock.unlock() }
        return result
    }
}

enum PassiveSmokeCommand {
    static let argument = "--passive-smoke"
    static let successLine = "nodavo-ui: development-passive-read-only-smoke-ok"
    static let failureLine = "nodavo-ui: development-passive-read-only-smoke-failed"
    private static let wholeCommandDeadlineSeconds = 45

    static func isRequested(arguments: [String]) -> Bool {
        arguments.count == 2 && arguments[1] == argument
    }

    static func run(client: any PassiveSmokeClient) async -> Bool {
        var succeeded = true
        do { _ = try await client.status() } catch { succeeded = false }
        do { _ = try await client.focusStatus() } catch { succeeded = false }
        do { _ = try await client.listTrustedPeers() } catch { succeeded = false }
        do { _ = try await client.listTransfers() } catch { succeeded = false }
        return succeeded
    }

    static func runAndExit() -> Never {
        let waiter = PassiveSmokeWaiter()
        Task.detached {
            waiter.finish(await run(client: ProductionPassiveSmokeClient()))
        }
        let succeeded = waiter.wait(seconds: wholeCommandDeadlineSeconds) == true
        let line = succeeded ? successLine : failureLine
        let handle = succeeded ? FileHandle.standardOutput : FileHandle.standardError
        handle.write(Data((line + "\n").utf8))
        Darwin.exit(succeeded ? EXIT_SUCCESS : EXIT_FAILURE)
    }
}
#endif
