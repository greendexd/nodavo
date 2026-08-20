import Foundation

enum FocusAuthority: Equatable {
    case unknown
    case local
    case controllingPeer
    case controlledByPeer
}

enum FocusOperationPhase: Equatable {
    case idle
    case acquireInFlight
    case acquireLeaseWindow
    case acquireReconciliation
    case releaseInFlight
    case releaseReconciliation
    case emergencyInFlight
    case statusReconciliation
    case outcomeUnknown
}

enum FocusNotice: Equatable {
    case none
    case rejected
    case statusUnavailable
}

struct FocusActionContext: Equatable {
    let hasConnectedPeer: Bool
    let isConnectedPhase: Bool
    let isInputReady: Bool
    let isLocalTopologyAvailable: Bool
    let isSessionTopologyReady: Bool

    static let unavailable = Self(
        hasConnectedPeer: false,
        isConnectedPhase: false,
        isInputReady: false,
        isLocalTopologyAvailable: false,
        isSessionTopologyReady: false
    )
}

struct FocusControlState: Equatable {
    var authority: FocusAuthority
    var phase: FocusOperationPhase
    var notice: FocusNotice
    var generation: UInt64
    var context: FocusActionContext

    static let initial = Self(
        authority: .unknown,
        phase: .idle,
        notice: .statusUnavailable,
        generation: 0,
        context: .unavailable
    )
}

enum FocusCommandContract {
    static let acquireLeaseMilliseconds: UInt32 = 5_000
    static let mutationDeadlineSeconds = 15
    static let reconciliationDeadlineSeconds = 8
    static let overallOperationDeadlineSeconds = 30

    static var maximumSequentialOperationSeconds: Int {
        mutationDeadlineSeconds
            + Int(acquireLeaseMilliseconds / 1_000)
            + reconciliationDeadlineSeconds
    }
}

enum FocusMutationFailureDisposition: Equatable {
    case rejected
    case outcomeUnknown

    static func classify(_ error: Error) -> Self {
        guard case let AgentClientError.agent(code, _) = error,
              code == "focus_rejected"
        else {
            return .outcomeUnknown
        }
        return .rejected
    }
}

enum FocusControlReducer {
    static func canAcquire(_ state: FocusControlState) -> Bool {
        state.phase == .idle
            && state.authority == .local
            && state.context.hasConnectedPeer
            && state.context.isConnectedPhase
            && state.context.isInputReady
            && state.context.isLocalTopologyAvailable
            && state.context.isSessionTopologyReady
    }

    // Returning input is a safety action. Exact nonlocal authority remains
    // releasable even when readiness or topology has degraded.
    static func canRelease(_ state: FocusControlState) -> Bool {
        state.phase == .idle
            && (state.authority == .controllingPeer || state.authority == .controlledByPeer)
    }

    static func isProgressVisible(_ state: FocusControlState) -> Bool {
        switch state.phase {
        case .acquireInFlight, .acquireLeaseWindow, .acquireReconciliation,
             .releaseInFlight, .releaseReconciliation, .emergencyInFlight,
             .statusReconciliation:
            true
        case .idle, .outcomeUnknown:
            false
        }
    }

    static func canBeginStatusRefresh(_ state: FocusControlState) -> Bool {
        state.phase == .idle || state.phase == .outcomeUnknown
    }

    static func beginStatusRefresh(
        _ state: FocusControlState,
        generation: UInt64
    ) -> FocusControlState {
        guard canBeginStatusRefresh(state) else { return state }
        var next = state
        next.phase = state.phase == .outcomeUnknown ? .statusReconciliation : .idle
        next.notice = .none
        next.generation = generation
        return next
    }

    static func beginAcquire(
        _ state: FocusControlState,
        generation: UInt64
    ) -> FocusControlState {
        guard canAcquire(state) else { return state }
        var next = state
        next.phase = .acquireInFlight
        next.notice = .none
        next.generation = generation
        return next
    }

    static func beginRelease(
        _ state: FocusControlState,
        generation: UInt64
    ) -> FocusControlState {
        guard canRelease(state) else { return state }
        var next = state
        next.phase = .releaseInFlight
        next.notice = .none
        next.generation = generation
        return next
    }

    // Emergency is unconditional and replaces the generation without claiming
    // local focus. Only its exact authoritative reply may establish authority.
    static func beginEmergency(
        _ state: FocusControlState,
        generation: UInt64
    ) -> FocusControlState {
        var next = state
        next.phase = .emergencyInFlight
        next.notice = .none
        next.generation = generation
        return next
    }

    static func applyMutationStatus(
        _ state: FocusControlState,
        generation: UInt64,
        authority: FocusAuthority,
        context: FocusActionContext
    ) -> FocusControlState {
        guard generation == state.generation else { return state }
        switch state.phase {
        case .acquireInFlight where authority == .local:
            var next = state
            next.authority = authority
            next.context = context
            next.phase = .acquireLeaseWindow
            next.notice = .none
            return next
        case .acquireInFlight:
            return idleWithStatus(state, authority: authority, context: context)
        case .releaseInFlight where authority == .local:
            return idleWithStatus(state, authority: authority, context: context)
        case .releaseInFlight:
            var next = state
            next.authority = authority
            next.context = context
            next.phase = .releaseReconciliation
            next.notice = .none
            return next
        case .emergencyInFlight:
            return idleWithStatus(state, authority: authority, context: context)
        default:
            return state
        }
    }

    static func applyReconciledStatus(
        _ state: FocusControlState,
        generation: UInt64,
        authority: FocusAuthority,
        context: FocusActionContext
    ) -> FocusControlState {
        guard generation == state.generation,
              state.phase == .acquireReconciliation
                || state.phase == .releaseReconciliation
                || state.phase == .statusReconciliation
        else { return state }
        return idleWithStatus(state, authority: authority, context: context)
    }

    static func applyOrdinaryStatus(
        _ state: FocusControlState,
        generation: UInt64,
        authority: FocusAuthority,
        context: FocusActionContext
    ) -> FocusControlState {
        guard generation == state.generation, state.phase == .idle else { return state }
        return idleWithStatus(state, authority: authority, context: context)
    }

    static func markAmbiguousMutation(
        _ state: FocusControlState,
        generation: UInt64
    ) -> FocusControlState {
        guard generation == state.generation else { return state }
        var next = state
        switch state.phase {
        case .acquireInFlight:
            next.phase = .acquireLeaseWindow
            next.notice = .none
            return next
        case .releaseInFlight:
            next.phase = .releaseReconciliation
            next.notice = .none
            return next
        case .emergencyInFlight:
            return unknownOutcome(state)
        default:
            return state
        }
    }

    static func markAcquireLeaseWindowElapsed(
        _ state: FocusControlState,
        generation: UInt64
    ) -> FocusControlState {
        guard generation == state.generation, state.phase == .acquireLeaseWindow else {
            return state
        }
        var next = state
        next.phase = .acquireReconciliation
        return next
    }

    static func rejectMutation(
        _ state: FocusControlState,
        generation: UInt64
    ) -> FocusControlState {
        guard generation == state.generation,
              state.phase == .acquireInFlight || state.phase == .releaseInFlight
        else { return state }
        var next = state
        next.phase = .idle
        next.notice = .rejected
        return next
    }

    static func failStatus(
        _ state: FocusControlState,
        generation: UInt64
    ) -> FocusControlState {
        guard generation == state.generation else { return state }
        if state.phase == .statusReconciliation {
            return unknownOutcome(state)
        }
        var next = state
        next.authority = .unknown
        next.phase = .idle
        next.notice = .statusUnavailable
        next.context = .unavailable
        return next
    }

    static func failReconciliation(
        _ state: FocusControlState,
        generation: UInt64
    ) -> FocusControlState {
        guard generation == state.generation,
              state.phase == .acquireLeaseWindow
                || state.phase == .acquireReconciliation
                || state.phase == .releaseReconciliation
                || state.phase == .statusReconciliation
        else { return state }
        return unknownOutcome(state)
    }

    static func expireOperation(
        _ state: FocusControlState,
        generation: UInt64
    ) -> FocusControlState {
        guard generation == state.generation else { return state }
        switch state.phase {
        case .acquireInFlight, .acquireLeaseWindow, .acquireReconciliation,
             .releaseInFlight, .releaseReconciliation:
            return unknownOutcome(state)
        case .idle, .emergencyInFlight, .statusReconciliation, .outcomeUnknown:
            return state
        }
    }

    private static func idleWithStatus(
        _ state: FocusControlState,
        authority: FocusAuthority,
        context: FocusActionContext
    ) -> FocusControlState {
        var next = state
        next.authority = authority
        next.phase = .idle
        next.notice = .none
        next.context = context
        return next
    }

    private static func unknownOutcome(_ state: FocusControlState) -> FocusControlState {
        var next = state
        next.authority = .unknown
        next.phase = .outcomeUnknown
        next.notice = .none
        next.context = .unavailable
        return next
    }
}
