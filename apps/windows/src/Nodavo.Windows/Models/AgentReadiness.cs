namespace Nodavo.Windows.Models;

internal enum InputEnvironmentState
{
    Ready,
    ActionRequired,
    BlockedByDesktop,
    Unavailable,
}

internal enum InputEnvironmentGuidance
{
    None,
    RefreshAfterNormalDesktop,
}

internal enum LocalDisplaysState
{
    Available,
    Unavailable,
}

internal enum PeerTopologyState
{
    NotConnected,
    Synchronizing,
    Ready,
    Unavailable,
}

internal sealed record AgentReadinessPresentation(
    InputEnvironmentState InputEnvironment,
    InputEnvironmentGuidance InputGuidance,
    LocalDisplaysState LocalDisplays,
    PeerTopologyState PeerTopology);

internal static class AgentReadinessReducer
{
    // This reducer deliberately keeps local display discovery and peer topology separate.
    // A locally available display never asserts that a peer layout is ready.
    internal static AgentReadinessPresentation Reduce(AgentReadinessSnapshot readiness) =>
        new(
            readiness.Input switch
            {
                "ready" => InputEnvironmentState.Ready,
                "blocked_by_permission" => InputEnvironmentState.ActionRequired,
                "blocked_by_desktop" => InputEnvironmentState.BlockedByDesktop,
                _ => InputEnvironmentState.Unavailable,
            },
            readiness.Input == "blocked_by_desktop"
                ? InputEnvironmentGuidance.RefreshAfterNormalDesktop
                : InputEnvironmentGuidance.None,
            readiness.LocalTopology == "available"
                ? LocalDisplaysState.Available
                : LocalDisplaysState.Unavailable,
            readiness.SessionTopology switch
            {
                "not_connected" => PeerTopologyState.NotConnected,
                "synchronizing" => PeerTopologyState.Synchronizing,
                "ready" => PeerTopologyState.Ready,
                _ => PeerTopologyState.Unavailable,
            });
}
