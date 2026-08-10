namespace Nodavo.Windows.Models;

internal enum AgentRunState
{
    Unknown,
    Stopped,
    Starting,
    Running,
    TimedOut,
    Unsupported,
    Failed,
}

internal enum AgentLaunchOutcome
{
    AlreadyRunning,
    Started,
    TimedOut,
    Unsupported,
    Failed,
}

internal enum AgentLaunchRequestResult
{
    Requested,
    Unsupported,
    Failed,
}

internal enum StartupRegistrationState
{
    Unknown,
    Disabled,
    DisabledByUser,
    DisabledByPolicy,
    Enabled,
    EnabledByPolicy,
    Unavailable,
}

internal enum StartupRecoveryKind
{
    None,
    EnableInWindowsSettings,
    ContactAdministrator,
    UnsupportedOrMissing,
}

internal enum StartupChangeAction
{
    None,
    Enable,
    Disable,
}

internal sealed record StartupControlState(
    bool IsEnabled,
    bool CanChange,
    StartupChangeAction Action,
    StartupRecoveryKind Recovery);

internal static class AgentLifecycleReducer
{
    internal static AgentRunState ReduceLaunch(AgentLaunchOutcome outcome) => outcome switch
    {
        AgentLaunchOutcome.AlreadyRunning or AgentLaunchOutcome.Started => AgentRunState.Running,
        AgentLaunchOutcome.TimedOut => AgentRunState.TimedOut,
        AgentLaunchOutcome.Unsupported => AgentRunState.Unsupported,
        _ => AgentRunState.Failed,
    };

    internal static StartupControlState ReduceStartup(StartupRegistrationState state) => state switch
    {
        StartupRegistrationState.Disabled => new(false, true, StartupChangeAction.Enable, StartupRecoveryKind.None),
        StartupRegistrationState.Enabled => new(true, true, StartupChangeAction.Disable, StartupRecoveryKind.None),
        StartupRegistrationState.DisabledByUser => new(
            false,
            false,
            StartupChangeAction.None,
            StartupRecoveryKind.EnableInWindowsSettings),
        StartupRegistrationState.DisabledByPolicy => new(
            false,
            false,
            StartupChangeAction.None,
            StartupRecoveryKind.ContactAdministrator),
        StartupRegistrationState.EnabledByPolicy => new(
            true,
            false,
            StartupChangeAction.None,
            StartupRecoveryKind.ContactAdministrator),
        StartupRegistrationState.Unavailable => new(
            false,
            false,
            StartupChangeAction.None,
            StartupRecoveryKind.UnsupportedOrMissing),
        _ => new(false, false, StartupChangeAction.None, StartupRecoveryKind.None),
    };
}
