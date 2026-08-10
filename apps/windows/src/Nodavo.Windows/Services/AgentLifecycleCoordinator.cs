using Nodavo.Windows.Models;

namespace Nodavo.Windows.Services;

internal interface IAgentReadinessProbe
{
    Task<bool> IsAgentReachableAsync(CancellationToken cancellationToken);
}

internal interface IAgentLifecyclePlatform
{
    Task<AgentLaunchRequestResult> LaunchAgentAsync(CancellationToken cancellationToken);

    Task<StartupRegistrationState> GetStartupStateAsync(CancellationToken cancellationToken);

    Task<StartupRegistrationState> SetStartupEnabledAsync(
        bool enabled,
        CancellationToken cancellationToken);
}

internal sealed record AgentLifecycleObservation(
    AgentRunState AgentState,
    StartupRegistrationState StartupState);

internal sealed class AgentLifecycleCoordinator
{
    private static readonly TimeSpan DefaultStartDeadline = TimeSpan.FromSeconds(12);
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromMilliseconds(250);
    private readonly IAgentReadinessProbe _probe;
    private readonly IAgentLifecyclePlatform _platform;
    private readonly TimeSpan _startDeadline;
    private readonly TimeSpan _pollInterval;
    private readonly SemaphoreSlim _operationGate = new(1, 1);

    internal AgentLifecycleCoordinator(
        IAgentReadinessProbe probe,
        IAgentLifecyclePlatform platform)
        : this(probe, platform, DefaultStartDeadline, DefaultPollInterval)
    {
    }

    internal AgentLifecycleCoordinator(
        IAgentReadinessProbe probe,
        IAgentLifecyclePlatform platform,
        TimeSpan startDeadline,
        TimeSpan pollInterval)
    {
        ArgumentNullException.ThrowIfNull(probe);
        ArgumentNullException.ThrowIfNull(platform);
        if (startDeadline <= TimeSpan.Zero || pollInterval <= TimeSpan.Zero ||
            pollInterval >= startDeadline)
        {
            throw new ArgumentOutOfRangeException(nameof(startDeadline));
        }

        _probe = probe;
        _platform = platform;
        _startDeadline = startDeadline;
        _pollInterval = pollInterval;
    }

    internal async Task<AgentLifecycleObservation> ObserveAsync(
        CancellationToken cancellationToken = default)
    {
        await _operationGate.WaitAsync(cancellationToken);
        try
        {
            bool reachable = await _probe.IsAgentReachableAsync(cancellationToken);
            StartupRegistrationState startup =
                await _platform.GetStartupStateAsync(cancellationToken);
            return new AgentLifecycleObservation(
                reachable ? AgentRunState.Running : AgentRunState.Stopped,
                startup);
        }
        finally
        {
            _operationGate.Release();
        }
    }

    internal async Task<AgentLaunchOutcome> EnsureAgentRunningAsync(
        CancellationToken cancellationToken = default)
    {
        await _operationGate.WaitAsync(cancellationToken);
        try
        {
            if (await _probe.IsAgentReachableAsync(cancellationToken))
            {
                return AgentLaunchOutcome.AlreadyRunning;
            }

            AgentLaunchRequestResult launch = await _platform.LaunchAgentAsync(cancellationToken);
            if (launch == AgentLaunchRequestResult.Unsupported)
            {
                return AgentLaunchOutcome.Unsupported;
            }
            if (launch != AgentLaunchRequestResult.Requested)
            {
                return AgentLaunchOutcome.Failed;
            }

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(_startDeadline);
            try
            {
                while (true)
                {
                    if (await _probe.IsAgentReachableAsync(deadline.Token))
                    {
                        return AgentLaunchOutcome.Started;
                    }
                    await Task.Delay(_pollInterval, deadline.Token);
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return AgentLaunchOutcome.TimedOut;
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    internal async Task<StartupRegistrationState> SetStartupEnabledAsync(
        bool enabled,
        CancellationToken cancellationToken = default)
    {
        await _operationGate.WaitAsync(cancellationToken);
        try
        {
            return await _platform.SetStartupEnabledAsync(enabled, cancellationToken);
        }
        finally
        {
            _operationGate.Release();
        }
    }
}
