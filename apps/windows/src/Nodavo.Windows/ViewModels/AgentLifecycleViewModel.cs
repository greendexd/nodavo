using System.ComponentModel;
using System.Runtime.CompilerServices;
using Microsoft.Windows.ApplicationModel.Resources;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;

namespace Nodavo.Windows.ViewModels;

public sealed class AgentLifecycleViewModel : INotifyPropertyChanged
{
    private readonly AgentLifecycleCoordinator _coordinator;
    private readonly ResourceLoader _resources;
    private AgentRunState _agentState = AgentRunState.Unknown;
    private StartupRegistrationState _startupState = StartupRegistrationState.Unknown;
    private int _operationInProgress;

    internal AgentLifecycleViewModel(
        AgentLifecycleCoordinator coordinator,
        ResourceLoader resources)
    {
        _coordinator = coordinator;
        _resources = resources;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string AgentStateText => _resources.GetString(_agentState switch
    {
        AgentRunState.Stopped => "LifecycleAgentStopped",
        AgentRunState.Starting => "LifecycleAgentStarting",
        AgentRunState.Running => "LifecycleAgentRunning",
        AgentRunState.TimedOut => "LifecycleAgentTimedOut",
        AgentRunState.Unsupported => "LifecycleAgentUnsupported",
        AgentRunState.Failed => "LifecycleAgentFailed",
        _ => "LifecycleAgentChecking",
    });

    public string AgentRecoveryText => _resources.GetString(_agentState switch
    {
        AgentRunState.Stopped => "LifecycleAgentStoppedHelp",
        AgentRunState.TimedOut => "LifecycleAgentTimedOutHelp",
        AgentRunState.Unsupported => "LifecycleAgentUnsupportedHelp",
        AgentRunState.Failed => "LifecycleAgentFailedHelp",
        _ => "LifecycleNoRecovery",
    });

    public string StartupStateText => _resources.GetString(_startupState switch
    {
        StartupRegistrationState.Disabled => "StartupDisabled",
        StartupRegistrationState.DisabledByUser => "StartupDisabledByUser",
        StartupRegistrationState.DisabledByPolicy => "StartupDisabledByPolicy",
        StartupRegistrationState.Enabled => "StartupEnabled",
        StartupRegistrationState.EnabledByPolicy => "StartupEnabledByPolicy",
        StartupRegistrationState.Unavailable => "StartupUnavailable",
        _ => "StartupChecking",
    });

    public string StartupRecoveryText => _resources.GetString(_startupState switch
    {
        StartupRegistrationState.Disabled => "StartupDisabledHelp",
        StartupRegistrationState.DisabledByUser => "StartupDisabledByUserHelp",
        StartupRegistrationState.DisabledByPolicy => "StartupDisabledByPolicyHelp",
        StartupRegistrationState.Enabled => "StartupEnabledHelp",
        StartupRegistrationState.EnabledByPolicy => "StartupEnabledByPolicyHelp",
        StartupRegistrationState.Unavailable => "StartupUnavailableHelp",
        _ => "StartupCheckingHelp",
    });

    public string StartupActionText => _resources.GetString(
        AgentLifecycleReducer.ReduceStartup(_startupState).Action switch
        {
            StartupChangeAction.Enable => "StartupEnableAction",
            StartupChangeAction.Disable => "StartupDisableAction",
            _ => "StartupManagedAction",
        });

    public bool IsLifecycleOperationInProgress => Volatile.Read(ref _operationInProgress) != 0;

    public bool CanStartAgent =>
        !IsLifecycleOperationInProgress && _agentState is not AgentRunState.Running and
            not AgentRunState.Starting;

    public bool CanChangeStartup =>
        !IsLifecycleOperationInProgress &&
        AgentLifecycleReducer.ReduceStartup(_startupState).CanChange;

    internal async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        if (!TryBeginOperation())
        {
            return;
        }

        try
        {
            AgentLifecycleObservation observation =
                await _coordinator.ObserveAsync(cancellationToken);
            _agentState = observation.AgentState;
            _startupState = observation.StartupState;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _agentState = AgentRunState.Failed;
            _startupState = StartupRegistrationState.Unavailable;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            _agentState = AgentRunState.Failed;
            _startupState = StartupRegistrationState.Unavailable;
        }
        finally
        {
            EndOperation();
        }
    }

    internal async Task StartAgentAsync(CancellationToken cancellationToken = default)
    {
        if (!TryBeginOperation())
        {
            return;
        }

        _agentState = AgentRunState.Starting;
        NotifyAll();
        try
        {
            AgentLaunchOutcome outcome =
                await _coordinator.EnsureAgentRunningAsync(cancellationToken);
            _agentState = AgentLifecycleReducer.ReduceLaunch(outcome);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _agentState = AgentRunState.TimedOut;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            _agentState = AgentRunState.Failed;
        }
        finally
        {
            EndOperation();
        }
    }

    internal async Task ChangeStartupAsync(CancellationToken cancellationToken = default)
    {
        StartupControlState control = AgentLifecycleReducer.ReduceStartup(_startupState);
        if (!control.CanChange || !TryBeginOperation())
        {
            return;
        }

        try
        {
            _startupState = await _coordinator.SetStartupEnabledAsync(
                control.Action == StartupChangeAction.Enable,
                cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _startupState = StartupRegistrationState.Unavailable;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            _startupState = StartupRegistrationState.Unavailable;
        }
        finally
        {
            EndOperation();
        }
    }

    private bool TryBeginOperation()
    {
        if (Interlocked.CompareExchange(ref _operationInProgress, 1, 0) != 0)
        {
            return false;
        }
        NotifyAll();
        return true;
    }

    private void EndOperation()
    {
        Interlocked.Exchange(ref _operationInProgress, 0);
        NotifyAll();
    }

    private void NotifyAll()
    {
        OnPropertyChanged(nameof(AgentStateText));
        OnPropertyChanged(nameof(AgentRecoveryText));
        OnPropertyChanged(nameof(StartupStateText));
        OnPropertyChanged(nameof(StartupRecoveryText));
        OnPropertyChanged(nameof(StartupActionText));
        OnPropertyChanged(nameof(IsLifecycleOperationInProgress));
        OnPropertyChanged(nameof(CanStartAgent));
        OnPropertyChanged(nameof(CanChangeStartup));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
