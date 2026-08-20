using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.UI.Dispatching;
using Microsoft.Windows.ApplicationModel.Resources;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;

namespace Nodavo.Windows.ViewModels;

internal sealed class AgentViewModel : INotifyPropertyChanged
{
    // Acquisition may use 15s for the mutation, the complete 5s ambiguity
    // lease, and one 8s status read. This linked deadline bounds that entire
    // one-shot workflow, including IPC overhead, without authorizing a resend.
    private static readonly TimeSpan FocusOperationDeadline = TimeSpan.FromSeconds(30);

    private enum FocusStatusApplication
    {
        Refresh,
        Mutation,
        Reconciliation,
    }

    private enum FocusFailureApplication
    {
        Refresh,
        Emergency,
        Reconciliation,
    }

    private readonly AgentClient _client;
    private readonly ResourceLoader _resources;
    private readonly DispatcherQueue _dispatcher;
    private bool _requestInProgress;
    private bool _emergencyInProgress;
    private CancellationTokenSource? _focusOperationCancellation;
    private long _requestGeneration;
    private FocusControlState _focusState = FocusControlState.Initial;
    private string _agentReachabilityText;
    private string _inputEnvironmentText;
    private string _inputEnvironmentGuidanceText;
    private string _localDisplaysText;
    private string _peerTopologyText;
    private string _statusText;
    private string _peerText;
    private string _inputOwnerText;
    private string _focusStateText;
    private string _focusGuidanceText;
    private string _statusGlyph = "\uE823";

    internal AgentViewModel(AgentClient client, ResourceLoader resources)
    {
        _client = client;
        _resources = resources;
        _dispatcher = DispatcherQueue.GetForCurrentThread();
        _agentReachabilityText = resources.GetString("ReadinessChecking");
        _inputEnvironmentText = resources.GetString("ReadinessChecking");
        _inputEnvironmentGuidanceText = string.Empty;
        _localDisplaysText = resources.GetString("ReadinessChecking");
        _peerTopologyText = resources.GetString("ReadinessChecking");
        _statusText = resources.GetString("StatusChecking");
        _peerText = resources.GetString("NoPeer");
        _inputOwnerText = resources.GetString("InputOwnerLocal");
        _focusStateText = resources.GetString("FocusStateUnavailable");
        _focusGuidanceText = resources.GetString("FocusGuidanceStatusUnavailable");
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string AgentReachabilityText
    {
        get => _agentReachabilityText;
        private set => SetField(ref _agentReachabilityText, value);
    }

    public string InputEnvironmentText
    {
        get => _inputEnvironmentText;
        private set => SetField(ref _inputEnvironmentText, value);
    }

    public string InputEnvironmentGuidanceText
    {
        get => _inputEnvironmentGuidanceText;
        private set => SetField(ref _inputEnvironmentGuidanceText, value);
    }

    public string LocalDisplaysText
    {
        get => _localDisplaysText;
        private set => SetField(ref _localDisplaysText, value);
    }

    public string PeerTopologyText
    {
        get => _peerTopologyText;
        private set => SetField(ref _peerTopologyText, value);
    }

    public string StatusText { get => _statusText; private set => SetField(ref _statusText, value); }
    public string PeerText { get => _peerText; private set => SetField(ref _peerText, value); }
    public string InputOwnerText
    {
        get => _inputOwnerText;
        private set => SetField(ref _inputOwnerText, value);
    }

    public string FocusStateText
    {
        get => _focusStateText;
        private set => SetField(ref _focusStateText, value);
    }

    public string FocusGuidanceText
    {
        get => _focusGuidanceText;
        private set => SetField(ref _focusGuidanceText, value);
    }

    public string StatusGlyph { get => _statusGlyph; private set => SetField(ref _statusGlyph, value); }

    public bool IsRequestInProgress
    {
        get => _requestInProgress;
        private set
        {
            if (SetField(ref _requestInProgress, value))
            {
                NotifyFocusControls();
            }
        }
    }

    public bool CanRequestRemoteFocus =>
        !IsRequestInProgress && FocusControlReducer.CanAcquire(_focusState);

    public bool CanReleaseFocus =>
        !IsRequestInProgress && FocusControlReducer.CanRelease(_focusState);

    public bool IsFocusOperationInProgress => FocusControlReducer.IsProgressVisible(_focusState);

    internal async Task RefreshAsync()
    {
        if (IsRequestInProgress)
        {
            return;
        }

        long generation = Interlocked.Increment(ref _requestGeneration);
        _focusState = FocusControlReducer.BeginStatusRefresh(_focusState, generation);
        UpdateFocusPresentation();
        IsRequestInProgress = true;
        SetChecking();
        StatusGlyph = "\uE823";
        try
        {
            AgentStatusSnapshot status = await _client.GetStatusAsync();
            if (IsCurrent(generation))
            {
                await ApplyAsync(status, generation, FocusStatusApplication.Refresh);
            }
        }
        catch (OperationCanceledException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusAgentTimeout",
                    generation,
                    FocusFailureApplication.Refresh);
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusAgentAccessDenied",
                    generation,
                    FocusFailureApplication.Refresh);
            }
        }
        catch (IOException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusAgentUnavailable",
                    generation,
                    FocusFailureApplication.Refresh);
            }
        }
        catch (Exception exception) when (
            exception is InvalidDataException or JsonException or InvalidOperationException or
            AgentProtocolException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusFailed",
                    generation,
                    FocusFailureApplication.Refresh);
            }
        }
        finally
        {
            if (IsCurrent(generation))
            {
                IsRequestInProgress = false;
            }
        }
    }

    internal async Task EmergencyStopAsync()
    {
        if (_emergencyInProgress)
        {
            return;
        }

        _focusOperationCancellation?.Cancel();
        long generation = Interlocked.Increment(ref _requestGeneration);
        _focusState = FocusControlReducer.BeginEmergency(_focusState, generation);
        UpdateFocusPresentation();
        _emergencyInProgress = true;
        IsRequestInProgress = true;
        try
        {
            AgentStatusSnapshot status = await _client.EmergencyStopAsync();
            if (IsCurrent(generation))
            {
                await ApplyAsync(status, generation, FocusStatusApplication.Mutation);
            }
        }
        catch (OperationCanceledException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusAgentTimeout",
                    generation,
                    FocusFailureApplication.Emergency);
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusAgentAccessDenied",
                    generation,
                    FocusFailureApplication.Emergency);
            }
        }
        catch (IOException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusAgentUnavailable",
                    generation,
                    FocusFailureApplication.Emergency);
            }
        }
        catch (Exception exception) when (
            exception is InvalidDataException or JsonException or InvalidOperationException or
            AgentProtocolException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusFailed",
                    generation,
                    FocusFailureApplication.Emergency);
            }
        }
        finally
        {
            _emergencyInProgress = false;
            if (IsCurrent(generation))
            {
                IsRequestInProgress = false;
            }
        }
    }

    internal async Task RequestRemoteFocusAsync()
    {
        if (IsRequestInProgress || !FocusControlReducer.CanAcquire(_focusState))
        {
            return;
        }

        long generation = Interlocked.Increment(ref _requestGeneration);
        _focusState = FocusControlReducer.BeginAcquire(_focusState, generation);
        UpdateFocusPresentation();
        IsRequestInProgress = true;
        using var deadline = new CancellationTokenSource(FocusOperationDeadline);
        _focusOperationCancellation = deadline;
        try
        {
            AgentStatusSnapshot status = await _client.RequestRemoteFocusAsync(deadline.Token);
            if (IsCurrent(generation))
            {
                await ApplyAsync(status, generation, FocusStatusApplication.Mutation);
                if (_focusState.Phase == FocusOperationPhase.AcquireLeaseWindow)
                {
                    await ReconcileAcquireAsync(generation, deadline.Token);
                }
            }
        }
        catch (AgentProtocolException exception) when (IsDeterministicFocusRejection(exception))
        {
            if (IsCurrent(generation))
            {
                await RejectFocusMutationAsync(generation);
            }
        }
        catch (Exception exception) when (IsAmbiguousFocusFailure(exception))
        {
            if (IsCurrent(generation))
            {
                await MarkAmbiguousMutationAsync(generation);
                if (_focusState.Phase == FocusOperationPhase.AcquireLeaseWindow)
                {
                    await ReconcileAcquireAsync(generation, deadline.Token);
                }
            }
        }
        finally
        {
            if (ReferenceEquals(_focusOperationCancellation, deadline))
            {
                _focusOperationCancellation = null;
            }
            if (IsCurrent(generation))
            {
                IsRequestInProgress = false;
            }
        }
    }

    internal async Task ReleaseFocusAsync()
    {
        if (IsRequestInProgress || !FocusControlReducer.CanRelease(_focusState))
        {
            return;
        }

        long generation = Interlocked.Increment(ref _requestGeneration);
        _focusState = FocusControlReducer.BeginRelease(_focusState, generation);
        UpdateFocusPresentation();
        IsRequestInProgress = true;
        using var deadline = new CancellationTokenSource(FocusOperationDeadline);
        _focusOperationCancellation = deadline;
        try
        {
            AgentStatusSnapshot status = await _client.ReleaseFocusAsync(deadline.Token);
            if (IsCurrent(generation))
            {
                await ApplyAsync(status, generation, FocusStatusApplication.Mutation);
                if (_focusState.Phase == FocusOperationPhase.ReleaseReconciliation)
                {
                    await ReconcileReleaseAsync(generation, deadline.Token);
                }
            }
        }
        catch (AgentProtocolException exception) when (IsDeterministicFocusRejection(exception))
        {
            if (IsCurrent(generation))
            {
                await RejectFocusMutationAsync(generation);
            }
        }
        catch (Exception exception) when (IsAmbiguousFocusFailure(exception))
        {
            if (IsCurrent(generation))
            {
                await MarkAmbiguousMutationAsync(generation);
                if (_focusState.Phase == FocusOperationPhase.ReleaseReconciliation)
                {
                    await ReconcileReleaseAsync(generation, deadline.Token);
                }
            }
        }
        finally
        {
            if (ReferenceEquals(_focusOperationCancellation, deadline))
            {
                _focusOperationCancellation = null;
            }
            if (IsCurrent(generation))
            {
                IsRequestInProgress = false;
            }
        }
    }

    private async Task ReconcileAcquireAsync(
        long generation,
        CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(
                TimeSpan.FromMilliseconds(FocusControlReducer.AcquireLeaseMilliseconds),
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusAgentTimeout",
                    generation,
                    FocusFailureApplication.Reconciliation);
            }
            return;
        }
        if (!IsCurrent(generation))
        {
            return;
        }

        await RunOnUiAsync(() =>
        {
            _focusState = FocusControlReducer.MarkAcquireLeaseWindowElapsed(
                _focusState,
                generation);
            UpdateFocusPresentation();
        }, generation);

        if (IsCurrent(generation) &&
            _focusState.Phase == FocusOperationPhase.AcquireReconciliation)
        {
            await ReconcileStatusAsync(generation, cancellationToken);
        }
    }

    private Task ReconcileReleaseAsync(long generation, CancellationToken cancellationToken) =>
        ReconcileStatusAsync(generation, cancellationToken);

    private async Task ReconcileStatusAsync(
        long generation,
        CancellationToken cancellationToken)
    {
        try
        {
            AgentStatusSnapshot status = await _client.GetStatusAsync(cancellationToken);
            if (IsCurrent(generation))
            {
                await ApplyAsync(status, generation, FocusStatusApplication.Reconciliation);
            }
        }
        catch (OperationCanceledException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusAgentTimeout",
                    generation,
                    FocusFailureApplication.Reconciliation);
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusAgentAccessDenied",
                    generation,
                    FocusFailureApplication.Reconciliation);
            }
        }
        catch (IOException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusAgentUnavailable",
                    generation,
                    FocusFailureApplication.Reconciliation);
            }
        }
        catch (Exception exception) when (
            exception is InvalidDataException or JsonException or InvalidOperationException or
            AgentProtocolException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync(
                    "StatusFailed",
                    generation,
                    FocusFailureApplication.Reconciliation);
            }
        }
    }

    private bool IsCurrent(long generation) =>
        generation == Interlocked.Read(ref _requestGeneration);

    private Task ApplyAsync(
        AgentStatusSnapshot status,
        long generation,
        FocusStatusApplication application) =>
        RunOnUiAsync(() =>
        {
            FocusAuthority authority = DecodeFocusAuthority(status.FocusState);
            FocusActionContext context = CreateFocusContext(status);
            _focusState = application switch
            {
                FocusStatusApplication.Mutation => FocusControlReducer.ApplyMutationStatus(
                    _focusState,
                    generation,
                    authority,
                    context),
                FocusStatusApplication.Reconciliation => FocusControlReducer.ApplyReconciledStatus(
                    _focusState,
                    generation,
                    authority,
                    context),
                _ when _focusState.Phase == FocusOperationPhase.StatusReconciliation =>
                    FocusControlReducer.ApplyReconciledStatus(
                        _focusState,
                        generation,
                        authority,
                        context),
                _ => FocusControlReducer.ApplyOrdinaryStatus(
                    _focusState,
                    generation,
                    authority,
                    context),
            };

            StatusText = _resources.GetString(status.Phase switch
            {
                "starting" => "StatusStarting",
                "pairing" => "StatusPairing",
                "connected" => "StatusConnected",
                "stopping" => "StatusStopping",
                _ => "StatusReady",
            });
            StatusGlyph = status.Phase switch
            {
                "connected" => "\uE8CE",
                "starting" or "stopping" => "\uE823",
                _ => "\uE930",
            };
            PeerText = status.ConnectedPeer ?? _resources.GetString("NoPeer");
            InputOwnerText = _resources.GetString(
                status.InputOwner == "remote" ? "InputOwnerRemote" : "InputOwnerLocal");
            AgentReachabilityText = _resources.GetString("ReadinessAgentReachable");

            AgentReadinessPresentation readiness = AgentReadinessReducer.Reduce(status.Readiness);
            InputEnvironmentText = _resources.GetString(readiness.InputEnvironment switch
            {
                InputEnvironmentState.Ready => "ReadinessInputReady",
                InputEnvironmentState.ActionRequired => "ReadinessInputActionRequired",
                InputEnvironmentState.BlockedByDesktop => "ReadinessInputBlockedByDesktop",
                _ => "ReadinessUnavailable",
            });
            InputEnvironmentGuidanceText = readiness.InputGuidance switch
            {
                InputEnvironmentGuidance.RefreshAfterNormalDesktop =>
                    _resources.GetString("ReadinessInputBlockedByDesktopHelp"),
                _ => string.Empty,
            };
            LocalDisplaysText = _resources.GetString(readiness.LocalDisplays switch
            {
                LocalDisplaysState.Available => "ReadinessLocalDisplaysAvailable",
                _ => "ReadinessUnavailable",
            });
            PeerTopologyText = _resources.GetString(readiness.PeerTopology switch
            {
                PeerTopologyState.NotConnected => "ReadinessPeerTopologyNotConnected",
                PeerTopologyState.Synchronizing => "ReadinessPeerTopologySynchronizing",
                PeerTopologyState.Ready => "ReadinessPeerTopologyReady",
                _ => "ReadinessUnavailable",
            });
            UpdateFocusPresentation();
        }, generation);

    private Task SetUnavailableAsync(
        string resourceKey,
        long generation,
        FocusFailureApplication application) =>
        RunOnUiAsync(() =>
        {
            _focusState = application switch
            {
                FocusFailureApplication.Emergency => FocusControlReducer.MarkAmbiguousMutation(
                    _focusState,
                    generation),
                FocusFailureApplication.Reconciliation =>
                    FocusControlReducer.FailReconciliation(_focusState, generation),
                _ => FocusControlReducer.FailStatus(_focusState, generation),
            };
            StatusText = _resources.GetString(resourceKey);
            AgentReachabilityText = _resources.GetString(resourceKey);
            StatusGlyph = "\uE783";
            PeerText = _resources.GetString("NoPeer");
            InputOwnerText = _resources.GetString("InputOwnerLocal");
            InputEnvironmentText = _resources.GetString("ReadinessUnavailable");
            InputEnvironmentGuidanceText = string.Empty;
            LocalDisplaysText = _resources.GetString("ReadinessUnavailable");
            PeerTopologyText = _resources.GetString("ReadinessUnavailable");
            UpdateFocusPresentation();
        }, generation);

    private Task MarkAmbiguousMutationAsync(long generation) =>
        RunOnUiAsync(() =>
        {
            _focusState = FocusControlReducer.MarkAmbiguousMutation(_focusState, generation);
            UpdateFocusPresentation();
        }, generation);

    private Task RejectFocusMutationAsync(long generation) =>
        RunOnUiAsync(() =>
        {
            _focusState = FocusControlReducer.RejectMutation(_focusState, generation);
            UpdateFocusPresentation();
        }, generation);

    private void SetChecking()
    {
        StatusText = _resources.GetString("StatusChecking");
        AgentReachabilityText = _resources.GetString("ReadinessChecking");
        PeerText = _resources.GetString("NoPeer");
        InputOwnerText = _resources.GetString("InputOwnerLocal");
        InputEnvironmentText = _resources.GetString("ReadinessChecking");
        InputEnvironmentGuidanceText = string.Empty;
        LocalDisplaysText = _resources.GetString("ReadinessChecking");
        PeerTopologyText = _resources.GetString("ReadinessChecking");
    }

    private void UpdateFocusPresentation()
    {
        FocusStateText = _resources.GetString(_focusState.Authority switch
        {
            FocusAuthority.Local => "FocusStateLocal",
            FocusAuthority.ControllingPeer => "FocusStateControllingPeer",
            FocusAuthority.ControlledByPeer => "FocusStateControlledByPeer",
            _ => "FocusStateUnavailable",
        });
        FocusGuidanceText = _resources.GetString(FocusGuidanceResource(_focusState));
        NotifyFocusControls();
    }

    private static string FocusGuidanceResource(FocusControlState state)
    {
        string? operation = state.Phase switch
        {
            FocusOperationPhase.AcquireInFlight => "FocusGuidanceAcquiring",
            FocusOperationPhase.AcquireLeaseWindow => "FocusGuidanceAcquireLeaseWindow",
            FocusOperationPhase.AcquireReconciliation => "FocusGuidanceReconciling",
            FocusOperationPhase.ReleaseInFlight => "FocusGuidanceReleasing",
            FocusOperationPhase.ReleaseReconciliation => "FocusGuidanceReconciling",
            FocusOperationPhase.EmergencyInFlight => "FocusGuidanceEmergency",
            FocusOperationPhase.StatusReconciliation => "FocusGuidanceReconciling",
            FocusOperationPhase.OutcomeUnknown => "FocusGuidanceOutcomeUnknown",
            _ => null,
        };
        if (operation is not null)
        {
            return operation;
        }
        if (state.Notice == FocusNotice.Rejected)
        {
            return "FocusGuidanceRejected";
        }
        if (state.Notice == FocusNotice.StatusUnavailable ||
            state.Authority == FocusAuthority.Unknown)
        {
            return "FocusGuidanceStatusUnavailable";
        }

        return state.Authority switch
        {
            FocusAuthority.ControllingPeer => "FocusGuidanceControllingPeer",
            FocusAuthority.ControlledByPeer => "FocusGuidanceControlledByPeer",
            FocusAuthority.Local when !state.Context.HasConnectedPeer ||
                !state.Context.IsConnectedPhase => "FocusGuidanceConnectPeer",
            FocusAuthority.Local when !state.Context.IsInputReady ||
                !state.Context.IsLocalTopologyAvailable ||
                !state.Context.IsSessionTopologyReady => "FocusGuidanceWaitForReadiness",
            FocusAuthority.Local => "FocusGuidanceReady",
            _ => "FocusGuidanceStatusUnavailable",
        };
    }

    private void NotifyFocusControls()
    {
        OnPropertyChanged(nameof(CanRequestRemoteFocus));
        OnPropertyChanged(nameof(CanReleaseFocus));
        OnPropertyChanged(nameof(IsFocusOperationInProgress));
    }

    private static FocusAuthority DecodeFocusAuthority(string focusState) => focusState switch
    {
        "local" => FocusAuthority.Local,
        "controlling_peer" => FocusAuthority.ControllingPeer,
        "controlled_by_peer" => FocusAuthority.ControlledByPeer,
        _ => FocusAuthority.Unknown,
    };

    private static FocusActionContext CreateFocusContext(AgentStatusSnapshot status) => new(
        status.ConnectedPeer is not null,
        status.Phase == "connected",
        status.Readiness.Input == "ready",
        status.Readiness.LocalTopology == "available",
        status.Readiness.SessionTopology == "ready");

    private static bool IsDeterministicFocusRejection(AgentProtocolException exception) =>
        exception.Code == "focus_rejected";

    private static bool IsAmbiguousFocusFailure(Exception exception) => exception is
        OperationCanceledException or
        UnauthorizedAccessException or
        IOException or
        InvalidDataException or
        JsonException or
        InvalidOperationException or
        AgentProtocolException;

    private Task RunOnUiAsync(Action action, long generation)
    {
        if (_dispatcher.HasThreadAccess)
        {
            if (IsCurrent(generation))
            {
                action();
            }
            return Task.CompletedTask;
        }

        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_dispatcher.TryEnqueue(() =>
        {
            try
            {
                if (IsCurrent(generation))
                {
                    action();
                }
                completion.SetResult();
            }
            catch (Exception exception)
            {
                completion.SetException(exception);
            }
        }))
        {
            completion.SetException(new InvalidOperationException("The UI dispatcher is unavailable."));
        }
        return completion.Task;
    }

    private bool SetField<T>(
        ref T field,
        T value,
        [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
