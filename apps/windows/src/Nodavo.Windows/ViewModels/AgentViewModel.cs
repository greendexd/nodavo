using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.UI.Dispatching;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;
using Microsoft.Windows.ApplicationModel.Resources;

namespace Nodavo.Windows.ViewModels;

internal sealed class AgentViewModel : INotifyPropertyChanged
{
    private readonly AgentClient _client;
    private readonly ResourceLoader _resources;
    private readonly DispatcherQueue _dispatcher;
    private bool _requestInProgress;
    private bool _emergencyInProgress;
    private long _requestGeneration;
    private string _agentReachabilityText;
    private string _inputEnvironmentText;
    private string _inputEnvironmentGuidanceText;
    private string _localDisplaysText;
    private string _peerTopologyText;
    private string _statusText;
    private string _peerText;
    private string _inputOwnerText;
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

    public string StatusGlyph { get => _statusGlyph; private set => SetField(ref _statusGlyph, value); }
    public bool IsRequestInProgress { get => _requestInProgress; private set => SetField(ref _requestInProgress, value); }

    internal async Task RefreshAsync()
    {
        if (IsRequestInProgress)
        {
            return;
        }

        long generation = Interlocked.Increment(ref _requestGeneration);
        IsRequestInProgress = true;
        SetChecking();
        StatusGlyph = "\uE823";
        try
        {
            AgentStatusSnapshot status = await _client.GetStatusAsync();
            if (IsCurrent(generation))
            {
                await ApplyAsync(status, generation);
            }
        }
        catch (OperationCanceledException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync("StatusAgentTimeout", generation);
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync("StatusAgentAccessDenied", generation);
            }
        }
        catch (IOException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync("StatusAgentUnavailable", generation);
            }
        }
        catch (Exception exception) when (
            exception is InvalidDataException or JsonException or InvalidOperationException or
            AgentProtocolException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync("StatusFailed", generation);
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

        long generation = Interlocked.Increment(ref _requestGeneration);
        _emergencyInProgress = true;
        IsRequestInProgress = true;
        try
        {
            AgentStatusSnapshot status = await _client.EmergencyStopAsync();
            if (IsCurrent(generation))
            {
                await ApplyAsync(status, generation);
            }
        }
        catch (OperationCanceledException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync("StatusAgentTimeout", generation);
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync("StatusAgentAccessDenied", generation);
            }
        }
        catch (IOException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync("StatusAgentUnavailable", generation);
            }
        }
        catch (Exception exception) when (
            exception is InvalidDataException or JsonException or InvalidOperationException or
            AgentProtocolException)
        {
            if (IsCurrent(generation))
            {
                await SetUnavailableAsync("StatusFailed", generation);
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

    private bool IsCurrent(long generation) =>
        generation == Interlocked.Read(ref _requestGeneration);

    private Task ApplyAsync(AgentStatusSnapshot status, long generation) =>
        RunOnUiAsync(() =>
        {
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
        }, generation);

    private Task SetUnavailableAsync(string resourceKey, long generation) =>
        RunOnUiAsync(() =>
        {
            StatusText = _resources.GetString(resourceKey);
            AgentReachabilityText = _resources.GetString(resourceKey);
            StatusGlyph = "\uE783";
            PeerText = _resources.GetString("NoPeer");
            InputOwnerText = _resources.GetString("InputOwnerLocal");
            InputEnvironmentText = _resources.GetString("ReadinessUnavailable");
            InputEnvironmentGuidanceText = string.Empty;
            LocalDisplaysText = _resources.GetString("ReadinessUnavailable");
            PeerTopologyText = _resources.GetString("ReadinessUnavailable");
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

    private void SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
