using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.ApplicationModel.Resources;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;

namespace Nodavo.Windows.Views;

public sealed partial class DevicesView : UserControl
{
    private static readonly TimeSpan MutationCompletionWindow = TimeSpan.FromSeconds(2);
    private readonly AgentClient _client;
    private readonly ResourceLoader _resources;
    private CancellationTokenSource? _attemptCancellation;
    private long _attemptVersion;
    private string? _pairingId;
    private bool _confirmationSubmitted;
    private readonly HashSet<string> _unresolvedPeerIds = new(StringComparer.Ordinal);
    private long _trustedRefreshGeneration;
    private long _trustedMutationGeneration;
    private bool _trustedRefreshInProgress;
    private bool _trustedRefreshPending;
    private string? _deferredPreferredPeerId;
    private bool _loadingGrantControls;
    private bool _trustedMutationInProgress;

    public DevicesView()
        : this(new AgentClient(), new ResourceLoader())
    {
    }

    internal DevicesView(AgentClient client, ResourceLoader resources)
    {
        _client = client;
        _resources = resources;
        InitializeComponent();
        ShowIdle();
        Loaded += DevicesView_Loaded;
    }

    private async void DevicesView_Loaded(object sender, RoutedEventArgs args)
    {
        if (TrustedPeersList.ItemsSource is null)
        {
            await RefreshTrustedPeersAsync();
        }
    }

    private async void RefreshTrustedButton_Click(object sender, RoutedEventArgs args) =>
        await RefreshTrustedPeersAsync();

    private async Task RefreshTrustedPeersAsync(string? preferredPeerId = null)
    {
        if (_trustedMutationInProgress || _trustedRefreshInProgress)
        {
            _trustedRefreshPending = true;
            _deferredPreferredPeerId ??= preferredPeerId;
            return;
        }

        long generation = ++_trustedRefreshGeneration;
        _trustedRefreshInProgress = true;
        string? selectedPeerId = preferredPeerId ?? SelectedTrustedPeer()?.PeerId;
        UpdateTrustedInteractionState();
        ShowTrustedStatus("TrustedDevicesLoading", InfoBarSeverity.Informational);
        try
        {
            IReadOnlyList<TrustedPeerSnapshot> peers = await _client.ListTrustedPeersAsync();
            if (generation != _trustedRefreshGeneration)
            {
                return;
            }
            ApplyTrustedPeers(peers, selectedPeerId);
            if (peers.Count == 0)
            {
                ShowTrustedStatus("TrustedDevicesEmpty", InfoBarSeverity.Informational);
            }
            else
            {
                ShowTrustedStatus("TrustedDevicesLoaded", InfoBarSeverity.Success);
            }
        }
        catch (Exception exception) when (
            exception is OperationCanceledException or
            IOException or JsonException or InvalidDataException or InvalidOperationException or
            UnauthorizedAccessException or AgentProtocolException)
        {
            if (generation == _trustedRefreshGeneration)
            {
                TrustedPeersList.ItemsSource = Array.Empty<TrustedPeerRow>();
                TrustedPeerDetails.Visibility = Visibility.Collapsed;
                ShowTrustedStatus(
                    exception is OperationCanceledException ? "TrustedDevicesTimeout" : "TrustedDevicesFailed",
                    InfoBarSeverity.Error);
            }
        }
        finally
        {
            bool runDeferredRefresh = false;
            string? deferredPeerId = null;
            if (generation == _trustedRefreshGeneration)
            {
                _trustedRefreshInProgress = false;
                UpdateTrustedInteractionState();
                (runDeferredRefresh, deferredPeerId) = TakeDeferredTrustedRefresh();
            }
            if (runDeferredRefresh)
            {
                await RefreshTrustedPeersAsync(deferredPeerId);
            }
        }
    }

    private void TrustedPeersList_SelectionChanged(
        object sender,
        SelectionChangedEventArgs args)
    {
        TrustedPeerSnapshot? peer = SelectedTrustedPeer();
        _loadingGrantControls = true;
        try
        {
            if (peer is null)
            {
                TrustedPeerDetails.Visibility = Visibility.Collapsed;
                return;
            }
            TrustedPeerDetails.Visibility = Visibility.Visible;
            TrustedPeerName.Text = peer.DisplayName;
            TrustedPeerState.Text = PeerStateLabel(peer.State);
            TrustedInputGrant.IsOn = peer.HasGrant("input");
            TrustedClipboardReadGrant.IsOn = peer.HasGrant("clipboard_read");
            TrustedClipboardWriteGrant.IsOn = peer.HasGrant("clipboard_write");
            TrustedFilesGrant.IsOn = peer.HasGrant("files");
        }
        finally
        {
            _loadingGrantControls = false;
            UpdateTrustedInteractionState();
        }
    }

    private async void TrustedGrant_Toggled(object sender, RoutedEventArgs args)
    {
        if (_loadingGrantControls || _trustedMutationInProgress || _trustedRefreshInProgress ||
            sender is not ToggleSwitch toggle || SelectedTrustedPeer() is not { State: "active" } peer)
        {
            return;
        }

        string capability = toggle == TrustedInputGrant ? "input" :
            toggle == TrustedClipboardReadGrant ? "clipboard_read" :
            toggle == TrustedClipboardWriteGrant ? "clipboard_write" : "files";
        bool requested = toggle.IsOn;
        bool previous = peer.HasGrant(capability);
        if (requested == previous)
        {
            return;
        }

        long mutation = ++_trustedMutationGeneration;
        _trustedMutationInProgress = true;
        UpdateTrustedInteractionState();
        ShowTrustedStatus("TrustedPermissionSaving", InfoBarSeverity.Informational);
        try
        {
            CapabilityChangeSnapshot changed =
                await _client.SetCapabilityAsync(peer.PeerId, capability, requested);
            if (mutation != _trustedMutationGeneration)
            {
                return;
            }
            if (changed.PeerId != peer.PeerId || changed.Capability != capability ||
                changed.Enabled != requested)
            {
                throw new InvalidDataException("Mismatched capability acknowledgement.");
            }

            if (TrustedPeersList.SelectedItem is TrustedPeerRow row)
            {
                row.ApplyCapability(capability, requested);
            }
            ShowTrustedStatus("TrustedPermissionSaved", InfoBarSeverity.Success);
        }
        catch (AgentProtocolException)
        {
            if (mutation == _trustedMutationGeneration)
            {
                SetToggleWithoutMutation(toggle, previous);
                ShowTrustedStatus("TrustedPermissionRejected", InfoBarSeverity.Error);
            }
        }
        catch (Exception exception) when (
            exception is OperationCanceledException or
            IOException or JsonException or InvalidDataException or InvalidOperationException or
            UnauthorizedAccessException)
        {
            if (mutation == _trustedMutationGeneration)
            {
                await ReconcileCapabilityAsync(mutation, peer.PeerId, capability, requested);
            }
        }
        finally
        {
            bool runDeferredRefresh = false;
            string? deferredPeerId = null;
            if (mutation == _trustedMutationGeneration)
            {
                _trustedMutationInProgress = false;
                UpdateTrustedInteractionState();
                (runDeferredRefresh, deferredPeerId) = TakeDeferredTrustedRefresh();
            }
            if (runDeferredRefresh)
            {
                await RefreshTrustedPeersAsync(deferredPeerId);
            }
        }
    }

    private async void RevokePeerButton_Click(object sender, RoutedEventArgs args)
    {
        if (_trustedMutationInProgress || _trustedRefreshInProgress ||
            SelectedTrustedPeer() is not { State: "active" } peer)
        {
            return;
        }

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = _resources.GetString("TrustedRevokeConfirmTitle"),
            Content = string.Format(
                _resources.GetString("TrustedRevokeConfirmMessage"), peer.DisplayName),
            PrimaryButtonText = _resources.GetString("TrustedRevokeConfirmAction"),
            CloseButtonText = _resources.GetString("TrustedRevokeConfirmCancel"),
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }
        if (_trustedMutationInProgress || _trustedRefreshInProgress ||
            SelectedTrustedPeer() is not { State: "active" } currentPeer ||
            currentPeer.PeerId != peer.PeerId)
        {
            ShowTrustedStatus("TrustedRevokeStateChanged", InfoBarSeverity.Warning);
            return;
        }
        peer = currentPeer;

        long mutation = ++_trustedMutationGeneration;
        _trustedMutationInProgress = true;
        UpdateTrustedInteractionState();
        ShowTrustedStatus("TrustedRevoking", InfoBarSeverity.Warning);
        try
        {
            await _client.RevokePeerAsync(peer.PeerId);
            if (mutation != _trustedMutationGeneration)
            {
                return;
            }
            await ReconcileRevocationAsync(mutation, peer.PeerId, waitForCompletion: false);
        }
        catch (AgentProtocolException)
        {
            if (mutation == _trustedMutationGeneration)
            {
                ShowTrustedStatus("TrustedRevokeRejected", InfoBarSeverity.Error);
            }
        }
        catch (Exception exception) when (
            exception is OperationCanceledException or
            IOException or JsonException or InvalidDataException or InvalidOperationException or
            UnauthorizedAccessException)
        {
            if (mutation == _trustedMutationGeneration)
            {
                await ReconcileRevocationAsync(mutation, peer.PeerId, waitForCompletion: true);
            }
        }
        finally
        {
            bool runDeferredRefresh = false;
            string? deferredPeerId = null;
            if (mutation == _trustedMutationGeneration)
            {
                _trustedMutationInProgress = false;
                UpdateTrustedInteractionState();
                (runDeferredRefresh, deferredPeerId) = TakeDeferredTrustedRefresh();
            }
            if (runDeferredRefresh)
            {
                await RefreshTrustedPeersAsync(deferredPeerId);
            }
        }
    }

    private async void ListenButton_Click(object sender, RoutedEventArgs args) =>
        await BeginPairingAsync("listen");

    private async void ConnectButton_Click(object sender, RoutedEventArgs args)
    {
        string endpoint = EndpointBox.Text.Trim();
        if (string.IsNullOrEmpty(endpoint))
        {
            ShowFailure("PairingInvalidEndpoint");
            return;
        }
        await BeginPairingAsync(endpoint);
    }

    private async Task BeginPairingAsync(string endpoint)
    {
        long attempt = ++_attemptVersion;
        _pairingId = null;
        _confirmationSubmitted = false;
        _attemptCancellation?.Cancel();
        _attemptCancellation?.Dispose();
        _attemptCancellation = new CancellationTokenSource();
        ShowWaiting();

        try
        {
            PairingCodeSnapshot result = await _client.BeginPairingAsync(
                endpoint,
                SelectedCapabilities(),
                _attemptCancellation.Token);
            if (attempt != _attemptVersion)
            {
                return;
            }

            _pairingId = result.PairingId;
            PeerNameText.Text = result.PeerName;
            CodeText.Text = result.Code;
            PairingStatus.Title = _resources.GetString("PairingCompareTitle");
            PairingStatus.Message = _resources.GetString("PairingCompareMessage");
            PairingStatus.Severity = InfoBarSeverity.Warning;
            CodePanel.Visibility = Visibility.Visible;
            BusyPanel.Visibility = Visibility.Collapsed;
            WaitingCancelButton.Visibility = Visibility.Collapsed;
            ListenButton.IsEnabled = false;
            ConnectButton.IsEnabled = false;
        }
        catch (OperationCanceledException)
        {
            if (attempt == _attemptVersion)
            {
                await StopTimedOutPairingAsync(attempt);
                if (attempt == _attemptVersion)
                {
                    ShowFailure("PairingTimedOut");
                }
            }
        }
        catch (AgentProtocolException)
        {
            if (attempt == _attemptVersion)
            {
                ShowFailure("PairingRejected");
            }
        }
        catch (Exception exception) when (
            exception is IOException or JsonException or
            InvalidDataException or InvalidOperationException or UnauthorizedAccessException or
            AgentProtocolException)
        {
            if (attempt == _attemptVersion)
            {
                ShowFailure("PairingFailed");
            }
        }
        finally
        {
            if (attempt == _attemptVersion)
            {
                _attemptCancellation?.Dispose();
                _attemptCancellation = null;
            }
        }
    }

    private async void ConfirmButton_Click(object sender, RoutedEventArgs args)
    {
        string? pairingId = _pairingId;
        if (pairingId is null || _confirmationSubmitted)
        {
            return;
        }

        long attempt = _attemptVersion;
        _attemptCancellation?.Dispose();
        _attemptCancellation = new CancellationTokenSource();
        _confirmationSubmitted = true;
        SetConfirming();
        try
        {
            PairingResultSnapshot result = await _client.ConfirmPairingAsync(
                pairingId,
                true,
                _attemptCancellation.Token);
            if (attempt != _attemptVersion)
            {
                return;
            }
            if (result.PairingId != pairingId)
            {
                ShowFailure("PairingFailed");
                return;
            }
            if (result.Paired)
            {
                _pairingId = null;
                _confirmationSubmitted = false;
                CodePanel.Visibility = Visibility.Collapsed;
                BusyPanel.Visibility = Visibility.Collapsed;
                PairingStatus.Title = _resources.GetString("PairingPairedTitle");
                PairingStatus.Message = _resources.GetString("PairingPairedMessage");
                PairingStatus.Severity = InfoBarSeverity.Success;
                ListenButton.IsEnabled = true;
                ConnectButton.IsEnabled = true;
                SetPermissionControlsEnabled(true);
                await RefreshTrustedPeersAsync();
            }
            else
            {
                ShowFailure("PairingDeclined");
            }
        }
        catch (OperationCanceledException)
        {
            if (attempt == _attemptVersion)
            {
                await StopTimedOutPairingAsync(attempt);
                if (attempt == _attemptVersion)
                {
                    ShowFailure("PairingTimedOut");
                }
            }
        }
        catch (Exception exception) when (
            exception is IOException or JsonException or
            InvalidDataException or InvalidOperationException or UnauthorizedAccessException or
            AgentProtocolException)
        {
            if (attempt == _attemptVersion)
            {
                ShowFailure("PairingFailed");
            }
        }
        finally
        {
            if (attempt == _attemptVersion)
            {
                _attemptCancellation?.Dispose();
                _attemptCancellation = null;
            }
        }
    }

    private async void CancelButton_Click(object sender, RoutedEventArgs args)
    {
        string? pairingId = _pairingId;
        bool confirmationSubmitted = _confirmationSubmitted;
        long cancelVersion = ++_attemptVersion;
        _attemptCancellation?.Cancel();
        _attemptCancellation?.Dispose();
        _attemptCancellation = null;
        _pairingId = null;
        _confirmationSubmitted = false;
        SetCancelling();

        try
        {
            if (confirmationSubmitted)
            {
                await _client.EmergencyStopAsync();
            }
            else if (pairingId is not null)
            {
                await _client.ConfirmPairingAsync(pairingId, false);
            }
            else
            {
                await _client.EmergencyStopAsync();
            }
        }
        catch (Exception exception) when (
            exception is OperationCanceledException or IOException or JsonException or
            InvalidDataException or InvalidOperationException or UnauthorizedAccessException or
            AgentProtocolException)
        {
            // Cancellation is local-first. The agent also has bounded pairing deadlines.
        }
        if (cancelVersion == _attemptVersion)
        {
            ShowIdle("PairingCancelled");
        }
    }

    private void ShowIdle(string messageKey = "PairingIdleMessage")
    {
        PairingStatus.Title = _resources.GetString("PairingIdleTitle");
        PairingStatus.Message = _resources.GetString(messageKey);
        PairingStatus.Severity = InfoBarSeverity.Informational;
        _confirmationSubmitted = false;
        BusyPanel.Visibility = Visibility.Collapsed;
        CodePanel.Visibility = Visibility.Collapsed;
        WaitingCancelButton.Visibility = Visibility.Collapsed;
        ListenButton.IsEnabled = true;
        ConnectButton.IsEnabled = true;
        ConfirmButton.IsEnabled = true;
        DeclineButton.IsEnabled = true;
        SetPermissionControlsEnabled(true);
    }

    private void ShowWaiting()
    {
        PairingStatus.Title = _resources.GetString("PairingWaitingTitle");
        PairingStatus.Message = _resources.GetString("PairingWaitingMessage");
        PairingStatus.Severity = InfoBarSeverity.Informational;
        BusyText.Text = _resources.GetString("PairingWaitingProgress");
        BusyPanel.Visibility = Visibility.Visible;
        CodePanel.Visibility = Visibility.Collapsed;
        WaitingCancelButton.Visibility = Visibility.Visible;
        ListenButton.IsEnabled = false;
        ConnectButton.IsEnabled = false;
        SetPermissionControlsEnabled(false);
    }

    private void SetConfirming()
    {
        PairingStatus.Title = _resources.GetString("PairingConfirmingTitle");
        PairingStatus.Message = _resources.GetString("PairingConfirmingMessage");
        PairingStatus.Severity = InfoBarSeverity.Informational;
        BusyText.Text = _resources.GetString("PairingConfirmingProgress");
        BusyPanel.Visibility = Visibility.Visible;
        ConfirmButton.IsEnabled = false;
        DeclineButton.IsEnabled = true;
    }

    private void SetCancelling()
    {
        BusyText.Text = _resources.GetString("PairingCancellingProgress");
        BusyPanel.Visibility = Visibility.Visible;
        WaitingCancelButton.Visibility = Visibility.Collapsed;
        ListenButton.IsEnabled = false;
        ConnectButton.IsEnabled = false;
        ConfirmButton.IsEnabled = false;
        DeclineButton.IsEnabled = false;
        SetPermissionControlsEnabled(false);
    }

    private void ShowFailure(string messageKey)
    {
        _pairingId = null;
        _confirmationSubmitted = false;
        PairingStatus.Title = _resources.GetString("PairingFailedTitle");
        PairingStatus.Message = _resources.GetString(messageKey);
        PairingStatus.Severity = InfoBarSeverity.Error;
        BusyPanel.Visibility = Visibility.Collapsed;
        CodePanel.Visibility = Visibility.Collapsed;
        WaitingCancelButton.Visibility = Visibility.Collapsed;
        ListenButton.IsEnabled = true;
        ConnectButton.IsEnabled = true;
        ConfirmButton.IsEnabled = true;
        DeclineButton.IsEnabled = true;
        SetPermissionControlsEnabled(true);
    }

    private string[] SelectedCapabilities()
    {
        var capabilities = new List<string>(4);
        if (InputPermission.IsChecked == true)
        {
            capabilities.Add("input");
        }
        if (ClipboardReadPermission.IsChecked == true)
        {
            capabilities.Add("clipboard_read");
        }
        if (ClipboardWritePermission.IsChecked == true)
        {
            capabilities.Add("clipboard_write");
        }
        if (FilesPermission.IsChecked == true)
        {
            capabilities.Add("files");
        }
        return capabilities.ToArray();
    }

    private void SetPermissionControlsEnabled(bool enabled)
    {
        InputPermission.IsEnabled = enabled;
        ClipboardReadPermission.IsEnabled = enabled;
        ClipboardWritePermission.IsEnabled = enabled;
        FilesPermission.IsEnabled = enabled;
    }

    private async Task StopTimedOutPairingAsync(long attempt)
    {
        try
        {
            await _client.EmergencyStopAsync();
        }
        catch (Exception exception) when (
            exception is OperationCanceledException or IOException or JsonException or
            InvalidDataException or InvalidOperationException or UnauthorizedAccessException or
            AgentProtocolException)
        {
            // The remote request already has a hard deadline; UI cleanup remains local-first.
        }

        if (attempt == _attemptVersion)
        {
            _confirmationSubmitted = false;
        }
    }

    private async Task ReconcileCapabilityAsync(
        long mutation,
        string peerId,
        string capability,
        bool requested)
    {
        _unresolvedPeerIds.Add(peerId);
        UpdateTrustedInteractionState();
        ShowTrustedStatus("TrustedPermissionReconciling", InfoBarSeverity.Warning);
        await Task.Delay(MutationCompletionWindow);

        try
        {
            IReadOnlyList<TrustedPeerSnapshot> peers = await _client.ListTrustedPeersAsync();
            if (mutation != _trustedMutationGeneration)
            {
                return;
            }
            TrustedPeerSnapshot? authoritative = peers.FirstOrDefault(peer => peer.PeerId == peerId);
            ApplyTrustedPeers(peers, peerId);
            if (authoritative is null)
            {
                ShowTrustedStatus("TrustedMutationPeerMissing", InfoBarSeverity.Error);
            }
            else if (authoritative.State != "active")
            {
                ShowTrustedStatus("TrustedMutationPeerRevoked", InfoBarSeverity.Warning);
            }
            else if (authoritative.HasGrant(capability) == requested)
            {
                ShowTrustedStatus("TrustedPermissionReconciledApplied", InfoBarSeverity.Success);
            }
            else
            {
                ShowTrustedStatus("TrustedPermissionReconciledNotApplied", InfoBarSeverity.Warning);
            }
        }
        catch (Exception exception) when (IsExpectedLocalFailure(exception))
        {
            if (mutation == _trustedMutationGeneration)
            {
                ShowTrustedStatus("TrustedMutationOutcomeUnknown", InfoBarSeverity.Error);
            }
        }
    }

    private async Task ReconcileRevocationAsync(
        long mutation,
        string peerId,
        bool waitForCompletion)
    {
        _unresolvedPeerIds.Add(peerId);
        UpdateTrustedInteractionState();
        ShowTrustedStatus(
            waitForCompletion ? "TrustedRevokeReconciling" : "TrustedRevokeVerifying",
            InfoBarSeverity.Warning);
        if (waitForCompletion)
        {
            await Task.Delay(MutationCompletionWindow);
        }

        try
        {
            IReadOnlyList<TrustedPeerSnapshot> peers = await _client.ListTrustedPeersAsync();
            if (mutation != _trustedMutationGeneration)
            {
                return;
            }
            TrustedPeerSnapshot? authoritative = peers.FirstOrDefault(peer => peer.PeerId == peerId);
            ApplyTrustedPeers(peers, peerId);
            if (authoritative?.State == "revoked")
            {
                ShowTrustedStatus("TrustedRevoked", InfoBarSeverity.Success);
            }
            else if (authoritative?.State == "active")
            {
                if (!waitForCompletion)
                {
                    _unresolvedPeerIds.Add(peerId);
                }
                ShowTrustedStatus(
                    waitForCompletion ? "TrustedRevokeReconciledNotApplied" : "TrustedRevokeVerificationFailed",
                    waitForCompletion ? InfoBarSeverity.Warning : InfoBarSeverity.Error);
            }
            else
            {
                ShowTrustedStatus("TrustedMutationPeerMissing", InfoBarSeverity.Error);
            }
        }
        catch (Exception exception) when (IsExpectedLocalFailure(exception))
        {
            if (mutation == _trustedMutationGeneration)
            {
                ShowTrustedStatus("TrustedMutationOutcomeUnknown", InfoBarSeverity.Error);
            }
        }
    }

    private void ApplyTrustedPeers(
        IReadOnlyList<TrustedPeerSnapshot> peers,
        string? selectedPeerId)
    {
        _unresolvedPeerIds.Clear();
        var rows = peers
            .Select(peer => new TrustedPeerRow(peer, PeerStateLabel(peer.State)))
            .ToArray();
        TrustedPeersList.ItemsSource = rows;
        TrustedPeersList.SelectedItem = rows.FirstOrDefault(row => row.Peer.PeerId == selectedPeerId);
        if (TrustedPeersList.SelectedItem is null && rows.Length > 0)
        {
            TrustedPeersList.SelectedIndex = 0;
        }
        if (rows.Length == 0)
        {
            TrustedPeerDetails.Visibility = Visibility.Collapsed;
        }
    }

    private void SetToggleWithoutMutation(ToggleSwitch toggle, bool enabled)
    {
        _loadingGrantControls = true;
        toggle.IsOn = enabled;
        _loadingGrantControls = false;
    }

    private static bool IsExpectedLocalFailure(Exception exception) =>
        exception is OperationCanceledException or IOException or JsonException or
        InvalidDataException or InvalidOperationException or UnauthorizedAccessException or
        AgentProtocolException;

    private (bool Run, string? PreferredPeerId) TakeDeferredTrustedRefresh()
    {
        if (!_trustedRefreshPending || _trustedMutationInProgress || _trustedRefreshInProgress)
        {
            return (false, null);
        }
        string? preferredPeerId = _deferredPreferredPeerId;
        _trustedRefreshPending = false;
        _deferredPreferredPeerId = null;
        return (true, preferredPeerId);
    }

    private TrustedPeerSnapshot? SelectedTrustedPeer() =>
        (TrustedPeersList.SelectedItem as TrustedPeerRow)?.Peer;

    private string PeerStateLabel(string state) =>
        _resources.GetString(state == "active" ? "TrustedStateActive" : "TrustedStateRevoked");

    private void UpdateTrustedInteractionState()
    {
        bool busy = _trustedRefreshInProgress || _trustedMutationInProgress;
        TrustedDevicesProgress.IsActive = busy;
        TrustedDevicesProgress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        RefreshTrustedButton.IsEnabled = !busy;
        TrustedPeersList.IsEnabled = !busy;
        TrustedPeerSnapshot? selected = SelectedTrustedPeer();
        SetTrustedControlsEnabled(
            !busy && selected?.State == "active" && !_unresolvedPeerIds.Contains(selected.PeerId));
    }

    private void SetTrustedControlsEnabled(bool enabled)
    {
        TrustedInputGrant.IsEnabled = enabled;
        TrustedClipboardReadGrant.IsEnabled = enabled;
        TrustedClipboardWriteGrant.IsEnabled = enabled;
        TrustedFilesGrant.IsEnabled = enabled;
        RevokePeerButton.IsEnabled = enabled;
    }

    private void ShowTrustedStatus(string key, InfoBarSeverity severity)
    {
        TrustedDevicesStatus.Title = _resources.GetString(key + "Title");
        TrustedDevicesStatus.Message = _resources.GetString(key + "Message");
        TrustedDevicesStatus.Severity = severity;
    }

    private sealed class TrustedPeerRow
    {
        internal TrustedPeerRow(TrustedPeerSnapshot peer, string stateLabel)
        {
            Peer = peer;
            DisplayText = $"{peer.DisplayName} · {stateLabel}";
        }

        public TrustedPeerSnapshot Peer { get; private set; }
        public string DisplayText { get; }

        internal void ApplyCapability(string capability, bool enabled)
        {
            var grants = new HashSet<string>(Peer.LocalGrants, StringComparer.Ordinal);
            if (enabled)
            {
                grants.Add(capability);
            }
            else
            {
                grants.Remove(capability);
            }
            Peer = Peer with { LocalGrants = grants };
        }
    }
}
