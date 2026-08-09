using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.ApplicationModel.Resources;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;

namespace Nodavo.Windows.Views;

public sealed partial class DevicesView : UserControl
{
    private readonly AgentClient _client;
    private readonly ResourceLoader _resources;
    private CancellationTokenSource? _attemptCancellation;
    private long _attemptVersion;
    private string? _pairingId;
    private bool _confirmationSubmitted;

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
        catch (OperationCanceledException) when (attempt != _attemptVersion)
        {
            // A newer action already owns the visible state.
        }
        catch (OperationCanceledException) when (attempt == _attemptVersion)
        {
            await StopTimedOutPairingAsync(attempt);
            if (attempt == _attemptVersion)
            {
                ShowFailure("PairingTimedOut");
            }
        }
        catch (AgentProtocolException) when (attempt == _attemptVersion)
        {
            ShowFailure("PairingRejected");
        }
        catch (Exception exception) when (
            attempt == _attemptVersion && exception is IOException or JsonException or
            InvalidDataException or InvalidOperationException or UnauthorizedAccessException)
        {
            ShowFailure("PairingFailed");
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
            }
            else
            {
                ShowFailure("PairingDeclined");
            }
        }
        catch (OperationCanceledException) when (attempt != _attemptVersion)
        {
            // A cancellation action now owns the visible state.
        }
        catch (OperationCanceledException) when (attempt == _attemptVersion)
        {
            await StopTimedOutPairingAsync(attempt);
            if (attempt == _attemptVersion)
            {
                ShowFailure("PairingTimedOut");
            }
        }
        catch (Exception exception) when (
            attempt == _attemptVersion && exception is IOException or JsonException or
            InvalidDataException or InvalidOperationException or UnauthorizedAccessException)
        {
            ShowFailure("PairingFailed");
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
            InvalidDataException or InvalidOperationException or UnauthorizedAccessException)
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
            InvalidDataException or InvalidOperationException or UnauthorizedAccessException)
        {
            // The remote request already has a hard deadline; UI cleanup remains local-first.
        }

        if (attempt == _attemptVersion)
        {
            _confirmationSubmitted = false;
        }
    }
}
