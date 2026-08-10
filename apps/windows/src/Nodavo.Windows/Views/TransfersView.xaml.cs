using System.Collections.ObjectModel;
using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.ApplicationModel.Resources;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;
using WinRT.Interop;

namespace Nodavo.Windows.Views;

public sealed partial class TransfersView : UserControl
{
    private const int MaximumSelectedPaths = 32;
    private readonly AgentClient _client;
    private readonly ResourceLoader _resources;
    private readonly ObservableCollection<SelectedPathRow> _selectedPaths = [];
    private bool _sendInProgress;
    private bool _outcomeUnknown;
    private long _operationGeneration;

    public TransfersView()
        : this(new AgentClient(), new ResourceLoader())
    {
    }

    internal TransfersView(AgentClient client, ResourceLoader resources)
    {
        _client = client;
        _resources = resources;
        InitializeComponent();
        SelectedPathsList.ItemsSource = _selectedPaths;
        ShowStatus("TransferIdle", InfoBarSeverity.Informational);
        UpdateSelectionControls();
    }

    private async void AddFilesButton_Click(object sender, RoutedEventArgs args)
    {
        try
        {
            var picker = new global::Windows.Storage.Pickers.FileOpenPicker
            {
                SuggestedStartLocation = global::Windows.Storage.Pickers.PickerLocationId.DocumentsLibrary,
                ViewMode = global::Windows.Storage.Pickers.PickerViewMode.List,
            };
            picker.FileTypeFilter.Add("*");
            InitializePicker(picker);
            IReadOnlyList<global::Windows.Storage.StorageFile> files = await picker.PickMultipleFilesAsync();
            if (files.Count > 0)
            {
                TryAddSelections(files.Select(file => file.Path));
            }
        }
        catch (Exception exception) when (
            exception is OperationCanceledException or InvalidOperationException or
            UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            ShowStatus("TransferPickerFailed", InfoBarSeverity.Error);
        }
    }

    private async void AddFolderButton_Click(object sender, RoutedEventArgs args)
    {
        try
        {
            var picker = new global::Windows.Storage.Pickers.FolderPicker
            {
                SuggestedStartLocation = global::Windows.Storage.Pickers.PickerLocationId.DocumentsLibrary,
                ViewMode = global::Windows.Storage.Pickers.PickerViewMode.List,
            };
            picker.FileTypeFilter.Add("*");
            InitializePicker(picker);
            global::Windows.Storage.StorageFolder? folder = await picker.PickSingleFolderAsync();
            if (folder is not null)
            {
                TryAddSelections([folder.Path]);
            }
        }
        catch (Exception exception) when (
            exception is OperationCanceledException or InvalidOperationException or
            UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            ShowStatus("TransferPickerFailed", InfoBarSeverity.Error);
        }
    }

    private static void InitializePicker(object picker)
    {
        if (App.MainWindow is null)
        {
            throw new InvalidOperationException("The main window is unavailable.");
        }
        nint windowHandle = WindowNative.GetWindowHandle(App.MainWindow);
        InitializeWithWindow.Initialize(picker, windowHandle);
    }

    private void TryAddSelections(IEnumerable<string> additions)
    {
        string[] freshSelections = additions.ToArray();
        string[] combined = _outcomeUnknown
            ? freshSelections
            : _selectedPaths.Select(row => row.FullPath).Concat(freshSelections).ToArray();
        try
        {
            string[] validated = AgentClient.ValidateSelectedPaths(combined);
            _selectedPaths.Clear();
            foreach (string path in validated)
            {
                string displayName = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar));
                _selectedPaths.Add(new SelectedPathRow(
                    path,
                    string.IsNullOrEmpty(displayName) ? _resources.GetString("TransferSelectedRoot") : displayName));
            }
            _outcomeUnknown = false;
            ShowStatus("TransferSelectionReady", InfoBarSeverity.Informational);
        }
        catch (InvalidDataException)
        {
            ShowStatus(
                combined.Length > MaximumSelectedPaths ? "TransferTooMany" : "TransferUnsafeSelection",
                InfoBarSeverity.Error);
        }
        UpdateSelectionControls();
    }

    private void SelectedPathsList_SelectionChanged(object sender, SelectionChangedEventArgs args) =>
        UpdateSelectionControls();

    private void RemoveSelectionButton_Click(object sender, RoutedEventArgs args)
    {
        if (SelectedPathsList.SelectedItem is SelectedPathRow selected)
        {
            _selectedPaths.Remove(selected);
        }
        UpdateSelectionControls();
    }

    private void ClearSelectionButton_Click(object sender, RoutedEventArgs args)
    {
        _selectedPaths.Clear();
        _outcomeUnknown = false;
        ShowStatus("TransferIdle", InfoBarSeverity.Informational);
        UpdateSelectionControls();
    }

    private async void SendButton_Click(object sender, RoutedEventArgs args)
    {
        if (_sendInProgress || _selectedPaths.Count == 0)
        {
            return;
        }

        long generation = ++_operationGeneration;
        _sendInProgress = true;
        SetSendBusy(true);
        ShowStatus("TransferSending", InfoBarSeverity.Informational);
        try
        {
            TransferQueuedSnapshot queued = await _client.SendFilesAsync(
                _selectedPaths.Select(row => row.FullPath).ToArray());
            if (generation != _operationGeneration)
            {
                return;
            }
            _selectedPaths.Clear();
            TransferStatus.Title = _resources.GetString("TransferQueuedTitle");
            TransferStatus.Message = string.Format(
                _resources.GetString("TransferQueuedMessage"), queued.RedactedTransferId);
            TransferStatus.Severity = InfoBarSeverity.Success;
        }
        catch (AgentProtocolException)
        {
            if (generation == _operationGeneration)
            {
                ShowStatus("TransferRejected", InfoBarSeverity.Error);
            }
        }
        catch (Exception exception) when (
            exception is OperationCanceledException or
            IOException or JsonException or InvalidDataException or InvalidOperationException or
            UnauthorizedAccessException)
        {
            if (generation == _operationGeneration)
            {
                _outcomeUnknown = true;
                ShowStatus("TransferOutcomeUnknown", InfoBarSeverity.Error);
            }
        }
        finally
        {
            _sendInProgress = false;
            SetSendBusy(false);
        }
    }

    private void SetSendBusy(bool busy)
    {
        AddFilesButton.IsEnabled = !busy;
        AddFolderButton.IsEnabled = !busy;
        SelectedPathsList.IsEnabled = !busy;
        SendProgressPanel.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        UpdateSelectionControls();
    }

    private void UpdateSelectionControls()
    {
        SelectionCountText.Text = string.Format(
            _resources.GetString("TransferSelectionCount"), _selectedPaths.Count, MaximumSelectedPaths);
        RemoveSelectionButton.IsEnabled = !_sendInProgress && SelectedPathsList.SelectedItem is not null;
        ClearSelectionButton.IsEnabled = !_sendInProgress && _selectedPaths.Count > 0;
        SendButton.IsEnabled = !_sendInProgress && !_outcomeUnknown && _selectedPaths.Count > 0;
    }

    private void ShowStatus(string key, InfoBarSeverity severity)
    {
        TransferStatus.Title = _resources.GetString(key + "Title");
        TransferStatus.Message = _resources.GetString(key + "Message");
        TransferStatus.Severity = severity;
    }

    private sealed record SelectedPathRow(string FullPath, string DisplayName);
}
