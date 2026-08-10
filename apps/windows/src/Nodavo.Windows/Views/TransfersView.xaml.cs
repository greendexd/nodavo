using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.ApplicationModel.Resources;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;
using Nodavo.Windows.ViewModels;
using WinRT.Interop;

namespace Nodavo.Windows.Views;

public sealed partial class TransfersView : UserControl
{
    private const int MaximumSelectedPaths = 32;
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);
    private readonly AgentClient _client;
    private readonly ResourceLoader _resources;
    private readonly ObservableCollection<SelectedPathRow> _selectedPaths = [];
    private readonly ObservableCollection<TransferDisplayRow> _transferRows = [];
    private readonly SemaphoreSlim _transferRequestGate = new(1, 1);
    private TransfersState _transferState = TransfersState.Empty;
    private TransferPollSchedule _pollSchedule = TransferPollSchedule.Empty;
    private CancellationTokenSource? _viewCancellation;
    private Task? _pollTask;
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
        TransferRowsList.ItemsSource = _transferRows;
        ShowStatus("TransferIdle", InfoBarSeverity.Informational);
        UpdateSelectionControls();
        SynchronizeTransferRows();
    }

    private void TransfersView_Loaded(object sender, RoutedEventArgs args)
    {
        if (_pollSchedule.IsLoaded)
        {
            return;
        }
        _pollSchedule = TransferPollLifecycle.Load(_pollSchedule);
        _viewCancellation = new CancellationTokenSource();
        StartPolling(forceOneRefresh: false);
    }

    private void TransfersView_Unloaded(object sender, RoutedEventArgs args)
    {
        _pollSchedule = TransferPollLifecycle.Unload(_pollSchedule);
        _viewCancellation?.Cancel();
        _viewCancellation?.Dispose();
        _viewCancellation = null;
        _transferState = TransfersViewModel.Stop(_transferState);
        SynchronizeTransferRows();
    }

    private void RefreshTransfersButton_Click(object sender, RoutedEventArgs args)
    {
        _transferState = TransfersViewModel.RestartAdmissionReconciliation(_transferState);
        SynchronizeTransferRows();
        StartPolling(forceOneRefresh: true);
    }

    private void StartPolling(bool forceOneRefresh)
    {
        if (forceOneRefresh)
        {
            _pollSchedule = TransferPollLifecycle.RequestForcedRefresh(_pollSchedule);
        }
        _pollSchedule = TransferPollLifecycle.TryStart(
            _pollSchedule,
            _transferState.HasPollingWork,
            out bool shouldStart);
        if (!shouldStart || _viewCancellation is null)
        {
            return;
        }
        _transferState = TransfersViewModel.Start(_transferState);
        long generation = _transferState.Generation;
        Task task = PollTransfersAsync(generation, _viewCancellation.Token);
        _pollTask = task;
        _ = ObservePollCompletionAsync(task);
    }

    private async Task PollTransfersAsync(
        long generation,
        CancellationToken cancellationToken)
    {
        bool shouldRefresh = true;
        while (shouldRefresh && !cancellationToken.IsCancellationRequested)
        {
            try
            {
                await _transferRequestGate.WaitAsync(cancellationToken);
                try
                {
                    TransferListSnapshot snapshot =
                        await _client.ListTransfersAsync(cancellationToken);
                    bool authoritative = TransfersViewModel.IsAuthoritativeSnapshot(
                        _transferState,
                        snapshot,
                        generation);
                    _transferState = TransfersViewModel.ApplySnapshot(
                        _transferState,
                        snapshot,
                        generation);
                    if (!authoritative)
                    {
                        _transferState = TransfersViewModel.MarkPollFailure(
                            _transferState,
                            generation);
                    }
                }
                finally
                {
                    _transferRequestGate.Release();
                }
                if (!IsCurrentTransferGeneration(generation))
                {
                    return;
                }
                SynchronizeTransferRows();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception) when (
                exception is OperationCanceledException or IOException or JsonException or
                InvalidDataException or InvalidOperationException or UnauthorizedAccessException or
                AgentProtocolException)
            {
                _transferState = TransfersViewModel.MarkPollFailure(_transferState, generation);
                if (!IsCurrentTransferGeneration(generation))
                {
                    return;
                }
                SynchronizeTransferRows();
            }

            (TransferPollSchedule schedule, bool forcedRefresh) =
                TransferPollLifecycle.TakeForcedRefresh(_pollSchedule);
            _pollSchedule = schedule;
            shouldRefresh = _transferState.HasPollingWork || forcedRefresh;
            if (shouldRefresh)
            {
                try
                {
                    await Task.Delay(PollInterval, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    private async Task ObservePollCompletionAsync(Task task)
    {
        try
        {
            await task;
        }
        finally
        {
            if (ReferenceEquals(_pollTask, task))
            {
                _pollTask = null;
                _pollSchedule = TransferPollLifecycle.CompleteLoop(_pollSchedule);
                if (_viewCancellation is not null && !_viewCancellation.IsCancellationRequested)
                {
                    StartPolling(forceOneRefresh: false);
                }
            }
        }
    }

    private async void CancelTransferButton_Click(object sender, RoutedEventArgs args)
    {
        if (sender is not Button { DataContext: TransferDisplayRow row } ||
            !TransfersViewModel.CanCancel(_transferState, row.TransferId) ||
            _viewCancellation is null)
        {
            return;
        }

        string transferId = row.TransferId;
        CancellationToken cancellationToken = _viewCancellation.Token;
        _transferState = TransfersViewModel.BeginCancel(_transferState, transferId);
        long generation = _transferState.Generation;
        SynchronizeTransferRows();
        try
        {
            await _transferRequestGate.WaitAsync(cancellationToken);
            try
            {
                TransferListSnapshot snapshot = await _client.CancelTransferAsync(
                    transferId,
                    cancellationToken);
                _transferState = TransfersViewModel.CompleteCancelSnapshot(
                    _transferState,
                    snapshot,
                    transferId,
                    generation);
            }
            finally
            {
                _transferRequestGate.Release();
            }
        }
        catch (AgentProtocolException)
        {
            _transferState = TransfersViewModel.RejectCancel(
                _transferState,
                transferId,
                generation);
            if (IsCurrentTransferGeneration(generation))
            {
                ShowStatus("TransferCancelRejected", InfoBarSeverity.Error);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception exception) when (
            exception is OperationCanceledException or IOException or JsonException or
            InvalidDataException or InvalidOperationException or UnauthorizedAccessException)
        {
            _transferState = TransfersViewModel.MarkCancelOutcomeUnknown(
                _transferState,
                transferId,
                generation);
        }

        if (IsCurrentTransferGeneration(generation))
        {
            SynchronizeTransferRows();
            StartPolling(forceOneRefresh: true);
        }
    }

    private bool IsCurrentTransferGeneration(long generation) =>
        _transferState.IsLoaded && _transferState.Generation == generation;

    private void SynchronizeTransferRows()
    {
        var expected = _transferState.Rows
            .Select(row => row.Snapshot.TransferId)
            .ToHashSet(StringComparer.Ordinal);
        for (int index = _transferRows.Count - 1; index >= 0; index--)
        {
            if (!expected.Contains(_transferRows[index].TransferId))
            {
                _transferRows.RemoveAt(index);
            }
        }

        for (int index = 0; index < _transferState.Rows.Count; index++)
        {
            TransferSnapshot snapshot = _transferState.Rows[index].Snapshot;
            TransferDisplayRow? existing = _transferRows
                .FirstOrDefault(row => row.TransferId == snapshot.TransferId);
            if (existing is null)
            {
                existing = new TransferDisplayRow(snapshot.TransferId);
                _transferRows.Insert(Math.Min(index, _transferRows.Count), existing);
            }
            existing.Update(snapshot, _transferState, _resources);
        }

        NoTransfersText.Visibility = _transferRows.Count == 0
            ? Visibility.Visible
            : Visibility.Collapsed;
        RenderFeedNotice();
    }

    private void RenderFeedNotice()
    {
        if (_transferState.CancelOutcomeUnknown)
        {
            ShowFeedNotice("TransferCancelUnknown", InfoBarSeverity.Warning);
        }
        else if (_transferState.AdmissionReconciliationPending)
        {
            ShowFeedNotice(
                _transferState.AdmissionReconciliationAttemptsRemaining > 0
                    ? "TransferAdmissionReconciling"
                    : "TransferAdmissionUnresolved",
                InfoBarSeverity.Warning);
        }
        else if (_transferState.IsStale)
        {
            ShowFeedNotice("TransferFeedStale", InfoBarSeverity.Warning);
        }
        else if (_transferState.Truncated)
        {
            ShowFeedNotice("TransferFeedTruncated", InfoBarSeverity.Informational);
        }
        else
        {
            TransferFeedNotice.IsOpen = false;
        }
    }

    private void ShowFeedNotice(string key, InfoBarSeverity severity)
    {
        TransferFeedNotice.Title = _resources.GetString(key + "Title");
        TransferFeedNotice.Message = _resources.GetString(key + "Message");
        TransferFeedNotice.Severity = severity;
        TransferFeedNotice.IsOpen = true;
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
            TransferQueuedSnapshot queued;
            await _transferRequestGate.WaitAsync();
            try
            {
                queued = await _client.SendFilesAsync(
                    _selectedPaths.Select(row => row.FullPath).ToArray());
            }
            finally
            {
                _transferRequestGate.Release();
            }
            if (generation != _operationGeneration)
            {
                return;
            }
            _selectedPaths.Clear();
            TransferStatus.Title = _resources.GetString("TransferQueuedTitle");
            TransferStatus.Message = string.Format(
                _resources.GetString("TransferQueuedMessage"), queued.RedactedTransferId);
            TransferStatus.Severity = InfoBarSeverity.Success;
            _transferState = TransfersViewModel.BeginAdmissionReconciliation(_transferState);
            SynchronizeTransferRows();
            StartPolling(forceOneRefresh: true);
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
                _transferState = TransfersViewModel.BeginAdmissionReconciliation(_transferState);
                SynchronizeTransferRows();
                StartPolling(forceOneRefresh: true);
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

    private sealed class TransferDisplayRow : INotifyPropertyChanged
    {
        private string _identifierText = string.Empty;
        private string _categoryText = string.Empty;
        private string _directionPhaseText = string.Empty;
        private string _progressText = string.Empty;
        private string _progressAutomationName = string.Empty;
        private string _failureText = string.Empty;
        private string _cancelText = string.Empty;
        private string _cancelAutomationName = string.Empty;
        private double _progressMaximum = 1;
        private double _progressValue;
        private bool _isProgressIndeterminate;
        private bool _canCancel;
        private Visibility _failureVisibility = Visibility.Collapsed;
        private Visibility _cancelVisibility = Visibility.Collapsed;

        internal TransferDisplayRow(string transferId) => TransferId = transferId;

        public event PropertyChangedEventHandler? PropertyChanged;

        internal string TransferId { get; }
        public string IdentifierText { get => _identifierText; private set => Set(ref _identifierText, value); }
        public string CategoryText { get => _categoryText; private set => Set(ref _categoryText, value); }
        public string DirectionPhaseText { get => _directionPhaseText; private set => Set(ref _directionPhaseText, value); }
        public string ProgressText { get => _progressText; private set => Set(ref _progressText, value); }
        public string ProgressAutomationName { get => _progressAutomationName; private set => Set(ref _progressAutomationName, value); }
        public string FailureText { get => _failureText; private set => Set(ref _failureText, value); }
        public string CancelText { get => _cancelText; private set => Set(ref _cancelText, value); }
        public string CancelAutomationName { get => _cancelAutomationName; private set => Set(ref _cancelAutomationName, value); }
        public double ProgressMaximum { get => _progressMaximum; private set => Set(ref _progressMaximum, value); }
        public double ProgressValue { get => _progressValue; private set => Set(ref _progressValue, value); }
        public bool IsProgressIndeterminate { get => _isProgressIndeterminate; private set => Set(ref _isProgressIndeterminate, value); }
        public bool CanCancel { get => _canCancel; private set => Set(ref _canCancel, value); }
        public Visibility FailureVisibility { get => _failureVisibility; private set => Set(ref _failureVisibility, value); }
        public Visibility CancelVisibility { get => _cancelVisibility; private set => Set(ref _cancelVisibility, value); }

        internal void Update(
            TransferSnapshot snapshot,
            TransfersState state,
            ResourceLoader resources)
        {
            IdentifierText = string.Format(
                resources.GetString("TransferIdentifierFormat"),
                snapshot.RedactedTransferId);
            CategoryText = resources.GetString(
                snapshot.IsTerminal ? "TransferRecentSession" : "TransferCurrent");
            string direction = resources.GetString(snapshot.Direction switch
            {
                TransferDirection.Inbound => "TransferDirectionInbound",
                _ => "TransferDirectionOutbound",
            });
            string phase = resources.GetString(snapshot.Phase switch
            {
                TransferPhase.Preparing => "TransferPhasePreparing",
                TransferPhase.Queued => "TransferPhaseQueued",
                TransferPhase.Transferring => "TransferPhaseTransferring",
                TransferPhase.Paused => "TransferPhasePaused",
                TransferPhase.Finalizing => "TransferPhaseFinalizing",
                TransferPhase.CancelRequested => "TransferPhaseCancelRequested",
                TransferPhase.Completed => "TransferPhaseCompleted",
                TransferPhase.Cancelled => "TransferPhaseCancelled",
                _ => "TransferPhaseFailed",
            });
            DirectionPhaseText = string.Format(
                resources.GetString("TransferDirectionPhaseFormat"),
                direction,
                phase);

            bool zeroByteNonterminal = !snapshot.IsTerminal && snapshot.TotalBytes == 0;
            IsProgressIndeterminate = !snapshot.IsTerminal &&
                (!snapshot.TotalBytes.HasValue || zeroByteNonterminal);
            ProgressMaximum = snapshot.TotalBytes is > 0 ? snapshot.TotalBytes.Value : 1;
            bool completedZeroBytes = snapshot.Phase == TransferPhase.Completed &&
                snapshot.ProcessedBytes == 0 && snapshot.TotalBytes == 0;
            ProgressValue = completedZeroBytes ? 1 : snapshot.ProcessedBytes ?? 0;
            ProgressText = completedZeroBytes
                ? resources.GetString("TransferProgressCompleteZero")
                : snapshot.ProcessedBytes.HasValue && snapshot.TotalBytes.HasValue
                ? string.Format(
                    resources.GetString("TransferProgressBytesFormat"),
                    snapshot.ProcessedBytes.Value,
                    snapshot.TotalBytes.Value)
                : resources.GetString("TransferProgressPending");
            ProgressAutomationName = string.Format(
                resources.GetString("TransferProgressAutomationFormat"),
                phase,
                ProgressText);

            FailureText = snapshot.Failure.HasValue
                ? resources.GetString(snapshot.Failure.Value switch
                {
                    TransferFailure.AdmissionFailed => "TransferFailureAdmission",
                    TransferFailure.SourceUnavailable => "TransferFailureSource",
                    TransferFailure.AuthorizationRevoked => "TransferFailureAuthorization",
                    TransferFailure.TransportFailed => "TransferFailureTransport",
                    TransferFailure.CleanupFailed => "TransferFailureCleanup",
                    _ => "TransferFailureInternal",
                })
                : string.Empty;
            FailureVisibility = snapshot.Failure.HasValue
                ? Visibility.Visible
                : Visibility.Collapsed;

            bool isOwner = state.CancelOwnerId == snapshot.TransferId;
            CancelText = isOwner && state.CancelInFlight
                ? resources.GetString("TransferCancelling")
                : isOwner && state.CancelOutcomeUnknown
                    ? resources.GetString("TransferRetryCancel")
                    : resources.GetString("TransferCancel");
            CancelAutomationName = string.Format(
                resources.GetString("TransferCancelAutomationFormat"),
                snapshot.RedactedTransferId);
            CanCancel = TransfersViewModel.CanCancel(state, snapshot.TransferId);
            CancelVisibility = snapshot.Cancellable && !snapshot.IsTerminal
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        private void Set<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
            {
                return;
            }
            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
