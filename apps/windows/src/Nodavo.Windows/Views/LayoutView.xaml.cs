using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.ApplicationModel.Resources;
using Nodavo.Windows.Models;
using Nodavo.Windows.Services;

namespace Nodavo.Windows.Views;

public sealed partial class LayoutView : UserControl
{
    private readonly AgentClient _client;
    private readonly ResourceLoader _resources;
    private readonly HashSet<string> _unresolvedPeerIds = new(StringComparer.Ordinal);
    private IReadOnlyList<TrustedPeerSnapshot> _peers = Array.Empty<TrustedPeerSnapshot>();
    private PeerPlacementControlState _placementState = PeerPlacementControlState.Initial;
    private bool _requestInProgress;
    private bool _loadingPeerSelection;
    private bool _loadingPlacementSelection;
    private long _operationGeneration;

    public LayoutView()
        : this(new AgentClient(), new ResourceLoader())
    {
    }

    internal LayoutView(AgentClient client, ResourceLoader resources)
    {
        _client = client;
        _resources = resources;
        InitializeComponent();
        PlacementSelector.ItemsSource = new[]
        {
            new PlacementChoice(PeerPlacement.Disabled, resources.GetString("LayoutPlacementDisabled")),
            new PlacementChoice(PeerPlacement.Left, resources.GetString("LayoutPlacementLeft")),
            new PlacementChoice(PeerPlacement.Right, resources.GetString("LayoutPlacementRight")),
            new PlacementChoice(PeerPlacement.Above, resources.GetString("LayoutPlacementAbove")),
            new PlacementChoice(PeerPlacement.Below, resources.GetString("LayoutPlacementBelow")),
        };
        ShowStatus("LayoutLoading", InfoBarSeverity.Informational);
        Loaded += LayoutView_Loaded;
    }

    private async void LayoutView_Loaded(object sender, RoutedEventArgs args)
    {
        if (PeerSelector.ItemsSource is null)
        {
            await RefreshPeersAsync();
        }
    }

    private async void RefreshLayoutButton_Click(object sender, RoutedEventArgs args) =>
        await RefreshPeersAsync();

    private async Task RefreshPeersAsync(string? preferredPeerId = null)
    {
        if (_requestInProgress)
        {
            return;
        }

        long generation = ++_operationGeneration;
        string? selectedPeerId = preferredPeerId ?? SelectedPeer()?.PeerId;
        _requestInProgress = true;
        UpdateInteractionState();
        ShowStatus("LayoutLoading", InfoBarSeverity.Informational);
        try
        {
            IReadOnlyList<TrustedPeerSnapshot> peers = await _client.ListTrustedPeersAsync();
            if (generation != _operationGeneration)
            {
                return;
            }

            // A successfully authenticated list is authoritative for every peer and
            // resolves any prior mutation whose acknowledgement was ambiguous.
            _unresolvedPeerIds.Clear();
            ApplyPeers(peers, selectedPeerId);
            ShowStatus(
                peers.Count == 0 ? "LayoutEmpty" : "LayoutLoaded",
                peers.Count == 0 ? InfoBarSeverity.Informational : InfoBarSeverity.Success);
        }
        catch (Exception exception) when (IsExpectedIpcFailure(exception))
        {
            if (generation == _operationGeneration)
            {
                ShowStatus(
                    exception is OperationCanceledException ? "LayoutTimeout" : "LayoutFailed",
                    InfoBarSeverity.Error);
            }
        }
        finally
        {
            if (generation == _operationGeneration)
            {
                _requestInProgress = false;
                UpdateInteractionState();
            }
        }
    }

    private void PeerSelector_SelectionChanged(object sender, SelectionChangedEventArgs args)
    {
        ApplySelectedPeer();
        if (_loadingPeerSelection || _requestInProgress)
        {
            return;
        }

        if (SelectedPeer() is not { } peer)
        {
            ShowStatus("LayoutEmpty", InfoBarSeverity.Informational);
        }
        else if (peer.State == "revoked")
        {
            ShowStatus("LayoutPeerRevoked", InfoBarSeverity.Warning);
        }
        else if (_unresolvedPeerIds.Contains(peer.PeerId))
        {
            ShowStatus("LayoutOutcomeUnknown", InfoBarSeverity.Error);
        }
        else
        {
            ShowStatus("LayoutReady", InfoBarSeverity.Informational);
        }
    }

    private void PlacementSelector_SelectionChanged(object sender, SelectionChangedEventArgs args)
    {
        if (!_loadingPlacementSelection)
        {
            UpdateInteractionState();
        }
    }

    private async void ApplyPlacementButton_Click(object sender, RoutedEventArgs args)
    {
        if (_requestInProgress ||
            SelectedPeer() is not { State: "active" } peer ||
            SelectedPlacement() is not { } requested ||
            peer.PeerId != _placementState.PeerId ||
            !PeerPlacementReducer.CanMutate(_placementState, requested))
        {
            return;
        }

        long generation = ++_operationGeneration;
        _placementState = PeerPlacementReducer.BeginMutation(
            _placementState,
            generation,
            requested);
        _requestInProgress = true;
        UpdateInteractionState();
        ShowStatus("LayoutSaving", InfoBarSeverity.Informational);
        try
        {
            // This exact mutation is sent at most once. Any lost, late, malformed,
            // or explicit error response is reconciled only with list_trusted_peers.
            PeerPlacementChangeSnapshot changed =
                await _client.SetPeerPlacementAsync(peer.PeerId, requested);
            if (generation != _operationGeneration)
            {
                return;
            }

            PeerPlacementControlState applied =
                PeerPlacementReducer.ApplyExactAcknowledgement(
                    _placementState,
                    generation,
                    changed.PeerId,
                    changed.Placement);
            if (applied == _placementState)
            {
                throw new InvalidDataException("Mismatched peer-placement acknowledgement.");
            }

            _placementState = applied;
            ReplaceAuthoritativePlacement(peer.PeerId, changed.Placement);
            ShowStatus("LayoutSaved", InfoBarSeverity.Success);
        }
        catch (Exception exception) when (IsExpectedIpcFailure(exception))
        {
            if (generation == _operationGeneration)
            {
                _placementState = PeerPlacementReducer.MarkAmbiguous(
                    _placementState,
                    generation);
                _unresolvedPeerIds.Add(peer.PeerId);
                await ReconcileAmbiguousPlacementAsync(
                    generation,
                    peer.PeerId,
                    requested);
            }
        }
        finally
        {
            if (generation == _operationGeneration)
            {
                _requestInProgress = false;
                UpdateInteractionState();
            }
        }
    }

    private async Task ReconcileAmbiguousPlacementAsync(
        long generation,
        string peerId,
        PeerPlacement requested)
    {
        _placementState = PeerPlacementReducer.BeginReconciliation(
            _placementState,
            generation);
        ShowStatus("LayoutReconciling", InfoBarSeverity.Warning);
        UpdateInteractionState();
        try
        {
            IReadOnlyList<TrustedPeerSnapshot> peers = await _client.ListTrustedPeersAsync();
            if (generation != _operationGeneration)
            {
                return;
            }

            TrustedPeerSnapshot? reconciled = peers.SingleOrDefault(
                candidate => candidate.PeerId == peerId);
            if (reconciled is not null)
            {
                _placementState = PeerPlacementReducer.ApplyAuthoritativeReconciliation(
                    _placementState,
                    generation,
                    peerId,
                    reconciled.Placement,
                    reconciled.State == "active");
            }

            _unresolvedPeerIds.Clear();
            ApplyPeers(peers, peerId);
            if (reconciled is null)
            {
                ShowStatus("LayoutPeerMissing", InfoBarSeverity.Warning);
            }
            else if (reconciled.State == "revoked")
            {
                ShowStatus("LayoutPeerRevoked", InfoBarSeverity.Warning);
            }
            else if (reconciled.Placement == requested)
            {
                ShowStatus("LayoutReconciledApplied", InfoBarSeverity.Success);
            }
            else
            {
                ShowStatus("LayoutReconciledNotApplied", InfoBarSeverity.Warning);
            }
        }
        catch (Exception exception) when (IsExpectedIpcFailure(exception))
        {
            if (generation == _operationGeneration)
            {
                _placementState = PeerPlacementReducer.FailReconciliation(
                    _placementState,
                    generation);
                ShowStatus("LayoutOutcomeUnknown", InfoBarSeverity.Error);
            }
        }
    }

    private void ApplyPeers(
        IReadOnlyList<TrustedPeerSnapshot> peers,
        string? preferredPeerId)
    {
        _peers = peers;
        var rows = peers.Select(peer => new LayoutPeerRow(
            peer,
            peer.State == "revoked"
                ? string.Format(
                    _resources.GetString("LayoutPeerRevokedDisplay"),
                    peer.DisplayName)
                : peer.DisplayName)).ToArray();

        _loadingPeerSelection = true;
        try
        {
            PeerSelector.ItemsSource = rows;
            PeerSelector.SelectedItem = rows.FirstOrDefault(
                row => row.Peer.PeerId == preferredPeerId) ??
                rows.FirstOrDefault(row => row.Peer.State == "active") ??
                rows.FirstOrDefault();
        }
        finally
        {
            _loadingPeerSelection = false;
        }
        ApplySelectedPeer();
    }

    private void ReplaceAuthoritativePlacement(string peerId, PeerPlacement placement)
    {
        _peers = _peers.Select(peer => peer.PeerId == peerId
            ? peer with { Placement = placement }
            : peer).ToArray();
        ApplyPeers(_peers, peerId);
    }

    private void ApplySelectedPeer()
    {
        TrustedPeerSnapshot? peer = SelectedPeer();
        if (peer is null)
        {
            _placementState = PeerPlacementControlState.Initial;
            LayoutDetails.Visibility = Visibility.Collapsed;
            UpdateInteractionState();
            return;
        }

        _placementState = PeerPlacementReducer.SelectAuthoritativePeer(
            peer.PeerId,
            peer.Placement,
            peer.State == "active",
            _unresolvedPeerIds.Contains(peer.PeerId),
            _operationGeneration);
        LayoutDetails.Visibility = Visibility.Visible;
        SelectedPeerName.Text = peer.DisplayName;
        SelectedPeerState.Text = peer.State == "active"
            ? _resources.GetString("TrustedStateActive")
            : _resources.GetString("TrustedStateRevoked");
        CurrentPlacementText.Text = PlacementLabel(peer.Placement);
        SetPlacementSelection(peer.Placement);
        UpdateInteractionState();
    }

    private void SetPlacementSelection(PeerPlacement placement)
    {
        _loadingPlacementSelection = true;
        try
        {
            PlacementSelector.SelectedItem = PlacementSelector.Items
                .OfType<PlacementChoice>()
                .Single(choice => choice.Placement == placement);
        }
        finally
        {
            _loadingPlacementSelection = false;
        }
    }

    private void UpdateInteractionState()
    {
        TrustedPeerSnapshot? peer = SelectedPeer();
        PeerPlacement? proposed = SelectedPlacement();
        bool active = peer?.State == "active";
        bool unresolved = peer is not null && _unresolvedPeerIds.Contains(peer.PeerId);

        RefreshLayoutButton.IsEnabled = !_requestInProgress;
        PeerSelector.IsEnabled = !_requestInProgress;
        PlacementSelector.IsEnabled = !_requestInProgress && active && !unresolved;
        ApplyPlacementButton.IsEnabled =
            !_requestInProgress &&
            active &&
            !unresolved &&
            proposed.HasValue &&
            PeerPlacementReducer.CanMutate(_placementState, proposed.Value);
        LayoutProgress.IsActive = _requestInProgress;
        LayoutProgress.Visibility = _requestInProgress
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private TrustedPeerSnapshot? SelectedPeer() =>
        (PeerSelector.SelectedItem as LayoutPeerRow)?.Peer;

    private PeerPlacement? SelectedPlacement() =>
        (PlacementSelector.SelectedItem as PlacementChoice)?.Placement;

    private string PlacementLabel(PeerPlacement placement) =>
        _resources.GetString(placement switch
        {
            PeerPlacement.Disabled => "LayoutPlacementDisabled",
            PeerPlacement.Left => "LayoutPlacementLeft",
            PeerPlacement.Right => "LayoutPlacementRight",
            PeerPlacement.Above => "LayoutPlacementAbove",
            PeerPlacement.Below => "LayoutPlacementBelow",
            _ => throw new InvalidDataException("Invalid peer placement."),
        });

    private void ShowStatus(string prefix, InfoBarSeverity severity)
    {
        LayoutStatus.Title = _resources.GetString(prefix + "Title");
        LayoutStatus.Message = _resources.GetString(prefix + "Message");
        LayoutStatus.Severity = severity;
        LayoutStatus.IsOpen = true;
    }

    private static bool IsExpectedIpcFailure(Exception exception) =>
        exception is OperationCanceledException or IOException or JsonException or
        InvalidDataException or InvalidOperationException or UnauthorizedAccessException or
        AgentProtocolException;

    private sealed record PlacementChoice(PeerPlacement Placement, string Label);

    private sealed record LayoutPeerRow(TrustedPeerSnapshot Peer, string DisplayText);
}
