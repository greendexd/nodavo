using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Nodavo.Windows.ViewModels;

namespace Nodavo.Windows.Views;

public sealed partial class OverviewView : UserControl
{
    private readonly AgentViewModel _agent;
    public AgentLifecycleViewModel Lifecycle { get; }

    internal OverviewView(AgentViewModel agent, AgentLifecycleViewModel lifecycle)
    {
        InitializeComponent();
        _agent = agent;
        Lifecycle = lifecycle;
        DataContext = agent;
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs args)
    {
        await _agent.RefreshAsync();
    }

    private async void EmergencyStopButton_Click(object sender, RoutedEventArgs args)
    {
        await _agent.EmergencyStopAsync();
    }

    private async void FocusAcquireButton_Click(object sender, RoutedEventArgs args)
    {
        await _agent.RequestRemoteFocusAsync();
    }

    private async void FocusReleaseButton_Click(object sender, RoutedEventArgs args)
    {
        await _agent.ReleaseFocusAsync();
    }

    private async void StartAgentButton_Click(object sender, RoutedEventArgs args)
    {
        await Lifecycle.StartAgentAsync();
        await _agent.RefreshAsync();
    }
}
