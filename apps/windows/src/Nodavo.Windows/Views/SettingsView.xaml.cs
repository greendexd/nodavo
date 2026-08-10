using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Nodavo.Windows.ViewModels;

namespace Nodavo.Windows.Views;

public sealed partial class SettingsView : UserControl
{
    private readonly AgentViewModel _agent;
    public AgentLifecycleViewModel Lifecycle { get; }

    internal SettingsView(AgentViewModel agent, AgentLifecycleViewModel lifecycle)
    {
        InitializeComponent();
        _agent = agent;
        Lifecycle = lifecycle;
        DataContext = agent;
    }

    private async void EmergencyStopButton_Click(object sender, RoutedEventArgs args)
    {
        await _agent.EmergencyStopAsync();
    }

    private async void StartupActionButton_Click(object sender, RoutedEventArgs args)
    {
        await Lifecycle.ChangeStartupAsync();
    }
}
