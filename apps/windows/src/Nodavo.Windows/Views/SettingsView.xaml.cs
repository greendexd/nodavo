using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Nodavo.Windows.ViewModels;

namespace Nodavo.Windows.Views;

public sealed partial class SettingsView : UserControl
{
    private readonly AgentViewModel _agent;

    internal SettingsView(AgentViewModel agent)
    {
        InitializeComponent();
        _agent = agent;
        DataContext = agent;
    }

    private async void EmergencyStopButton_Click(object sender, RoutedEventArgs args)
    {
        await _agent.EmergencyStopAsync();
    }
}
