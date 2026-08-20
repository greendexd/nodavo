using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Nodavo.Windows.Services;
using Nodavo.Windows.ViewModels;
using Nodavo.Windows.Views;
using Microsoft.Windows.ApplicationModel.Resources;
using WinRT.Interop;

namespace Nodavo.Windows;

public sealed partial class MainWindow : Window
{
    private readonly AgentViewModel _agent;
    private readonly AgentLifecycleViewModel _lifecycle;
    private readonly IReadOnlyDictionary<string, UIElement> _sections;

    public MainWindow()
    {
        InitializeComponent();

        var resources = new ResourceLoader();
        Title = resources.GetString("ProductName");
        ConfigureWindow();

        var agentClient = new AgentClient();
        _agent = new AgentViewModel(agentClient, resources);
        _lifecycle = new AgentLifecycleViewModel(
            new AgentLifecycleCoordinator(agentClient, new PackagedAgentLifecyclePlatform()),
            resources);
        _sections = new Dictionary<string, UIElement>(StringComparer.Ordinal)
        {
            ["overview"] = new OverviewView(_agent, _lifecycle),
            ["devices"] = new DevicesView(agentClient, resources),
            ["layout"] = new LayoutView(agentClient, resources),
            ["transfers"] = new TransfersView(agentClient, resources),
            ["settings"] = new SettingsView(_agent, _lifecycle),
        };

        Navigation.SelectedItem = OverviewItem;
        SectionContent.Content = _sections["overview"];
        Activated += OnActivated;
    }

    private void ConfigureWindow()
    {
        var windowHandle = WindowNative.GetWindowHandle(this);
        var windowId = Win32Interop.GetWindowIdFromWindow(windowHandle);
        AppWindow appWindow = AppWindow.GetFromWindowId(windowId);
        appWindow.Resize(new global::Windows.Graphics.SizeInt32(920, 650));
    }

    private async void OnActivated(object sender, WindowActivatedEventArgs args)
    {
        if (args.WindowActivationState != WindowActivationState.Deactivated)
        {
            await Task.WhenAll(_agent.RefreshAsync(), _lifecycle.RefreshAsync());
        }
    }

    private void Navigation_SelectionChanged(
        NavigationView sender,
        NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer?.Tag is string section &&
            _sections.TryGetValue(section, out UIElement? content))
        {
            SectionContent.Content = content;
        }
    }
}
