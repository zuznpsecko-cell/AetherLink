using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Platform;
using AetherLink.Gui.Services;
using AetherLink.Gui.ViewModels;
using AetherLink.Gui.Views;

namespace AetherLink.Gui;

public partial class App : Application
{
    private TrayIcon? _tray;
    private MainViewModel? _vm;

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        Services.GuiLog.Init();
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            _vm = new MainViewModel();
            var window = new MainWindow { DataContext = _vm };
            window.Closing += (_, _) => _vm.Shutdown();
            desktop.MainWindow = window;

            _tray = new TrayIcon
            {
                Icon = new WindowIcon(AssetLoader.Open(new Uri("avares://AetherLink.Gui/Assets/avalonia-logo.ico"))),
                ToolTipText = "AetherLink",
                Menu = BuildTrayMenu(window),
            };
            TrayIcon.SetIcons(this, new TrayIcons { _tray });
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static string AutostartLabel()
        => AutostartService.IsEnabled ? "Autostart: on" : "Autostart: off";

    private NativeMenu BuildTrayMenu(Window window)
    {
        var menu = new NativeMenu();
        var toggle = new NativeMenuItem("Connect / Disconnect");
        toggle.Click += (_, _) =>
        {
            if (_vm?.ConnectDisconnectCommand.CanExecute(null) == true)
            {
                _vm.ConnectDisconnectCommand.Execute(null);
            }
        };
        var show = new NativeMenuItem("Show window");
        show.Click += (_, _) =>
        {
            window.Show();
            window.Activate();
        };
        var quit = new NativeMenuItem("Quit");
        quit.Click += (_, _) =>
        {
            _tray = null;
            Services.GuiLog.Close();
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.Shutdown();
            }
        };
        menu.Add(toggle);
        menu.Add(show);
        var autostart = new NativeMenuItem(AutostartLabel());
        autostart.Click += (_, _) =>
        {
            AutostartService.SetEnabled(!AutostartService.IsEnabled);
            autostart.Header = AutostartLabel();
        };
        menu.Add(autostart);
        menu.Add(new NativeMenuItemSeparator());
        menu.Add(quit);
        return menu;
    }
}
