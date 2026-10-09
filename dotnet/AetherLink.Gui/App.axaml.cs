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
            // Bounded teardown: down() can wait on an in-flight up() and on
            // pump joins; the window must still close (a missed teardown is
            // recovered by the stale-state auto-restore on the next Connect).
            window.Closing += (_, _) => _vm.Shutdown(TimeSpan.FromSeconds(10));
            desktop.MainWindow = window;
            if (desktop.Args?.Contains("--minimized") == true)
            {
                // Autostart passes --minimized: stay in the tray.
                window.WindowState = WindowState.Minimized;
            }

            // Task Manager kills, sign-out and Windows shutdown skip the
            // window's Closing event. Without these hooks the tunnel outlives
            // the process with routes and DNS still pointing into the TUN, and
            // the machine is offline until someone runs a manual restore.
            // ProcessExit gets only ~2s from the runtime: keep the wait short.
            AppDomain.CurrentDomain.ProcessExit += (_, _) => _vm?.Shutdown(TimeSpan.FromSeconds(2));
            Microsoft.Win32.SystemEvents.SessionEnding += (_, _) => _vm?.Shutdown(TimeSpan.FromSeconds(2));

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
