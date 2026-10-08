using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AetherLink.Gui.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private readonly Services.TunnelService _tunnel = new();

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Down";

    [ObservableProperty]
    public partial string LastError { get; set; } = "";

    [ObservableProperty]
    public partial string EgressIp { get; set; } = "-";

    [ObservableProperty]
    public partial string ServerAddr { get; set; } = "";

    [ObservableProperty]
    public partial string OuterSni { get; set; } = "";

    [ObservableProperty]
    public partial string Psk { get; set; } = "";

    [ObservableProperty]
    public partial string DnsMode { get; set; } = "tunnel";

    [ObservableProperty]
    public partial bool FullTunnel { get; set; } = true;

    [ObservableProperty]
    public partial string ConfigPath { get; set; } = "";

    [ObservableProperty]
    public partial string LogText { get; set; } = "";

    public ObservableCollection<Models.RouteRule> Rules { get; } = new();

    public bool IsUp => _tunnel.IsUp;
    public string ConnectLabel => IsUp ? "Disconnect" : "Connect";

    public MainViewModel()
    {
        _tunnel.Changed += () =>
        {
            StatusText = _tunnel.IsUp ? $"Up ({_tunnel.ServerLabel})" : _tunnel.StatusText;
            LastError = _tunnel.LastError;
            OnPropertyChanged(nameof(IsUp));
            OnPropertyChanged(nameof(ConnectLabel));
        };
        ConfigPath = Services.ConfigService.ResolvePath();
        LoadConfig();
    }

    private string? ValidateRules()
    {
        for (var i = 0; i < Rules.Count; i++)
        {
            var r = Rules[i];
            if (string.IsNullOrWhiteSpace(r.Name))
            {
                return $"rule #{i + 1}: name is empty (core requires a name)";
            }

            if (r.Action != "direct" && r.Action != "tunnel")
            {
                return $"rule '{r.Name}': action must be direct|tunnel";
            }

            if (string.IsNullOrWhiteSpace(r.WhenValue))
            {
                return $"rule '{r.Name}': match value is empty";
            }
        }

        return null;
    }

    [RelayCommand]
    private async Task ConnectDisconnect()
    {
        LastError = "";
        if (_tunnel.IsUp)
        {
            await Task.Run(() => _tunnel.Down()).ConfigureAwait(false);
            EgressIp = "-";
            return;
        }

        var ruleError = ValidateRules();
        if (ruleError is not null)
        {
            LastError = $"config error: {ruleError}";
            Services.GuiLog.Warn($"connect blocked: {ruleError}");
            return;
        }

        SaveConfig();
        var raw = Services.ConfigService.RawText(ConfigPath);
        var label = ServerAddr;
        var ok = await Task.Run(() =>
        {
            try
            {
                _tunnel.Up(raw, label);
                return true;
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                return false;
            }
        }).ConfigureAwait(false);
        if (ok)
        {
            await RefreshEgressAsync().ConfigureAwait(false);
        }
    }

    [RelayCommand]
    private async Task RefreshEgress()
    {
        await RefreshEgressAsync().ConfigureAwait(false);
    }

    private async Task RefreshEgressAsync()
    {
        EgressIp = "checking...";
        EgressIp = await Services.EgressService.GetEgressIpAsync().ConfigureAwait(false);
    }

    [RelayCommand]
    private void AddRule() => Rules.Add(new Models.RouteRule());

    [RelayCommand]
    private void RemoveRule(Models.RouteRule? r)
    {
        if (r is not null)
        {
            Rules.Remove(r);
        }
    }

    [RelayCommand]
    private void ReloadLogs()
    {
        try
        {
            // Prefer this app's own log; fall back to newest core log.
            var guiLog = Services.GuiLog.CurrentPath;
            if (!string.IsNullOrEmpty(guiLog) && File.Exists(guiLog))
            {
                LogText = File.ReadAllText(guiLog);
                return;
            }

            var dir = Path.Combine(AppContext.BaseDirectory, "logs");
            var latest = new DirectoryInfo(dir).GetFiles("*.txt")
                .OrderByDescending(f => f.LastWriteTime)
                .FirstOrDefault();
            LogText = latest is null ? "(no logs yet)" : File.ReadAllText(latest.FullName);
        }
        catch (Exception ex)
        {
            LogText = $"log read failed: {ex.Message}";
        }
    }

    public void LoadConfig()
    {
        try
        {
            var cfg = Services.ConfigService.Load(ConfigPath);
            ServerAddr = cfg.Client.ServerAddr;
            OuterSni = cfg.Client.OuterSni;
            Psk = cfg.Client.Psk;
            DnsMode = cfg.FullTunnel.DnsMode;
            FullTunnel = cfg.FullTunnel.Enabled;
            Rules.Clear();
            foreach (var r in cfg.Routing.Rules)
            {
                Rules.Add(r);
            }
        }
        catch (Exception ex)
        {
            LastError = $"config load: {ex.Message}";
        }
    }

    public void SaveConfig()
    {
        try
        {
            var cfg = new Models.GuiClientConfig
            {
                Client = new Models.ClientSection
                {
                    ServerAddr = ServerAddr,
                    OuterSni = OuterSni,
                    Psk = Psk,
                },
                FullTunnel = new Models.FullTunnelSection
                {
                    Enabled = FullTunnel,
                    DnsMode = DnsMode,
                },
                Routing = new Models.RoutingSection { Rules = Rules.ToList() },
            };
            Services.ConfigService.Save(ConfigPath, cfg);
        }
        catch (Exception ex)
        {
            LastError = $"config save: {ex.Message}";
        }
    }

    public void Shutdown() => _tunnel.Down();
}
