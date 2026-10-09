using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AetherLink.Gui.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private readonly Services.TunnelService _tunnel = new();

    // UI-thread only. Set while an Up/Down/restore is in flight so repeated
    // clicks cannot queue a second tunnel behind the first.
    private bool _busy;

    // UI-thread only. Set when the user presses Disconnect while a Connect
    // is still in flight: the teardown runs as soon as up() returns (it is
    // bounded by the core's connect/handshake timeouts).
    private bool _disconnectRequested;

    // Guards TeardownAsync against re-entry (user click + auto-teardown on a
    // dead pump can race); TunnelService.Down is idempotent under _opGate.
    private int _teardownInFlight;

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
    public string ConnectLabel => _busy && !_tunnel.IsUp ? "Cancel" : IsUp ? "Disconnect" : "Connect";

    public MainViewModel()
    {
        // Changed fires on worker and poll threads; bindings must only be
        // touched on the UI thread.
        // Notifications must never break the caller: this also runs from the
        // process-exit teardown, where a throw would abort the cleanup.
        _tunnel.Changed += () =>
        {
            try
            {
                Dispatcher.UIThread.Post(OnTunnelChanged);
            }
            catch (Exception ex)
            {
                Services.GuiLog.Warn($"ui notify skipped: {ex.Message}");
            }
        };
        ConfigPath = Services.ConfigService.ResolvePath();
        LoadConfig();
    }

    private void OnTunnelChanged()
    {
        StatusText = _tunnel.PumpDead
            ? "Lost"
            : _tunnel.IsUp ? $"Up ({_tunnel.ServerLabel})" : _tunnel.StatusText;
        if (!string.IsNullOrEmpty(_tunnel.LastError))
        {
            LastError = _tunnel.LastError;
        }

        OnPropertyChanged(nameof(IsUp));
        OnPropertyChanged(nameof(ConnectLabel));

        // A dead pump leaves the default route in the TUN, which means no
        // connectivity at all. Restore the network now instead of leaving the
        // user offline behind a green "Up".
        if (_tunnel.PumpDead && !_busy)
        {
            LastError = "Tunnel lost: the link to the server died. Network restored; press Connect to retry.";
            _ = TeardownAsync();
        }
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
        if (_tunnel.IsUp)
        {
            await TeardownAsync();
            return;
        }

        if (_busy)
        {
            // A Connect is still in flight (slow/unreachable server). The
            // click must not be swallowed: mark the cancel and tear down as
            // soon as up() returns — down() waits on the same gate, and the
            // core's connect/handshake timeouts bound that wait.
            _disconnectRequested = true;
            StatusText = "Disconnecting...";
            await TeardownAsync();
            return;
        }

        LastError = "";
        if (string.IsNullOrWhiteSpace(ServerAddr))
        {
            LastError = "config error: server address is empty";
            return;
        }

        if (string.IsNullOrWhiteSpace(Psk))
        {
            LastError = "config error: PSK is empty";
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
        _disconnectRequested = false;
        _busy = true;
        StatusText = "Connecting...";
        OnPropertyChanged(nameof(ConnectLabel));
        bool ok;
        try
        {
            ok = await Task.Run(() => _tunnel.Up(raw, label));
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Services.GuiLog.Error($"up threw: {ex.Message}");
            ok = false;
        }

        if (!ok && _tunnel.StaleState && !_disconnectRequested)
        {
            // A previous run died without teardown and its state file blocks
            // bring-up (routes/DNS may still point into a dead TUN). Restore
            // the network from it and retry once, automatically — otherwise
            // Connect could never succeed until a manual "Restore network".
            Services.GuiLog.Warn("stale tunnel state: restoring network, retrying connect");
            LastError = "Previous session left the network in tunnel state — restoring, retrying…";
            string? cleanupErr;
            try
            {
                cleanupErr = await Task.Run(() => _tunnel.ForceCleanup());
            }
            catch (Exception ex)
            {
                cleanupErr = ex.Message;
            }

            if (cleanupErr is null)
            {
                try
                {
                    ok = await Task.Run(() => _tunnel.Up(raw, label));
                }
                catch (Exception ex)
                {
                    LastError = ex.Message;
                    Services.GuiLog.Error($"up retry threw: {ex.Message}");
                    ok = false;
                }
            }
            else
            {
                LastError = $"restore failed: {cleanupErr}";
                Services.GuiLog.Error($"stale-state cleanup failed: {cleanupErr}");
            }
        }

        _busy = false;
        OnPropertyChanged(nameof(ConnectLabel));

        OnTunnelChanged();
        if (ok && _disconnectRequested)
        {
            // Cancelled while connecting: tear down immediately.
            await TeardownAsync();
            return;
        }

        if (ok)
        {
            await RefreshEgressAsync();
        }
    }

    private async Task TeardownAsync()
    {
        // One teardown at a time. Deliberately NOT gated on _busy: a
        // Disconnect pressed while Connect is in flight must run (it waits
        // on TunnelService's gate until up() returns) instead of being
        // ignored — that ignore was the "disconnect hangs" bug.
        if (Interlocked.Exchange(ref _teardownInFlight, 1) != 0)
        {
            return;
        }

        try
        {
            await Task.Run(() => _tunnel.Down());
        }
        catch (Exception ex)
        {
            LastError = $"disconnect failed: {ex.Message}";
            Services.GuiLog.Error($"down threw: {ex.Message}");
        }
        finally
        {
            _teardownInFlight = 0;
        }

        EgressIp = "-";
        OnTunnelChanged();
    }

    [RelayCommand]
    private async Task RestoreNetwork()
    {
        if (_busy || _tunnel.IsUp)
        {
            LastError = "Disconnect first, then restore the network.";
            return;
        }

        LastError = "";
        _busy = true;
        string? err;
        try
        {
            err = await Task.Run(() => _tunnel.ForceCleanup());
        }
        catch (Exception ex)
        {
            err = ex.Message;
        }
        finally
        {
            _busy = false;
        }

        if (err is not null)
        {
            LastError = $"restore failed: {err}";
        }

        OnTunnelChanged();
        await RefreshEgressAsync();
    }

    [RelayCommand]
    private async Task RefreshEgress()
    {
        await RefreshEgressAsync();
    }

    private async Task RefreshEgressAsync()
    {
        EgressIp = "checking...";
        EgressIp = await Services.EgressService.GetEgressIpAsync();
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
                // Drop fully-empty rows (stale junk from builds without
                // validation); anything half-filled stays for the user to fix.
                if (string.IsNullOrWhiteSpace(r.Name) && string.IsNullOrWhiteSpace(r.WhenValue))
                {
                    continue;
                }

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

    /// <summary>Window close: bring the tunnel down, bounded wait.</summary>
    public void Shutdown() => Shutdown(TimeSpan.FromSeconds(10));

    /// <summary>
    /// Window close / process exit / logoff: always bring the tunnel down.
    ///
    /// Never blocks the caller indefinitely: down() waits for any in-flight
    /// up() (bounded by the core's connect/handshake timeouts) and joins the
    /// pump threads. On timeout the process exits anyway; the leftover state
    /// file is recovered automatically on the next Connect (stale-state
    /// auto-restore), so a missed teardown cannot wedge the machine.
    /// </summary>
    public void Shutdown(TimeSpan timeout)
    {
        try
        {
            Task.Run(() => _tunnel.Down()).Wait(timeout);
        }
        catch (Exception ex)
        {
            Services.GuiLog.Error($"shutdown teardown failed: {ex.Message}");
        }
    }
}
