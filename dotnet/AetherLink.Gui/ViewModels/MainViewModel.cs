using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AetherLink.Gui.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private readonly Services.ITunnelController _tunnel;
    private readonly Services.EndpointSwitcher _switcher;
    private readonly Services.EndpointBook _book = new();
    private readonly Action<Action> _uiPost;
    private readonly Func<Task<string>> _egress;

    // Set while LoadConfig fills the book: selection changes must not save
    // or trigger a reconnect during startup.
    private bool _loading;

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

    // Preserves non-UI transport fields (mtu, pad_multiple, keepalive_s,
    // wintun_dll_path, include_private_lan_direct, default_action) across Save.
    private Models.GuiClientConfig _config = new();

    [ObservableProperty]
    public partial string StatusText { get; set; } = "Down";

    [ObservableProperty]
    public partial string LastError { get; set; } = "";

    [ObservableProperty]
    public partial string EgressIp { get; set; } = "-";

    [ObservableProperty]
    public partial string DnsMode { get; set; } = "tunnel";

    [ObservableProperty]
    public partial bool FullTunnel { get; set; } = true;

    [ObservableProperty]
    public partial string ConfigPath { get; set; } = "";

    [ObservableProperty]
    public partial string LogText { get; set; } = "";

    public ObservableCollection<Models.RouteRule> Rules { get; } = new();

    public ObservableCollection<Models.EndpointProfile> Endpoints => _book.Items;

    [ObservableProperty]
    public partial Models.EndpointProfile? SelectedEndpoint { get; set; }

    public bool IsUp => _tunnel.IsUp;
    public string ConnectLabel => _busy && !_tunnel.IsUp ? "Cancel" : IsUp ? "Disconnect" : "Connect";
    public bool HasSelection => SelectedEndpoint is not null;
    public bool CanDeleteEndpoint => _book.CanRemove && !_busy;
    public bool CanEditEndpoints => !_busy;

    /// <summary>
    /// Completes when the automatic Down/Up of a profile switch finishes.
    /// Exposed for tests; the UI observes status text instead.
    /// </summary>
    internal Task SwitchCompletion { get; private set; } = Task.CompletedTask;

    public MainViewModel()
        : this(new Services.TunnelService(), null, null, null)
    {
    }

    internal MainViewModel(
        Services.ITunnelController tunnel,
        string? configPath = null,
        Action<Action>? uiPost = null,
        Func<Task<string>>? egress = null)
    {
        _tunnel = tunnel;
        _switcher = new Services.EndpointSwitcher(tunnel);
        _uiPost = uiPost ?? (a => Dispatcher.UIThread.Post(a));
        _egress = egress ?? (() => Services.EgressService.GetEgressIpAsync());

        // Changed fires on worker and poll threads; bindings must only be
        // touched on the UI thread.
        // Notifications must never break the caller: this also runs from the
        // process-exit teardown, where a throw would abort the cleanup.
        _tunnel.Changed += () =>
        {
            try
            {
                _uiPost(OnTunnelChanged);
            }
            catch (Exception ex)
            {
                Services.GuiLog.Warn($"ui notify skipped: {ex.Message}");
            }
        };
        ConfigPath = string.IsNullOrEmpty(configPath)
            ? Services.ConfigService.ResolvePath()
            : configPath;
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
            if (string.IsNullOrEmpty(LastError))
            {
                LastError = "Tunnel lost: the link to the server died. Network restored; press Connect to retry.";
            }

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
        var endpointError = _book.Validate();
        if (endpointError is not null)
        {
            LastError = $"config error: {endpointError}";
            Services.GuiLog.Warn($"connect blocked: {endpointError}");
            return;
        }

        var endpoint = SelectedEndpoint;
        if (endpoint is null)
        {
            LastError = "config error: select an endpoint";
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
        var label = endpoint.Name;
        _disconnectRequested = false;
        _busy = true;
        StatusText = "Connecting...";
        OnPropertyChanged(nameof(ConnectLabel));
        OnPropertyChanged(nameof(CanEditEndpoints));
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
        OnPropertyChanged(nameof(CanEditEndpoints));

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
        OnPropertyChanged(nameof(CanEditEndpoints));
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
            RaiseBusyChanged();
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
        EgressIp = await _egress();
    }

    [RelayCommand]
    private void AddEndpoint()
    {
        var endpoint = _book.Add();
        SelectedEndpoint = endpoint;
        RaiseBookChanged();
    }

    [RelayCommand]
    private void DuplicateEndpoint()
    {
        var source = SelectedEndpoint ?? _book.Active;
        if (source is null)
        {
            AddEndpoint();
            return;
        }

        var copy = _book.Duplicate(source);
        SelectedEndpoint = copy;
        RaiseBookChanged();
    }

    [RelayCommand]
    private void DeleteEndpoint()
    {
        var target = SelectedEndpoint;
        if (target is null || !_book.Remove(target))
        {
            RaiseBookChanged();
            return;
        }

        SelectedEndpoint = _book.Active;
        SaveConfig();
        RaiseBookChanged();
    }

    private void RaiseBookChanged()
    {
        OnPropertyChanged(nameof(CanDeleteEndpoint));
        OnPropertyChanged(nameof(HasSelection));
    }

    private void RaiseBusyChanged()
    {
        OnPropertyChanged(nameof(CanEditEndpoints));
        OnPropertyChanged(nameof(CanDeleteEndpoint));
    }

    partial void OnSelectedEndpointChanged(Models.EndpointProfile? value)
    {
        OnPropertyChanged(nameof(HasSelection));
        if (_loading)
        {
            return;
        }

        _book.Select(value);
        if (value is null)
        {
            return;
        }

        SaveConfig();
        if (_tunnel.IsUp && !_busy)
        {
            SwitchCompletion = SwitchToAsync(value);
        }
    }

    /// <summary>
    /// Selection changed while the tunnel is up: Down, then Up on the new
    /// profile. A failure leaves the tunnel down with the network restored;
    /// the selected profile stays so Connect can retry it.
    /// </summary>
    private async Task SwitchToAsync(Models.EndpointProfile target)
    {
        LastError = "";
        _disconnectRequested = false;
        _busy = true;
        StatusText = "Switching...";
        OnPropertyChanged(nameof(ConnectLabel));
        OnPropertyChanged(nameof(CanEditEndpoints));

        Services.EndpointSwitchResult result;
        try
        {
            result = await Task.Run(() => _switcher.Switch(
                target,
                () => Services.ConfigService.RawText(ConfigPath),
                () => _disconnectRequested));
        }
        catch (Exception ex)
        {
            result = new Services.EndpointSwitchResult(
                Services.EndpointSwitchOutcome.Failed, ex.Message);
            Services.GuiLog.Error($"switch threw: {ex.Message}");
        }
        finally
        {
            _busy = false;
            OnPropertyChanged(nameof(ConnectLabel));
            RaiseBusyChanged();
        }

        if (result.Error is not null)
        {
            LastError = result.Error;
        }

        OnTunnelChanged();
        if (result.Outcome == Services.EndpointSwitchOutcome.Reconnected)
        {
            await RefreshEgressAsync();
        }
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
            _config = cfg;
            _loading = true;
            try
            {
                _book.Load(cfg.Client.Endpoints, cfg.Client.ActiveEndpoint);
                SelectedEndpoint = _book.Active;
            }
            finally
            {
                _loading = false;
            }

            DnsMode = cfg.FullTunnel.DnsMode;
            FullTunnel = cfg.FullTunnel.Enabled;
            RaiseBookChanged();
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
            _config.Client.Endpoints = _book.Items.ToList();
            _config.Client.ActiveEndpoint = SelectedEndpoint?.Name ?? "";
            _config.FullTunnel.Enabled = FullTunnel;
            _config.FullTunnel.DnsMode = DnsMode;
            _config.Routing.Rules = Rules.ToList();
            Services.ConfigService.Save(ConfigPath, _config);
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
        // Persist the latest profile edits even when the user never connected.
        SaveConfig();
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
