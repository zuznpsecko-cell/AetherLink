// Tunnel lifecycle for the GUI: owns the core handle, runs up/down off
// the UI thread, polls status while up. UI binds to IsUp/StatusText/LastError.
//
// Threading: Up/Down/ForceCleanup run on worker threads and are serialized by
// _opGate. The poll thread never takes that gate (Down waits for the poll to
// stop while holding it), so it only reads the handle it was started with.
// Changed is raised from any thread; subscribers must marshal to the UI thread.

using System.Text.Json;

namespace AetherLink.Gui.Services;

internal sealed class TunnelService : IDisposable
{
    // Held across native calls on purpose: a second Connect, or a Disconnect
    // racing an Up, must wait instead of interleaving. The core keeps a single
    // state file, so two live tunnels in one process corrupt each other's
    // route/DNS snapshot.
    private readonly object _opGate = new();

    private nuint _handle;
    private CancellationTokenSource? _pollCts;
    private Task? _pollTask;

    public bool IsUp { get; private set; }

    /// <summary>
    /// Set when the core reports the tunnel as up but its pump has stopped.
    /// Routes and DNS still point into the dead TUN, so the host must tear it
    /// down (the UI does this) instead of showing "Up".
    /// </summary>
    public bool PumpDead { get; private set; }

    public string StatusText { get; private set; } = "Down";
    public string LastError { get; private set; } = "";
    public string ServerLabel { get; private set; } = "";

    public event Action? Changed;

    /// <summary>Bring the tunnel up. Returns true when it is up afterwards.</summary>
    public bool Up(string configJson, string serverLabel)
    {
        lock (_opGate)
        {
            if (IsUp)
            {
                return true;
            }

            GuiLog.Info($"up requested ({serverLabel})");
            LastError = "";
            PumpDead = false;
            var handle = Native.aether_client_create(configJson);
            if (handle == nuint.Zero)
            {
                Fail(Native.LastError());
                GuiLog.Error($"create failed: {LastError}");
                return false;
            }

            if (Native.aether_client_up(handle) != 0)
            {
                var err = Native.LastError();
                // Core already rolls routes/DNS back on failure; the down call
                // only releases whatever a half-finished attempt left behind.
                _ = Native.aether_client_down(handle);
                Fail($"{err} (routes/DNS rolled back by core).");
                return false;
            }

            _handle = handle;
            IsUp = true;
            ServerLabel = serverLabel;
            StatusText = "Up";
            GuiLog.Info($"tunnel up ({serverLabel})");
            StartPolling(handle);
        }

        Changed?.Invoke();
        return true;
    }

    /// <summary>Tear the tunnel down and restore routes/DNS. Idempotent.</summary>
    public void Down()
    {
        lock (_opGate)
        {
            GuiLog.Info("tunnel down requested");
            StopPolling();
            var handle = _handle;
            _handle = nuint.Zero;
            if (handle != nuint.Zero && Native.aether_client_down(handle) != 0)
            {
                GuiLog.Error($"down reported: {Native.LastError()}");
            }

            IsUp = false;
            PumpDead = false;
            StatusText = "Down";
        }

        Changed?.Invoke();
    }

    /// <summary>
    /// Replay the persisted state file (routes, DNS, adapter) after a crash,
    /// kill or power loss left the machine without connectivity. Refused while
    /// this process holds a live tunnel. Returns null on success.
    /// </summary>
    public string? ForceCleanup()
    {
        lock (_opGate)
        {
            if (IsUp)
            {
                return "tunnel is up in this app: disconnect first";
            }

            var rc = Native.aether_client_force_cleanup();
            if (rc == 0)
            {
                GuiLog.Info("force cleanup ok (network restored from state file)");
                return null;
            }

            var err = Native.LastError();
            GuiLog.Error($"force cleanup failed: {err}");
            return err;
        }
    }

    public static string SummarizeStatus(string statusJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(statusJson);
            var root = doc.RootElement;
            var up = root.TryGetProperty("up", out var u) && u.GetBoolean();
            var server = root.TryGetProperty("server", out var s) ? s.GetString() : "?";
            return up ? $"Up ({server})" : "Down";
        }
        catch
        {
            return statusJson;
        }
    }

    /// <summary>
    /// The core's "pump_alive" flag, or null when the core predates it
    /// (treated as unknown, never as dead).
    /// </summary>
    private static bool? ReadPumpAlive(string statusJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(statusJson);
            if (doc.RootElement.TryGetProperty("pump_alive", out var p)
                && (p.ValueKind == JsonValueKind.True || p.ValueKind == JsonValueKind.False))
            {
                return p.GetBoolean();
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private void StartPolling(nuint handle)
    {
        StopPolling();
        _pollCts = new CancellationTokenSource();
        var token = _pollCts.Token;
        _pollTask = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), token).ConfigureAwait(false);
                    if (token.IsCancellationRequested)
                    {
                        break;
                    }

                    var buf = new byte[4096];
                    if (Native.aether_client_status(handle, buf, (nuint)buf.Length) == 0)
                    {
                        var end = Array.IndexOf(buf, (byte)0);
                        var json = System.Text.Encoding.UTF8.GetString(buf, 0, end < 0 ? buf.Length : end);
                        if (ReadPumpAlive(json) == false)
                        {
                            // Stop polling: the UI takes it from here (teardown).
                            PumpDead = true;
                            StatusText = "Lost";
                            GuiLog.Error("tunnel lost: pump stopped (link to server died)");
                            Changed?.Invoke();
                            break;
                        }

                        StatusText = SummarizeStatus(json);
                        Changed?.Invoke();
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    // Polling is best-effort; up/down state is authoritative.
                }
            }
        }, token);
    }

    private void StopPolling()
    {
        try
        {
            _pollCts?.Cancel();
            _pollTask?.Wait(TimeSpan.FromSeconds(3));
        }
        catch
        {
        }
        finally
        {
            _pollTask = null;
            _pollCts?.Dispose();
            _pollCts = null;
        }
    }

    private void Fail(string err)
    {
        IsUp = false;
        PumpDead = false;
        LastError = err;
        StatusText = "Failed";
        GuiLog.Error($"tunnel failed: {err}");
        Changed?.Invoke();
    }

    public void Dispose() => Down();
}
