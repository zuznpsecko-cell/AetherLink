// Tunnel lifecycle for the GUI: owns the core handle, runs up/down off
// the UI thread, polls status while up. UI binds to IsUp/StatusText/LastError.

using System.Text.Json;

namespace AetherLink.Gui.Services;

internal sealed class TunnelService : IDisposable
{
    private nuint _handle;
    private CancellationTokenSource? _pollCts;
    private Task? _pollTask;

    public bool IsUp { get; private set; }
    public string StatusText { get; private set; } = "Down";
    public string LastError { get; private set; } = "";
    public string ServerLabel { get; private set; } = "";

    public event Action? Changed;

    public void Up(string configJson, string serverLabel)
    {
        if (IsUp)
        {
            return;
        }

        LastError = "";
        var handle = Native.aether_client_create(configJson);
        if (handle == nuint.Zero)
        {
            Fail(Native.LastError());
            return;
        }

        _handle = handle;
        if (Native.aether_client_up(_handle) != 0)
        {
            var err = Native.LastError();
            _ = Native.aether_client_down(_handle);
            _handle = nuint.Zero;
            Fail($"{err} (routes/DNS rolled back by core).");
            return;
        }

        IsUp = true;
        ServerLabel = serverLabel;
        StatusText = "Up";
        StartPolling();
        Changed?.Invoke();
    }

    public void Down()
    {
        StopPolling();
        if (_handle != nuint.Zero)
        {
            _ = Native.aether_client_down(_handle);
            _handle = nuint.Zero;
        }

        IsUp = false;
        StatusText = "Down";
        Changed?.Invoke();
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

    private void StartPolling()
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
                    if (token.IsCancellationRequested || _handle == nuint.Zero)
                    {
                        break;
                    }

                    var buf = new byte[4096];
                    if (Native.aether_client_status(_handle, buf, (nuint)buf.Length) == 0)
                    {
                        var end = Array.IndexOf(buf, (byte)0);
                        var json = System.Text.Encoding.UTF8.GetString(buf, 0, end < 0 ? buf.Length : end);
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
        LastError = err;
        StatusText = "Failed";
        Changed?.Invoke();
    }

    public void Dispose() => Down();
}
