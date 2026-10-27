using AetherLink.Gui.Services;

namespace AetherLink.Gui.Tests;

/// <summary>Test double for the native tunnel: records calls, no P/Invoke.</summary>
internal sealed class FakeTunnelController : ITunnelController
{
    public List<string> Calls { get; } = new();

    public bool IsUp { get; set; }
    public bool PumpDead { get; set; }
    public bool StaleState { get; set; }
    public string StatusText { get; set; } = "Down";
    public string LastError { get; set; } = "";
    public string ServerLabel { get; set; } = "";

    public bool UpResult { get; set; } = true;

    public event Action? Changed;

    public bool Up(string configRaw, string serverLabel)
    {
        Calls.Add($"up:{serverLabel}:{configRaw}");
        if (UpResult)
        {
            IsUp = true;
            ServerLabel = serverLabel;
            StatusText = "Up";
            LastError = "";
        }
        else
        {
            IsUp = false;
            StatusText = "Failed";
            LastError = "connect failed";
        }

        Changed?.Invoke();
        return UpResult;
    }

    public void Down()
    {
        Calls.Add("down");
        IsUp = false;
        PumpDead = false;
        StatusText = "Down";
        Changed?.Invoke();
    }

    public string? ForceCleanup()
    {
        Calls.Add("cleanup");
        return null;
    }
}
