namespace AetherLink.Gui.Services;

/// <summary>
/// Tunnel lifecycle as the UI needs it. Extracted so endpoint switching and
/// the view model can be tested without P/Invoke into aetherlink_core.
/// </summary>
public interface ITunnelController
{
    bool IsUp { get; }
    bool PumpDead { get; }
    bool StaleState { get; }
    string StatusText { get; }
    string LastError { get; }
    string ServerLabel { get; }

    event Action? Changed;

    /// <summary>Bring the tunnel up. Returns true when it is up afterwards.</summary>
    bool Up(string configRaw, string serverLabel);

    /// <summary>Tear the tunnel down and restore routes/DNS. Idempotent.</summary>
    void Down();

    /// <summary>Replay a persisted state file after a crash. Null on success.</summary>
    string? ForceCleanup();
}
