using AetherLink.Gui.Models;

namespace AetherLink.Gui.Services;

public enum EndpointSwitchOutcome
{
    /// <summary>Tunnel was down: the selection changed, nothing was called.</summary>
    SelectedOnly,

    /// <summary>Tunnel was up and is up again on the new profile.</summary>
    Reconnected,

    /// <summary>Disconnect was requested while switching; the tunnel stays down.</summary>
    Cancelled,

    /// <summary>Reconnect failed; the tunnel is down and the network restored.</summary>
    Failed,
}

public sealed record EndpointSwitchResult(EndpointSwitchOutcome Outcome, string? Error = null);

/// <summary>
/// Switching profiles while the tunnel is up: Down -> rebuild config -> Up.
/// Kept free of UI types so the ordering is unit-tested with a fake tunnel.
/// </summary>
public sealed class EndpointSwitcher
{
    private readonly ITunnelController _tunnel;

    public EndpointSwitcher(ITunnelController tunnel)
    {
        _tunnel = tunnel;
    }

    public EndpointSwitchResult Switch(
        EndpointProfile target,
        Func<string> buildConfig,
        Func<bool> isCancelled)
        => throw new NotImplementedException();
}
