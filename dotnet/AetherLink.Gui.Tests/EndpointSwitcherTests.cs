using AetherLink.Gui.Models;
using AetherLink.Gui.Services;
using Xunit;

namespace AetherLink.Gui.Tests;

public sealed class EndpointSwitcherTests
{
    private static EndpointProfile Target(string name = "backup") => new()
    {
        Name = name,
        ServerAddr = "backup.example.com:443",
        OuterSni = "backup.example.com",
        Psk = "psk",
    };

    [Fact]
    public void Switch_WhenDown_OnlySelects()
    {
        var tunnel = new FakeTunnelController { IsUp = false };
        var built = 0;

        var result = new EndpointSwitcher(tunnel).Switch(
            Target(),
            () => { built++; return "config"; },
            () => false);

        Assert.Equal(EndpointSwitchOutcome.SelectedOnly, result.Outcome);
        Assert.Equal(0, built);
        Assert.Empty(tunnel.Calls);
    }

    [Fact]
    public void Switch_WhenUp_ReconnectsDownThenUp()
    {
        var tunnel = new FakeTunnelController { IsUp = true };
        var built = 0;

        var result = new EndpointSwitcher(tunnel).Switch(
            Target(),
            () => { built++; return "new-config"; },
            () => false);

        Assert.Equal(EndpointSwitchOutcome.Reconnected, result.Outcome);
        Assert.Equal(1, built);
        Assert.Equal(new[] { "down", "up:backup:new-config" }, tunnel.Calls);
        Assert.True(tunnel.IsUp);
        Assert.Equal("backup", tunnel.ServerLabel);
    }

    [Fact]
    public void Switch_UpFailure_LeavesTunnelDownAndReportsError()
    {
        var tunnel = new FakeTunnelController { IsUp = true, UpResult = false };

        var result = new EndpointSwitcher(tunnel).Switch(
            Target(),
            () => "new-config",
            () => false);

        Assert.Equal(EndpointSwitchOutcome.Failed, result.Outcome);
        Assert.Equal("connect failed", result.Error);
        Assert.False(tunnel.IsUp);
        Assert.Equal(new[] { "down", "up:backup:new-config" }, tunnel.Calls);
    }

    [Fact]
    public void Switch_CancelledAfterDown_DoesNotBuildOrReconnect()
    {
        var tunnel = new FakeTunnelController { IsUp = true };
        var built = 0;

        var result = new EndpointSwitcher(tunnel).Switch(
            Target(),
            () => { built++; return "new-config"; },
            () => true);

        Assert.Equal(EndpointSwitchOutcome.Cancelled, result.Outcome);
        Assert.Equal(0, built);
        Assert.Equal(new[] { "down" }, tunnel.Calls);
        Assert.False(tunnel.IsUp);
    }
}
