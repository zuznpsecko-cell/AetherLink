using AetherLink.Gui.Models;
using AetherLink.Gui.Services;
using Xunit;

namespace AetherLink.Gui.Tests;

public sealed class EndpointRulesTests
{
    private static EndpointProfile Profile(
        string name = "home",
        string addr = "server.example.com:443",
        string sni = "server.example.com",
        string psk = "secret")
        => new() { Name = name, ServerAddr = addr, OuterSni = sni, Psk = psk };

    [Fact]
    public void ValidProfile_IsAccepted()
    {
        var p = Profile();
        Assert.Null(EndpointRules.Validate(p, new[] { p }));
    }

    [Fact]
    public void EmptyName_IsRejected()
    {
        var p = Profile(name: "  ");
        Assert.Equal("endpoint name is empty", EndpointRules.Validate(p, new[] { p }));
    }

    [Fact]
    public void TooLongName_IsRejected()
    {
        var p = Profile(name: new string('x', 65));
        Assert.Equal($"endpoint name is too long (max {EndpointRules.MaxNameLength})",
            EndpointRules.Validate(p, new[] { p }));
    }

    [Fact]
    public void DuplicateName_IsRejectedCaseInsensitively()
    {
        var a = Profile(name: "Home");
        var b = Profile(name: "home");
        Assert.Equal("endpoint name 'home' is used twice", EndpointRules.Validate(b, new[] { a, b }));
    }

    [Theory]
    [InlineData("server.example.com")]
    [InlineData(":443")]
    [InlineData("server.example.com:0")]
    [InlineData("server.example.com:65536")]
    [InlineData("server.example.com:http")]
    public void BadServerAddress_IsRejected(string addr)
    {
        var p = Profile(addr: addr);
        Assert.Equal("endpoint 'home': server address must be host:port",
            EndpointRules.Validate(p, new[] { p }));
    }

    [Fact]
    public void EmptyPsk_IsRejected()
    {
        var p = Profile(psk: "   ");
        Assert.Equal("endpoint 'home': PSK is empty", EndpointRules.Validate(p, new[] { p }));
    }

    [Fact]
    public void EmptySni_IsAccepted_AndFallsBackToHost()
    {
        var p = Profile(addr: "10.0.0.5:8443", sni: "");
        Assert.Null(EndpointRules.Validate(p, new[] { p }));
        Assert.Equal("10.0.0.5", EndpointRules.EffectiveSni(p));
    }

    [Fact]
    public void ConfiguredSni_IsUsedAsIs()
    {
        var p = Profile(addr: "10.0.0.5:8443", sni: "selmedia.ru");
        Assert.Equal("selmedia.ru", EndpointRules.EffectiveSni(p));
    }

    [Fact]
    public void ValidateAll_RequiresAtLeastOneEndpoint()
    {
        Assert.Equal("add at least one endpoint", EndpointRules.ValidateAll(Array.Empty<EndpointProfile>()));
    }

    [Fact]
    public void ValidateAll_ReturnsFirstProblem()
    {
        var ok = Profile();
        var bad = Profile(name: "");
        Assert.Equal("endpoint name is empty", EndpointRules.ValidateAll(new[] { ok, bad }));
        Assert.Null(EndpointRules.ValidateAll(new[] { ok }));
    }
}
