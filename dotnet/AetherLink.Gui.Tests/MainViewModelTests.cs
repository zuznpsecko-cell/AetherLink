using AetherLink.Gui.Models;
using AetherLink.Gui.Services;
using AetherLink.Gui.ViewModels;
using Xunit;

namespace AetherLink.Gui.Tests;

public sealed class MainViewModelTests : IDisposable
{
    private const string TwoEndpoints = """
        client:
          active_endpoint: home
          endpoints:
            - name: home
              server_addr: home.example.com:443
              outer_sni: home.example.com
              psk: psk-home
            - name: backup
              server_addr: backup.example.com:8443
              outer_sni: backup.example.com
              psk: psk-backup
          server_addr: home.example.com:443
          outer_sni: home.example.com
          psk: psk-home
        full_tunnel:
          enabled: true
        routing:
          rules: []
        """;

    private readonly string _dir = Path.Combine(
        Path.GetTempPath(), "aetherlink-gui-vm-tests", Guid.NewGuid().ToString("N"));

    private readonly string _path;
    private readonly FakeTunnelController _tunnel = new();

    public MainViewModelTests()
    {
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "client.yaml");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch
        {
        }
    }

    private MainViewModel Create(string? yaml = null)
    {
        if (yaml is not null)
        {
            File.WriteAllText(_path, yaml);
        }

        return new MainViewModel(
            _tunnel,
            _path,
            uiPost: action => action(),
            egress: () => Task.FromResult("203.0.113.9"));
    }

    private static void Fill(EndpointProfile endpoint, string name, string addr, string psk = "psk")
    {
        endpoint.Name = name;
        endpoint.ServerAddr = addr;
        endpoint.OuterSni = "sni.example.com";
        endpoint.Psk = psk;
    }

    [Fact]
    public void AddEndpoint_AddsAndSelects()
    {
        var vm = Create();

        vm.AddEndpointCommand.Execute(null);

        var only = Assert.Single(vm.Endpoints);
        Assert.Same(only, vm.SelectedEndpoint);
        Assert.True(vm.HasSelection);
    }

    [Fact]
    public void Connect_UsesSelectedEndpoint_AndSavesMirror()
    {
        var vm = Create();
        vm.AddEndpointCommand.Execute(null);
        Fill(vm.SelectedEndpoint!, "home", "home.example.com:443", "psk-home");

        vm.ConnectDisconnectCommand.ExecuteAsync(null).GetAwaiter().GetResult();

        var call = Assert.Single(_tunnel.Calls);
        Assert.StartsWith("up:home:", call);
        var raw = call["up:home:".Length..];
        Assert.Contains("active_endpoint: home", raw);
        Assert.Contains("server_addr: home.example.com:443", raw);
        Assert.Contains("psk: psk-home", raw);

        var saved = ConfigService.Load(_path);
        var endpoint = Assert.Single(saved.Client.Endpoints);
        Assert.Equal("home", endpoint.Name);
        Assert.Equal("home.example.com:443", saved.Client.ServerAddr);
        Assert.Equal("home", saved.Client.ActiveEndpoint);
        Assert.True(vm.IsUp);
        Assert.Equal("Up (home)", vm.StatusText);
    }

    [Fact]
    public void Connect_WithInvalidEndpoint_DoesNotCallNative()
    {
        var vm = Create();
        vm.AddEndpointCommand.Execute(null);
        Fill(vm.SelectedEndpoint!, "home", "not-an-address");
        _tunnel.Calls.Clear();

        vm.ConnectDisconnectCommand.ExecuteAsync(null).GetAwaiter().GetResult();

        Assert.Empty(_tunnel.Calls);
        Assert.Contains("server address must be host:port", vm.LastError);
    }

    [Fact]
    public void Connect_WithNoEndpoints_DoesNotCallNative()
    {
        var vm = Create();

        vm.ConnectDisconnectCommand.ExecuteAsync(null).GetAwaiter().GetResult();

        Assert.Empty(_tunnel.Calls);
        Assert.Contains("add at least one endpoint", vm.LastError);
    }

    [Fact]
    public void Switch_WhenUp_ReconnectsWithSelectedProfile()
    {
        var vm = Create(TwoEndpoints);
        vm.ConnectDisconnectCommand.ExecuteAsync(null).GetAwaiter().GetResult();
        Assert.True(vm.IsUp);

        vm.SelectedEndpoint = vm.Endpoints[1];
        vm.SwitchCompletion.GetAwaiter().GetResult();

        Assert.Equal(3, _tunnel.Calls.Count);
        Assert.Equal("down", _tunnel.Calls[1]);
        Assert.StartsWith("up:backup:", _tunnel.Calls[2]);
        Assert.True(vm.IsUp);
        Assert.Equal("Up (backup)", vm.StatusText);
        Assert.Contains("active_endpoint: backup", File.ReadAllText(_path));
    }

    [Fact]
    public void Switch_WhenDown_OnlySelectsAndSaves()
    {
        var vm = Create(TwoEndpoints);

        vm.SelectedEndpoint = vm.Endpoints[1];
        vm.SwitchCompletion.GetAwaiter().GetResult();

        Assert.Empty(_tunnel.Calls);
        Assert.Contains("active_endpoint: backup", File.ReadAllText(_path));
    }

    [Fact]
    public void DeleteEndpoint_RemovesSelected_AndKeepsLast()
    {
        var vm = Create(TwoEndpoints);

        vm.DeleteEndpointCommand.Execute(null);

        var remaining = Assert.Single(vm.Endpoints);
        Assert.Equal("backup", remaining.Name);
        Assert.Same(remaining, vm.SelectedEndpoint);
        Assert.False(vm.CanDeleteEndpoint);

        vm.DeleteEndpointCommand.Execute(null);
        Assert.Single(vm.Endpoints);
    }

    [Fact]
    public void LoadConfig_MigratesLegacySingleServer()
    {
        var vm = Create("""
            client:
              server_addr: legacy.example.com:443
              outer_sni: legacy.example.com
              psk: legacy-psk
            """);

        var only = Assert.Single(vm.Endpoints);
        Assert.Equal("default", only.Name);
        Assert.Same(only, vm.SelectedEndpoint);
    }
}
