using AetherLink.Gui.Models;
using AetherLink.Gui.Services;
using Xunit;

namespace AetherLink.Gui.Tests;

public sealed class ConfigServiceTests : IDisposable
{
    private readonly string _dir = Path.Combine(
        Path.GetTempPath(), "aetherlink-gui-tests", Guid.NewGuid().ToString("N"));

    public ConfigServiceTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch
        {
            // Best effort: a leaked temp dir must not fail the test.
        }
    }

    private string Write(string yaml)
    {
        var path = Path.Combine(_dir, "client.yaml");
        File.WriteAllText(path, yaml);
        return path;
    }

    private static EndpointProfile Endpoint(
        string name, string addr, string sni = "", string psk = "psk")
        => new() { Name = name, ServerAddr = addr, OuterSni = sni, Psk = psk };

    [Fact]
    public void Load_ReadsEndpointsAndActive()
    {
        var path = Write("""
            client:
              active_endpoint: backup
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
            """);

        var cfg = ConfigService.Load(path);

        Assert.Equal(2, cfg.Client.Endpoints.Count);
        Assert.Equal("backup", cfg.Client.ActiveEndpoint);
        Assert.Equal("home", cfg.Client.Endpoints[0].Name);
        Assert.Equal("backup.example.com:8443", cfg.Client.Endpoints[1].ServerAddr);
        Assert.Equal("backup.example.com", cfg.Client.Endpoints[1].OuterSni);
        Assert.Equal("psk-backup", cfg.Client.Endpoints[1].Psk);
    }

    [Fact]
    public void Load_LegacySingleServer_CreatesDefaultProfile()
    {
        var path = Write("""
            client:
              server_addr: legacy.example.com:443
              outer_sni: legacy.example.com
              psk: legacy-psk
            """);

        var cfg = ConfigService.Load(path);

        var only = Assert.Single(cfg.Client.Endpoints);
        Assert.Equal("default", only.Name);
        Assert.Equal("legacy.example.com:443", only.ServerAddr);
        Assert.Equal("legacy.example.com", only.OuterSni);
        Assert.Equal("legacy-psk", only.Psk);
        Assert.Equal("default", cfg.Client.ActiveEndpoint);
    }

    [Fact]
    public void Load_EmptyEndpointList_FallsBackToMirror()
    {
        var path = Write("""
            client:
              active_endpoint: ""
              endpoints: []
              server_addr: legacy.example.com:443
              outer_sni: legacy.example.com
              psk: legacy-psk
            """);

        var cfg = ConfigService.Load(path);

        var only = Assert.Single(cfg.Client.Endpoints);
        Assert.Equal("default", only.Name);
        Assert.Equal("default", cfg.Client.ActiveEndpoint);
    }

    [Fact]
    public void Load_UnknownActive_UsesFirstProfile()
    {
        var path = Write("""
            client:
              active_endpoint: missing
              endpoints:
                - name: home
                  server_addr: home.example.com:443
                  psk: psk-home
                - name: backup
                  server_addr: backup.example.com:443
                  psk: psk-backup
            """);

        var cfg = ConfigService.Load(path);

        Assert.Equal("home", cfg.Client.ActiveEndpoint);
    }

    [Fact]
    public void Load_EndpointsWinOverMirror()
    {
        var path = Write("""
            client:
              active_endpoint: home
              endpoints:
                - name: home
                  server_addr: home.example.com:443
                  outer_sni: home-sni.example.com
                  psk: psk-home
              server_addr: stale.example.com:443
              outer_sni: stale.example.com
              psk: stale-psk
            """);

        var cfg = ConfigService.Load(path);

        var only = Assert.Single(cfg.Client.Endpoints);
        Assert.Equal("home.example.com:443", only.ServerAddr);
        Assert.Equal("home-sni.example.com", only.OuterSni);
        Assert.Equal("psk-home", only.Psk);
        Assert.Equal("home", cfg.Client.ActiveEndpoint);
    }

    [Fact]
    public void Save_WritesEndpointsActiveAndLegacyMirror()
    {
        var cfg = new GuiClientConfig();
        cfg.Client.Endpoints = new List<EndpointProfile>
        {
            Endpoint("home", "home.example.com:443", "home.example.com", "psk-home"),
            Endpoint("backup", "backup.example.com:8443", "", "psk-backup"),
        };
        cfg.Client.ActiveEndpoint = "backup";
        cfg.Client.PadMultiple = 64;
        cfg.Client.KeepaliveS = 20;
        cfg.Client.WintunDllPath = "./custom.dll";
        cfg.FullTunnel.Mtu = 1300;
        cfg.FullTunnel.DnsMode = "tunnel";
        var path = Path.Combine(_dir, "saved.yaml");

        ConfigService.Save(path, cfg);
        var raw = File.ReadAllText(path);
        var reloaded = ConfigService.Load(path);

        Assert.Contains("endpoints:", raw);
        Assert.Contains("active_endpoint: backup", raw);
        Assert.Equal(2, reloaded.Client.Endpoints.Count);
        Assert.Equal("backup", reloaded.Client.ActiveEndpoint);
        Assert.Equal("backup.example.com:8443", reloaded.Client.ServerAddr);
        // Empty SNI is mirrored as the host so core reads a usable SNI.
        Assert.Equal("backup.example.com", reloaded.Client.OuterSni);
        Assert.Equal("psk-backup", reloaded.Client.Psk);
        Assert.Equal(64, reloaded.Client.PadMultiple);
        Assert.Equal(20, reloaded.Client.KeepaliveS);
        Assert.Equal("./custom.dll", reloaded.Client.WintunDllPath);
        Assert.Equal(1300, reloaded.FullTunnel.Mtu);
    }

    [Fact]
    public void Save_KeepsSharedRoutingSettings()
    {
        var cfg = new GuiClientConfig();
        cfg.Client.Endpoints = new List<EndpointProfile>
        {
            Endpoint("home", "home.example.com:443", psk: "psk-home"),
        };
        cfg.Client.ActiveEndpoint = "home";
        cfg.Routing.Rules.Add(new RouteRule
        {
            Name = "lan",
            Action = "direct",
            WhenKind = "cidr",
            WhenValue = "192.168.0.0/16",
        });
        var path = Path.Combine(_dir, "routing.yaml");

        ConfigService.Save(path, cfg);
        var reloaded = ConfigService.Load(path);

        var rule = Assert.Single(reloaded.Routing.Rules);
        Assert.Equal("lan", rule.Name);
        Assert.Equal("direct", rule.Action);
        Assert.Equal("cidr", rule.WhenKind);
        Assert.Equal("192.168.0.0/16", rule.WhenValue);
    }

    [Fact]
    public void Save_WithoutEndpoints_WritesEmptyMirror()
    {
        var cfg = new GuiClientConfig();
        var path = Path.Combine(_dir, "empty.yaml");

        ConfigService.Save(path, cfg);
        var reloaded = ConfigService.Load(path);

        Assert.Empty(reloaded.Client.Endpoints);
        Assert.Equal("", reloaded.Client.ServerAddr);
        Assert.Equal("", reloaded.Client.ActiveEndpoint);
    }
}
