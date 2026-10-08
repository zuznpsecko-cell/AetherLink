// Config file handling: explicit mapping between YAML documents and the
// UI model (nested `when:` needs manual translation; attributes alone
// cannot express the one-of shape). The core re-validates on Up().

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace AetherLink.Gui.Services;

internal static class ConfigService
{
    public static string ResolvePath(string? overridePath = null)
    {
        if (!string.IsNullOrEmpty(overridePath) && File.Exists(overridePath))
        {
            return Path.GetFullPath(overridePath);
        }

        var exeDir = AppContext.BaseDirectory;
        foreach (var name in new[] { "client.local.yaml", "client.yaml" })
        {
            var p = Path.Combine(exeDir, name);
            if (File.Exists(p))
            {
                return p;
            }
        }

        return Path.Combine(exeDir, "client.local.yaml");
    }

    private static IDictionary<object, object?> AsMap(object? node)
        => node as IDictionary<object, object?> ?? new Dictionary<object, object?>();

    private static string Str(object? v) => v?.ToString() ?? "";

    public static Models.GuiClientConfig Load(string path)
    {
        var cfg = new Models.GuiClientConfig();
        if (!File.Exists(path))
        {
            return cfg;
        }

        var des = new DeserializerBuilder().Build();
        var root = AsMap(des.Deserialize<object>(File.ReadAllText(path)));
        if (root.TryGetValue("client", out var c))
        {
            var m = AsMap(c);
            if (m.TryGetValue("server_addr", out var v)) cfg.Client.ServerAddr = Str(v);
            if (m.TryGetValue("outer_sni", out v)) cfg.Client.OuterSni = Str(v);
            if (m.TryGetValue("psk", out v)) cfg.Client.Psk = Str(v);
            if (m.TryGetValue("pad_multiple", out v) && int.TryParse(Str(v), out var pm))
            {
                cfg.Client.PadMultiple = pm;
            }
            if (m.TryGetValue("keepalive_s", out v) && int.TryParse(Str(v), out var ka))
            {
                cfg.Client.KeepaliveS = ka;
            }
            if (m.TryGetValue("wintun_dll_path", out v) && Str(v).Length > 0)
            {
                cfg.Client.WintunDllPath = Str(v);
            }
        }

        if (root.TryGetValue("full_tunnel", out var f))
        {
            var m = AsMap(f);
            if (m.TryGetValue("enabled", out var v) && bool.TryParse(Str(v), out var en))
            {
                cfg.FullTunnel.Enabled = en;
            }
            if (m.TryGetValue("dns_mode", out v)) cfg.FullTunnel.DnsMode = Str(v);
            if (m.TryGetValue("mtu", out v) && int.TryParse(Str(v), out var mtu))
            {
                cfg.FullTunnel.Mtu = mtu;
            }
            if (m.TryGetValue("kill_switch", out v) && bool.TryParse(Str(v), out var ks))
            {
                cfg.FullTunnel.KillSwitch = ks;
            }
            if (m.TryGetValue("restore_on_exit", out v) && bool.TryParse(Str(v), out var ro))
            {
                cfg.FullTunnel.RestoreOnExit = ro;
            }
            if (m.TryGetValue("include_private_lan_direct", out v) && bool.TryParse(Str(v), out var lan))
            {
                cfg.FullTunnel.IncludePrivateLanDirect = lan;
            }
        }

        if (root.TryGetValue("routing", out var r))
        {
            var m = AsMap(r);
            if (m.TryGetValue("default_action", out var v)) cfg.Routing.DefaultAction = Str(v);
            if (m.TryGetValue("rules", out var rs) && rs is IEnumerable<object> list)
            {
                foreach (var item in list)
                {
                    cfg.Routing.Rules.Add(Models.RouteRule.FromMapping(AsMap(item)));
                }
            }
        }

        return cfg;
    }

    public static void Save(string path, Models.GuiClientConfig cfg)
    {
        var rules = new List<object>();
        foreach (var r in cfg.Routing.Rules)
        {
            rules.Add(r.ToMapping());
        }

        var root = new Dictionary<string, object>
        {
            ["client"] = new Dictionary<string, object>
            {
                ["server_addr"] = cfg.Client.ServerAddr,
                ["outer_sni"] = cfg.Client.OuterSni,
                ["psk"] = cfg.Client.Psk,
                ["pad_multiple"] = cfg.Client.PadMultiple,
                ["keepalive_s"] = cfg.Client.KeepaliveS,
                ["wintun_dll_path"] = cfg.Client.WintunDllPath,
            },
            ["full_tunnel"] = new Dictionary<string, object>
            {
                ["enabled"] = cfg.FullTunnel.Enabled,
                ["mtu"] = cfg.FullTunnel.Mtu,
                ["dns_mode"] = cfg.FullTunnel.DnsMode,
                ["kill_switch"] = cfg.FullTunnel.KillSwitch,
                ["restore_on_exit"] = cfg.FullTunnel.RestoreOnExit,
                ["include_private_lan_direct"] = cfg.FullTunnel.IncludePrivateLanDirect,
            },
            ["routing"] = new Dictionary<string, object>
            {
                ["default_action"] = cfg.Routing.DefaultAction,
                ["rules"] = rules,
            },
        };
        var ser = new SerializerBuilder()
            .WithNamingConvention(NullNamingConvention.Instance)
            .Build();
        File.WriteAllText(path, ser.Serialize(root));
    }

    /// Raw text the core consumes (core parses YAML itself).
    public static string RawText(string path) => File.Exists(path) ? File.ReadAllText(path) : "";
}
