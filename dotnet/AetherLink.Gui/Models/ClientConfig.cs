// Typed subset of configs/client.example.yaml that the GUI edits.
// Unknown keys are dropped on save (documented v1 limitation); the core
// re-validates everything at Up() time.

using YamlDotNet.Serialization;

namespace AetherLink.Gui.Models;

public sealed class ClientSection
{
    [YamlMember(Alias = "server_addr")]
    public string ServerAddr { get; set; } = "";

    [YamlMember(Alias = "outer_sni")]
    public string OuterSni { get; set; } = "";

    [YamlMember(Alias = "psk")]
    public string Psk { get; set; } = "";

    [YamlMember(Alias = "pad_multiple")]
    public int PadMultiple { get; set; } = 128;
}

public sealed class FullTunnelSection
{
    [YamlMember(Alias = "enabled")]
    public bool Enabled { get; set; } = true;

    [YamlMember(Alias = "mtu")]
    public int Mtu { get; set; } = 1400;

    [YamlMember(Alias = "dns_mode")]
    public string DnsMode { get; set; } = "tunnel";
}

public sealed class RouteRule
{
    // Flat UI shape; serialized as {name, action, priority?, when:{kind: value}}
    // to match the core schema (Rule::from_doc).
    [YamlMember(Alias = "name")]
    public string Name { get; set; } = "";

    [YamlMember(Alias = "action")]
    public string Action { get; set; } = "direct";

    [YamlMember(Alias = "priority")]
    public int Priority { get; set; } = 50;

    [YamlIgnore]
    public string WhenKind { get; set; } = "domain";

    [YamlIgnore]
    public string WhenValue { get; set; } = "";

    public string Display => string.IsNullOrEmpty(WhenValue) ? Name : $"{WhenKind}:{WhenValue}";

    public Dictionary<string, object> ToMapping() => new()
    {
        ["name"] = Name,
        ["action"] = Action,
        ["priority"] = Priority,
        ["when"] = new Dictionary<string, object> { [WhenKind] = WhenValue },
    };

    public static RouteRule FromMapping(IDictionary<object, object?> map)
    {
        static string Str(object? v) => v?.ToString() ?? "";
        var r = new RouteRule();
        foreach (var kv in map)
        {
            var k = Str(kv.Key);
            if (k == "name") r.Name = Str(kv.Value);
            else if (k == "action") r.Action = Str(kv.Value);
            else if (k == "priority" && int.TryParse(Str(kv.Value), out var p)) r.Priority = p;
            else if (k == "when" && kv.Value is IDictionary<object, object?> w)
            {
                foreach (var ww in w)
                {
                    r.WhenKind = Str(ww.Key);
                    r.WhenValue = Str(ww.Value);
                    break;
                }
            }
        }
        return r;
    }
}

public sealed class RoutingSection
{
    [YamlMember(Alias = "default_action")]
    public string DefaultAction { get; set; } = "tunnel";

    [YamlMember(Alias = "rules")]
    public List<RouteRule> Rules { get; set; } = new();
}

public sealed class GuiClientConfig
{
    [YamlMember(Alias = "client")]
    public ClientSection Client { get; set; } = new();

    [YamlMember(Alias = "full_tunnel")]
    public FullTunnelSection FullTunnel { get; set; } = new();

    [YamlMember(Alias = "routing")]
    public RoutingSection Routing { get; set; } = new();
}
