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
    // Free-form rule document row; the core validates on load.
    // Common shape: {action, domain} | {action, cidr} — kept generic.
    [YamlMember(Alias = "action")]
    public string Action { get; set; } = "direct";

    [YamlMember(Alias = "domain")]
    public string? Domain { get; set; }

    [YamlMember(Alias = "cidr")]
    public string? Cidr { get; set; }

    public string Display => string.IsNullOrEmpty(Domain) ? (Cidr ?? "?") : Domain;
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
