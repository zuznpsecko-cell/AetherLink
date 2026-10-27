using System.Globalization;
using AetherLink.Gui.Models;

namespace AetherLink.Gui.Services;

/// <summary>
/// Validation shared by the editor, Save and Connect. The core re-validates
/// the whole document on aether_client_create; this is the early, friendly
/// layer so the UI never sends an obviously broken profile to native code.
/// </summary>
public static class EndpointRules
{
    public const int MaxNameLength = 64;

    /// <summary>Null when valid, otherwise a user-facing message.</summary>
    public static string? Validate(EndpointProfile endpoint, IEnumerable<EndpointProfile> all)
    {
        var name = endpoint.Name.Trim();
        if (name.Length == 0)
        {
            return "endpoint name is empty";
        }

        if (name.Length > MaxNameLength)
        {
            return $"endpoint name is too long (max {MaxNameLength})";
        }

        if (!TryParseAddress(endpoint.ServerAddr, out _, out _))
        {
            return $"endpoint '{name}': server address must be host:port";
        }

        if (string.IsNullOrWhiteSpace(endpoint.Psk))
        {
            return $"endpoint '{name}': PSK is empty";
        }

        foreach (var other in all)
        {
            if (ReferenceEquals(other, endpoint))
            {
                continue;
            }

            if (string.Equals(other.Name.Trim(), name, StringComparison.OrdinalIgnoreCase))
            {
                return $"endpoint name '{name}' is used twice";
            }
        }

        return null;
    }

    /// <summary>Validates every profile and the "at least one" rule.</summary>
    public static string? ValidateAll(IEnumerable<EndpointProfile> endpoints)
    {
        var list = endpoints as IReadOnlyList<EndpointProfile> ?? endpoints.ToList();
        if (list.Count == 0)
        {
            return "add at least one endpoint";
        }

        foreach (var endpoint in list)
        {
            var error = Validate(endpoint, list);
            if (error is not null)
            {
                return error;
            }
        }

        return null;
    }

    /// <summary>SNI the core will use: the configured one, or the host.</summary>
    public static string EffectiveSni(EndpointProfile endpoint)
    {
        var sni = endpoint.OuterSni.Trim();
        if (sni.Length > 0)
        {
            return sni;
        }

        return TryParseAddress(endpoint.ServerAddr, out var host, out _) ? host : "";
    }

    private static bool TryParseAddress(string addr, out string host, out int port)
    {
        host = "";
        port = 0;
        var value = addr.Trim();
        var sep = value.LastIndexOf(':');
        if (sep <= 0 || sep == value.Length - 1)
        {
            return false;
        }

        host = value[..sep].Trim();
        if (host.Length == 0)
        {
            return false;
        }

        return int.TryParse(
                   value[(sep + 1)..].Trim(),
                   NumberStyles.None,
                   CultureInfo.InvariantCulture,
                   out port)
               && port is > 0 and <= 65535;
    }
}
