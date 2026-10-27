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
        => throw new NotImplementedException();

    /// <summary>Validates every profile and the "at least one" rule.</summary>
    public static string? ValidateAll(IEnumerable<EndpointProfile> endpoints)
        => throw new NotImplementedException();

    /// <summary>SNI the core will use: the configured one, or the host.</summary>
    public static string EffectiveSni(EndpointProfile endpoint)
        => throw new NotImplementedException();
}
