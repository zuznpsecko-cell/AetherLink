// Egress proof: which IP the world sees (must equal the VPS when up).

namespace AetherLink.Gui.Services;

internal static class EgressService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    public static async Task<string> GetEgressIpAsync(CancellationToken token = default)
    {
        try
        {
            var ip = (await Http.GetStringAsync("https://ifconfig.me", token).ConfigureAwait(false)).Trim();
            // ifconfig.me answers plain IP text; anything else (HTML error
            // page when rate-limited, captive portal) is not an address.
            if (System.Net.IPAddress.TryParse(ip, out _))
            {
                return ip;
            }

            return "unavailable (unexpected reply — rate-limited?)";
        }
        catch (Exception ex)
        {
            return $"error: {ex.GetType().Name}";
        }
    }
}

// SYNTAX_BREAK_TEST_12345

