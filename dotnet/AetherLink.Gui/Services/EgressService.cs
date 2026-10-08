// Egress proof: which IP the world sees (must equal the VPS when up).

namespace AetherLink.Gui.Services;

internal static class EgressService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };

    public static async Task<string> GetEgressIpAsync(CancellationToken token = default)
    {
        try
        {
            var ip = await Http.GetStringAsync("https://ifconfig.me", token).ConfigureAwait(false);
            return ip.Trim();
        }
        catch (Exception ex)
        {
            return $"error: {ex.GetType().Name}";
        }
    }
}
