// Autostart via HKCU Run key (per-user, no admin needed for the key
// itself; the app still elevates at startup through its manifest).

using Microsoft.Win32;

namespace AetherLink.Gui.Services;

internal static class AutostartService
{
    private const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "AetherLink";

    private static string ExePath
        => System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
            ?? Path.Combine(AppContext.BaseDirectory, "AetherLink.Gui.exe");

    public static bool IsEnabled
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, false);
            return key?.GetValue(ValueName) is string;
        }
    }

    public static void SetEnabled(bool enabled)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey, true)
            ?? throw new InvalidOperationException("Cannot open Run key for writing.");
        if (enabled)
        {
            key.SetValue(ValueName, $"\"{ExePath}\" --minimized");
        }
        else
        {
            key.DeleteValue(ValueName, false);
        }
    }
}
