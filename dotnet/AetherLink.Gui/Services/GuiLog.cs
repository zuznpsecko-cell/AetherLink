// GUI file logging (Serilog): app events, tunnel lifecycle, errors.
// Log file lives next to the exe: logs/gui-<date>.log. The Logs tab tails it.

using Serilog;

namespace AetherLink.Gui.Services;

internal static class GuiLog
{
    private static bool _ready;
    private static string _path = "";

    public static string CurrentPath => _path;

    public static void Init()
    {
        if (_ready)
        {
            return;
        }

        try
        {
            var dir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(dir);
            _path = Path.Combine(dir, $"gui-{DateTime.Now:yyyy-MM-dd}.log");
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.File(
                    _path,
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 7,
                    outputTemplate: "{Timestamp:HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
                .CreateLogger();
            _ready = true;
            Info("GUI started");
            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
                Fatal($"unhandled: {e.ExceptionObject}");
        }
        catch
        {
            // Logging must never break the app.
        }
    }

    public static void Debug(string msg)
    {
        try { Log.Debug(msg); } catch { }
    }

    public static void Info(string msg)
    {
        try { Log.Information(msg); } catch { }
    }

    public static void Warn(string msg)
    {
        try { Log.Warning(msg); } catch { }
    }

    public static void Error(string msg)
    {
        try { Log.Error(msg); } catch { }
    }

    public static void Fatal(string msg)
    {
        try { Log.Fatal(msg); } catch { }
    }

    public static void Close()
    {
        try { Log.CloseAndFlush(); } catch { }
    }
}
