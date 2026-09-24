// AetherLink Client host (.NET).
//
// THIN HOST: config + TUN/Wintun load path + FFI up/down into aetherlink_core.
// Packet capture (Wintun ring buffers / /dev/net/tun), netstack, crypto and
// mux live in Rust only (AGENT_INSTRUCTIONS §1.1).
// This file must never grow SslStream/AEAD/HMAC usage.
//
// Windows: keep wintun.dll next to the published exe; the core loads it from
// the host directory (client.wintun_dll_path in config).

using System.Runtime.InteropServices;
using System.Text;

internal static partial class Native
{
    private const string Lib = "aetherlink_core";

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nuint aether_client_create(string configJson);

    [LibraryImport(Lib)]
    internal static partial int aether_client_up(nuint handle);

    [LibraryImport(Lib)]
    internal static partial int aether_client_down(nuint handle);

    [LibraryImport(Lib)]
    internal static partial int aether_client_status(nuint handle, byte[] outJson, nuint outLen);

    [LibraryImport(Lib)]
    internal static partial int aether_client_force_cleanup();

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial string? aether_last_error();

    internal static string LastError()
        => aether_last_error() ?? "unknown core error";
}

internal sealed class AetherClient : IDisposable
{
    private nuint _handle;

    internal nuint Handle => _handle;

    public AetherClient(string configJson)
    {
        _handle = Native.aether_client_create(configJson);
        if (_handle == nuint.Zero)
        {
            throw new InvalidOperationException($"aether_client_create failed: {Native.LastError()}");
        }
    }

    public void Up()
    {
        if (Native.aether_client_up(_handle) != 0)
        {
            throw new InvalidOperationException($"aether_client_up failed: {Native.LastError()} (routes/DNS rolled back by core).");
        }
    }

    public string Status()
    {
        var buf = new byte[4096];
        if (Native.aether_client_status(_handle, buf, (nuint)buf.Length) != 0)
        {
            throw new InvalidOperationException($"aether_client_status failed: {Native.LastError()}");
        }

        var end = Array.IndexOf(buf, (byte)0);
        return Encoding.UTF8.GetString(buf, 0, end < 0 ? buf.Length : end);
    }

    public void Down()
    {
        if (_handle != nuint.Zero)
        {
            _ = Native.aether_client_down(_handle);
            _handle = nuint.Zero;
        }
    }

    public void Dispose()
    {
        Down();
    }
}

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length < 2)
        {
            return Usage();
        }

        var configJson = await File.ReadAllTextAsync(args[0]);
        switch (args[1])
        {
            case "up":
                using (var client = new AetherClient(configJson))
                {
                    client.Up();
                    Console.WriteLine("Tunnel up. Press Ctrl+C to bring it down (DNS/routes restored).");
                    using var done = new ManualResetEventSlim(false);
                    Console.CancelKeyPress += (_, e) => { e.Cancel = true; done.Set(); };
                    // Console close / logoff / shutdown: finally below may not
                    // run, so best-effort down here too (hard kill still
                    // relies on the UpState journal replay via down/cleanup).
                    void OnProcessExit(object? sender, EventArgs e)
                    {
                        try { client.Down(); } catch { }
                    }
                    AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
                    try
                    {
                        done.Wait();
                    }
                    finally
                    {
                        AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
                        Console.WriteLine("Bringing tunnel down, restoring network/DNS...");
                        try { client.Down(); } catch { }
                    }
                }

                return 0;
            case "cleanup":
                // Idempotent: restores routes+DNS from the persistent snapshot, even after a crash.
                return Native.aether_client_force_cleanup() == 0 ? 0 : 1;
            case "down":
                // Graceful teardown without Ctrl+C wrestling: replays the
                // state-file log through a fresh client, then reports.
                using (var downClient = new AetherClient(configJson))
                {
                    if (Native.aether_client_down(downClient.Handle) != 0)
                    {
                        Console.Error.WriteLine($"down failed: {Native.LastError()}");
                        return 1;
                    }
                }

                Console.WriteLine("Tunnel down, network/DNS restored.");
                return 0;
            case "status":
                // Prints the status JSON of a freshly created (down) client.
                using (var client = new AetherClient(configJson))
                {
                    Console.WriteLine(client.Status());
                    return 0;
                }
            default:
                return Usage();
        }
    }

    private static int Usage()
    {
        Console.Error.WriteLine("Usage: AetherLink.Client <config> <up|down|cleanup|status>");
        return 2;
    }
}
