// AetherLink Server host (.NET).
//
// THIN HOST: config + service wiring + FFI calls into aetherlink_core.
// The TLS data plane, AUTH, AEAD and mux live in Rust only (AGENT_INSTRUCTIONS §1.1).
// This file must never grow SslStream/AEAD/HMAC usage.

using System.Runtime.InteropServices;

internal static partial class Native
{
    private const string Lib = "aetherlink_core";

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nuint aether_server_start(string configJson);

    [LibraryImport(Lib)]
    internal static partial int aether_server_stop(nuint handle);

    // 1 = serving, 0 = the accept loop ended by itself (reason in
    // aether_last_error), negative = invalid handle.
    [LibraryImport(Lib)]
    internal static partial int aether_server_is_running(nuint handle);

    // The core returns a pointer into its thread-local error buffer: valid
    // until the next FFI call on this thread, owned by the core — copy the
    // text, never free the pointer. (Marshalling it as `string` would make
    // the runtime free Rust-allocated memory with CoTaskMemFree.)
    [LibraryImport(Lib)]
    internal static partial IntPtr aether_last_error();

    internal static string LastError()
        => Marshal.PtrToStringUTF8(aether_last_error()) ?? "unknown core error";
}

internal sealed class AetherServer : IDisposable
{
    private nuint _handle;

    public void Start(string configJson)
    {
        if (_handle != nuint.Zero)
        {
            throw new InvalidOperationException("Server already running.");
        }

        var handle = Native.aether_server_start(configJson);
        if (handle == nuint.Zero)
        {
            throw new InvalidOperationException($"aether_server_start failed: {Native.LastError()}");
        }

        _handle = handle;
    }

    /// <summary>
    /// False once the core's accept loop has stopped on its own (the listener
    /// failed); <paramref name="reason"/> then carries the core's error text.
    /// </summary>
    public bool IsServing(out string reason)
    {
        reason = string.Empty;
        if (_handle == nuint.Zero)
        {
            reason = "server not started";
            return false;
        }

        if (Native.aether_server_is_running(_handle) == 1)
        {
            return true;
        }

        reason = Native.LastError();
        return false;
    }

    public void Dispose()
    {
        if (_handle != nuint.Zero)
        {
            Native.aether_server_stop(_handle);
            _handle = nuint.Zero;
        }
    }
}

internal static class Program
{
    public static async Task Main(string[] args)
    {
        var configPath = args.Length > 0 ? args[0] : "server.yaml";
        var configJson = await File.ReadAllTextAsync(configPath);

        using var server = new AetherServer();
        server.Start(configJson);
        Console.WriteLine("AetherLink server running. Press Ctrl+C to stop.");

        using var done = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; done.Set(); };

        // Watch the core while waiting: if the listener dies, exit non-zero so
        // the supervisor (systemd Restart=on-failure, a Windows service
        // recovery action) restarts us. Idling here would leave a process that
        // looks healthy but accepts nothing.
        while (!done.Wait(TimeSpan.FromSeconds(1)))
        {
            if (!server.IsServing(out var reason))
            {
                Console.Error.WriteLine($"AetherLink server stopped: {reason}");
                Environment.ExitCode = 1;
                return;
            }
        }
    }
}
