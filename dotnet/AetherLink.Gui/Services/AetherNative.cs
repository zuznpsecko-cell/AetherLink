// Thin FFI bridge to aetherlink_core (mirrors dotnet/AetherLink.Client).
// No protocol logic here: config + up/down/status only.

using System.Runtime.InteropServices;

namespace AetherLink.Gui.Services;

internal static partial class Native
{
    private const string Lib = "aetherlink_core";

    /// <summary>
    /// Core error code for "a leftover state file blocks bring-up"
    /// (previous run died without teardown). The GUI auto-recovers:
    /// force_cleanup + one retry.
    /// </summary>
    internal const int StaleStateCode = -11;

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nuint aether_client_create(string configJson);

    [LibraryImport(Lib)]
    internal static partial int aether_client_up(nuint handle);

    [LibraryImport(Lib)]
    internal static partial int aether_client_down(nuint handle);

    /// <summary>
    /// Release a client handle (best-effort down + drop from the core's
    /// handle map). Called after down and after a failed up so repeated
    /// connects do not accumulate clients.
    /// </summary>
    [LibraryImport(Lib)]
    internal static partial int aether_client_free(nuint handle);

    [LibraryImport(Lib)]
    internal static partial int aether_client_status(nuint handle, byte[] outJson, nuint outLen);

    [LibraryImport(Lib)]
    internal static partial int aether_client_force_cleanup();

    // The core returns a pointer into its thread-local error buffer: valid
    // until the next FFI call on this thread, owned by the core — copy the
    // text, never free the pointer. (Marshalling it as `string` would make
    // the runtime free Rust-allocated memory with CoTaskMemFree.)
    [LibraryImport(Lib)]
    internal static partial IntPtr aether_last_error();

    internal static string LastError()
        => Marshal.PtrToStringUTF8(aether_last_error()) ?? "unknown core error";
}
