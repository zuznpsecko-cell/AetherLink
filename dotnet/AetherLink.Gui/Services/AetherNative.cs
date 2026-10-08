// Thin FFI bridge to aetherlink_core (mirrors dotnet/AetherLink.Client).
// No protocol logic here: config + up/down/status only.

using System.Runtime.InteropServices;
using System.Text;

namespace AetherLink.Gui.Services;

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
