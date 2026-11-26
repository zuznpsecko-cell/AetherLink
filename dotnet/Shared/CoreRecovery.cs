// Shared by the .NET hosts (compiled into AetherLink.Gui and AetherLink.Client
// via <Compile Link>): what to do with the core's FFI result codes. Pure
// policy, no P/Invoke, so the GUI test project can cover it without the
// native library.

namespace AetherLink.Interop;

/// <summary>
/// Core FFI result codes the hosts act on (crates/aetherlink-ffi; DEC-024).
/// Everything else is a plain failure with text in aether_last_error.
/// </summary>
internal static class CoreCodes
{
    internal const int Success = 0;

    /// <summary>A leftover state file (a run that died without teardown) blocks up.</summary>
    internal const int StaleState = -11;

    /// <summary>Another call on the same handle is in flight; nothing happened.</summary>
    internal const int Busy = -12;
}

/// <summary>What a host does after `up` returned a code.</summary>
internal enum UpAction
{
    Done,

    /// <summary>Restore the network from the state file, then try up once more.</summary>
    CleanupAndRetry,

    Fail,
}

internal static class CoreRecovery
{
    /// <summary>Calls made for an operation that keeps answering Busy.</summary>
    internal const int BusyAttempts = 5;

    /// <summary>Pause between Busy retries.</summary>
    internal static readonly TimeSpan BusyDelay = TimeSpan.FromMilliseconds(200);

    /// <summary>
    /// Policy for a finished `up` (Busy already retried): StaleState gets one
    /// cleanup + retry, a second StaleState or any other code fails.
    /// </summary>
    internal static UpAction ForUp(int rc, bool cleanupTried) => rc switch
    {
        CoreCodes.Success => UpAction.Done,
        CoreCodes.StaleState when !cleanupTried => UpAction.CleanupAndRetry,
        _ => UpAction.Fail,
    };

    /// <summary>
    /// Run <paramref name="call"/> until it stops answering Busy, at most
    /// <see cref="BusyAttempts"/> times. Busy means the core did nothing, so
    /// repeating the call is always safe. Returns the last code.
    /// </summary>
    internal static int RetryWhileBusy(Func<int> call, Action<TimeSpan>? sleep = null)
    {
        sleep ??= static pause => Thread.Sleep(pause);
        var rc = call();
        for (var attempt = 1; attempt < BusyAttempts && rc == CoreCodes.Busy; attempt++)
        {
            sleep(BusyDelay);
            rc = call();
        }

        return rc;
    }

    /// <summary>
    /// `up` with the full recovery the GUI performs: Busy is retried, and a
    /// StaleState answer runs <paramref name="cleanup"/> (restore the network
    /// from the state file) and tries once more. A failed cleanup keeps the
    /// original StaleState code. Returns the final code.
    /// </summary>
    internal static int UpWithRecovery(
        Func<int> up,
        Func<int> cleanup,
        Action<string>? log = null,
        Action<TimeSpan>? sleep = null)
    {
        var cleanupTried = false;
        while (true)
        {
            var rc = RetryWhileBusy(up, sleep);
            if (ForUp(rc, cleanupTried) != UpAction.CleanupAndRetry)
            {
                return rc;
            }

            cleanupTried = true;
            log?.Invoke("stale tunnel state from a previous run: restoring network, retrying up");
            if (RetryWhileBusy(cleanup, sleep) != CoreCodes.Success)
            {
                log?.Invoke("network restore failed; not retrying up");
                return rc;
            }
        }
    }

    /// <summary>Readable name for logs and errors.</summary>
    internal static string Describe(int rc) => rc switch
    {
        CoreCodes.Success => "Success",
        CoreCodes.StaleState => "StaleState (-11)",
        CoreCodes.Busy => "Busy (-12)",
        _ => $"code {rc}",
    };
}
