using AetherLink.Interop;
using Xunit;

namespace AetherLink.Gui.Tests;

/// <summary>
/// FFI result-code policy shared by the GUI and the CLI host
/// (dotnet/Shared/CoreRecovery.cs): Busy (-12) is retried, StaleState (-11)
/// gets one network restore + retry. The native library is never loaded:
/// calls are scripted lambdas.
/// </summary>
public sealed class CoreRecoveryTests
{
    /// <summary>Returns the scripted codes in order, then repeats the last one.</summary>
    private sealed class Script
    {
        private readonly int[] _codes;

        public Script(params int[] codes) => _codes = codes;

        public int Calls { get; private set; }

        public int Next() => _codes[Math.Min(Calls++, _codes.Length - 1)];
    }

    private static readonly Action<TimeSpan> NoSleep = _ => { };

    [Fact]
    public void CodesMatchTheCoreAbi()
    {
        // crates/aetherlink-ffi: StaleState = -11, Busy = -12 (DEC-024).
        Assert.Equal(0, CoreCodes.Success);
        Assert.Equal(-11, CoreCodes.StaleState);
        Assert.Equal(-12, CoreCodes.Busy);
    }

    // UpAction is internal, so the expected value travels as its name (a
    // public test method cannot take an internal parameter type).
    [Theory]
    [InlineData(0, false, "Done")]
    [InlineData(-11, false, "CleanupAndRetry")]
    [InlineData(-11, true, "Fail")]
    [InlineData(-12, false, "Fail")]
    [InlineData(-3, false, "Fail")]
    public void UpPolicy(int rc, bool cleanupTried, string expected)
        => Assert.Equal(expected, CoreRecovery.ForUp(rc, cleanupTried).ToString());

    [Fact]
    public void Busy_IsRetriedUntilTheCallGoesThrough()
    {
        var call = new Script(CoreCodes.Busy, CoreCodes.Busy, CoreCodes.Success);
        var pauses = new List<TimeSpan>();

        var rc = CoreRecovery.RetryWhileBusy(call.Next, pauses.Add);

        Assert.Equal(CoreCodes.Success, rc);
        Assert.Equal(3, call.Calls);
        Assert.Equal(new[] { CoreRecovery.BusyDelay, CoreRecovery.BusyDelay }, pauses);
    }

    [Fact]
    public void Busy_RetriesAreBounded()
    {
        var call = new Script(CoreCodes.Busy);

        var rc = CoreRecovery.RetryWhileBusy(call.Next, NoSleep);

        Assert.Equal(CoreCodes.Busy, rc);
        Assert.Equal(CoreRecovery.BusyAttempts, call.Calls);
    }

    [Fact]
    public void OtherFailures_AreNotRetried()
    {
        var call = new Script(-3);

        Assert.Equal(-3, CoreRecovery.RetryWhileBusy(call.Next, NoSleep));
        Assert.Equal(1, call.Calls);
    }

    [Fact]
    public void StaleState_RestoresNetworkThenRetriesUpOnce()
    {
        var up = new Script(CoreCodes.StaleState, CoreCodes.Success);
        var cleanup = new Script(CoreCodes.Success);
        var log = new List<string>();

        var rc = CoreRecovery.UpWithRecovery(up.Next, cleanup.Next, log.Add, NoSleep);

        Assert.Equal(CoreCodes.Success, rc);
        Assert.Equal(2, up.Calls);
        Assert.Equal(1, cleanup.Calls);
        Assert.Contains(log, line => line.Contains("restoring network"));
    }

    [Fact]
    public void StaleState_Twice_FailsWithoutLooping()
    {
        var up = new Script(CoreCodes.StaleState);
        var cleanup = new Script(CoreCodes.Success);

        var rc = CoreRecovery.UpWithRecovery(up.Next, cleanup.Next, sleep: NoSleep);

        Assert.Equal(CoreCodes.StaleState, rc);
        Assert.Equal(2, up.Calls);
        Assert.Equal(1, cleanup.Calls);
    }

    [Fact]
    public void FailedCleanup_KeepsStaleStateAndSkipsTheRetry()
    {
        var up = new Script(CoreCodes.StaleState);
        var cleanup = new Script(-1);

        var rc = CoreRecovery.UpWithRecovery(up.Next, cleanup.Next, sleep: NoSleep);

        Assert.Equal(CoreCodes.StaleState, rc);
        Assert.Equal(1, up.Calls);
    }

    [Fact]
    public void BusyUp_ThenStaleState_StillRecovers()
    {
        var up = new Script(CoreCodes.Busy, CoreCodes.StaleState, CoreCodes.Success);
        var cleanup = new Script(CoreCodes.Busy, CoreCodes.Success);

        var rc = CoreRecovery.UpWithRecovery(up.Next, cleanup.Next, sleep: NoSleep);

        Assert.Equal(CoreCodes.Success, rc);
        Assert.Equal(3, up.Calls);
        Assert.Equal(2, cleanup.Calls);
    }

    [Fact]
    public void PlainFailure_IsReturnedAsIs()
    {
        var up = new Script(-3);
        var cleanup = new Script(CoreCodes.Success);

        Assert.Equal(-3, CoreRecovery.UpWithRecovery(up.Next, cleanup.Next, sleep: NoSleep));
        Assert.Equal(0, cleanup.Calls);
    }

    [Theory]
    [InlineData(-11, "StaleState (-11)")]
    [InlineData(-12, "Busy (-12)")]
    [InlineData(-3, "code -3")]
    public void Describe_NamesTheCodesHostsActOn(int rc, string expected)
        => Assert.Equal(expected, CoreRecovery.Describe(rc));
}
