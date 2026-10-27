using AetherLink.Gui.Services;
using Xunit;

namespace AetherLink.Gui.Tests;

public sealed class EndpointBookTests
{
    [Fact]
    public void EmptyBook_RequiresAtLeastOneEndpoint()
    {
        var book = new EndpointBook();
        Assert.Equal("add at least one endpoint", book.Validate());
    }
}
