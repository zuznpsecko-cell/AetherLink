using AetherLink.Gui.Models;
using AetherLink.Gui.Services;
using Xunit;

namespace AetherLink.Gui.Tests;

public sealed class EndpointBookTests
{
    private static EndpointProfile Profile(string name, string addr = "example.com:443")
        => new() { Name = name, ServerAddr = addr, OuterSni = "example.com", Psk = "psk" };

    [Fact]
    public void EmptyBook_RequiresAtLeastOneEndpoint()
    {
        var book = new EndpointBook();
        Assert.Equal("add at least one endpoint", book.Validate());
    }

    [Fact]
    public void Add_CreatesUniqueNames_AndSelectsNewProfile()
    {
        var book = new EndpointBook();

        var first = book.Add();
        var second = book.Add();

        Assert.Equal(new[] { "endpoint", "endpoint 2" }, book.Items.Select(i => i.Name));
        Assert.Same(second, book.Active);
        Assert.Equal(2, book.Items.Count);
    }

    [Fact]
    public void Duplicate_CopiesFields_AndGivesUniqueName()
    {
        var book = new EndpointBook();
        var source = Profile("home");
        book.Load(new[] { source }, "home");

        var copy = book.Duplicate(source);
        var copy2 = book.Duplicate(source);

        Assert.Equal("home (copy)", copy.Name);
        Assert.Equal("home (copy 2)", copy2.Name);
        Assert.Equal("example.com:443", copy.ServerAddr);
        Assert.Equal("example.com", copy.OuterSni);
        Assert.Equal("psk", copy.Psk);
        Assert.Same(copy2, book.Active);
        Assert.Equal(3, book.Items.Count);
    }

    [Fact]
    public void Remove_Active_SelectsNeighbour()
    {
        var book = new EndpointBook();
        var a = Profile("a");
        var b = Profile("b");
        var c = Profile("c");
        book.Load(new[] { a, b, c }, "b");

        Assert.True(book.Remove(b));
        Assert.Same(c, book.Active);
        Assert.Equal(new[] { a, c }, book.Items);
    }

    [Fact]
    public void Remove_LastProfile_IsRefused()
    {
        var book = new EndpointBook();
        var only = Profile("only");
        book.Load(new[] { only }, "only");

        Assert.False(book.CanRemove);
        Assert.False(book.Remove(only));
        Assert.Single(book.Items);
        Assert.Same(only, book.Active);
    }

    [Fact]
    public void Remove_UnknownProfile_IsIgnored()
    {
        var book = new EndpointBook();
        var a = Profile("a");
        var b = Profile("b");
        book.Load(new[] { a, b }, "a");

        Assert.False(book.Remove(Profile("ghost")));
        Assert.Equal(2, book.Items.Count);
    }

    [Fact]
    public void Select_UnknownProfile_IsIgnored()
    {
        var book = new EndpointBook();
        var a = Profile("a");
        book.Load(new[] { a }, "a");

        book.Select(Profile("ghost"));

        Assert.Same(a, book.Active);
    }

    [Fact]
    public void Load_ResolvesActiveByName_CaseInsensitively()
    {
        var book = new EndpointBook();
        var a = Profile("a");
        var b = Profile("B");
        book.Load(new[] { a, b }, "b");

        Assert.Same(b, book.Active);
    }

    [Fact]
    public void Load_UnknownActive_FallsBackToFirst()
    {
        var book = new EndpointBook();
        var a = Profile("a");
        var b = Profile("b");
        book.Load(new[] { a, b }, "missing");

        Assert.Same(a, book.Active);
    }

    [Fact]
    public void Load_Empty_ClearsSelection()
    {
        var book = new EndpointBook();
        book.Load(Array.Empty<EndpointProfile>(), null);

        Assert.Empty(book.Items);
        Assert.Null(book.Active);
    }

    [Fact]
    public void Validate_ReportsDuplicateNames()
    {
        var book = new EndpointBook();
        book.Load(new[] { Profile("home"), Profile("HOME") }, "home");

        Assert.Equal("endpoint name 'home' is used twice", book.Validate());
    }
}
