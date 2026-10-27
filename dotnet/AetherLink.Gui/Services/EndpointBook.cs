using System.Collections.ObjectModel;
using AetherLink.Gui.Models;

namespace AetherLink.Gui.Services;

/// <summary>
/// List of endpoint profiles plus the active one. Pure UI state: no Avalonia
/// and no native calls, so every invariant is unit-testable.
/// </summary>
public sealed class EndpointBook
{
    public ObservableCollection<EndpointProfile> Items { get; } = new();

    public EndpointProfile? Active { get; private set; }

    /// <summary>The last profile cannot be removed: Connect needs a target.</summary>
    public bool CanRemove => Items.Count > 1;

    public EndpointProfile Add() => throw new NotImplementedException();

    public EndpointProfile Duplicate(EndpointProfile source) => throw new NotImplementedException();

    public bool Remove(EndpointProfile endpoint) => throw new NotImplementedException();

    public void Select(EndpointProfile? endpoint) => throw new NotImplementedException();

    public void Load(IEnumerable<EndpointProfile> items, string? activeName)
        => throw new NotImplementedException();

    /// <summary>First validation error for the whole book, or null.</summary>
    public string? Validate() => throw new NotImplementedException();
}
