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

    public EndpointProfile Add()
    {
        var profile = new EndpointProfile { Name = UniqueName("endpoint") };
        Items.Add(profile);
        Active = profile;
        return profile;
    }

    public EndpointProfile Duplicate(EndpointProfile source)
    {
        var baseName = string.IsNullOrWhiteSpace(source.Name) ? "endpoint" : source.Name.Trim();
        var copy = source.Copy();
        copy.Name = UniqueCopyName(baseName);
        Items.Add(copy);
        Active = copy;
        return copy;
    }

    public bool Remove(EndpointProfile endpoint)
    {
        if (!CanRemove)
        {
            return false;
        }

        var index = Items.IndexOf(endpoint);
        if (index < 0)
        {
            return false;
        }

        Items.RemoveAt(index);
        if (ReferenceEquals(Active, endpoint))
        {
            Active = Items[Math.Min(index, Items.Count - 1)];
        }

        return true;
    }

    public void Select(EndpointProfile? endpoint)
    {
        if (endpoint is not null && Items.Contains(endpoint))
        {
            Active = endpoint;
        }
    }

    public void Load(IEnumerable<EndpointProfile> items, string? activeName)
    {
        Items.Clear();
        foreach (var item in items)
        {
            Items.Add(item);
        }

        Active = Items.FirstOrDefault(
                     i => string.Equals(
                         i.Name.Trim(),
                         activeName?.Trim(),
                         StringComparison.OrdinalIgnoreCase))
                 ?? Items.FirstOrDefault();
    }

    /// <summary>First validation error for the whole book, or null.</summary>
    public string? Validate() => EndpointRules.ValidateAll(Items);

    private string UniqueName(string baseName)
    {
        if (!NameTaken(baseName))
        {
            return baseName;
        }

        for (var n = 2; ; n++)
        {
            var candidate = $"{baseName} {n}";
            if (!NameTaken(candidate))
            {
                return candidate;
            }
        }
    }

    private string UniqueCopyName(string baseName)
    {
        if (!NameTaken($"{baseName} (copy)"))
        {
            return $"{baseName} (copy)";
        }

        for (var n = 2; ; n++)
        {
            var candidate = $"{baseName} (copy {n})";
            if (!NameTaken(candidate))
            {
                return candidate;
            }
        }
    }

    private bool NameTaken(string name)
        => Items.Any(i => string.Equals(i.Name.Trim(), name, StringComparison.OrdinalIgnoreCase));
}
