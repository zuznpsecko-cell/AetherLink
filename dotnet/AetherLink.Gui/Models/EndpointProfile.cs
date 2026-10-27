using CommunityToolkit.Mvvm.ComponentModel;

namespace AetherLink.Gui.Models;

/// <summary>
/// One named connection profile. Full tunnel, MTU and routing rules stay
/// shared between profiles; only the endpoint fields live here.
/// PSK is a secret: never include it in logs or error messages.
/// </summary>
public sealed partial class EndpointProfile : ObservableObject
{
    [ObservableProperty]
    public partial string Name { get; set; } = "";

    [ObservableProperty]
    public partial string ServerAddr { get; set; } = "";

    [ObservableProperty]
    public partial string OuterSni { get; set; } = "";

    [ObservableProperty]
    public partial string Psk { get; set; } = "";

    public string Display => string.IsNullOrWhiteSpace(Name) ? "(unnamed)" : Name;

    partial void OnNameChanged(string value) => OnPropertyChanged(nameof(Display));

    public EndpointProfile Copy() => new()
    {
        Name = Name,
        ServerAddr = ServerAddr,
        OuterSni = OuterSni,
        Psk = Psk,
    };
}
