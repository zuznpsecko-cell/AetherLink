// Config file handling: locate, load and save the YAML the core parses.
// The core re-validates on Up(); errors surface from there, not here.

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace AetherLink.Gui.Services;

internal static class ConfigService
{
    public static string ResolvePath(string? overridePath = null)
    {
        if (!string.IsNullOrEmpty(overridePath) && File.Exists(overridePath))
        {
            return Path.GetFullPath(overridePath);
        }

        var exeDir = AppContext.BaseDirectory;
        foreach (var name in new[] { "client.local.yaml", "client.yaml" })
        {
            var p = Path.Combine(exeDir, name);
            if (File.Exists(p))
            {
                return p;
            }
        }

        return Path.Combine(exeDir, "client.local.yaml");
    }

    public static Models.GuiClientConfig Load(string path)
    {
        var text = File.ReadAllText(path);
        var des = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
        return des.Deserialize<Models.GuiClientConfig>(text) ?? new Models.GuiClientConfig();
    }

    public static void Save(string path, Models.GuiClientConfig cfg)
    {
        var ser = new SerializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build();
        File.WriteAllText(path, ser.Serialize(cfg));
    }

    /// Raw text the core consumes (core parses YAML itself).
    public static string RawText(string path) => File.Exists(path) ? File.ReadAllText(path) : "";
}
