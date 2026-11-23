using Microsoft.Extensions.Configuration;

// Compiled into MFAService and MFAWeb (linked from each .csproj). The default host builders read
// appsettings.{Environment}.json (and, in Development, user secrets) on top of appsettings.json.
// Those are extra files beside the program that nobody here creates, so the only way one exists is
// that someone put it there -- and a file that silently overrides FirewallService:GmsaAccount,
// BouncerConfig:AllowedPorts or Smtp:* is exactly what an attacker with write access to an install
// folder would leave behind. Read appsettings.json only. (MFAAdmin already builds its configuration
// from appsettings.json alone.) Environment variables and the command line stay: setting those for
// a service already takes administrator rights.
internal static class ConfigFiles
{
    internal static void UseAppSettingsJsonOnly(IConfigurationBuilder configuration)
    {
        var others = configuration.Sources
            .OfType<FileConfigurationSource>()
            .Where(s => !string.Equals(s.Path, "appsettings.json", StringComparison.OrdinalIgnoreCase))
            .ToList();
        foreach (var source in others)
            configuration.Sources.Remove(source);
    }
}
