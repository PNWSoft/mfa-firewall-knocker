using System.Text;
using Microsoft.Extensions.Configuration;

// Compiled into MFAWeb, MFAService and MFAAdmin (linked from each .csproj), so all three apply
// the same rule to the same key.
internal static class DpapiEntropy
{
    // On Windows, users.dat is DPAPI-protected at LocalMachine scope, so this value is the only
    // thing stopping another process on the same host from decrypting it -- and the placeholder
    // in appsettings.example.json is published in the public source repository. Refuse to start
    // rather than run with a missing, short or known value.
    //
    // On Linux there is no DPAPI: the database (users.json) is plain JSON protected by file
    // permissions, and the value is never used. It is not required there, and is ignored if present.
    internal static byte[] Load(IConfiguration config)
    {
        if (!OperatingSystem.IsWindows()) return Array.Empty<byte>();

        string? value = config["DpapiEntropy"];
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException("DpapiEntropy must be configured in appsettings.json. Set it to a unique random string for your deployment.");
        if (value.Contains("REPLACE-WITH", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("DpapiEntropy is still set to the placeholder from appsettings.example.json. That value is public and offers no protection. Generate a unique random string for this deployment.");
        if (value.Trim().Length < 16)
            throw new InvalidOperationException("DpapiEntropy must be at least 16 characters. Generate a unique random string for this deployment (e.g. 32 random bytes, base64-encoded).");
        return Encoding.UTF8.GetBytes(value);
    }
}
