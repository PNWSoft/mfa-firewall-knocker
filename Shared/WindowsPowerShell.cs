// Compiled into MFAService and MFAAdmin (linked from each .csproj).
internal static class WindowsPowerShell
{
    // Windows PowerShell by absolute path (normally
    // C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe), never by bare name. A bare
    // name makes CreateProcess look in the application's own directory first, so a
    // powershell.exe placed beside MFAService.exe would run as LocalSystem, and one beside
    // MFAAdmin.exe would run elevated. Windows only.
    internal static string ExePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "WindowsPowerShell", "v1.0", "powershell.exe");
}
