using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

// Compiled into MFAService and MFAAdmin (linked from each .csproj): the two writers of the user
// database must take the same lock, so they must find it the same way. MFAWeb never writes the
// database and never takes it.
//
// The lock is an exclusive open of "users.lock" beside the database, on both platforms.
// It used to be a .NET named mutex, and both platforms had a problem with that:
// - Linux: the runtime chooses where a named mutex's backing files live. Runtime 10.0.12 used
//   /tmp/.dotnet; runtime 10.0.14 uses $XDG_RUNTIME_DIR or the account's home directory. Under
//   the documented systemd unit (ProtectHome=true) MFAService then failed at startup, and outside
//   it the service and an MFAAdmin started from a login shell could hold two different "global"
//   mutexes.
// - Windows: any local user can create an object in the Global\ namespace. Creating
//   Global\MFA_DB_LOCK first, with a DACL that excludes SYSTEM, stopped MFAService and MFAAdmin
//   from starting -- no grants, no expiry, no reset.
// The database directory is already restricted to the administrators and the two components, so
// a lock file there is out of reach of ordinary local users on both platforms.
internal static class DbFileLock
{
    // How .NET reports that another holder has the lock: the raw errno EWOULDBLOCK (11) on Linux,
    // ERROR_SHARING_VIOLATION (32) on Windows.
    private static bool IsHeldByAnother(IOException ex)
        => OperatingSystem.IsWindows() ? (ex.HResult & 0xFFFF) == 32 : ex.HResult == 11;

    // An exclusive lock on "<database directory>/users.lock". On Linux .NET takes an
    // flock(LOCK_EX) for FileShare.None; on Windows FileShare.None is a sharing mode. Either way
    // another open of the same file -- in this process or any other -- fails until the holder
    // releases it, and the OS releases it if the holder dies, so a crash cannot leave the
    // database locked. The file is readable only by its owner (Linux, 0600) or by SYSTEM and
    // Administrators (Windows), so the web account, which can read the database
    // directory, cannot open the lock file and hold it.
    internal static IDisposable? TryAcquire(string dbPath, TimeSpan timeout)
    {
        string dir = Path.GetDirectoryName(Path.GetFullPath(dbPath))
            ?? throw new InvalidOperationException($"No directory for database path '{dbPath}'.");
        string lockPath = Path.Combine(dir, "users.lock");
        if (OperatingSystem.IsWindows()) EnsureWindowsLockFile(lockPath);

        var options = new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
        };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            try
            {
                return new FileStream(lockPath, options);
            }
            catch (IOException ex) when (IsHeldByAnother(ex))
            {
                // Held by another process or thread. Any other failure (missing directory, full
                // or read-only filesystem, permissions) propagates: it is not worth waiting for,
                // and reporting it as a timeout would hide the cause.
                if (DateTime.UtcNow >= deadline) return null;
                Thread.Sleep(50);
            }
        }
    }

    // The lock file's own protected ACL: SYSTEM and Administrators only. Not the database
    // directory's inherited one, which also lets the web account read; and not the creating
    // account by name, which for an elevated MFAAdmin would let that administrator's unelevated
    // processes open the file and hold the lock. Applied on creation and re-applied every time,
    // so a file created some other way, or by an earlier build, is corrected.
    [SupportedOSPlatform("windows")]
    private static void EnsureWindowsLockFile(string lockPath)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, AccessControlType.Allow));
        try
        {
            using var created = new FileInfo(lockPath).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                FileShare.None, 4096, FileOptions.None, security);
            return;
        }
        catch (IOException) when (File.Exists(lockPath)) { /* already there: correct its ACL below */ }
        new FileInfo(lockPath).SetAccessControl(security);
    }
}
