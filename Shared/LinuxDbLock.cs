// Compiled into MFAService and MFAAdmin (linked from each .csproj): the two writers of the user
// database must take the same lock, so they must find it the same way.
//
// Linux only. Windows keeps its ACL'd named mutex (Global\MFA_DB_LOCK). On Linux a .NET named
// mutex is backed by files whose location the runtime chooses: runtime 10.0.12 used /tmp/.dotnet,
// runtime 10.0.14 uses $XDG_RUNTIME_DIR or the account's home directory. Under the documented
// systemd unit (ProtectHome=true) that made MFAService fail at startup, and outside it MFAService
// and an MFAAdmin started from a login shell could end up holding two different "global" mutexes.
// A lock file at a fixed path beside the database depends on neither.
internal static class LinuxDbLock
{
    // How .NET reports that another holder has the lock: the raw errno EWOULDBLOCK (11) on Linux,
    // ERROR_SHARING_VIOLATION (32) on Windows, where only the tests run this.
    private static bool IsHeldByAnother(IOException ex)
        => OperatingSystem.IsWindows() ? (ex.HResult & 0xFFFF) == 32 : ex.HResult == 11;

    // An exclusive lock on "<database directory>/users.lock". .NET takes an flock(LOCK_EX) for
    // FileShare.None on Unix, which another open of the same file -- in this process or any
    // other -- cannot share until it is released; the kernel releases it if the holder dies, so
    // a crash cannot leave the database locked. The file is created 0600 for root, so the web
    // account cannot open it and hold the lock.
    internal static IDisposable? TryAcquire(string dbPath, TimeSpan timeout)
    {
        string dir = Path.GetDirectoryName(Path.GetFullPath(dbPath))
            ?? throw new InvalidOperationException($"No directory for database path '{dbPath}'.");
        string lockPath = Path.Combine(dir, "users.lock");
        var options = new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
        };
        // Only Linux reaches this in production; the guard lets the tests run on Windows too.
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
}
