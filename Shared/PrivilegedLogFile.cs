using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

// Compiled into MFAService and MFAAdmin (linked from each .csproj), whose daily log files live in
// the log directory MFAWeb also writes to. The web account may create files there, so it can put
// something at tomorrow's mfaservice_<date>.log or mfaadmin_<date>.log before the privileged
// component does: a symbolic link (root would append to whatever file it names), a regular file
// it owns (it could forge, rewrite or delete the privileged log, and keep doing so through a
// handle it holds open), or a named pipe (opening it for writing blocks, stalling every thread
// that logs -- including the firewall sweeper).
//
// So before the first write to a day's file, Prepare() checks what is at the path without
// following or opening it, and uses it only if it is a regular file this process's account owns,
// with a single link. Anything else is renamed aside, never opened, and a fresh file is created
// with O_EXCL / CreateNew. If even that is impossible, it falls back to a uniquely named file, so
// the log is never silently switched off.
internal static class PrivilegedLogFile
{
    // Returns the path to write the day's log to (normally `path` itself) and a note describing
    // anything found and set aside, for the caller to log, or null.
    internal static (string Path, string? Note) Prepare(string path)
    {
        var notes = new List<string>();
        string? dir = System.IO.Path.GetDirectoryName(path);

        // On Linux the directory must be sticky (INSTALL.md: 3770 root:mfaipc): only then can no
        // other account rename or remove a file that belongs to root once it is checked. Running as
        // root, restore the bit if it is missing (an install that skipped an upgrade step, or a
        // directory created by default); otherwise say so.
        if (OperatingSystem.IsLinux() && dir != null)
        {
            var dirMode = File.GetUnixFileMode(dir);
            if ((dirMode & UnixFileMode.StickyBit) == 0)
            {
                // Best effort, never a reason to stop logging: under the documented MFAService unit
                // the attempt fails (RestrictSUIDSGID refuses a mode that keeps the setgid bit), so
                // the service only reports it; MFAAdmin, run as root outside that sandbox, repairs it.
                try
                {
                    if (geteuid() != 0) throw new UnauthorizedAccessException("not running as root");
                    File.SetUnixFileMode(dir, dirMode | UnixFileMode.StickyBit);
                    notes.Add($"log directory {dir} was not sticky; set the sticky bit (INSTALL.md: mode 3770)");
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                {
                    notes.Add($"log directory {dir} is not sticky (expected mode 3770, as in INSTALL.md) " +
                              $"and could not be changed here ({ex.Message}); run 'sudo chmod +t {dir}'");
                }
            }
        }

        for (int attempt = 0; attempt < 5; attempt++)
        {
            EntryState state;
            try { state = OperatingSystem.IsWindows() ? InspectWindows(path) : InspectUnix(path); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                notes.Add($"could not inspect {System.IO.Path.GetFileName(path)} ({ex.Message})");
                break;   // to the uniquely named file below
            }
            if (state == EntryState.Missing)
            {
                if (TryCreateNew(path)) return (path, Join(notes));
                continue;   // something appeared at the path in between; inspect it
            }
            if (state == EntryState.Ours) return (path, Join(notes));

            string aside = System.IO.Path.Combine(dir ?? ".", "untrusted-" + DateTime.UtcNow.ToString("yyyyMMddHHmmssfff") +
                                                  "-" + System.IO.Path.GetFileName(path));
            if (TryMoveAside(path, aside))
            {
                notes.Add($"set aside {System.IO.Path.GetFileName(path)}, which this account did not create ({Describe(state)}), as {System.IO.Path.GetFileName(aside)}");
                continue;
            }
            notes.Add($"{System.IO.Path.GetFileName(path)} was not created by this account ({Describe(state)}) and could not be set aside");
            break;
        }

        // Last resort: a name nobody could have prepared in advance.
        string unique = CreateUnique(path);
        notes.Add($"writing to {System.IO.Path.GetFileName(unique)} instead");
        return (unique, Join(notes));
    }

    // A new file next to `path` under a name nobody could have prepared in advance
    // (<name>_<random>.log; the date stays at the front, so retention still reads it). Also the
    // caller's fallback when the checked file then cannot be opened -- on Windows the web account
    // can read the log directory, so it can hold a day's file open with no sharing while no
    // privileged process has it open, and the log must not stop because of that.
    internal static string CreateUnique(string path)
    {
        string dir = System.IO.Path.GetDirectoryName(path) ?? ".";
        string unique = System.IO.Path.Combine(dir, System.IO.Path.GetFileNameWithoutExtension(path) + "_" +
                                               Guid.NewGuid().ToString("N")[..12] + System.IO.Path.GetExtension(path));
        if (!TryCreateNew(unique))
            throw new IOException($"could not create a log file at {unique}");
        return unique;
    }

    private enum EntryState { Missing, Ours, NotRegular, ForeignOwner, MultipleLinks }

    private static string Describe(EntryState state) => state switch
    {
        EntryState.NotRegular    => "not a regular file: a link, pipe, directory or device",
        EntryState.ForeignOwner  => "owned by another account",
        EntryState.MultipleLinks => "a hard link to another file",
        _                        => state.ToString(),
    };

    private static bool TryCreateNew(string path)
    {
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;   // see InspectUnix
            using var created = new FileStream(path, options);   // O_CREAT|O_EXCL: never follows a link
            return true;
        }
        catch (IOException) { return false; }
    }

    // ---- Linux / Unix: statx() without following links -------------------------------------

    [UnsupportedOSPlatform("windows")]
    private static EntryState InspectUnix(string path)
    {
        // struct statx: stx_nlink at offset 16, stx_uid at 20, stx_mode at 28 (fixed layout on
        // every architecture, unlike struct stat).
        var buffer = new byte[256];
        if (statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID, buffer) != 0)
        {
            int errno = Marshal.GetLastPInvokeError();
            if (errno == ENOENT) return EntryState.Missing;
            throw new IOException($"could not inspect {path} (errno {errno})");
        }
        uint nlink = BitConverter.ToUInt32(buffer, 16);
        uint uid   = BitConverter.ToUInt32(buffer, 20);
        ushort mode = BitConverter.ToUInt16(buffer, 28);
        if ((mode & S_IFMT) != S_IFREG) return EntryState.NotRegular;
        if (uid != geteuid()) return EntryState.ForeignOwner;
        if (nlink != 1) return EntryState.MultipleLinks;
        // Owner only. Readable by the group (mfaipc, i.e. the web account), the web account could
        // hold an advisory lock on it and make every append fail. Earlier builds created 0640.
        if ((mode & 0x3F) != 0)
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return EntryState.Ours;
    }

    private static bool TryMoveAside(string path, string aside)
    {
        if (OperatingSystem.IsWindows())
        {
            try { File.Move(path, aside); return true; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
        }
        return rename(path, aside) == 0;   // renames the entry itself, whatever it is; never follows
    }

    private const int AT_FDCWD = -100;
    private const int AT_SYMLINK_NOFOLLOW = 0x100;
    private const uint STATX_TYPE = 0x1, STATX_MODE = 0x2, STATX_NLINK = 0x4, STATX_UID = 0x8;
    private const ushort S_IFMT = 0xF000, S_IFREG = 0x8000;
    private const int ENOENT = 2;

    [DllImport("libc", SetLastError = true)]
    private static extern int statx(int dirfd, string pathname, int flags, uint mask, byte[] statxbuf);

    [DllImport("libc", SetLastError = true)]
    private static extern int rename(string oldpath, string newpath);

    [DllImport("libc")]
    private static extern uint geteuid();

    // ---- Windows: owner and reparse-point check -----------------------------------------------

    [SupportedOSPlatform("windows")]
    private static EntryState InspectWindows(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists && !Directory.Exists(path)) return EntryState.Missing;
        if (Directory.Exists(path) || info.Attributes.HasFlag(FileAttributes.ReparsePoint)) return EntryState.NotRegular;

        // A file whose owner cannot even be read was not created by us: its creator set a DACL that
        // leaves us out. Treat it as foreign; setting it aside needs only rights on the directory.
        SecurityIdentifier? owner;
        try { owner = info.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier; }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException) { return EntryState.ForeignOwner; }

        using var me = WindowsIdentity.GetCurrent();
        bool trusted = owner != null && ((me.User != null && owner.Equals(me.User))
            || owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
            || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));
        if (!trusted) return EntryState.ForeignOwner;
        // A hard link to a file of ours elsewhere would pass the owner check.
        return WindowsLinkCount(path) == 1 ? EntryState.Ours : EntryState.MultipleLinks;
    }

    // Number of hard links, read through a handle opened for attributes only (no data access, any
    // sharing, not following a reparse point). Anything unreadable counts as more than one.
    [SupportedOSPlatform("windows")]
    private static uint WindowsLinkCount(string path)
    {
        const uint FILE_READ_ATTRIBUTES = 0x80, OPEN_EXISTING = 3, SHARE_ALL = 0x7;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000, FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        using var handle = CreateFileW(path, FILE_READ_ATTRIBUTES, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (handle.IsInvalid) return uint.MaxValue;
        var info = new byte[52];   // BY_HANDLE_FILE_INFORMATION; nNumberOfLinks at offset 40
        return GetFileInformationByHandle(handle, info) ? BitConverter.ToUInt32(info, 40) : uint.MaxValue;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle hFile, byte[] lpFileInformation);

    private static string? Join(List<string> notes) => notes.Count == 0 ? null : string.Join("; ", notes);
}
