extern alias Web;
extern alias Admin;

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
#if ALLOW_TOTP
using OtpNet;
#endif

// Standalone regression runner: no service hosts, IPC endpoints, administrator
// privileges, real credentials, or firewall commands are involved.
string testDirectory = Path.Combine(AppContext.BaseDirectory, "replay-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(testDirectory);
int passed = 0;
try
{
    Run("all three models preserve the persisted watermark", () =>
    {
        string json = JsonSerializer.Serialize(new UserEntry { LastAcceptedTotpTimeStep = 123456 });
        var webUser = JsonSerializer.Deserialize<Web::UserEntry>(json)!;
        var adminUser = JsonSerializer.Deserialize<Admin::MFAAdmin.UserEntry>(JsonSerializer.Serialize(webUser))!;
        var serviceUser = JsonSerializer.Deserialize<UserEntry>(JsonSerializer.Serialize(adminUser))!;
        Assert(serviceUser.LastAcceptedTotpTimeStep == 123456, "An unrelated component write discarded the watermark.");
        Assert(JsonSerializer.Deserialize<UserEntry>("{}")!.LastAcceptedTotpTimeStep == null,
            "Legacy records must deserialize without inventing a consumed step.");
    });

#if ALLOW_TOTP
    Run("one successful TOTP cannot authorize a second request", () =>
    {
        using var store = NewStore();
        var totp = new Totp(Base32Encoding.ToBytes(store.ReadUser().TotpSecret));
        string code = totp.ComputeTotp();
        Assert(totp.VerifyTotp(code, out long matched, new VerificationWindow(1, 1)), "Initial OTP verification failed.");
        Assert(Consume(store, matched) == "SUCCESS", "First successful OTP was rejected.");
        Assert(totp.VerifyTotp(code, out long repeated, new VerificationWindow(1, 1)), "The reproduction needs an otherwise-valid repeated OTP.");
        Assert(Consume(store, repeated).Contains("already consumed"), "A valid but previously-used OTP authorized a second request.");
        Assert(store.Writes == 1, "A rejected replay changed persisted state.");
    });

    Run("concurrent identical requests authorize exactly once", () =>
    {
        using var store = NewStore();
        long step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        int successes = 0;
        Parallel.For(0, 32, _ =>
        {
            if (Consume(store, step) == "SUCCESS") Interlocked.Increment(ref successes);
        });
        Assert(successes == 1 && store.Writes == 1, $"Expected one grant/write, observed {successes}/{store.Writes}.");
    });

    Run("a fresh reader rejects a persisted step after restart", () =>
    {
        long step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        string filePath;
        using (var first = NewStore())
        {
            filePath = first.FilePath;
            Assert(Consume(first, step) == "SUCCESS", "Initial acceptance failed.");
        }
        using var restarted = new JsonUserStore(filePath);
        Assert(Consume(restarted, step).Contains("already consumed"), "Restart allowed the previously consumed step.");
        Assert(restarted.ReadUser().LastAcceptedTotpTimeStep == step, "Watermark was not persisted.");
    });

    Run("older steps cannot move the watermark backwards", () =>
    {
        using var store = NewStore();
        var now = DateTimeOffset.UtcNow;
        long step = now.ToUnixTimeSeconds() / 30;
        Assert(Consume(store, step, now) == "SUCCESS", "Initial acceptance failed.");
        Assert(Consume(store, step - 1, now).Contains("already consumed"), "An older drift-window code was accepted.");
        Assert(Consume(store, step + 1, now) == "SUCCESS", "A new step inside the drift window was rejected.");
        Assert(store.ReadUser().LastAcceptedTotpTimeStep == step + 1, "Watermark regressed.");
    });

    Run("malformed, expired and far-future steps cannot poison state", () =>
    {
        using var store = NewStore();
        var now = DateTimeOffset.UtcNow;
        long step = now.ToUnixTimeSeconds() / 30;
        Assert(Consume(store, step - 2, now).StartsWith("ERROR:"), "Expired step was accepted.");
        Assert(Consume(store, step + 2, now).StartsWith("ERROR:"), "Future step was accepted.");
        Assert(TotpReplayProtection.Consume("user@example.test", "-1", Fingerprint("JBSWY3DPEHPK3PXP"),
            store.AcquireLock, store.Load, store.Save, now).StartsWith("ERROR:"), "Malformed step was accepted.");
        Assert(store.Writes == 0, "Invalid input changed persisted state.");
    });

    Run("reprovisioning invalidates in-flight proofs against the old secret", () =>
    {
        using var store = NewStore();
        string previousFingerprint = Fingerprint(store.ReadUser().TotpSecret);
        var users = store.Load();
        users[0].TotpSecret = "KRSXG5DSNFXGOIDB";
        store.Save(users);
        string result = TotpReplayProtection.Consume("user@example.test", CurrentStep(), previousFingerprint,
            store.AcquireLock, store.Load, store.Save, DateTimeOffset.UtcNow);
        Assert(result.Contains("enrollment changed"), "An old-secret proof survived reprovisioning.");
        Assert(store.ReadUser().LastAcceptedTotpTimeStep == null, "Rejected old proof consumed the new enrollment's step.");
    });

    Run("missing or unconfirmed enrollment cannot consume a step", () =>
    {
        using var store = NewStore();
        var users = store.Load();
        users[0].TotpConfirmed = false;
        store.Save(users);
        Assert(Consume(store, long.Parse(CurrentStep(), CultureInfo.InvariantCulture)).Contains("not enrolled"),
            "An unconfirmed enrollment was accepted.");
        Assert(TotpReplayProtection.Consume("absent@example.test", CurrentStep(), Fingerprint("JBSWY3DPEHPK3PXP"),
            store.AcquireLock, store.Load, store.Save, DateTimeOffset.UtcNow).Contains("not enrolled"),
            "A nonexistent account was accepted.");
    });

    Run("lock and persistence failures cannot report authorization", () =>
    {
        using var store = NewStore();
        string result = TotpReplayProtection.Consume("user@example.test", CurrentStep(), Fingerprint("JBSWY3DPEHPK3PXP"),
            () => null, store.Load, store.Save, DateTimeOffset.UtcNow);
        Assert(result.Contains("lock timeout"), "Lock failure was accepted.");
        bool threw = false;
        try
        {
            TotpReplayProtection.Consume("user@example.test", CurrentStep(), Fingerprint("JBSWY3DPEHPK3PXP"),
                store.AcquireLock, store.Load, _ => throw new IOException("Simulated disk failure"), DateTimeOffset.UtcNow);
        }
        catch (IOException) { threw = true; }
        Assert(threw, "A failed save returned success.");
        Assert(store.ReadUser().LastAcceptedTotpTimeStep == null, "Failed persistence changed the on-disk record.");
    });
#else
    Run("the default service rejects the optional TOTP consume command", () =>
        Assert(DatabaseLockService.ProcessDbRequest("CONSUME_TOTP|user@example.test|123|fingerprint") == "ERROR: Unknown DB command",
            "The passkey-only service exposed a TOTP command."));
#endif

    Console.WriteLine($"PASS: {passed} replay protection regression checks.");
}
finally
{
    // Only files created immediately within this unique test directory are removed.
    foreach (string file in Directory.EnumerateFiles(testDirectory)) File.Delete(file);
    Directory.Delete(testDirectory);
}

void Run(string name, Action check)
{
    check();
    passed++;
    Console.WriteLine("PASS: " + name);
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

#if ALLOW_TOTP
JsonUserStore NewStore()
{
    string path = Path.Combine(testDirectory, Guid.NewGuid().ToString("N") + ".json");
    // Deliberately omit the new property to exercise migration from the old schema.
    File.WriteAllText(path, "[{\"Username\":\"user@example.test\",\"TotpSecret\":\"JBSWY3DPEHPK3PXP\",\"TotpConfirmed\":true}]");
    return new JsonUserStore(path);
}

static string Consume(JsonUserStore store, long step, DateTimeOffset? now = null)
    => TotpReplayProtection.Consume("user@example.test", step.ToString(CultureInfo.InvariantCulture),
        Fingerprint("JBSWY3DPEHPK3PXP"), store.AcquireLock, store.Load, store.Save, now ?? DateTimeOffset.UtcNow);

static string CurrentStep() => (DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30).ToString(CultureInfo.InvariantCulture);
static string Fingerprint(string secret) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

sealed class JsonUserStore(string filePath) : IDisposable
{
    private readonly Mutex mutex = new(false);
    public string FilePath { get; } = filePath;
    public int Writes { get; private set; }

    public IDisposable? AcquireLock() => mutex.WaitOne(TimeSpan.FromSeconds(10)) ? new MutexLease(mutex) : null;
    public List<UserEntry> Load() => JsonSerializer.Deserialize<List<UserEntry>>(File.ReadAllText(FilePath))!;
    public UserEntry ReadUser() => Load()[0];

    public void Save(List<UserEntry> users)
    {
        string temporary = FilePath + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, users);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, FilePath, overwrite: true);
        Writes++;
    }

    public void Dispose() => mutex.Dispose();

    private sealed class MutexLease(Mutex mutex) : IDisposable
    {
        public void Dispose() => mutex.ReleaseMutex();
    }
}
#endif
