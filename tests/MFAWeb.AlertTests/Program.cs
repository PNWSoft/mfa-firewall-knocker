using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;

// Real HTTP route regressions, using only synthetic accounts and an ephemeral
// loopback listener. Every HTTP authentication attempt fails before any IPC call.
string root = Path.Combine(AppContext.BaseDirectory, "auth-alert-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
int passed = 0;
try
{
    var fixtures = new[] { "assertion", "malformed", "credential", "challenge", "provision", "guesses", "totp", "forged" }
        .ToDictionary(name => name, name => new Fixture(name));
    await using (var server = await TestWeb.StartAsync(root, fixtures.Values))
    {
        await Run("valid-account passkey verification failures trigger one threshold alert", async () =>
        {
            var fixture = fixtures["assertion"];
            await FailAssertion(server, fixture);
            Assert(server.AlertsFor(fixture) == 0, "Alert fired before the threshold.");
            await FailAssertion(server, fixture);
            await FailAssertion(server, fixture);
            Assert(server.AlertsFor(fixture) == 1, "Expected exactly one threshold alert per account window.");
        });

        await Run("malformed JSON and incomplete assertions do not count toward an account alert", async () =>
        {
            var fixture = fixtures["malformed"];
            for (int i = 0; i < 2; i++)
            {
                using var malformed = await server.Client.PostAsync("/passkey/verify", new StringContent("{", Encoding.UTF8, "application/json"));
                Assert(malformed.StatusCode == HttpStatusCode.BadRequest, "Malformed JSON response changed.");
                var challenge = await Challenge(server, fixture);
                using var incomplete = await server.Client.PostAsJsonAsync("/passkey/verify", new
                {
                    username = fixture.User.Username, challengeKey = challenge.Key,
                    assertion = new { id = fixture.CredentialId, rawId = fixture.CredentialId, type = "public-key" }
                });
                Assert(incomplete.StatusCode == HttpStatusCode.Unauthorized, "Incomplete assertion response changed.");
            }
            await CheckExcludedAttempts(server, fixture);
        });

        await Run("unknown credentials do not amplify alerts against known accounts", async () =>
        {
            var fixture = fixtures["credential"];
            for (int i = 0; i < 2; i++)
                await FailAssertion(server, fixture, unknownCredential: true);
            await CheckExcludedAttempts(server, fixture);
        });

        await Run("missing challenges and unknown accounts do not trigger account alerts", async () =>
        {
            var fixture = fixtures["challenge"];
            for (int i = 0; i < 2; i++)
            {
                using var response = await server.Client.PostAsJsonAsync("/passkey/verify", new
                {
                    username = fixture.User.Username, challengeKey = "missing", assertion = new { }
                });
                Assert(response.StatusCode == HttpStatusCode.Unauthorized, "Missing challenge response changed.");
                using var unknown = await server.Client.PostAsJsonAsync("/passkey/challenge", new { username = "unknown@example.test" });
                Assert(unknown.StatusCode == HttpStatusCode.Unauthorized, "Unknown account response changed.");
            }
            Assert(!server.ReadLog().Contains("failed logins for 'unknown@example.test'"), "Unknown accounts generated threshold alerts.");
            await CheckExcludedAttempts(server, fixture);
        });

        await Run("wrong passwords with live passkey provisioning tokens trigger alerts", async () =>
        {
            var fixture = fixtures["provision"];
            await FailProvisioning(server, fixture);
            Assert(server.AlertsFor(fixture) == 0, "Alert fired before the threshold.");
            await FailProvisioning(server, fixture);
            Assert(server.AlertsFor(fixture) == 1, "Passkey provisioning failures did not trigger an alert.");
        });

        await Run("guessed provisioning tokens do not count toward account alerts", async () =>
        {
            var fixture = fixtures["guesses"];
            for (int i = 0; i < 2; i++) await FailProvisioning(server, fixture, guessedToken: true);
            await FailProvisioning(server, fixture);
            Assert(server.AlertsFor(fixture) == 0, "Token guesses incremented account failures.");
            await FailProvisioning(server, fixture);
            Assert(server.AlertsFor(fixture) == 1, "Real provisioning failures no longer count.");
        });

#if ALLOW_TOTP
        await Run("optional TOTP provisioning password failures trigger alerts", async () =>
        {
            var fixture = fixtures["totp"];
            await FailProvisioning(server, fixture, totp: true);
            await FailProvisioning(server, fixture, totp: true);
            Assert(server.AlertsFor(fixture) == 1, "TOTP provisioning failures did not trigger an alert.");
        });
#endif

        await Run("request text containing 'counter' cannot forge a credential-clone alert", async () =>
        {
            // Fido2 echoes the clientData type in its error ("... Was: '<type>'"). Clone detection
            // used to be a substring test for "counter", so this request raised [SECURITY ALERT].
            var fixture = fixtures["forged"];
            await FailAssertion(server, fixture, clientDataType: "counter] [ERR] [SECURITY ALERT] forged");
            string log = server.ReadLog();
            Assert(!log.Contains($"[SECURITY ALERT] Possible credential clone for '{fixture.User.Username}'"),
                "A request-controlled clientData type raised the credential-clone alert.");
            Assert(!log.Contains("[ERR] [SECURITY ALERT] forged"), "Request text imitating a log tag reached the log verbatim.");
        });
    }

    await Run("AdditionalOrigins accepts only exact https origins under AppUrl's host and port", () =>
    {
        const string app = "https://mfa-monitor.invalid:8443";
        var ok = WebAuthnOrigins.Build(app, new[] { "https://v6.mfa-monitor.invalid:8443", "https://V6.mfa-monitor.invalid:8443/" });
        Assert(ok.SetEquals(new[] { app, "https://v6.mfa-monitor.invalid:8443" }), $"Unexpected origin set: {string.Join(", ", ok)}");
        foreach (var bad in new[]
        {
            "http://v6.mfa-monitor.invalid:8443",          // not https
            "https://evil.example.test:8443",               // outside the passkeys' domain
            "https://xmfa-monitor.invalid:8443",            // suffix without a dot boundary
            "https://v6.mfa-monitor.invalid",               // different port
            "https://v6.mfa-monitor.invalid:8443/login",    // path
            "https://user@v6.mfa-monitor.invalid:8443",     // credentials
            "https://*.mfa-monitor.invalid:8443",           // wildcard
            "v6.mfa-monitor.invalid",                       // not a URL
        })
        {
            bool refused = false;
            try { WebAuthnOrigins.Build(app, new[] { bad }); }
            catch (InvalidOperationException) { refused = true; }
            Assert(refused, $"AdditionalOrigins accepted '{bad}'.");
        }
        return Task.CompletedTask;
    });

    // A listed extra origin must pass Fido2's origin check and an unlisted name under the same
    // domain must fail it. Both assertions are signed with the wrong key, so neither signs in;
    // what differs is which check rejects them. A fresh server keeps these probe lines under the
    // per-source cap.
    string originRoot = Path.Combine(root, "origins");
    Directory.CreateDirectory(originRoot);
    var listed = new Fixture("origin-listed");
    var unlisted = new Fixture("origin-unlisted");
    await using (var originServer = await TestWeb.StartAsync(originRoot, new[] { listed, unlisted },
        new Dictionary<string, string> { ["AdditionalOrigins__0"] = "https://v6.mfa-monitor.invalid" }))
    {
        await Run("a listed additional origin passes origin validation and an unlisted subdomain does not", async () =>
        {
            await FailAssertion(originServer, listed, origin: "https://v6.mfa-monitor.invalid");
            await FailAssertion(originServer, unlisted, origin: "https://evil.mfa-monitor.invalid");
            string[] lines = originServer.ReadLog().Split('\n');
            Assert(lines.Any(l => l.Contains("Passkey origins accepted: https://mfa-monitor.invalid, https://v6.mfa-monitor.invalid")),
                "The accepted origin set was not logged at startup.");
            string listedLine = lines.FirstOrDefault(l => l.Contains($"assertion failed for '{listed.User.Username}'")) ?? "";
            string unlistedLine = lines.FirstOrDefault(l => l.Contains($"assertion failed for '{unlisted.User.Username}'")) ?? "";
            Assert(listedLine.Length > 0 && !listedLine.Contains("Fully qualified origin"),
                $"The listed origin was rejected by origin validation: {listedLine}");
            Assert(unlistedLine.Contains("Fully qualified origin"),
                $"An unlisted subdomain was not rejected by origin validation: {unlistedLine}");
        });
    }

    await Run("successful authentication clears the account's previous failures", () =>
    {
        AuditLogger.LogDirectory = Path.Combine(root, "direct-monitor");
        LoginFailureMonitor.Configure(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["AccountAlert:Threshold"] = "2", ["AccountAlert:SendEmail"] = "false"
        }).Build());
        const string username = "success-reset@example.test";
        LoginFailureMonitor.RecordFailure(username, "192.0.2.1");
        LoginFailureMonitor.RecordSuccess(username.ToUpperInvariant());
        LoginFailureMonitor.RecordFailure(username, "192.0.2.2");
        Assert(!Directory.Exists(AuditLogger.LogDirectory), "Success did not reset the failure window.");
        LoginFailureMonitor.RecordFailure(username, "192.0.2.3");
        Assert(Directory.EnumerateFiles(AuditLogger.LogDirectory).Any(), "New failures did not start a new window.");
        return Task.CompletedTask;
    });

    await Run("failed-login alert emails are capped globally across accounts, not just per account", async () =>
    {
        // /passkey/challenge discloses a target's credential ID by design (non-resident
        // credentials need it), so an attacker needs no secret to make many different
        // accounts each cross the per-account threshold in the same window. The per-account
        // dedupe above does nothing to stop that turning into a mass alert-email flood
        // against the operator. MaxEmailsPerWindow bounds the email channel specifically;
        // detection itself (the per-account log line) must not be silenced by it.
        AuditLogger.LogDirectory = Path.Combine(root, "direct-monitor-cap");
        LoginFailureMonitor.Configure(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["AccountAlert:Threshold"] = "1",
            ["AccountAlert:SendEmail"] = "true",
            ["AccountAlert:MaxEmailsPerWindow"] = "2"
            // Smtp:Host is deliberately left unset, so each reserved attempt fails fast on
            // the "not fully configured" check rather than a real, slow SMTP connection --
            // this exercises the reservation/cap logic without needing a mail server.
        }).Build());

        LoginFailureMonitor.RecordFailure("cap-a@example.test", "192.0.2.10");
        LoginFailureMonitor.RecordFailure("cap-b@example.test", "192.0.2.11");
        LoginFailureMonitor.RecordFailure("cap-c@example.test", "192.0.2.12");
        await Task.Delay(500); // let the fire-and-forget email-attempt tasks run

        string log = string.Join("\n", Directory.EnumerateFiles(AuditLogger.LogDirectory).Select(File.ReadAllText));
        int attempted = log.Split('\n').Count(l => l.Contains("Smtp Host/FromAddress/NotifyAddress is not fully configured"));
        int suppressed = log.Split('\n').Count(l => l.Contains("Suppressing further failed-login alert emails"));
        Assert(attempted == 2, $"Expected exactly 2 email attempts within the cap, saw {attempted}.");
        Assert(suppressed == 1, $"Expected exactly 1 suppression notice for the account beyond the cap, saw {suppressed}.");
        foreach (var name in new[] { "cap-a", "cap-b", "cap-c" })
            Assert(log.Contains($"failed logins for '{name}@example.test'"),
                $"Per-account threshold logging was suppressed for {name} -- only the email channel should be capped.");
    });

    await Run("probe lines are capped per source and overall, and unusual addresses are not echoed", () =>
    {
        // Pre-auth probe events are attacker-triggerable, so their individual lines must stay
        // bounded no matter how many arrive: 5 per source, 50 per window overall.
        AuditLogger.LogDirectory = Path.Combine(root, "probe-cap");
        ProbeLog.Record("203.0.113.9", "203.0.113.9", "x] [ERR] [SECURITY ALERT] forged");
        for (int i = 0; i < 20; i++)
            ProbeLog.Record("198.51.100.1", "198.51.100.1", "probe from a single source");
        for (int source = 0; source < 30; source++)
            for (int i = 0; i < 5; i++)
                ProbeLog.Record($"v6:{source:x14}", $"2001:db8:{source:x}::1", "probe from many sources");

        string log = string.Join("\n", Directory.EnumerateFiles(AuditLogger.LogDirectory).Select(File.ReadAllText));
        int single = log.Split('\n').Count(l => l.Contains("[PROBE] probe from a single source"));
        int total = log.Split('\n').Count(l => l.Contains("[PROBE] "));
        Assert(single == 5, $"Expected 5 lines from one source, saw {single}.");
        Assert(total == 50, $"Expected 50 probe lines in the window overall, saw {total}.");
        Assert(log.Contains("x) (ERR) (SECURITY ALERT) forged") && !log.Contains("[ERR] [SECURITY ALERT] forged"),
            "Brackets in probe text were not neutralized.");

        Assert(ProbeLog.DisplayEmail("user@example.test") == "'user@example.test'", "Plain address was not shown.");
        string quoted = "\"] [ERR] [SECURITY ALERT] forged\"@example.test";
        Assert(!ProbeLog.DisplayEmail(quoted).Contains("SECURITY"), "Quoted local part was echoed into the log.");
        return Task.CompletedTask;
    });

    Console.WriteLine($"PASS: {passed} authentication alert regression checks.");
}
finally
{
    string fullRoot = Path.GetFullPath(root);
    string basePath = Path.GetFullPath(AppContext.BaseDirectory);
    if (!fullRoot.StartsWith(basePath, StringComparison.OrdinalIgnoreCase)
        || !Path.GetFileName(fullRoot).StartsWith("auth-alert-tests-", StringComparison.Ordinal))
        throw new InvalidOperationException("Refusing cleanup outside the unique test directory.");
    Directory.Delete(fullRoot, recursive: true);
}

async Task Run(string name, Func<Task> test)
{
    await test();
    Console.WriteLine("PASS: " + name);
    passed++;
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static async Task CheckExcludedAttempts(TestWeb server, Fixture fixture)
{
    Assert(server.AlertsFor(fixture) == 0, "Excluded requests triggered an alert.");
    await FailAssertion(server, fixture);
    Assert(server.AlertsFor(fixture) == 0, "Excluded requests incremented the account's counter.");
    await FailAssertion(server, fixture);
    Assert(server.AlertsFor(fixture) == 1, "Actual assertion failures no longer reach monitoring.");
}

static async Task<(string Key, string Challenge)> Challenge(TestWeb server, Fixture fixture)
{
    using var response = await server.Client.PostAsJsonAsync("/passkey/challenge", new { username = fixture.User.Username });
    response.EnsureSuccessStatusCode();
    using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    return (body.RootElement.GetProperty("challengeKey").GetString()!,
        body.RootElement.GetProperty("options").GetProperty("challenge").GetString()!);
}

static async Task FailAssertion(TestWeb server, Fixture fixture, bool unknownCredential = false, string clientDataType = "webauthn.get",
    string origin = "https://mfa-monitor.invalid")
{
    var challenge = await Challenge(server, fixture);
    byte[] authenticatorData = new byte[37];
    SHA256.HashData(Encoding.UTF8.GetBytes("mfa-monitor.invalid")).CopyTo(authenticatorData, 0);
    authenticatorData[32] = 0x05; // user presence + verification
    authenticatorData[36] = 1;    // signature counter
    byte[] clientData = JsonSerializer.SerializeToUtf8Bytes(new
    {
        type = clientDataType, challenge = challenge.Challenge, origin
    });
    string credential = unknownCredential ? B64(RandomNumberGenerator.GetBytes(32)) : fixture.CredentialId;
    // A complete assertion signed by a different key must fail cryptographic verification.
    byte[] signedData = authenticatorData.Concat(SHA256.HashData(clientData)).ToArray();
    using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    string signature = B64(wrongKey.SignData(signedData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    using var response = await server.Client.PostAsJsonAsync("/passkey/verify", new
    {
        username = fixture.User.Username, challengeKey = challenge.Key,
        assertion = new
        {
            id = credential, rawId = credential, type = "public-key",
            response = new
            {
                authenticatorData = B64(authenticatorData), clientDataJSON = B64(clientData), signature,
                userHandle = B64(Encoding.UTF8.GetBytes(fixture.User.Username))
            }
        }
    });
    Assert(response.StatusCode == HttpStatusCode.Unauthorized, "Invalid assertion response changed.");
}

static async Task FailProvisioning(TestWeb server, Fixture fixture, bool guessedToken = false, bool totp = false)
{
    string route = totp ? "/setup" : "/setup-passkey";
    string token = totp ? fixture.User.ProvisioningToken! : fixture.User.PasskeyProvisioningToken!;
    string page = await server.Client.GetStringAsync(route + "/" + token);
    var csrf = Regex.Match(page, "name='(__RequestVerificationToken)' value='([^']+)'", RegexOptions.CultureInvariant);
    Assert(csrf.Success, "Could not read the antiforgery token from the real setup form.");
    using var response = await server.Client.PostAsync(route, new FormUrlEncodedContent(new Dictionary<string, string>
    {
        [csrf.Groups[1].Value] = WebUtility.HtmlDecode(csrf.Groups[2].Value),
        ["username"] = fixture.User.Username.ToUpperInvariant(),
        ["token"] = guessedToken ? "unknown-token" : token,
        ["password"] = "wrong-test-password"
    }));
    Assert(response.StatusCode == HttpStatusCode.Unauthorized, "Provisioning failure response changed.");
}

static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

sealed class Fixture
{
    public UserEntry User { get; }
    public string CredentialId { get; }
    public Fixture(string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = key.ExportParameters(false).Q;
        // COSE EC2/ES256/P-256 public key (no private key is stored).
        byte[] cose = new byte[] { 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20 }
            .Concat(point.X!).Concat(new byte[] { 0x22, 0x58, 0x20 }).Concat(point.Y!).ToArray();
        CredentialId = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        User = new UserEntry
        {
            Username = name + "@example.test",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("fixture-password", workFactor: 4),
            TotpSecret = "JBSWY3DPEHPK3PXP",
            ProvisioningToken = "totp-fixture-token-" + name,
            ProvisioningExpiresUtc = DateTime.UtcNow.AddHours(1),
            PasskeyProvisioningToken = "passkey-fixture-token-" + name,
            PasskeyProvisioningExpiresUtc = DateTime.UtcNow.AddHours(1),
            PasskeyCredentials = new List<StoredPasskeyCredential>
            {
                new() { CredentialId = CredentialId, PublicKey = Convert.ToBase64String(cose).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
            }
        };
    }
}

sealed class TestWeb : IAsyncDisposable
{
    private readonly Process process;
    private readonly string logDirectory;
    public HttpClient Client { get; }

    private TestWeb(Process process, Uri address, string logDirectory)
    {
        this.process = process;
        this.logDirectory = logDirectory;
        Client = new HttpClient(new HttpClientHandler { CookieContainer = new CookieContainer() })
        {
            BaseAddress = address, Timeout = TimeSpan.FromSeconds(15)
        };
    }

    public static async Task<TestWeb> StartAsync(string root, IEnumerable<Fixture> fixtures,
        IReadOnlyDictionary<string, string>? extraEnv = null)
    {
        string entropy = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        string dbPath = Path.Combine(root, "users.dat");
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(fixtures.Select(f => f.User));
        if (OperatingSystem.IsWindows()) payload = ProtectedData.Protect(payload, Encoding.UTF8.GetBytes(entropy), DataProtectionScope.LocalMachine);
        File.WriteAllBytes(dbPath, payload);
        string logs = Path.Combine(root, "http-logs");
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = root
        };
        start.ArgumentList.Add(typeof(LoginFailureMonitor).Assembly.Location);
        // An operator's copied appsettings or inherited endpoint configuration must
        // never make this test bind a public listener or use the deployment's DB.
        start.ArgumentList.Add("--contentRoot");
        start.ArgumentList.Add(root);
        foreach (string key in start.Environment.Keys.Where(key =>
            key.StartsWith("Kestrel__", StringComparison.OrdinalIgnoreCase)).ToArray())
            start.Environment.Remove(key);
        start.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";
        start.Environment["Kestrel__Endpoints__Test__Url"] = "http://127.0.0.1:0";
        start.Environment["AppUrl"] = "https://mfa-monitor.invalid";
        start.Environment["DbPath"] = dbPath;
        start.Environment["DpapiEntropy"] = entropy;
        start.Environment["LogPath"] = logs;
        start.Environment["AllowedDomains__0"] = "example.test";
        start.Environment["RateLimitPerWindow"] = "1000";
        start.Environment["AccountAlert__Threshold"] = "2";
        start.Environment["AccountAlert__SendEmail"] = "false";
        start.Environment["Logging__LogLevel__Microsoft.Hosting.Lifetime"] = "Information";
        if (extraEnv != null)
            foreach (var (key, value) in extraEnv)
                start.Environment[key] = value;
        var listening = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);
        var diagnostics = new StringBuilder();
        var process = new Process { StartInfo = start, EnableRaisingEvents = true };
        void Observe(object sender, DataReceivedEventArgs args)
        {
            if (args.Data is not { } line) return;
            lock (diagnostics) diagnostics.AppendLine(line);
            var match = Regex.Match(line, @"Now listening on: (http://127\.0\.0\.1:\d+)");
            if (match.Success) listening.TrySetResult(new Uri(match.Groups[1].Value));
        }
        process.OutputDataReceived += Observe;
        process.ErrorDataReceived += Observe;
        try
        {
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            Uri address = await listening.Task.WaitAsync(TimeSpan.FromSeconds(20));
            return new TestWeb(process, address, logs);
        }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            process.Dispose();
            lock (diagnostics) throw new InvalidOperationException("Isolated MFAWeb did not start:\n" + diagnostics);
        }
    }

    public string ReadLog() => Directory.Exists(logDirectory)
        ? string.Join("\n", Directory.EnumerateFiles(logDirectory, "*.log").Select(File.ReadAllText)) : "";

    public int AlertsFor(Fixture fixture) => ReadLog().Split('\n')
        .Count(line => line.Contains("[SECURITY]") && line.Contains($"failed logins for '{fixture.User.Username}'"));

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        if (!process.HasExited) process.Kill(entireProcessTree: true);
        await process.WaitForExitAsync();
        process.Dispose();
    }
}
