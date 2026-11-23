using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;

// Harmless child modes exercise the real process runner without launching a shell or firewall.
if (args.FirstOrDefault() == "child")
{
    switch (args[1])
    {
        case "failure": Console.Error.Write("expected diagnostic"); return 7;
        case "flood": Console.Error.Write(new string('x', 256 * 1024)); Console.Write("complete"); return 0;
        case "sleep": Thread.Sleep(TimeSpan.FromSeconds(30)); return 0;
        default: throw new InvalidOperationException("Unknown child mode");
    }
}

ServiceLogger.LogDirectory = Path.Combine(AppContext.BaseDirectory, "test-logs");
const string Request = "8.8.8.8|review@example.com";
const string RequestV6 = "2001:4860:4860::8888|review@example.com";
int failed = 0;
int ran = 0;
Test("subprocess exit failure includes stderr", () =>
{
    var error = Throws<InvalidOperationException>(() => FirewallCommandRunner.Run(Child("failure")));
    Check(error.Message.Contains("code 7") && error.Message.Contains("expected diagnostic"));
});
Test("subprocess drains stderr and stdout concurrently", () =>
{
    var output = FirewallCommandRunner.Run(Child("flood"), TimeSpan.FromSeconds(10));
    Check(output.StandardOutput == "complete" && output.StandardError.Length == 256 * 1024);
});
Test("subprocess timeout terminates bounded execution", () =>
{
    var watch = Stopwatch.StartNew();
    Throws<TimeoutException>(() => FirewallCommandRunner.Run(Child("sleep"), TimeSpan.FromMilliseconds(250)));
    Check(watch.Elapsed < TimeSpan.FromSeconds(5));
});
Test("Linux grant command failure reaches IPC", () =>
{
    var commands = new FakeCommands { FailInsert = true };
    Check(Worker(commands).ProcessFirewallRequest(Request).StartsWith("ERROR:"));
});
Test("Linux missing grant after command success reaches IPC", () =>
{
    var commands = new FakeCommands { IgnoreInsert = true };
    Check(Worker(commands).ProcessFirewallRequest(Request).StartsWith("ERROR:"));
});
Test("Linux grant identities separate ports and protocols on renew", () =>
{
    var commands = new FakeCommands();
    var worker = Worker(commands, "2222/TCP", "22/UDP", "22/TCP");
    Check(worker.ProcessFirewallRequest(Request) == "SUCCESS");
    Check(worker.ProcessFirewallRequest(Request) == "SUCCESS");
    Check(commands.Rules.Count == 3);
    foreach (var suffix in new[] { "_2222_TCP", "_22_UDP", "_22_TCP" })
        Check(commands.Rules.Count(rule => rule.Contains(suffix + " user:")) == 1);
});
Test("Linux expiry removes legacy and current names but preserves future and unrelated rules", () =>
{
    var commands = new FakeCommands();
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_22", 1));
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_22_TCP", 1));
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_2222_TCP", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()));
    commands.Rules.Add(Rule("other_MFA_Temp_rule", 1));
    Worker(commands).SweepExpiredRules();
    Check(commands.Rules.Count == 2);
    Check(commands.Rules.Any(rule => rule.Contains("_2222_TCP")));
    Check(commands.Rules.Any(rule => rule.Contains("other_MFA_Temp_rule")));
});
Test("Linux failed deletion is not logged as removed", () =>
{
    var commands = new FakeCommands { IgnoreDelete = true };
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_22_TCP", 1));
    string log = CaptureConsole(() => Throws<InvalidOperationException>(() => Worker(commands).SweepExpiredRules()));
    Check(commands.Rules.Count == 1 && !log.Contains("removed:") && !log.Contains("Done. Removed"));
});
Test("Linux custom prefixes with spaces preserve renewals and legacy expiry", () =>
{
    var commands = new FakeCommands();
    commands.Rules.Add(Rule("MFA Temp_8.8.8.8_22", 1));
    commands.Rules.Add(Rule("MFA Temp_8.8.8.8_2222_TCP", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()));
    var worker = WorkerWithPrefix(commands, "MFA Temp_");
    Check(worker.ProcessFirewallRequest(Request) == "SUCCESS");
    Check(worker.ProcessFirewallRequest(Request) == "SUCCESS");
    Check(commands.Rules.Count == 3);
    worker.SweepExpiredRules();
    Check(commands.Rules.Count == 2);
    Check(commands.Rules.Count(rule => rule.Contains("MFA Temp_8.8.8.8_22_TCP user:")) == 1);
    Check(commands.Rules.Count(rule => rule.Contains("MFA Temp_8.8.8.8_2222_TCP exp:")) == 1);
});
Test("rule prefixes that would break quoting or rule parsing are refused at startup", () =>
{
    foreach (var bad in new[] { "MFA\"Temp_", "MFA'Temp_", "MFA$(id)_", "MFA`Temp_", "MFA_Temp_\n", "", new string('A', 65) })
    {
        bool refused = false;
        try { WorkerWithPrefix(new FakeCommands(), bad); }
        catch (InvalidOperationException) { refused = true; }
        Check(refused);
    }
    Check(FirewallWorkerService.ValidateRulePrefix("MFA Temp_.-1") == "MFA Temp_.-1");
});
Test("quoted local parts are refused before reaching a firewall command", () =>
{
    // MailAddress accepts these; the Windows rule description would carry the text verbatim.
    var commands = new FakeCommands();
    foreach (var user in new[] { "\"x Exp: 2000-01-01 00:00\"@example.com", "\"a b\"@example.com" })
        Check(Worker(commands).ProcessFirewallRequest($"8.8.8.8|{user}") == "ERROR: Invalid username");
    Check(commands.Rules.Count == 0 && commands.WindowsNames.Count == 0);
});
Test("SMTP without TLS is accepted only for a relay on this machine", () =>
{
    static IConfiguration Smtp(string? useSsl) => new ConfigurationBuilder()
        .AddInMemoryCollection(useSsl == null ? Array.Empty<KeyValuePair<string, string?>>()
            : new[] { new KeyValuePair<string, string?>("Smtp:UseSsl", useSsl) }).Build();

    Check(SmtpTransportPolicy.GetUseSsl(Smtp(null), "mail.example.com"));      // default is TLS
    Check(SmtpTransportPolicy.GetUseSsl(Smtp("true"), "mail.example.com"));
    Throws<InvalidOperationException>(() => SmtpTransportPolicy.GetUseSsl(Smtp("yes"), "localhost"));

    foreach (var local in new[] { "localhost", "LOCALHOST.", "127.0.0.1", "127.5.5.5", "[::1]" })
        Check(!SmtpTransportPolicy.GetUseSsl(Smtp("false"), local));

    // Hostnames are never resolved, even this machine's own name.
    foreach (var remote in new[] { "8.8.8.8", "fe80::1", "fe80::1%2", "169.254.1.1", "0.0.0.0", "::",
                                   "224.0.0.1", "mail.example.com", System.Net.Dns.GetHostName() })
        Throws<InvalidOperationException>(() => SmtpTransportPolicy.GetUseSsl(Smtp("false"), remote));

    // An address assigned to one of this machine's interfaces that is Up counts as local.
    var own = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
        .SelectMany(n => n.GetIPProperties().UnicastAddresses)
        .Where(u => !System.Net.IPAddress.IsLoopback(u.Address) && !u.Address.IsIPv6LinkLocal
                    && !u.Address.ToString().StartsWith("169.254.")
                    && (!OperatingSystem.IsWindows() || u.DuplicateAddressDetectionState ==
                        System.Net.NetworkInformation.DuplicateAddressDetectionState.Preferred))
        .Select(u => u.Address).FirstOrDefault();
    if (own != null) Check(!SmtpTransportPolicy.GetUseSsl(Smtp("false"), own.ToString()));
    else Console.WriteLine("  (no non-loopback address on an Up interface; host-local case not exercised)");
});
Test("Linux deletion command error reaches caller", () =>
{
    var commands = new FakeCommands { FailDelete = true };
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_22_TCP", 1));
    Throws<InvalidOperationException>(() => Worker(commands).SweepExpiredRules());
    Check(commands.Rules.Count == 1);
});
Test("expiry sweeps immediately after IPC ownership", () =>
{
    var commands = new FakeCommands();
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_22_TCP", 1));
    using var cancellation = new CancellationTokenSource();
    IpcOwnership.MarkClaimed();
    Task sweeper = Worker(commands).RunSweeperAsync(cancellation.Token);
    Check(commands.Rules.Count == 0);
    cancellation.Cancel();
    Throws<OperationCanceledException>(() => sweeper.GetAwaiter().GetResult());
});
Test("Windows grant command failure reaches IPC", () =>
{
    var commands = new FakeCommands { IsWindows = true, FailInsert = true };
    Check(Worker(commands).ProcessFirewallRequest(Request).StartsWith("ERROR:"));
});
Test("Windows missing grant after command success reaches IPC", () =>
{
    var commands = new FakeCommands { IsWindows = true, IgnoreInsert = true };
    Check(Worker(commands).ProcessFirewallRequest(Request).StartsWith("ERROR:"));
});
Test("Windows protocol identities do not overwrite", () =>
{
    var commands = new FakeCommands { IsWindows = true };
    Check(Worker(commands, "22/TCP", "22/UDP").ProcessFirewallRequest(Request) == "SUCCESS");
    Check(commands.WindowsNames.SetEquals(new[] { "MFA_Temp_8.8.8.8_22_TCP", "MFA_Temp_8.8.8.8_22_UDP" }));
});
Test("Windows deletion verification failure is not logged as removed", () =>
{
    var commands = new FakeCommands { IsWindows = true, FailDelete = true };
    string log = CaptureConsole(() => Throws<InvalidOperationException>(() => Worker(commands).SweepExpiredRules()));
    Check(!log.Contains("removed:") && !log.Contains("Done. Removed"));
});
Test("invalid port configuration never reports success", () =>
{
    var commands = new FakeCommands();
    Check(Worker(commands, "invalid", "0/TCP", "22/OTHER").ProcessFirewallRequest(Request).StartsWith("ERROR:"));
    Check(commands.Rules.Count == 0);
    // A valid entry before a bad one must not be opened either: no partial grant.
    Check(Worker(commands, "22/TCP", "bad").ProcessFirewallRequest(Request).StartsWith("ERROR:"));
    Check(commands.Rules.Count == 0 && !commands.SeenScripts.Any(s => s.Contains(" -I ")));
});
Test("IPv6 zone ID is rejected before it can reach a shell command", () =>
{
    // IPAddress.TryParse accepts a zone ID (RFC 4007) containing arbitrary characters, including
    // shell metacharacters, and its own ToString() silently drops it -- so using the raw input
    // string past validation let a crafted zone ID survive into the privileged firewall
    // command built for the actual grant. FakeCommands.Iptables/PowerShell record every command
    // that would have run, so this proves the payload never reaches that far, not just that the
    // response happens to be an error.
    var commands = new FakeCommands();
    var worker = Worker(commands);
    foreach (var payload in new[] { "2001:db8::1%$(id)", "2001:db8::1%';calc;#", "2001:db8::1%eth0" })
    {
        Check(worker.ProcessFirewallRequest($"{payload}|review@example.com").StartsWith("ERROR:"));
        Check(commands.Rules.Count == 0);
        // Rejected before OpenFirewallPort runs at all -- no shell command is ever built,
        // not merely one that happens not to contain the payload.
        Check(commands.SeenScripts.Count == 0);
    }
});
Test("IPv6 grant lands in ip6tables, never iptables", () =>
{
    var commands = new FakeCommands();
    Check(Worker(commands).ProcessFirewallRequest(RequestV6) == "SUCCESS");
    Check(commands.Rules.Count == 0);
    Check(commands.Rules6.Count == 1);
    Check(commands.Rules6[0].Contains("2001:4860:4860::8888") && commands.Rules6[0].Contains("_22_TCP user:review@example.com exp:"));
});
Test("IPv4 and IPv6 grants coexist in their own tables without cross-deleting", () =>
{
    var commands = new FakeCommands();
    var worker = Worker(commands);
    Check(worker.ProcessFirewallRequest(Request) == "SUCCESS");
    Check(worker.ProcessFirewallRequest(RequestV6) == "SUCCESS");
    Check(commands.Rules.Count == 1 && commands.Rules6.Count == 1);
    // Renewing the IPv4 grant must not touch the IPv6 table, and vice versa.
    Check(worker.ProcessFirewallRequest(Request) == "SUCCESS");
    Check(commands.Rules.Count == 1 && commands.Rules6.Count == 1);
});
Test("Linux expiry sweeps both iptables and ip6tables tables", () =>
{
    var commands = new FakeCommands();
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_22_TCP", 1));
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_2222_TCP", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()));
    commands.Rules6.Add(Rule6("MFA_Temp_2001:4860:4860::8888_22_TCP", 1));
    commands.Rules6.Add(Rule6("MFA_Temp_2001:4860:4860::8888_2222_TCP", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()));
    Worker(commands).SweepExpiredRules();
    Check(commands.Rules.Count == 1 && commands.Rules.Any(r => r.Contains("_2222_TCP")));
    Check(commands.Rules6.Count == 1 && commands.Rules6.Any(r => r.Contains("_2222_TCP")));
});
Test("IPv6 grant widens to the configured prefix's containing network", () =>
{
    // Privacy-address/cellular rotation stays within the same /64, so the rule should match the
    // network, not the exact host that happened to authenticate. IPv4 is unaffected by this
    // setting -- see the Ipv6GrantPrefixLength constants' comment.
    var commands = new FakeCommands();
    Check(WorkerWithIpv6PrefixLength(commands, 64).ProcessFirewallRequest(RequestV6) == "SUCCESS");
    Check(commands.Rules6.Count == 1);
    Check(commands.Rules6[0].Contains("-s 2001:4860:4860::/64 ") && commands.Rules6[0].Contains("_22_TCP user:review@example.com exp:"));
});
Test("IPv6 grant prefix length below the documented minimum is clamped, not rejected", () =>
{
    var commands = new FakeCommands();
    Check(WorkerWithIpv6PrefixLength(commands, 32).ProcessFirewallRequest(RequestV6) == "SUCCESS");
    Check(commands.Rules6.Count == 1 && commands.Rules6[0].Contains("-s 2001:4860:4860::/64 "));
});
Test("Windows IPv6 grant also widens to the configured prefix's containing network", () =>
{
    // The widening logic lives above the platform branch in OpenFirewallPort and Windows'
    // -RemoteAddress accepts CIDR the same way ip6tables does -- this is not Linux-only.
    var commands = new FakeCommands { IsWindows = true };
    Check(WorkerWithIpv6PrefixLength(commands, 64).ProcessFirewallRequest(RequestV6) == "SUCCESS");
    Check(commands.SeenScripts.Any(s => s.Contains("$ip    = '2001:4860:4860::/64'")));
});
Test("expired provisioning is cleared, but the password only when TOTP was never confirmed", () =>
{
    var now = DateTime.UtcNow;
    var expired = now.AddMinutes(-1);

    // Unused window, TOTP never confirmed: the password has no further purpose either.
    var neverConfirmed = new UserEntry
    {
        PasswordHash = "real-hash", TotpConfirmed = false,
        ProvisioningToken = "totp-token", ProvisioningExpiresUtc = expired,
        PasskeyProvisioningToken = "passkey-token", PasskeyProvisioningExpiresUtc = expired,
        PasskeyRegistrationReady = true
    };
    Check(DatabaseLockService.TryCleanExpiredProvisioning(neverConfirmed, now));
    Check(neverConfirmed.PasswordHash == "" && neverConfirmed.ProvisioningToken == null
        && neverConfirmed.ProvisioningExpiresUtc == null && neverConfirmed.PasskeyProvisioningToken == null
        && neverConfirmed.PasskeyProvisioningExpiresUtc == null && !neverConfirmed.PasskeyRegistrationReady);

    // Same expired window, but TOTP WAS confirmed: the password is this account's ongoing
    // /auth login credential now, not just a registration bootstrap -- must survive.
    var totpConfirmed = new UserEntry
    {
        PasswordHash = "real-hash", TotpConfirmed = true,
        PasskeyProvisioningToken = "passkey-token", PasskeyProvisioningExpiresUtc = expired,
        PasskeyRegistrationReady = true
    };
    Check(DatabaseLockService.TryCleanExpiredProvisioning(totpConfirmed, now));
    Check(totpConfirmed.PasswordHash == "real-hash"); // must survive -- it's the ongoing /auth login credential
    Check(totpConfirmed.PasskeyProvisioningToken == null && !totpConfirmed.PasskeyRegistrationReady);

    // Not yet expired: nothing should change.
    var stillLive = new UserEntry
    {
        PasswordHash = "real-hash", PasskeyProvisioningToken = "t", PasskeyProvisioningExpiresUtc = now.AddMinutes(30)
    };
    Check(!DatabaseLockService.TryCleanExpiredProvisioning(stillLive, now));
    Check(stillLive.PasswordHash == "real-hash" && stillLive.PasskeyProvisioningToken == "t");

    // Already clean and expired: idempotent, reports no change on a second pass.
    Check(!DatabaseLockService.TryCleanExpiredProvisioning(neverConfirmed, now));
});
Test("Linux grant comment records the username, and parsing recovers it", () =>
{
    var commands = new FakeCommands();
    Check(Worker(commands).ProcessFirewallRequest(Request) == "SUCCESS");
    Check(commands.Rules.Count == 1 && commands.Rules[0].Contains("\"MFA_Temp_8.8.8.8_22_TCP user:review@example.com exp:"));
    Check(LinuxIptables.TryParseManagedRule(commands.Rules[0], "MFA_Temp_", out var name, out var expiry, out var user));
    Check(name == "MFA_Temp_8.8.8.8_22_TCP" && user == "review@example.com" && expiry > DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    // A rule written before the tag existed still parses, with no user.
    Check(LinuxIptables.TryParseManagedRule(Rule("MFA_Temp_8.8.8.8_22_TCP", 5), "MFA_Temp_", out name, out expiry, out user));
    Check(name == "MFA_Temp_8.8.8.8_22_TCP" && expiry == 5 && user == null);

    // Prefixes with spaces still split correctly, and another prefix's rules are not ours.
    Check(LinuxIptables.TryParseManagedRule(Rule("MFA Temp_8.8.8.8_22_TCP user:a.b+c@example.com", 5), "MFA Temp_", out name, out _, out user));
    Check(name == "MFA Temp_8.8.8.8_22_TCP" && user == "a.b+c@example.com");
    Check(!LinuxIptables.TryParseManagedRule(Rule("other_8.8.8.8_22_TCP user:a@example.com", 5), "MFA_Temp_", out _, out _, out _));
});
Test("a tagged rule is still recognized and expired by the 0.4.x parser", () =>
{
    // Downgrade safety: the parser in 0.4.1 and earlier, verbatim. If it could not read the new
    // comment, a downgrade would leave every open grant as a standing rule.
    var old = new Regex(@"(?:^|\s)--comment ""(?<name>[^""]+) exp:(?<expiry>\d+)""(?:\s|$)");
    var match = old.Match(Rule(LinuxIptables.Comment("MFA_Temp_8.8.8.8_22_TCP", "review@example.com", 42)[..^" exp:42".Length], 42));
    Check(match.Success && match.Groups["name"].Value.StartsWith("MFA_Temp_") && match.Groups["expiry"].Value == "42");
});
Test("a username too long for an iptables comment is refused before any rule is written", () =>
{
    var commands = new FakeCommands();
    string user = "a@" + string.Join('.', Enumerable.Repeat(new string('b', 60), 4)) + ".com";
    Check(Worker(commands).ProcessFirewallRequest($"8.8.8.8|{user}").Contains("too long"));
    Check(commands.Rules.Count == 0 && !commands.SeenScripts.Any(s => s.Contains(" -I ")));

    // A username that fits a 2-digit port's comment but not a 5-digit one is refused before the
    // first port is opened, not after: no partial grant.
    string Comment(string port) => LinuxIptables.Comment($"MFA_Temp_8.8.8.8_{port}_TCP", "", 99_999_999_999);
    int room = LinuxIptables.MaxCommentLength - Comment("22").Length;
    string local = new string('c', room - "@example.com".Length - 1);
    string edge = local + "@example.com";
    Check(Comment("22").Length + edge.Length <= LinuxIptables.MaxCommentLength);
    Check(Comment("51820").Length + edge.Length > LinuxIptables.MaxCommentLength);
    var two = new FakeCommands();
    Check(Worker(two, "22/TCP", "51820/UDP").ProcessFirewallRequest($"8.8.8.8|{edge}").Contains("too long"));
    Check(two.Rules.Count == 0 && !two.SeenScripts.Any(s => s.Contains(" -I ")));
});
Test("iptables runs without a shell, waits for the lock, and deletes the exact listed rule", () =>
{
    Check(LinuxIptables.Arguments(new[] { "-S", "INPUT" }).SequenceEqual(new[] { "-w", "5", "-S", "INPUT" }));
    Throws<ArgumentException>(() => LinuxIptables.BinaryPath("sh"));
    Throws<ArgumentException>(() => LinuxIptables.BinaryPath("/bin/iptables"));

    string line = "-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -m comment --comment \"MFA Temp_8.8.8.8_22_TCP user:a@example.com exp:9\" -j ACCEPT";
    Check(LinuxIptables.DeleteArguments(line).SequenceEqual(new[] { "-D", "INPUT", "-s", "8.8.8.8/32", "-p", "tcp", "-m", "tcp",
        "--dport", "22", "-m", "comment", "--comment", "MFA Temp_8.8.8.8_22_TCP user:a@example.com exp:9", "-j", "ACCEPT" }));
    // Exactly as iptables 1.8.10 prints a comment holding ' " and \ (captured from a real ruleset).
    Check(LinuxIptables.SplitRuleLine(@"-A INPUT -m comment --comment ""a\'b \""q\"" back\\slash"" -j ACCEPT")[5] == @"a'b ""q"" back\slash");
    Throws<InvalidOperationException>(() => LinuxIptables.DeleteArguments("-A FORWARD -j ACCEPT"));
    Throws<InvalidOperationException>(() => LinuxIptables.DeleteArguments("-A INPUT --comment \"unterminated"));
});
Test("DpapiEntropy is required and validated on Windows only", () =>
{
    static IConfiguration Entropy(string? value) => new ConfigurationBuilder()
        .AddInMemoryCollection(value == null ? Array.Empty<KeyValuePair<string, string?>>()
            : new[] { new KeyValuePair<string, string?>("DpapiEntropy", value) }).Build();

    if (OperatingSystem.IsWindows())
    {
        foreach (var bad in new[] { null, "", "REPLACE-WITH-A-UNIQUE-RANDOM-STRING", "too-short" })
            Throws<InvalidOperationException>(() => DpapiEntropy.Load(Entropy(bad)));
        Check(DpapiEntropy.Load(Entropy("0123456789abcdef")).Length == 16);
    }
    else
    {
        // Unused on Linux (users.dat is plain JSON), so neither required nor checked.
        Check(DpapiEntropy.Load(Entropy(null)).Length == 0);
        Check(DpapiEntropy.Load(Entropy("REPLACE-WITH-A-UNIQUE-RANDOM-STRING")).Length == 0);
    }
});
Test("the database lock file excludes a second holder until released", () =>
{
    // On Windows the lock file is SYSTEM and Administrators only, as MFAService (LocalSystem) and
    // MFAAdmin (elevated) run; an unelevated test process cannot open it. CI runs elevated.
    if (OperatingSystem.IsWindows() && !IsElevated())
    {
        Console.WriteLine("  (skipped: needs an elevated process on Windows)");
        return;
    }
    string dir = Path.Combine(Path.GetTempPath(), "mfa-lock-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    try
    {
        string db = Path.Combine(dir, "users.json");
        // A lock file that already exists with inherited permissions is corrected on first use.
        if (OperatingSystem.IsWindows()) File.WriteAllText(Path.Combine(dir, "users.lock"), "");
        using (var first = DbFileLock.TryAcquire(db, TimeSpan.FromSeconds(1)))
        {
            Check(first != null);
            var watch = Stopwatch.StartNew();
            Check(DbFileLock.TryAcquire(db, TimeSpan.FromMilliseconds(300)) == null);
            Check(watch.Elapsed >= TimeSpan.FromMilliseconds(250));
        }
        using (var again = DbFileLock.TryAcquire(db, TimeSpan.FromSeconds(1))) Check(again != null);
        Check(File.Exists(Path.Combine(dir, "users.lock")));
        if (!OperatingSystem.IsWindows())
            Check(File.GetUnixFileMode(Path.Combine(dir, "users.lock")) == (UnixFileMode.UserRead | UnixFileMode.UserWrite));
        // Its own protected ACL, not the directory's inherited one (which lets the web account
        // read the database directory): SYSTEM and Administrators only.
        if (OperatingSystem.IsWindows())
            Check(LockFileAclIsPrivate(Path.Combine(dir, "users.lock")));
    }
    finally { Directory.Delete(dir, true); }
});
Test("Windows grants record their expiry in invariant form under any system culture", () =>
{
    // ':' in a .NET format string is the culture's time separator: '.' in fi-FI, da-DK, id-ID.
    // The sweeper parses this text, so a culture-formatted expiry was never removed.
    var previous = System.Globalization.CultureInfo.CurrentCulture;
    try
    {
        foreach (var culture in new[] { "fi-FI", "da-DK", "id-ID", "th-TH" })
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo(culture);
            var commands = new FakeCommands { IsWindows = true };
            Check(Worker(commands).ProcessFirewallRequest(Request) == "SUCCESS");
            string script = commands.SeenScripts.First(s => s.Contains("New-NetFirewallRule"));
            var exp = Regex.Match(script, @"Exp: (\d{4})-\d{2}-\d{2} \d{2}:\d{2} UTC'");
            // Gregorian year even under th-TH (whose calendar is 543 years ahead); +1 allows a
            // run that straddles New Year.
            Check(exp.Success && int.Parse(exp.Groups[1].Value) is var year
                  && (year == DateTime.UtcNow.Year || year == DateTime.UtcNow.Year + 1));
        }
    }
    finally { System.Globalization.CultureInfo.CurrentCulture = previous; }
});
Test("Windows expiry carries on past a failed or unreadable rule and reports both", () =>
{
    var commands = new FakeCommands
    {
        IsWindows = true,
        SweeperOutput = string.Join('\n',
            "REMOVED|MFA_Temp_8.8.8.8_22_TCP",
            "FAILED|MFA_Temp_9.9.9.9_22_TCP|access denied",
            "UNPARSEABLE|MFA_Temp_1.1.1.1_22_TCP",
            "REMOVED|MFA_Temp_4.4.4.4_22_TCP")
    };
    string log = CaptureConsole(() =>
    {
        var error = Throws<InvalidOperationException>(() => Worker(commands).SweepExpiredRules());
        Check(error.Message.Contains("MFA_Temp_9.9.9.9_22_TCP: access denied") && error.Message.Contains("MFA_Temp_1.1.1.1_22_TCP has the prefix but no readable expiry")
              && error.Message.Contains("removed 2 rule(s)"));
    });
    Check(log.Contains("removed: MFA_Temp_8.8.8.8_22_TCP") && log.Contains("removed: MFA_Temp_4.4.4.4_22_TCP"));
    // The script itself handles each rule on its own and accepts the older '.' time separator.
    string script = commands.SeenScripts.Single(s => s.Contains("Remove-NetFirewallRule"));
    Check(script.Contains("[:.]") && script.Contains("catch") && script.Contains("[cultureinfo]::InvariantCulture"));
});
Test("Linux expiry carries on past a rule it cannot delete, in both tables", () =>
{
    var commands = new FakeCommands { FailDeleteMatching = "9.9.9.9" };
    commands.Rules.Add(Rule("MFA_Temp_9.9.9.9_22_TCP", 1).Replace("8.8.8.8/32", "9.9.9.9/32"));
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_22_TCP", 1));
    commands.Rules6.Add(Rule6("MFA_Temp_2001:4860:4860::8888_22_TCP", 1));
    commands.Rules.Add("-A INPUT -s 7.7.7.7/32 -p tcp -m tcp --dport 22 -m comment --comment \"MFA_Temp_7.7.7.7_22_TCP\" -j ACCEPT");
    // iptables prints a one-word comment without quotes.
    commands.Rules.Add("-A INPUT -s 6.6.6.6/32 -p tcp -m tcp --dport 22 -m comment --comment MFA_Temp_mine -j ACCEPT");
    var error = Throws<InvalidOperationException>(() => Worker(commands).SweepExpiredRules());
    Check(error.Message.Contains("MFA_Temp_9.9.9.9_22_TCP") && error.Message.Contains("no readable expiry") && error.Message.Contains("removed 2 rule(s)"));
    Check(error.Message.Contains("MFA_Temp_7.7.7.7_22_TCP") && error.Message.Contains("--comment MFA_Temp_mine"));
    Check(commands.Rules.Count == 3 && commands.Rules6.Count == 0);
    Check(commands.Rules.Any(r => r.Contains("9.9.9.9")) && commands.Rules.Any(r => r.Contains("7.7.7.7")));
});
Test("privileged log files: only a regular file of our own is used; anything else is set aside", () =>
{
    string dir = Path.Combine(Path.GetTempPath(), "mfa-logs-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    try
    {
        // Missing: created. Present and ours: used as is, with no note.
        string day = Path.Combine(dir, "mfaservice_2026-01-01.log");
        var (created, note) = PrivilegedLogFile.Prepare(day);
        Check(created == day && File.Exists(day) && (note == null || note.Contains("not sticky")));
        File.AppendAllText(day, "ours");
        (created, note) = PrivilegedLogFile.Prepare(day);
        Check(created == day && File.ReadAllText(day) == "ours" && (note == null || note.Contains("not sticky")));

        if (!OperatingSystem.IsWindows())
        {
            string target = Path.Combine(dir, "target.txt");
            File.WriteAllText(target, "untouched");

            string link = Path.Combine(dir, "mfaservice_2026-01-02.log");
            File.CreateSymbolicLink(link, target);
            (created, note) = PrivilegedLogFile.Prepare(link);
            Check(created == link && new FileInfo(link).LinkTarget == null && note!.Contains("set aside"));

            string hard = Path.Combine(dir, "mfaservice_2026-01-03.log");
            Check(Process.Start("ln", new[] { target, hard })!.WaitForExit(5000));
            (created, note) = PrivilegedLogFile.Prepare(hard);
            Check(created == hard && note!.Contains("hard link"));

            string fifo = Path.Combine(dir, "mfaservice_2026-01-04.log");
            Check(Process.Start("mkfifo", new[] { fifo })!.WaitForExit(5000));
            (created, note) = PrivilegedLogFile.Prepare(fifo);   // must not block
            Check(created == fifo && (File.GetUnixFileMode(fifo) & UnixFileMode.UserWrite) != 0 && note!.Contains("not a regular file"));
            File.AppendAllText(fifo, "ok");                      // a regular file now: does not block

            Check(File.ReadAllText(target) == "untouched");
            Check(Directory.GetFileSystemEntries(dir, "untrusted-*").Length == 3);
        }
    }
    finally { Directory.Delete(dir, true); }
});
Test("Windows privileged log files: links and files we cannot inspect are set aside", () =>
{
    if (!OperatingSystem.IsWindows()) return;
    if (!IsElevated()) { Console.WriteLine("  (skipped: needs an elevated process on Windows)"); return; }
    string dir = Path.Combine(Path.GetTempPath(), "mfa-wlogs-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    static void Run(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true,
                                               RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var proc = Process.Start(psi)!;
        proc.WaitForExit(15000);
        if (proc.ExitCode != 0) throw new Exception($"{file} {string.Join(' ', args)} failed: {proc.StandardError.ReadToEnd()}");
    }
    try
    {
        string target = Path.Combine(dir, "target.txt");
        File.WriteAllText(target, "untouched");

        string link = Path.Combine(dir, "mfaservice_2026-01-01.log");
        File.CreateSymbolicLink(link, target);
        var (used, note) = PrivilegedLogFile.Prepare(link);
        Check(used == link && !new FileInfo(link).Attributes.HasFlag(FileAttributes.ReparsePoint) && note!.Contains("set aside"));

        string hard = Path.Combine(dir, "mfaservice_2026-01-02.log");
        Run("cmd.exe", "/c", "mklink", "/H", hard, target);
        (used, note) = PrivilegedLogFile.Prepare(hard);
        Check(used == hard && note!.Contains("hard link"));

        // Owned by LOCAL SERVICE, with a DACL that leaves us out, so its owner cannot be read.
        string foreign = Path.Combine(dir, "mfaservice_2026-01-03.log");
        File.WriteAllText(foreign, "[forged]");
        Run("icacls.exe", foreign, "/setowner", "*S-1-5-19");
        Run("icacls.exe", foreign, "/inheritance:r", "/grant:r", "*S-1-5-19:F");
        // Either outcome is safe: set aside and replaced, or -- when Windows refuses even the
        // rename, as it can for a file whose DACL leaves us out -- left in place while the log
        // goes to a uniquely named file. Never written to, and always reported.
        (used, note) = PrivilegedLogFile.Prepare(foreign);
        Check(note!.Contains("not created by this account") && File.Exists(used) && File.ReadAllText(used) == "");
        Check(used == foreign ? note.Contains("set aside") : note.Contains("writing to"));

        Check(File.ReadAllText(target) == "untouched");
        Check(Directory.GetFileSystemEntries(dir, "untrusted-*").Length >= 2);
    }
    finally
    {
        Run("takeown.exe", "/f", dir, "/r", "/d", "y");
        Run("icacls.exe", dir, "/reset", "/t", "/q");
        Directory.Delete(dir, true);
    }
});
Test("an IPv4-mapped IPv6 address is granted as IPv4", () =>
{
    var commands = new FakeCommands();
    Check(Worker(commands).ProcessFirewallRequest("::ffff:8.8.8.8|review@example.com") == "SUCCESS");
    Check(commands.Rules.Count == 1 && commands.Rules6.Count == 0 && commands.Rules[0].Contains("-s 8.8.8.8/32 "));
});
Test("an IPv4-mapped private or loopback address is refused", () =>
{
    var commands = new FakeCommands();
    foreach (string mapped in new[] { "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:192.168.1.1" })
        Check(Worker(commands).ProcessFirewallRequest($"{mapped}|review@example.com") != "SUCCESS");
    Check(commands.Rules.Count == 0 && commands.Rules6.Count == 0);
});
// The host reads appsettings.json only: an appsettings.{Environment}.json beside the program,
// which only someone with write access there could have created, must not override it.
Test("configuration ignores environment-named settings files", () =>
{
    string dir = Path.Combine(Path.GetTempPath(), "mfa-cfg-" + Guid.NewGuid().ToString("N")[..8]);
    Directory.CreateDirectory(dir);
    try
    {
        File.WriteAllText(Path.Combine(dir, "appsettings.json"), "{\"FirewallService\":{\"GmsaAccount\":\"mfaweb\"}}");
        File.WriteAllText(Path.Combine(dir, "appsettings.Production.json"), "{\"FirewallService\":{\"GmsaAccount\":\"attacker\"}}");
        var b = Microsoft.Extensions.Hosting.Host.CreateApplicationBuilder(new Microsoft.Extensions.Hosting.HostApplicationBuilderSettings
            { ContentRootPath = dir, EnvironmentName = "Production" });
        Check(b.Configuration["FirewallService:GmsaAccount"] == "attacker");   // the default would use it
        ConfigFiles.UseAppSettingsJsonOnly(b.Configuration);
        Check(b.Configuration["FirewallService:GmsaAccount"] == "mfaweb");
    }
    finally { Directory.Delete(dir, true); }
});
// Runs the real expiry script against the real Windows Firewall, using disabled rules under a
// random prefix that are always removed afterwards. Opt-in: it needs an elevated process and
// changes the machine's firewall configuration, so CI's throwaway Windows runner turns it on.
if (OperatingSystem.IsWindows() && Environment.GetEnvironmentVariable("MFA_LIVE_FIREWALL_TESTS") == "1")
    Test("Windows expiry against the real firewall: old and new formats, beyond-max, unreadable", () =>
    {
        string prefix = "MFAtest" + Guid.NewGuid().ToString("N")[..8] + "_";
        string Make(string suffix, string description)
        {
            string name = prefix + suffix;
            FirewallWorkerService.RunPowerShell($"New-NetFirewallRule -Name '{name}' -DisplayName '{name}' " +
                $"-Description '{description}' -Direction Inbound -Protocol TCP -LocalPort 22 " +
                "-RemoteAddress 192.0.2.10 -Action Allow -Enabled False | Out-Null");
            return name;
        }
        bool Exists(string name) => FirewallWorkerService.RunPowerShell(
            $"Get-NetFirewallRule -ErrorAction Stop | Where-Object {{ $_.Name -eq '{name}' }} | Select-Object -ExpandProperty Name").Trim() == name;
        try
        {
            var invariant = System.Globalization.CultureInfo.InvariantCulture;
            string colon = Make("expired_colon", "User: a@example.com Exp: 2000-01-01 00:00 UTC");
            string dot = Make("expired_dot", "User: a@example.com Exp: 2000-01-01 00.00 UTC");
            string liveRule = Make("live", $"User: a@example.com Exp: {DateTime.UtcNow.AddHours(2).ToString("yyyy-MM-dd HH:mm", invariant)} UTC");
            string thai = Make("beyond_max", $"User: a@example.com Exp: {DateTime.UtcNow.Year + 543}-01-01 00:00 UTC");
            string unreadable = Make("unreadable", "no expiry here");

            var error = Throws<InvalidOperationException>(() => WorkerWithPrefix(new SystemFirewallCommands(), prefix).SweepExpiredRules());
            Check(error.Message.Contains(unreadable) && error.Message.Contains("removed 3 rule(s)"));
            Check(!Exists(colon) && !Exists(dot) && !Exists(thai));
            Check(Exists(liveRule) && Exists(unreadable));
        }
        finally
        {
            FirewallWorkerService.RunPowerShell($"Get-NetFirewallRule -ErrorAction SilentlyContinue | " +
                $"Where-Object {{ $_.Name -like '{prefix}*' }} | Remove-NetFirewallRule");
        }
    });
Test("Linux expiry removes a rule whose expiry is beyond the maximum a grant can have", () =>
{
    var commands = new FakeCommands();
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_22_TCP", DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds()));
    commands.Rules.Add(Rule("MFA_Temp_8.8.8.8_2222_TCP", DateTimeOffset.UtcNow.AddHours(47).ToUnixTimeSeconds()));
    Worker(commands).SweepExpiredRules();
    Check(commands.Rules.Count == 1 && commands.Rules[0].Contains("_2222_TCP"));
});
Console.WriteLine(failed == 0 ? $"All {ran} regression checks passed." : $"{failed} regression check(s) failed.");
return failed == 0 ? 0 : 1;

void Test(string name, Action action)
{
    ran++;
    try { action(); Console.WriteLine($"PASS {name}"); }
    catch (Exception ex) { failed++; Console.WriteLine($"FAIL {name}: {ex}"); }
}
static void Check(bool condition) { if (!condition) throw new Exception("Assertion failed"); }
static T Throws<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T error) { return error; }
    throw new Exception($"Expected {typeof(T).Name}");
}
static string CaptureConsole(Action action)
{
    var previous = Console.Out;
    using var captured = new StringWriter();
    try { Console.SetOut(captured); action(); return captured.ToString(); }
    finally { Console.SetOut(previous); }
}
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
static bool LockFileAclIsPrivate(string path)
{
    var acl = new FileInfo(path).GetAccessControl();
    if (!acl.AreAccessRulesProtected) return false;
    foreach (System.Security.AccessControl.FileSystemAccessRule rule in
             acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
    {
        var sid = (System.Security.Principal.SecurityIdentifier)rule.IdentityReference;
        if (!sid.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid)
            && !sid.IsWellKnown(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid))
            return false;
    }
    return true;
}
static bool IsElevated()
{
    if (!OperatingSystem.IsWindows()) return Environment.UserName == "root";
    using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
    return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
}
static ProcessStartInfo Child(string mode)
{
    var start = new ProcessStartInfo(Environment.ProcessPath!);
    if (Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        start.ArgumentList.Add(typeof(FakeCommands).Assembly.Location);
    start.ArgumentList.Add("child");
    start.ArgumentList.Add(mode);
    return start;
}
static FirewallWorkerService Worker(FakeCommands commands, params string[] ports)
    => WorkerWithPrefix(commands, "MFA_Temp_", ports);
static FirewallWorkerService WorkerWithPrefix(IFirewallCommands commands, string prefix, params string[] ports)
{
    if (ports.Length == 0) ports = new[] { "22/TCP" };
    var entries = ports.Select((port, index) => new KeyValuePair<string, string?>($"BouncerConfig:AllowedPorts:{index}", port))
        .Append(new KeyValuePair<string, string?>("BouncerConfig:RulePrefix", prefix));
    return new FirewallWorkerService(new ConfigurationBuilder().AddInMemoryCollection(entries).Build(), commands);
}
static FirewallWorkerService WorkerWithIpv6PrefixLength(FakeCommands commands, int prefixLength, params string[] ports)
{
    if (ports.Length == 0) ports = new[] { "22/TCP" };
    var entries = ports.Select((port, index) => new KeyValuePair<string, string?>($"BouncerConfig:AllowedPorts:{index}", port))
        .Append(new KeyValuePair<string, string?>("BouncerConfig:RulePrefix", "MFA_Temp_"))
        .Append(new KeyValuePair<string, string?>("BouncerConfig:Ipv6GrantPrefixLength", prefixLength.ToString()));
    return new FirewallWorkerService(new ConfigurationBuilder().AddInMemoryCollection(entries).Build(), commands);
}
static string Rule(string name, long expiry)
    => $"-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -m comment --comment \"{name} exp:{expiry}\" -j ACCEPT";
static string Rule6(string name, long expiry)
    => $"-A INPUT -s 2001:4860:4860::8888/128 -p tcp -m tcp --dport 22 -m comment --comment \"{name} exp:{expiry}\" -j ACCEPT";

sealed class FakeCommands : IFirewallCommands
{
    public bool IsWindows { get; init; }
    public bool FailInsert { get; init; }
    public bool IgnoreInsert { get; init; }
    public bool FailDelete { get; init; }
    public bool IgnoreDelete { get; init; }
    // Fail only the deletion of rules whose line contains this text (Linux).
    public string? FailDeleteMatching { get; init; }
    // What the Windows expiry script prints, line by line (REMOVED|, FAILED|, UNPARSEABLE|).
    public string SweeperOutput { get; init; } = "";
    public List<string> Rules { get; } = new();
    public List<string> Rules6 { get; } = new();
    public HashSet<string> WindowsNames { get; } = new();
    public List<string> SeenScripts { get; } = new();

    public string PowerShell(string script)
    {
        SeenScripts.Add(script);
        if (script.Contains("Remove-NetFirewallRule"))
        {
            if (FailDelete) throw new InvalidOperationException("Expired rule remains after deletion");
            return SweeperOutput;
        }
        if (script.Contains("New-NetFirewallRule"))
        {
            if (FailInsert) throw new InvalidOperationException("Command failed with code 1");
            if (!IgnoreInsert) WindowsNames.Add(Regex.Match(script, @"\$n\s*=\s*'([^']+)'").Groups[1].Value);
            return "";
        }
        string name = Regex.Match(script, @"\.Name -eq '([^']+)'").Groups[1].Value;
        return WindowsNames.Contains(name) ? name : "";
    }

    public string Iptables(string table, params string[] args)
    {
        // Recorded as a readable command line; the real runner passes each argument separately.
        SeenScripts.Add($"{table} {string.Join(' ', args)}");
        if (Array.IndexOf(LinuxIptables.Tables, table) < 0) throw new Exception("Unexpected table");
        var (rules, mask) = table == "iptables" ? (Rules, "32") : (Rules6, "128");

        if (args is ["-S", "INPUT"]) return string.Join('\n', rules);
        if (args.Length > 2 && args[0] == "-D" && args[1] == "INPUT")
        {
            if (FailDelete) throw new InvalidOperationException("Command failed with code 1");
            if (FailDeleteMatching != null && string.Join(' ', args).Contains(FailDeleteMatching))
                throw new InvalidOperationException("Command failed with code 1");
            // Delete only on an exact match of the parsed rule, as iptables -D does.
            if (!IgnoreDelete)
                rules.RemoveAll(r => LinuxIptables.SplitRuleLine(r).Skip(2).SequenceEqual(args.Skip(2)));
            return "";
        }
        if (args.Length > 2 && args[0] == "-I" && args[1] == "INPUT")
        {
            if (FailInsert) throw new InvalidOperationException("Command failed with code 1");
            if (!IgnoreInsert)
            {
                string Arg(string flag) => args[Array.IndexOf(args, flag) + 1];
                // A widened IPv6 source already carries its own /prefix (see OpenFirewallPort);
                // only bare host addresses get the implicit /32 or /128 appended here.
                string source = Arg("-s");
                if (!source.Contains('/')) source += $"/{mask}";
                string proto = Arg("-p");
                rules.Add($"-A INPUT -s {source} -p {proto} -m {proto} --dport {Arg("--dport")} -m comment --comment \"{Arg("--comment")}\" -j ACCEPT");
            }
            return "";
        }
        throw new Exception("Unexpected firewall operation");
    }
}
