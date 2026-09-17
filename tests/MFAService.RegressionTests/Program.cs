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
        Check(commands.Rules.Count(rule => rule.Contains(suffix + " exp:")) == 1);
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
    Check(commands.Rules.Count(rule => rule.Contains("MFA Temp_8.8.8.8_22_TCP exp:")) == 1);
    Check(commands.Rules.Count(rule => rule.Contains("MFA Temp_8.8.8.8_2222_TCP exp:")) == 1);
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
});
Test("IPv6 zone ID is rejected before it can reach a shell command", () =>
{
    // IPAddress.TryParse accepts a zone ID (RFC 4007) containing arbitrary characters, including
    // shell metacharacters, and its own ToString() silently drops it -- so using the raw input
    // string past validation let a crafted zone ID survive into the privileged bash -c /
    // PowerShell command built for the actual grant. FakeCommands.Bash/PowerShell receive the
    // exact script that would have run, so this proves the payload never reaches that far, not
    // just that the response happens to be an error.
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
    Check(commands.Rules6[0].Contains("2001:4860:4860::8888") && commands.Rules6[0].Contains("_22_TCP exp:"));
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
    Check(commands.Rules6[0].Contains("-s 2001:4860:4860::/64 ") && commands.Rules6[0].Contains("_22_TCP exp:"));
});
Test("IPv6 grant prefix length below the documented minimum is clamped, not rejected", () =>
{
    var commands = new FakeCommands();
    Check(WorkerWithIpv6PrefixLength(commands, 32).ProcessFirewallRequest(RequestV6) == "SUCCESS");
    Check(commands.Rules6.Count == 1 && commands.Rules6[0].Contains("-s 2001:4860:4860::/64 "));
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
Console.WriteLine(failed == 0 ? "All 23 regression checks passed." : $"{failed} regression check(s) failed.");
return failed == 0 ? 0 : 1;

void Test(string name, Action action)
{
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
static FirewallWorkerService WorkerWithPrefix(FakeCommands commands, string prefix, params string[] ports)
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
            return "";
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

    public string Bash(string script)
    {
        SeenScripts.Add(script);
        foreach (var (table, rules, mask) in new (string, List<string>, string)[]
                 { ("iptables", Rules, "32"), ("ip6tables", Rules6, "128") })
        {
            if (script == $"{table} -S INPUT") return string.Join('\n', rules);
            if (script.StartsWith($"{table} -D INPUT"))
            {
                if (FailDelete) throw new InvalidOperationException("Command failed with code 1");
                if (!IgnoreDelete) rules.Remove("-A INPUT" + script[$"{table} -D INPUT".Length..]);
                return "";
            }
            if (script.StartsWith($"{table} -I INPUT"))
            {
                if (FailInsert) throw new InvalidOperationException("Command failed with code 1");
                if (!IgnoreInsert)
                {
                    var match = Regex.Match(script, @"-p (\w+) --dport (\d+) -s (\S+).*--comment '([^']+)'$");
                    if (!match.Success) throw new Exception("Unexpected insertion format");
                    // A widened IPv6 source already carries its own /prefix (see OpenFirewallPort);
                    // only bare host addresses get the implicit /32 or /128 appended here.
                    string source = match.Groups[3].Value;
                    if (!source.Contains('/')) source += $"/{mask}";
                    rules.Add($"-A INPUT -s {source} -p {match.Groups[1].Value} -m {match.Groups[1].Value} --dport {match.Groups[2].Value} -m comment --comment \"{match.Groups[4].Value}\" -j ACCEPT");
                }
                return "";
            }
        }
        throw new Exception("Unexpected firewall operation");
    }
}
