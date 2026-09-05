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
Console.WriteLine(failed == 0 ? "All 16 regression checks passed." : $"{failed} regression check(s) failed.");
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
static string Rule(string name, long expiry)
    => $"-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -m comment --comment \"{name} exp:{expiry}\" -j ACCEPT";

sealed class FakeCommands : IFirewallCommands
{
    public bool IsWindows { get; init; }
    public bool FailInsert { get; init; }
    public bool IgnoreInsert { get; init; }
    public bool FailDelete { get; init; }
    public bool IgnoreDelete { get; init; }
    public List<string> Rules { get; } = new();
    public HashSet<string> WindowsNames { get; } = new();

    public string PowerShell(string script)
    {
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
        if (script == "iptables -S INPUT") return string.Join('\n', Rules);
        if (script.StartsWith("iptables -D INPUT"))
        {
            if (FailDelete) throw new InvalidOperationException("Command failed with code 1");
            if (!IgnoreDelete) Rules.Remove("-A INPUT" + script["iptables -D INPUT".Length..]);
            return "";
        }
        if (script.StartsWith("iptables -I INPUT"))
        {
            if (FailInsert) throw new InvalidOperationException("Command failed with code 1");
            if (!IgnoreInsert)
            {
                var match = Regex.Match(script, @"-p (\w+) --dport (\d+) -s (\S+).*--comment '([^']+)'$");
                if (!match.Success) throw new Exception("Unexpected insertion format");
                Rules.Add($"-A INPUT -s {match.Groups[3].Value}/32 -p {match.Groups[1].Value} -m {match.Groups[1].Value} --dport {match.Groups[2].Value} -m comment --comment \"{match.Groups[4].Value}\" -j ACCEPT");
            }
            return "";
        }
        throw new Exception("Unexpected firewall operation");
    }
}
