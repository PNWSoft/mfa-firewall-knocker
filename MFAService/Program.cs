// Copyright (c) 2026 Pacific Northwest Software, Inc.
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net.Mail;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using System.Reflection;
using System.Text.RegularExpressions;

Directory.SetCurrentDirectory(AppContext.BaseDirectory);

var builder = Host.CreateApplicationBuilder(args);
ServiceLogger.SetMinLevel(builder.Configuration["Logging:AppMinLevel"]);

var _asm = Assembly.GetExecutingAssembly();
var _ver = _asm.GetName().Version?.ToString(3) ?? "unknown";
var _built = _asm.GetCustomAttributes<AssemblyMetadataAttribute>()
    .FirstOrDefault(a => a.Key == "BuildDate")?.Value ?? "unknown";
ServiceLogger.Log($"MFAService v{_ver} (built {_built} UTC) starting...");

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "MFA Service";
});
builder.Services.AddHostedService<FirewallWorkerService>();
builder.Services.AddHostedService<DatabaseLockService>();
builder.Services.AddHostedService<CertificateMonitorService>();

await builder.Build().RunAsync();

// ---------------------------------------------------------------------------
// Logger: writes to console + daily rotating log file
// ---------------------------------------------------------------------------
public enum LogSeverity { Debug, Info, Warning, Error }

internal static class ServiceLogger
{
    private static readonly string LogDirectory = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? @"C:\ProgramData\MFAAuth\Logs"
        : @"/var/log/mfa-auth";

    private static readonly object _lock = new();
    private static LogSeverity _minLevel = LogSeverity.Info;

    public static void SetMinLevel(string? level) =>
        _minLevel = level?.ToLowerInvariant() switch
        {
            "debug"            => LogSeverity.Debug,
            "warning" or "warn"=> LogSeverity.Warning,
            "error"            => LogSeverity.Error,
            _                  => LogSeverity.Info
        };

    public static void Debug(string message)   => Write(message, LogSeverity.Debug);
    public static void Log(string message)     => Write(message, LogSeverity.Info);
    public static void Warn(string message)    => Write(message, LogSeverity.Warning);
    public static void Error(string message)   => Write(message, LogSeverity.Error);

    private static void Write(string message, LogSeverity level)
    {
        if (level < _minLevel) return;

        message = SanitizeForLog(message);

        string tag = level switch
        {
            LogSeverity.Debug   => "DEBUG",
            LogSeverity.Warning => "WARN",
            LogSeverity.Error   => "ERROR",
            _                   => "INFO"
        };

        string entry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC] [{tag}] {message}";
        Console.WriteLine(entry);
        try
        {
            if (!Directory.Exists(LogDirectory))
                Directory.CreateDirectory(LogDirectory);
            string path = Path.Combine(LogDirectory, $"mfaservice_{DateTime.UtcNow:yyyy-MM-dd}.log");
            lock (_lock)
            {
                File.AppendAllText(path, entry + Environment.NewLine);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[LOG ERROR] Could not write to log file: {ex.Message}");
        }
    }

    // Strips control characters to prevent log injection (ANSI escape sequences,
    // NUL bytes, carriage returns). Newlines and tabs are kept so multi-line
    // exception traces stay readable; attacker-controlled IPC input cannot contain
    // a newline (the pipe reader stops at '\n'), so this is not a log-forging vector.
    private static string SanitizeForLog(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return raw;
        var sb = new StringBuilder(raw.Length);
        foreach (char c in raw)
        {
            if (c == '\n' || c == '\t' || (c >= 32 && c <= 126)) sb.Append(c);
            else sb.Append('?');
        }
        return sb.ToString();
    }
}

// -----------------------------------------------------------------------
// FIREWALL WORKER SERVICE
// Runs the IPC server and the firewall rule sweeper in parallel.
// Must run as LocalSystem (Windows) or root (Linux).
// -----------------------------------------------------------------------
public class FirewallWorkerService : BackgroundService
{
    private readonly IConfiguration _config;
    private static string _rulePrefix = "MFA_Temp_";

    public FirewallWorkerService(IConfiguration config)
    {
        _config = config;
        _rulePrefix = config["BouncerConfig:RulePrefix"] ?? "MFA_Temp_";
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ServiceLogger.Log("[WORKER] Firewall Worker Service starting...");
        try
        {
            await Task.WhenAll(
                RunIpcServerAsync(stoppingToken),
                RunSweeperAsync(stoppingToken)
            );
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ServiceLogger.Log($"[WORKER] Fatal error — service stopping: {ex}");
            throw;
        }
        ServiceLogger.Log("[WORKER] Firewall Worker Service stopped.");
    }

    // -----------------------------------------------------------------------
    // IPC SERVER
    // -----------------------------------------------------------------------
    private async Task RunIpcServerAsync(CancellationToken stoppingToken)
    {
        ServiceLogger.Log("[IPC] Server starting...");
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            await RunWindowsPipeServerAsync(stoppingToken);
        else
#pragma warning disable CA1416 // Validate platform compatibility
            await RunUnixSocketServerAsync(stoppingToken);
#pragma warning restore CA1416 // Validate platform compatibility
        ServiceLogger.Log("[IPC] Server stopped.");
    }

    [SupportedOSPlatform("windows")]
    private async Task RunWindowsPipeServerAsync(CancellationToken stoppingToken)
    {
        string gmsaName = _config["FirewallService:GmsaAccount"];
        if (string.IsNullOrEmpty(gmsaName))
        {
            throw new Exception("gMSA account name not found in configuration.");
        }

        // Convert the string to an NTAccount object
        var gmsaAccount = new NTAccount(gmsaName);
      
        // ACL: LocalSystem gets full control; gMSA (MFAWeb) gets read/write only.
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            gmsaAccount,
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        ServiceLogger.Debug($"[IPC] Pipe security built for gMSA '{gmsaName}'. Creating pipe...");
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                // Create one server instance per connection — loop back after each.
                pipe = NamedPipeServerStreamAcl.Create(
                    "MFAFirewallPipe",
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 0,
                    outBufferSize: 0,
                    security);

                ServiceLogger.Debug("[IPC] Pipe created, waiting for connection...");
                await pipe.WaitForConnectionAsync(stoppingToken);
                ServiceLogger.Debug("[IPC] Client connected.");
                // Fire-and-forget: handle the connection while immediately
                // looping back to listen for the next one.
                _ = HandlePipeConnectionAsync(pipe, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                pipe?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                ServiceLogger.Warn($"[IPC] Named pipe error: {ex.GetType().Name}: {ex.Message}");
                pipe?.Dispose();
            }
        }
    }

    [SupportedOSPlatform("linux")]
    private async Task RunUnixSocketServerAsync(CancellationToken stoppingToken)
    {
        const string socketPath = "/run/mfafirewall.sock";
        if (File.Exists(socketPath)) File.Delete(socketPath);

        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(socketPath));
        listener.Listen(backlog: 10);

        // 0660: owner (root) rw, group (www-data) rw, others none.
        // Add MFAWeb's service account to the www-data group at deployment time.
        File.SetUnixFileMode(socketPath,
            UnixFileMode.UserRead  | UnixFileMode.UserWrite |
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var client = await listener.AcceptAsync(stoppingToken);
                _ = HandleUnixConnectionAsync(client, stoppingToken);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            listener.Dispose();
            if (File.Exists(socketPath)) File.Delete(socketPath);
        }
    }

    [SupportedOSPlatform("windows")]
    private async Task HandlePipeConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using (pipe)
        {
            try
            {
                ServiceLogger.Debug("[IPC] Handler reading request...");

                // Read until newline — direct bytes, no StreamReader buffering/BOM issues
                const int MaxRequestBytes = 1024;
                var buffer = new List<byte>(256);
                var singleByte = new byte[1];
                while (buffer.Count < MaxRequestBytes)
                {
                    int n = await pipe.ReadAsync(singleByte, ct);
                    if (n == 0 || singleByte[0] == (byte)'\n') break;
                    if (singleByte[0] != (byte)'\r') buffer.Add(singleByte[0]);
                }
                if (buffer.Count >= MaxRequestBytes)
                {
                    ServiceLogger.Log("[IPC] Request exceeded maximum size — rejected.");
                    byte[] rejection = Encoding.UTF8.GetBytes("ERROR: Request too large\n");
                    await pipe.WriteAsync(rejection, ct);
                    await pipe.FlushAsync(ct);
                    return;
                }

                string request = Encoding.UTF8.GetString(buffer.ToArray());
                ServiceLogger.Debug($"[IPC] Request read: '{RedactRequest(request)}'");

                string response = ProcessFirewallRequest(request);

                byte[] responseBytes = Encoding.UTF8.GetBytes(response + "\n");
                await pipe.WriteAsync(responseBytes, ct);
                await pipe.FlushAsync(ct);
            }
            catch (Exception ex) { ServiceLogger.Warn($"[IPC] Pipe handler error: {ex.GetType().Name}: {ex.Message}"); }
        }
    }

    private async Task HandleUnixConnectionAsync(Socket socket, CancellationToken ct)
    {
        using var stream = new NetworkStream(socket, ownsSocket: true);
        try
        {
            var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            var writer = new StreamWriter(stream, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };

            string? request = await reader.ReadLineAsync(ct);
            string response = ProcessFirewallRequest(request);
            await writer.WriteLineAsync(response.AsMemory(), ct);
        }
        catch (Exception ex) { ServiceLogger.Log($"[IPC] Unix handler error: {ex.Message}"); }
    }

    // Request format: "IP|Username" or "DB:COMMAND|..."
    private string ProcessFirewallRequest(string? request)
    {
        if (string.IsNullOrWhiteSpace(request))
            return "ERROR: Empty request";

        ServiceLogger.Log($"[IPC] Request received: {RedactRequest(request)}");

        // Route database write commands to DatabaseLockService
        if (request.StartsWith("DB:", StringComparison.OrdinalIgnoreCase))
            return DatabaseLockService.ProcessDbRequest(request.Substring(3));

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var parts = request.Split('|');

        // STRICT ENFORCEMENT: Only accept exactly 2 parameters from the Web App.
        if (parts.Length != 2)
            return "ERROR: Invalid request format. Expected 'IP|Username'";

        string ip = parts[0].Trim();
        string username = parts[1].Trim();

        // 1. READ CONFIG (The Absolute Source of Truth)
        var allowedPorts = _config.GetSection("BouncerConfig:AllowedPorts").Get<string[]>() ?? Array.Empty<string>();
        int expirationHours = _config.GetValue<int>("BouncerConfig:ExpirationHours", 1);

        if (allowedPorts.Length == 0)
        {
            ServiceLogger.Warn("[IPC] SECURITY WARNING: No AllowedPorts configured in BouncerConfig.");
            return "ERROR: Server misconfiguration.";
        }

        // 2. VALIDATE INPUTS
        if (!System.Net.IPAddress.TryParse(ip, out _))
            return "ERROR: Invalid IP address";
        // Defense in depth: re-enforce the "external addresses only" policy on the
        // privileged side, so a compromised/bypassed MFAWeb cannot make SYSTEM open
        // a firewall rule for a private/loopback source. MFAWeb checks this too.
        if (!IsPublicIpAddress(ip))
        {
            ServiceLogger.Warn($"[SECURITY] Refused firewall rule for non-public IP: {ip}");
            return "ERROR: Only public IP addresses may be authorized";
        }
        if (!MailAddress.TryCreate(username, out _))
            return "ERROR: Invalid username";
        if (expirationHours < 1)
            expirationHours = 1; // Fallback sanity check

        try
        {
            // 3. APPLY RULES FOR ALL CONFIGURED PORTS
            foreach (var portProto in allowedPorts)
            {
                var ppParts = portProto.Split('/');
                if (ppParts.Length != 2)
                {
                    ServiceLogger.Warn($"[IPC] Configured port '{portProto}' is invalid. Skipping.");
                    continue;
                }

                if (!int.TryParse(ppParts[0].Trim(), out int port)) continue;
                string protocol = ppParts[1].Trim().ToUpperInvariant();

                OpenFirewallPort(ip, port, username, protocol, expirationHours);
            }

            ServiceLogger.Log($"[IPC] Request completed in {sw.ElapsedMilliseconds}ms");
            return "SUCCESS";
        }
        catch (Exception ex)
        {
            ServiceLogger.Error($"[FIREWALL ERROR] {ex.Message} (after {sw.ElapsedMilliseconds}ms)");
            return $"ERROR: {ex.Message}";
        }
    }

    // Returns false for private, loopback, link-local, CGNAT, and unspecified
    // ranges — mirrors MFAWeb's IsPublicIpAddress so the privileged side enforces
    // the same "external addresses only" policy independently.
    private static bool IsPublicIpAddress(string ipString)
    {
        if (!System.Net.IPAddress.TryParse(ipString, out var ip))
            return false;

        // Normalize IPv4-mapped IPv6 (e.g. ::ffff:10.0.0.1) so it's judged by its IPv4 value.
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            byte[] b = ip.GetAddressBytes();
            if (b[0] == 10) return false;                                   // 10.0.0.0/8
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;      // 172.16.0.0/12
            if (b[0] == 192 && b[1] == 168) return false;                   // 192.168.0.0/16
            if (b[0] == 127) return false;                                  // 127.0.0.0/8 loopback
            if (b[0] == 169 && b[1] == 254) return false;                   // 169.254.0.0/16 link-local
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;     // 100.64.0.0/10 CGNAT
            if (b[0] == 0) return false;                                    // 0.0.0.0/8
        }
        else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6SiteLocal || ip.IsIPv6LinkLocal || System.Net.IPAddress.IsLoopback(ip)
                || ip.Equals(System.Net.IPAddress.IPv6Any))                 // :: (unspecified)
                return false;
            byte[] b = ip.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC) return false;                        // fc00::/7 ULA
        }
        return true;
    }

    // IPC requests may carry secrets in DB: commands (provisioning tokens, credential
    // material). Log only the command name, never the arguments. Firewall requests
    // ("IP|Username") are not secret and pass through.
    private static string RedactRequest(string request)
    {
        if (request.StartsWith("DB:", StringComparison.OrdinalIgnoreCase))
        {
            string body = request.Substring(3);
            int bar = body.IndexOf('|');
            string cmd = bar < 0 ? body : body.Substring(0, bar);
            return $"DB:{cmd}|<redacted>";
        }
        return request;
    }

    // -----------------------------------------------------------------------
    // FIREWALL OPERATIONS
    // -----------------------------------------------------------------------
    private static void OpenFirewallPort(string ip, int port, string username, string protocol, int expirationHours)
    {
        string expiresClean = DateTime.UtcNow.AddHours(expirationHours).ToString("yyyy-MM-dd HH:mm UTC");
        string ruleName     = $"{_rulePrefix}{ip}_{port}";
        var fw = System.Diagnostics.Stopwatch.StartNew();
        ServiceLogger.Log($"[FIREWALL] Configuring rule: {ruleName}...");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Escape single quotes for PowerShell string safety ('' is the PS escape for ')
            string safeUsername = username.Replace("'", "''");
            string description  = $"User: {safeUsername} Exp: {expiresClean}";

            string script = $@"
                $n     = '{ruleName}';
                $desc  = '{description}';
                $ip    = '{ip}';
                $p     = {port};
                $proto = '{protocol}';

                if (Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue) {{
                    Set-NetFirewallRule -Name $n `
                        -Description $desc `
                        -RemoteAddress $ip `
                        -LocalPort $p `
                        -Protocol $proto `
                        -Enabled True `
                        -Profile Any `
                        -ErrorAction Stop
                }} else {{
                    New-NetFirewallRule -Name $n -DisplayName $n `
                        -Group 'MFA Firewall' `
                        -Description $desc `
                        -Direction Inbound `
                        -LocalPort $p `
                        -Protocol $proto `
                        -Action Allow `
                        -RemoteAddress $ip `
                        -Enabled True `
                        -Profile Any `
                        -ErrorAction Stop
                }}
            ";

            RunPowerShell(script);
            ServiceLogger.Debug($"[FIREWALL] Rule script completed in {fw.ElapsedMilliseconds}ms. Verifying...");

            string verifyOutput = RunPowerShell(
                $"Get-NetFirewallRule -Name '{ruleName}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
            ).Trim();
            ServiceLogger.Debug($"[FIREWALL] Verify completed in {fw.ElapsedMilliseconds}ms total.");

            if (verifyOutput.Equals(ruleName, StringComparison.OrdinalIgnoreCase))
                ServiceLogger.Log($"[SUCCESS] Rule verified: {protocol}/{port} OPEN for {ip}.");
            else
                ServiceLogger.Log($"[FAILED] Rule '{ruleName}' could not be verified after creation.");
        }
        else
        {
            // Linux: iptables-based implementation.
            // If your distro uses nftables, ufw, or firewalld instead, replace the
            // iptables calls below with the equivalent commands for your backend.
            // The rule name and expiry format used in the comment must stay consistent
            // with SweepExpiredRules so the sweeper can find and remove them.
            string proto    = protocol.ToLowerInvariant();
            long   expEpoch = DateTimeOffset.UtcNow.AddHours(expirationHours).ToUnixTimeSeconds();
            string comment  = $"{ruleName} exp:{expEpoch}";

            // Upsert: remove any existing rule for this IP+port, then insert a fresh one.
            // iptables -I is not idempotent on its own — without the delete step it would
            // stack duplicate rules on repeated logins from the same IP.
            string existing = RunBash("iptables -S INPUT 2>/dev/null");
            foreach (string line in existing.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.TrimStart().StartsWith("-A INPUT") && line.Contains(ruleName))
                    RunBash("iptables " + line.TrimStart().Replace("-A INPUT", "-D INPUT"));
            }

            RunBash($"iptables -I INPUT -p {proto} --dport {port} -s {ip} -j ACCEPT -m comment --comment '{comment}'");
            ServiceLogger.Debug($"[FIREWALL] iptables rule inserted in {fw.ElapsedMilliseconds}ms. Verifying...");

            string verify = RunBash($"iptables -C INPUT -p {proto} --dport {port} -s {ip} -j ACCEPT 2>/dev/null && echo OK || echo FAIL");
            if (verify.Trim() == "OK")
                ServiceLogger.Log($"[SUCCESS] iptables rule verified: {protocol}/{port} OPEN for {ip}.");
            else
                ServiceLogger.Log($"[FAILED] iptables rule could not be verified: {protocol}/{port} for {ip}.");
        }
    }

    internal static string RunPowerShell(string script)
    {
        string full   = $"$ProgressPreference = 'SilentlyContinue'; Import-Module NetSecurity -ErrorAction SilentlyContinue; {script}";
        string base64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(full));

        var psi = new ProcessStartInfo("powershell.exe",
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {base64}")
        {
            CreateNoWindow       = true,
            UseShellExecute      = false,
            RedirectStandardOutput = true,
            RedirectStandardError  = true
        };

        var ps = System.Diagnostics.Stopwatch.StartNew();
        using var proc = Process.Start(psi);
        if (proc == null) return string.Empty;
        ServiceLogger.Debug($"[PS] Process started in {ps.ElapsedMilliseconds}ms");

        string output = proc.StandardOutput.ReadToEnd().Trim();
        string error  = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        ServiceLogger.Debug($"[PS] Process exited in {ps.ElapsedMilliseconds}ms (exit code {proc.ExitCode})");

        if (!string.IsNullOrWhiteSpace(error) && !error.Contains("<Objs"))
            ServiceLogger.Error($"[PS ERROR] {error.Trim()}");

        return output;
    }

    internal static string RunBash(string script)
    {
        var psi = new ProcessStartInfo("/bin/bash");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(script);
        psi.CreateNoWindow        = true;
        psi.UseShellExecute       = false;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError  = true;

        var sw = System.Diagnostics.Stopwatch.StartNew();
        using var proc = Process.Start(psi);
        if (proc == null) return string.Empty;

        string output = proc.StandardOutput.ReadToEnd().Trim();
        string error  = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        ServiceLogger.Debug($"[BASH] Exited in {sw.ElapsedMilliseconds}ms (exit code {proc.ExitCode})");

        if (!string.IsNullOrWhiteSpace(error))
            ServiceLogger.Error($"[BASH ERROR] {error.Trim()}");

        return output;
    }

    // -----------------------------------------------------------------------
    // FIREWALL SWEEPER: Remove expired rules every 5 minutes
    // -----------------------------------------------------------------------
    private static async Task RunSweeperAsync(CancellationToken stoppingToken)
    {
        ServiceLogger.Log("[SWEEPER] Starting...");
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(5));

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try { SweepExpiredRules(); }
            catch (Exception ex) { ServiceLogger.Log($"[SWEEPER ERROR] {ex.Message}"); }
        }
    }

    private static void SweepExpiredRules()
    {
        ServiceLogger.Log("[SWEEPER] Checking for expired rules...");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            string reaperScript = $@"
                $rules = Get-NetFirewallRule -DisplayName '{_rulePrefix}*' -ErrorAction SilentlyContinue
                $nowUtcString = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')

                foreach ($rule in $rules) {{
                    if ($rule.Description -match 'Exp:\s*(\d{{4}}-\d{{2}}-\d{{2}}\s\d{{2}}:\d{{2}})') {{
                        $expString = $matches[1]
                        if ($nowUtcString -gt $expString) {{
                            Remove-NetFirewallRule -Name $rule.Name
                            Write-Output $rule.DisplayName
                        }}
                    }}
                }}
            ";

            string results = RunPowerShell(reaperScript).Trim();

            if (!string.IsNullOrWhiteSpace(results))
            {
                var removed = results.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var rule in removed)
                    ServiceLogger.Log($"[SWEEPER] Expired rule removed: {rule}");
                ServiceLogger.Log($"[SWEEPER] Done. Removed {removed.Length} rule(s).");
            }
            else
            {
                ServiceLogger.Log("[SWEEPER] No expired rules found.");
            }
        }
        else
        {
            // Linux: parse 'iptables -S INPUT' and delete any of our rules whose
            // stored expiry epoch has passed.  Update these commands if your distro
            // uses nftables, ufw, or firewalld instead of iptables.
            string rules = RunBash("iptables -S INPUT 2>/dev/null");
            if (string.IsNullOrWhiteSpace(rules))
            {
                ServiceLogger.Log("[SWEEPER] No iptables rules found.");
                return;
            }

            long nowEpoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            int  count    = 0;

            foreach (string line in rules.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!line.Contains(_rulePrefix)) continue;

                var expMatch = Regex.Match(line, @"exp:(\d+)");
                if (!expMatch.Success) continue;

                if (nowEpoch <= long.Parse(expMatch.Groups[1].Value)) continue;

                // Delete by replaying the save-format rule with -D instead of -A
                RunBash("iptables " + line.TrimStart().Replace("-A INPUT", "-D INPUT"));

                var nameMatch = Regex.Match(line, Regex.Escape(_rulePrefix) + @"[^\s'""]+");
                ServiceLogger.Log($"[SWEEPER] Expired iptables rule removed: {(nameMatch.Success ? nameMatch.Value : "unknown")}");
                count++;
            }

            ServiceLogger.Log(count > 0
                ? $"[SWEEPER] Done. Removed {count} rule(s)."
                : "[SWEEPER] No expired rules found.");
        }
    }
}

// -----------------------------------------------------------------------
// DATABASE LOCK SERVICE
// Hardens users.dat with ReadOnly at startup (defense-in-depth on top of
// NTFS ACLs). SaveUsers() clears and immediately restores ReadOnly around
// every write, so no periodic sweep is needed.
// -----------------------------------------------------------------------
public class DatabaseLockService : BackgroundService
{
    private static readonly string DbPath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? @"C:\ProgramData\MFAAuth\users.dat"
        : @"/etc/mfa-auth/users.json";

    private static byte[] Entropy = Array.Empty<byte>();

    // Cross-process mutex — shared by MFAWeb, MFAService, and MFAAdmin to serialize all DB reads/writes.
    // ACL-restricted so only SYSTEM, Builtin Administrators, and the gMSA can acquire it.
    // Initialized in the constructor so the service account name comes from appsettings.
    private static System.Threading.Mutex _dbMutex = null!;

    public DatabaseLockService(IConfiguration config)
    {
        string? entropyStr = config["DpapiEntropy"];
        if (string.IsNullOrWhiteSpace(entropyStr))
            throw new InvalidOperationException("DpapiEntropy must be configured in appsettings.json. Set it to a unique random string for your deployment.");
        Entropy = Encoding.UTF8.GetBytes(entropyStr);
        _dbMutex ??= CreateSecureDbMutex(config["FirewallService:GmsaAccount"]);
    }

    private static System.Threading.Mutex CreateSecureDbMutex(string? serviceAccount)
    {
        const string mutexName = @"Global\MFA_DB_LOCK";

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new System.Threading.Mutex(false, mutexName);

        var security = new MutexSecurity();

        // SYSTEM — full control
        security.AddAccessRule(new MutexAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            MutexRights.FullControl, AccessControlType.Allow));

        // Builtin Administrators — covers MFAAdmin running elevated
        security.AddAccessRule(new MutexAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            MutexRights.FullControl, AccessControlType.Allow));

        // gMSA service account — runs MFAWeb and MFAService
        if (!string.IsNullOrWhiteSpace(serviceAccount))
            security.AddAccessRule(new MutexAccessRule(
                new NTAccount(serviceAccount),
                MutexRights.FullControl, AccessControlType.Allow));

        return MutexAcl.Create(false, mutexName, out _, security);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Ensure the DB file is ReadOnly at startup. SaveUsers() will clear and
        // restore this attribute around every write, so no periodic sweep is needed.
        if (File.Exists(DbPath))
        {
            var attrs = File.GetAttributes(DbPath);
            if ((attrs & FileAttributes.ReadOnly) == 0)
            {
                File.SetAttributes(DbPath, attrs | FileAttributes.ReadOnly);
                ServiceLogger.Log("[DB] ReadOnly attribute applied to database at startup.");
            }

            // On Linux, enforce mode 640 so only the owning user (root) and the
            // service group (which MFAWeb's account must be a member of) can read
            // the file, and nobody else.  This corrects any permissive umask left
            // by MFAAdmin when it first created the file.
            // Group ownership (chown root:<service-group>) must be set once at
            // deployment time — there is no managed API for chown.
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var desired = UnixFileMode.UserRead | UnixFileMode.UserWrite |
                              UnixFileMode.GroupRead;          // 640
                if (File.GetUnixFileMode(DbPath) != desired)
                {
                    File.SetUnixFileMode(DbPath, desired);
                    ServiceLogger.Log("[DB] Unix file mode set to 640.");
                }
            }
        }
        return Task.CompletedTask;
    }

    // -----------------------------------------------------------------------
    // DATABASE READ / WRITE (MFAService is the sole writer)
    // -----------------------------------------------------------------------
    private static List<UserEntry> LoadUsers()
    {
        if (!File.Exists(DbPath)) return new List<UserEntry>();
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                byte[] encrypted = File.ReadAllBytes(DbPath);
                byte[] raw       = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.LocalMachine);
                return JsonSerializer.Deserialize<List<UserEntry>>(Encoding.UTF8.GetString(raw)) ?? new List<UserEntry>();
            }
            return JsonSerializer.Deserialize<List<UserEntry>>(File.ReadAllText(DbPath)) ?? new List<UserEntry>();
        }
        catch (Exception ex)
        {
            ServiceLogger.Error($"[DB] Failed to load database: {ex.Message}");
            return new List<UserEntry>();
        }
    }

    private static void SaveUsers(List<UserEntry> users)
    {
        // Clear ReadOnly before writing; restore it immediately after.
        // The caller always holds the cross-process mutex, so no other writer
        // can race between the attribute clear and the attribute restore.
        if (File.Exists(DbPath))
        {
            var attrs = File.GetAttributes(DbPath);
            if ((attrs & FileAttributes.ReadOnly) != 0)
                File.SetAttributes(DbPath, attrs & ~FileAttributes.ReadOnly);
        }

        string json = JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true });
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            byte[] encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), Entropy, DataProtectionScope.LocalMachine);
            File.WriteAllBytes(DbPath, encrypted);
        }
        else
        {
            File.WriteAllText(DbPath, json);
        }

        // Re-apply ReadOnly now that the write is complete.
        if (File.Exists(DbPath))
        {
            File.SetAttributes(DbPath, File.GetAttributes(DbPath) | FileAttributes.ReadOnly);
            // On Linux also enforce 640 — WriteAllText/WriteAllBytes can create the file
            // with a permissive umask if it didn't exist yet.
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                File.SetUnixFileMode(DbPath, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                                             UnixFileMode.GroupRead);   // 640
        }
    }

    // -----------------------------------------------------------------------
    // DB IPC COMMAND DISPATCHER
    // Called by FirewallWorkerService when a request starts with "DB:"
    // Commands: BURN_TOTP_TOKEN | SET_PASSKEY_TOKEN | UPDATE_SIGN_COUNT | ADD_PASSKEY
    // -----------------------------------------------------------------------
    internal static string ProcessDbRequest(string command)
    {
        var parts = command.Split('|');
        string op = parts[0].Trim().ToUpperInvariant();
        try
        {
            return op switch
            {
                "BURN_TOTP_TOKEN"     when parts.Length == 2 => BurnTotpToken(parts[1].Trim()),
                "SET_PASSKEY_TOKEN"   when parts.Length == 4 => SetPasskeyToken(parts[1].Trim(), parts[2].Trim(), parts[3].Trim()),
                "RENEW_PASSKEY_TOKEN" when parts.Length == 2 => RenewPasskeyToken(parts[1].Trim()),
                "UPDATE_SIGN_COUNT"   when parts.Length == 3 => UpdateSignCount(parts[1].Trim(), parts[2].Trim()),
                "ADD_PASSKEY"         when parts.Length == 5 => AddPasskey(parts[1].Trim(), parts[2].Trim(), parts[3].Trim(), parts[4].Trim()),
                _ => "ERROR: Unknown DB command"
            };
        }
        catch (Exception ex)
        {
            ServiceLogger.Error($"[DB] Command '{op}' failed: {ex.Message}");
            return $"ERROR: {ex.Message}";
        }
    }

    private static string BurnTotpToken(string token)
    {
        using var lk = AcquireDbLock();
        if (lk == null) return "ERROR: DB lock timeout";

        var users = LoadUsers();
        var user = users.FirstOrDefault(u => u.ProvisioningToken == token);
        if (user == null || user.ProvisioningExpiresUtc == null || DateTime.UtcNow > user.ProvisioningExpiresUtc)
            return "ERROR: Token not found or expired";

        user.ProvisioningToken      = null;
        user.ProvisioningExpiresUtc = null;
        user.TotpConfirmed          = true;
        SaveUsers(users);
        ServiceLogger.Log($"[DB] TOTP provisioning token burned for '{user.Username}'");
        return "SUCCESS";
    }

    // Atomically burns the old passkey provisioning token (e.g. from the email link) and
    // issues a fresh short-lived one.  Called immediately after password verification so the
    // email link becomes worthless, and only the in-page token can complete registration.
    private static string RenewPasskeyToken(string oldToken)
    {
        using var lk = AcquireDbLock();
        if (lk == null) return "ERROR: DB lock timeout";

        var users = LoadUsers();
        var user = users.FirstOrDefault(u => u.PasskeyProvisioningToken == oldToken);
        if (user == null || user.PasskeyProvisioningExpiresUtc == null || DateTime.UtcNow > user.PasskeyProvisioningExpiresUtc)
            return "ERROR: Token not found or expired";
        if (user.PasskeyCredentials.Count > 0)
            return "ERROR: User already has passkeys";

        string newToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        user.PasskeyProvisioningToken      = newToken;
        user.PasskeyProvisioningExpiresUtc = DateTime.UtcNow.AddMinutes(5);
        user.PasskeyRegistrationReady      = true;   // password was just verified upstream
        SaveUsers(users);
        ServiceLogger.Log($"[DB] Passkey provisioning token renewed for '{user.Username}' (old token invalidated)");
        return newToken;
    }

    private static string SetPasskeyToken(string username, string pkToken, string expiresUtcIso)
    {
        if (!DateTime.TryParse(expiresUtcIso, null, System.Globalization.DateTimeStyles.RoundtripKind, out var expiresUtc))
            return "ERROR: Invalid expiry date";

        using var lk = AcquireDbLock();
        if (lk == null) return "ERROR: DB lock timeout";

        var users = LoadUsers();
        var user = users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (user == null) return "ERROR: User not found";
        if (user.PasskeyCredentials.Count > 0) return "ERROR: User already has passkeys";

        user.PasskeyProvisioningToken      = pkToken;
        user.PasskeyProvisioningExpiresUtc = expiresUtc;
        user.PasskeyRegistrationReady      = true;   // issued only after a successful login
        SaveUsers(users);
        ServiceLogger.Log($"[DB] Passkey provisioning token set for '{username}'");
        return "SUCCESS";
    }

    private static string UpdateSignCount(string credentialId, string newCountStr)
    {
        if (!uint.TryParse(newCountStr, out uint newCount))
            return "ERROR: Invalid sign count";

        using var lk = AcquireDbLock();
        if (lk == null) return "ERROR: DB lock timeout";

        var users = LoadUsers();
        foreach (var user in users)
        {
            var cred = user.PasskeyCredentials.FirstOrDefault(c => c.CredentialId == credentialId);
            if (cred != null)
            {
                cred.SignCount = newCount;
                SaveUsers(users);
                ServiceLogger.Log($"[DB] Sign count updated for credential '{credentialId}'");
                return "SUCCESS";
            }
        }
        return "ERROR: Credential not found";
    }

    private static string AddPasskey(string provToken, string credentialId, string publicKey, string signCountStr)
    {
        if (!uint.TryParse(signCountStr, out uint signCount))
            return "ERROR: Invalid sign count";

        using var lk = AcquireDbLock();
        if (lk == null) return "ERROR: DB lock timeout";

        var users = LoadUsers();
        var user = users.FirstOrDefault(u => u.PasskeyProvisioningToken == provToken);
        if (user == null || user.PasskeyProvisioningExpiresUtc == null || DateTime.UtcNow > user.PasskeyProvisioningExpiresUtc)
            return "ERROR: Provisioning token not found or expired";
        // Authoritative gate: an emailed provisioning token is not registration-ready
        // until the password has been verified (RenewPasskeyToken) or it was minted
        // post-login (SetPasskeyToken). Blocks registering a passkey straight from an
        // intercepted email link without the password.
        if (!user.PasskeyRegistrationReady)
        {
            ServiceLogger.Warn($"[DB] Rejected passkey registration for '{user.Username}': token not password-verified");
            return "ERROR: Registration not authorized";
        }

        user.PasskeyCredentials.Add(new StoredPasskeyCredential
        {
            CredentialId  = credentialId,
            PublicKey     = publicKey,
            SignCount     = signCount,
            RegisteredUtc = DateTime.UtcNow
        });
        user.PasskeyProvisioningToken      = null;
        user.PasskeyProvisioningExpiresUtc = null;
        user.PasskeyRegistrationReady      = false;
        SaveUsers(users);
        ServiceLogger.Log($"[DB] Passkey credential registered for '{user.Username}'");
        return "SUCCESS";
    }

    private static IDisposable? AcquireDbLock()
    {
        try
        {
            if (!_dbMutex.WaitOne(TimeSpan.FromSeconds(10))) return null;
        }
        catch (AbandonedMutexException)
        {
            // A prior process crashed while holding the lock; Windows transferred ownership to us.
            ServiceLogger.Warn("[DB LOCK] Mutex was abandoned by a prior process — ownership transferred, proceeding.");
        }
        return new DbLock(_dbMutex);
    }

    private sealed class DbLock : IDisposable
    {
        readonly Mutex _m;
        internal DbLock(Mutex m) => _m = m;
        public void Dispose() => _m.ReleaseMutex();
    }

}

// -----------------------------------------------------------------------
// CERTIFICATE MONITOR SERVICE
// Watches the Windows cert store for the site's TLS certificate and emails
// the admins before it expires. Lives here (not in MFAWeb) so the alert still
// fires in the exact failure mode we care about: when no usable cert exists and
// MFAWeb can't serve HTTPS. Windows-only; a no-op elsewhere.
// -----------------------------------------------------------------------
public class CertificateMonitorService : BackgroundService
{
    private readonly IConfiguration _config;
    private readonly string _hostname;
    private readonly StoreName _storeName;
    private readonly StoreLocation _storeLocation;
    private readonly int _warnDays;
    private readonly TimeSpan _checkInterval;
    private DateTime _lastEmailUtc = DateTime.MinValue;

    public CertificateMonitorService(IConfiguration config)
    {
        _config = config;
        _hostname = config["HttpsCert:Subject"]
            ?? new Uri(config["AppUrl"] ?? "https://localhost").Host;
        _storeName = Enum.TryParse<StoreName>(config["HttpsCert:Store"], ignoreCase: true, out var sn)
            ? sn : StoreName.My;
        _storeLocation = Enum.TryParse<StoreLocation>(config["HttpsCert:Location"], ignoreCase: true, out var sl)
            ? sl : StoreLocation.LocalMachine;
        _warnDays = int.TryParse(config["CertAlert:WarnDays"], out var w) ? w : 20;
        int hours = int.TryParse(config["CertAlert:CheckIntervalHours"], out var h) && h >= 1 ? h : 12;
        _checkInterval = TimeSpan.FromHours(hours);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // The cert store is a Windows concept; on Linux TLS is handled by files/ACME.
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        ServiceLogger.Log($"[CERT] Monitor started for '{_hostname}' in {_storeLocation}/{_storeName}; " +
            $"warn at {_warnDays} day(s), checking every {_checkInterval.TotalHours:0}h.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try { CheckOnce(); }
            catch (Exception ex) { ServiceLogger.Error($"[CERT] Check failed: {ex.Message}"); }

            try { await Task.Delay(_checkInterval, stoppingToken); }
            catch (TaskCanceledException) { break; }
        }
    }

    [SupportedOSPlatform("windows")]
    private void CheckOnce()
    {
        var (found, notAfter, thumbprint) = InspectNewestCert();
        if (!found)
        {
            ServiceLogger.Warn($"[CERT] No certificate matching '{_hostname}' found in {_storeLocation}/{_storeName}.");
            MaybeEmail($"[MFA] TLS certificate MISSING for {_hostname}",
                $"No certificate matching '{_hostname}' was found in {_storeLocation}\\{_storeName} on this server.\n" +
                "MFAWeb cannot serve HTTPS until a valid certificate is installed.");
            return;
        }

        // X509 NotAfter is local time.
        int days = (int)Math.Floor((notAfter - DateTime.Now).TotalDays);
        if (days < 0)
        {
            ServiceLogger.Warn($"[CERT] Certificate for '{_hostname}' EXPIRED {-days} day(s) ago ({notAfter:yyyy-MM-dd}).");
            MaybeEmail($"[MFA] TLS certificate EXPIRED for {_hostname}",
                $"The certificate for '{_hostname}' (thumbprint {thumbprint}) expired on {notAfter:yyyy-MM-dd HH:mm}.\n" +
                "MFAWeb cannot serve valid HTTPS until it is renewed.");
        }
        else if (days <= _warnDays)
        {
            ServiceLogger.Warn($"[CERT] Certificate for '{_hostname}' expires in {days} day(s) ({notAfter:yyyy-MM-dd}).");
            MaybeEmail($"[MFA] TLS certificate expires in {days} day(s) for {_hostname}",
                $"The certificate for '{_hostname}' (thumbprint {thumbprint}) expires on {notAfter:yyyy-MM-dd HH:mm} — " +
                $"{days} day(s) from now.\nRenew it before then to avoid an outage.");
        }
        else
        {
            ServiceLogger.Debug($"[CERT] Certificate for '{_hostname}' healthy: {days} day(s) remaining ({notAfter:yyyy-MM-dd}).");
            _lastEmailUtc = DateTime.MinValue; // reset throttle so the next problem alerts immediately
        }
    }

    // Newest (latest-expiring) cert whose CN or SAN matches the hostname, ignoring
    // validity dates so we can report an already-expired cert rather than "missing".
    [SupportedOSPlatform("windows")]
    private (bool found, DateTime notAfter, string thumbprint) InspectNewestCert()
    {
        using var store = new X509Store(_storeName, _storeLocation);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

        X509Certificate2? best = null;
        foreach (var cert in store.Certificates)
        {
            bool matches;
            try { matches = cert.MatchesHostname(_hostname); }
            catch { matches = false; }
            if (matches && (best is null || cert.NotAfter > best.NotAfter))
                best = cert;
        }
        return best is null ? (false, default, "") : (true, best.NotAfter, best.Thumbprint);
    }

    // At most one email per 24h while a problem persists; reset to immediate once healthy.
    private void MaybeEmail(string subject, string body)
    {
        if (DateTime.UtcNow - _lastEmailUtc < TimeSpan.FromHours(24)) return;
        if (SendEmail(subject, body)) _lastEmailUtc = DateTime.UtcNow;
    }

    private bool SendEmail(string subject, string body)
    {
        var host   = _config["Smtp:Host"];
        var from   = _config["Smtp:FromAddress"];
        var notify = _config["Smtp:NotifyAddress"];
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(from) || string.IsNullOrWhiteSpace(notify))
        {
            ServiceLogger.Warn("[CERT] Smtp Host/FromAddress/NotifyAddress not fully configured — cannot send certificate alert.");
            return false;
        }

        int  port   = int.TryParse(_config["Smtp:Port"], out var p) ? p : 25;
        bool useSsl = bool.TryParse(_config["Smtp:UseSsl"], out var s) && s;
        var  user   = _config["Smtp:Username"];
        var  pass   = _config["Smtp:Password"];

        try
        {
            using var msg = new MailMessage(from, notify)
            {
                Subject = subject,
                Body    = body + "\n\n-- MFAService certificate monitor"
            };
            using var client = new SmtpClient(host, port) { EnableSsl = useSsl };
            if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(pass))
                client.Credentials = new System.Net.NetworkCredential(user, pass);

            client.Send(msg);
            ServiceLogger.Log($"[CERT] Alert email sent to {notify}: {subject}");
            return true;
        }
        catch (Exception ex)
        {
            ServiceLogger.Error($"[CERT] Failed to send alert email: {ex.Message}");
            return false;
        }
    }
}

public class UserEntry
{
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string TotpSecret { get; set; } = string.Empty;
    // True once the user has visited the setup page and scanned their QR code.
    // MFAAdmin sets this to false on add/reprovision; BurnTotpToken sets it to true.
    public bool TotpConfirmed { get; set; } = false;
    public string? ProvisioningToken { get; set; }
    public DateTime? ProvisioningExpiresUtc { get; set; }
    public List<StoredPasskeyCredential> PasskeyCredentials { get; set; } = new();
    public string? PasskeyProvisioningToken { get; set; }
    public DateTime? PasskeyProvisioningExpiresUtc { get; set; }
    // True only after the password has been verified (RenewPasskeyToken) or for a
    // token minted post-login (SetPasskeyToken). The emailed provisioning token is
    // NOT registration-ready. AddPasskey enforces this so an intercepted email link
    // cannot register a credential without passing the password gate.
    public bool PasskeyRegistrationReady { get; set; } = false;
}

public class StoredPasskeyCredential
{
    public string CredentialId { get; set; } = string.Empty;   // base64url
    public string PublicKey { get; set; } = string.Empty;      // base64url (COSE)
    public uint SignCount { get; set; }
    public DateTime RegisteredUtc { get; set; }
}
