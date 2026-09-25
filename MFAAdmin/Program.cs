// Copyright (c) 2026 Pacific Northwest Software, Inc.
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

using MailKit.Net.Smtp;
using Microsoft.Extensions.Configuration;
using MimeKit;
using MimeKit.Utils;
using OtpNet;
using QRCoder;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace MFAAdmin
{
    public enum LogSeverity { Debug, Info, Warning, Error }

    internal static class AdminLogger
    {
        private static readonly string LogDirectory = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? @"C:\ProgramData\MFAAuth\Logs"
            : @"/var/log/mfa-auth";

        private static readonly object _lock = new();
        private static LogSeverity _minLevel = LogSeverity.Info;

        public static void SetMinLevel(string? level) =>
            _minLevel = level?.ToLowerInvariant() switch
            {
                "debug"             => LogSeverity.Debug,
                "warning" or "warn" => LogSeverity.Warning,
                "error"             => LogSeverity.Error,
                _                   => LogSeverity.Info
            };

        public static void Debug(string message)   => Write(message, LogSeverity.Debug);
        public static void Log(string message)     => Write(message, LogSeverity.Info);
        public static void Warn(string message)    => Write(message, LogSeverity.Warning);
        public static void Error(string message)   => Write(message, LogSeverity.Error);

        private static void Write(string message, LogSeverity level)
        {
            if (level < _minLevel) return;

            string tag = level switch
            {
                LogSeverity.Debug   => "DBG",
                LogSeverity.Warning => "WRN",
                LogSeverity.Error   => "ERR",
                _                   => "INF"
            };

            string entry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC] [{tag}] {message}";
            Console.WriteLine(entry);
            try
            {
                if (!Directory.Exists(LogDirectory))
                    Directory.CreateDirectory(LogDirectory);
                lock (_lock)
                {
                    DeleteExpiredLogs("mfaadmin_");
                    File.AppendAllText(
                        Path.Combine(LogDirectory, $"mfaadmin_{DateTime.UtcNow:yyyy-MM-dd}.log"),
                        entry + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LOG ERROR] Could not write to log file: {ex.Message}");
            }
        }

        // Daily files are kept for LogRetentionDays, then deleted by the first write of a new UTC day.
        // Dated by file name rather than mtime, so a touched or copied old file still ages out.
        private const int LogRetentionDays = 90;
        private static DateTime _lastRetentionSweepDay = DateTime.MinValue;

        // Caller holds _lock. A failure is only reported to the console, so it never blocks the log write.
        private static void DeleteExpiredLogs(string prefix)
        {
            var today = DateTime.UtcNow.Date;
            if (_lastRetentionSweepDay == today) return;
            _lastRetentionSweepDay = today;
            try
            {
                foreach (var file in Directory.EnumerateFiles(LogDirectory, prefix + "*.log"))
                {
                    string datePart = Path.GetFileNameWithoutExtension(file).Substring(prefix.Length);
                    if (DateTime.TryParseExact(datePart, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.None, out var day)
                        && day < today.AddDays(-LogRetentionDays))
                        File.Delete(file);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LOG ERROR] Could not remove expired log files: {ex.Message}");
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
        // Preserve the service's replay watermark on every unrelated admin DB write.
        public long? LastAcceptedTotpTimeStep { get; set; }
        public string? ProvisioningToken { get; set; }
        public DateTime? ProvisioningExpiresUtc { get; set; }
        public List<StoredPasskeyCredential> PasskeyCredentials { get; set; } = new();
        public string? PasskeyProvisioningToken { get; set; }
        public DateTime? PasskeyProvisioningExpiresUtc { get; set; }
        // True only once the password has been verified (via /setup-passkey) or the
        // user is already authenticated (post-login add-passkey). The emailed
        // provisioning token is NOT registration-ready — it must pass the password
        // gate first. Guards the /register-passkey routes and AddPasskey.
        public bool PasskeyRegistrationReady { get; set; } = false;
    }

    public class StoredPasskeyCredential
    {
        public string CredentialId { get; set; } = string.Empty;
        public string PublicKey { get; set; } = string.Empty;
        public uint SignCount { get; set; }
        public DateTime RegisteredUtc { get; set; }
    }

    class Program
    {
        // Cross-process mutex — shared by MFAService and MFAAdmin, the only two writers, to serialize
        // their writes. MFAWeb never writes the store and does not participate in this mutex.
        // ACL-restricted so only SYSTEM, Builtin Administrators, and the gMSA can acquire it.
        // Initialized in Main() after config is loaded so the service account name comes from appsettings.
        private static System.Threading.Mutex _dbMutex = null!;

#pragma warning disable CA1416
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
#pragma warning restore CA1416

        // OS-Aware File Paths
        private static string DbPath =>
            Config?["DbPath"] ?? (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? @"C:\ProgramData\MFAAuth\users.dat"
                : @"/etc/mfa-auth/users.json");

        private static string SiteName => Config?["SiteName"] ?? "MFA Auth";

        // Same character set MFAService enforces on BouncerConfig:RulePrefix. A prefix it would
        // refuse can't match any rule it created, so diag/reset/delete refuse it too rather than
        // scanning for, or removing, rules under a name that doesn't belong to this tool.
        private static readonly Regex RulePrefixPattern = new(@"^[A-Za-z0-9 _.-]{1,64}\z");

        // The only username form accepted by 'add', and by MFAService for firewall requests.
        // MailAddress also accepts quoted local parts ("any text"@domain) and other forms carrying
        // spaces, quotes or '|', which are misparsed where usernames are written into firewall
        // rule descriptions ("User: <name> Exp: <time>") and IPC requests.
        private static readonly Regex PlainEmailPattern = new(@"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\z");

        private static string RulePrefix
        {
            get
            {
                string prefix = Config?["RulePrefix"] ?? "MFA_Temp_";
                if (!RulePrefixPattern.IsMatch(prefix))
                    throw new InvalidOperationException("RulePrefix may contain only letters, digits, space, " +
                        "'_', '.' and '-' (1-64 characters); it must match MFAService's BouncerConfig:RulePrefix.");
                return prefix;
            }
        }

        // Validation above already excludes "'", so this is belt-and-braces: RulePrefix is
        // interpolated into single-quoted PowerShell strings. Use this, never the raw property, there.
        private static string RulePrefixPsEscaped => RulePrefix.Replace("'", "''");

        // TOTP support is a COMPILE-TIME decision (-p:AllowTotp=true), not a config value, so
        // it cannot drift out of step with MFAWeb at runtime. Without the flag no TOTP secret
        // is ever generated and users.dat holds no recoverable shared secret — only passkey
        // public keys and BCrypt hashes.
#if ALLOW_TOTP
        private const bool TotpEnabled = true;
#else
        private const bool TotpEnabled = false;
#endif

        // DPAPI Entropy (Windows Only) — loaded from config in Main()
        private static byte[] Entropy = Array.Empty<byte>();

        private static IConfigurationRoot Config = null!;   // set first thing in Main

        static void Main(string[] args)
        {
            Config = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            AdminLogger.SetMinLevel(Config["Logging:AppMinLevel"]);
            // DpapiEntropy must be a real per-deployment secret. DPAPI here is LocalMachine scope,
            // so this value is the only thing stopping another process on the same host from
            // decrypting users.dat — and the placeholder in appsettings.example.json is published
            // in the public source repository. Refuse to start rather than run with a known value.
            string? entropyStr = Config["DpapiEntropy"];
            if (string.IsNullOrWhiteSpace(entropyStr))
                throw new InvalidOperationException("DpapiEntropy must be configured in appsettings.json. Set it to a unique random string for your deployment.");
            if (entropyStr.Contains("REPLACE-WITH", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("DpapiEntropy is still set to the placeholder from appsettings.example.json. That value is public and offers no protection. Generate a unique random string for this deployment.");
            if (entropyStr.Trim().Length < 16)
                throw new InvalidOperationException("DpapiEntropy must be at least 16 characters. Generate a unique random string for this deployment (e.g. 32 random bytes, base64-encoded).");
            Entropy = Encoding.UTF8.GetBytes(entropyStr);

            // Surface the authentication posture on every run. Which mode is active decides
            // whether 'add'/'reprovision' mint a TOTP secret and whether the provisioning email
            // carries an authenticator-app link, so an operator should never have to guess --
            // particularly since this key must match MFAWeb's and a mismatch is otherwise silent.
#if ALLOW_TOTP
            AdminLogger.Warn("[WARN] TOTP is ENABLED (built with AllowTotp). Accounts will be provisioned with a TOTP secret. " +
                             "Ensure MFAWeb was built with the same flag.");
#else
            AdminLogger.Log("[INFO] TOTP is not enabled (built without AllowTotp). Passkey-only: no TOTP secret will be stored.");
#endif

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (!IsWindowsAdministrator())
                {
                    AdminLogger.Log("[INFO] Requesting Administrator privileges...");
                    try
                    {
                        var exeName = Process.GetCurrentProcess().MainModule?.FileName;

                        // --- NEW: Append our hidden flag ---
                        string argsString = string.Join(" ", args) + " --elevated-pause";

                        var startInfo = new ProcessStartInfo(exeName ?? "MFAAdmin.exe")
                        {
                            UseShellExecute = true,
                            Verb = "runas",
                            Arguments = argsString.Trim()
                        };
                        Process.Start(startInfo);
                    }
                    catch (System.ComponentModel.Win32Exception)
                    {
                        AdminLogger.Error("[ERROR] UAC prompt declined. Administrator rights are required.");
                    }
                    return; // Close the un-elevated Windows instance
                }
            }

            _dbMutex = CreateSecureDbMutex(Config["FirewallService:GmsaAccount"]);

            // Ensure the directory exists before doing anything
            var dir = Path.GetDirectoryName(DbPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            bool isElevatedPrompt = args.Contains("--elevated-pause");
            var cleanArgs = args.Where(a => a != "--elevated-pause").ToArray();

            // Checked once here rather than only when diag/reset/delete first read it, so a bad
            // value is a readable error on every command instead of an unhandled exception partway
            // through one (which, in the elevated Windows console, closed before it could be read).
            if (!RulePrefixPattern.IsMatch(Config["RulePrefix"] ?? "MFA_Temp_"))
            {
                AdminLogger.Error("[ERROR] RulePrefix may contain only letters, digits, space, '_', '.' and '-' " +
                                  "(1-64 characters); it must match MFAService's BouncerConfig:RulePrefix.");
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && isElevatedPrompt)
                {
                    Console.WriteLine("\nPress any key to exit...");
                    Console.ReadKey();
                }
                return;
            }

            if (cleanArgs.Length == 0)
            {
                var _asm = Assembly.GetExecutingAssembly();
                var _ver = _asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                           ?? _asm.GetName().Version?.ToString(3) ?? "unknown";
                Console.WriteLine("========================================");
                Console.WriteLine($"       {SiteName} MFA Admin Tool          ");
                Console.WriteLine($"       v{_ver}");
                Console.WriteLine("========================================");
                Console.WriteLine("Usage: MFAAdmin [add|list|delete|diag|reset|reprovision|export|import|purge-totp] [username|filepath]");
                return;
            }

            var cmd = cleanArgs[0].ToLower();

            switch (cmd)
            {
                case "add":
                    AddUser(cleanArgs.Length > 1 ? cleanArgs[1] : "");
                    break;
                case "list":
                    ListUsers();
                    break;
                case "delete":
                    DeleteUser(cleanArgs.Length > 1 ? cleanArgs[1] : "");
                    break;
                case "diag":
                    ShowDiagnostics();
                    break;
                case "reset":
                    ResetFirewall();
                    break;
                case "reprovision":
                    ReprovisionUser(cleanArgs.Length > 1 ? cleanArgs[1] : "");
                    break;
                case "export":
                    ExportUsers(cleanArgs.Length > 1 ? cleanArgs[1] : "");
                    break;
                case "import":
                    ImportUsers(cleanArgs.Length > 1 ? cleanArgs[1] : "");
                    break;
                case "purge-totp":
                    PurgeTotpSecrets();
                    break;
                default:
                    AdminLogger.Log("Unknown command. Use: add, list, delete, diag, reset, reprovision, export, import, purge-totp");
                    break;
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && isElevatedPrompt)
            {
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }

        static void AddUser(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                Console.Write("Enter User Email: ");
                username = Console.ReadLine()?.Trim() ?? "";
            }

            if (string.IsNullOrEmpty(username)) return;

            var allowedDomains = Config.GetSection("AllowedDomains").Get<string[]>() ?? Array.Empty<string>();

            if (!MailAddress.TryCreate(username, out var mailAddress) ||
                !allowedDomains.Any(d => d.Equals(mailAddress.Host, StringComparison.OrdinalIgnoreCase)))
            {
                AdminLogger.Error($"[ERROR] Invalid domain. Must be a valid email from: {string.Join(", ", allowedDomains)}");
                return;
            }

            username = mailAddress.Address;

            // A quoted local part containing "Exp: 2000-01-01 00:00", for instance, would expire
            // that user's own Windows grants on the next sweep. See PlainEmailPattern.
            if (!PlainEmailPattern.IsMatch(username))
            {
                AdminLogger.Error("[ERROR] Username must be a plain email address: letters, digits and . _ % + - " +
                                  "before the @, with no quotes or spaces.");
                return;
            }

            // Credentials generated outside the lock — BCrypt hashing is expensive
            string password = GenerateRandomPassword(12);
            // Passkey-only deployments mint no TOTP secret at all, so there is nothing
            // recoverable to steal from users.dat for accounts that never use TOTP.
            string base32Secret = TotpEnabled
                ? Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(32))
                : "";
            string provisioningToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
            string passkeyToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
            DateTime expiresUtc = DateTime.UtcNow.AddMinutes(60);
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

            using (AcquireDbLock())
            {
                var users = LoadUsers();

                if (users.Any(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase)))
                {
                    AdminLogger.Error($"[ERROR] User '{username}' already exists.");
                    return;
                }

                users.Add(new UserEntry
                {
                    Username = username,
                    PasswordHash = passwordHash,
                    TotpSecret = base32Secret,
                    TotpConfirmed = false,
                    // Only meaningful when TOTP is compiled in. Minting one otherwise leaves a
                    // token nothing can ever redeem or clear (BurnTotpToken is compiled out too).
                    ProvisioningToken = TotpEnabled ? provisioningToken : null,
                    ProvisioningExpiresUtc = TotpEnabled ? expiresUtc : (DateTime?)null,
                    PasskeyProvisioningToken = passkeyToken,
                    PasskeyProvisioningExpiresUtc = expiresUtc,
                    PasskeyRegistrationReady = false   // emailed token must pass the password gate first
                });

                UnlockDatabase();
                SaveUsers(users);
            }

            AdminLogger.Log($"[SUCCESS] User {username} provisioned.");
            AdminLogger.Log($"[INFO] Setup links expire at: {expiresUtc.ToLocalTime():HH:mm} (Local Time)");

            string baseUrl = Config["BouncerUrl"] ?? "";
            string totpUrl    = TotpEnabled ? $"{baseUrl.TrimEnd('/')}/setup/{provisioningToken}" : "";
            string passkeyUrl = $"{baseUrl.TrimEnd('/')}/setup-passkey/{passkeyToken}";

            AdminLogger.Log("[INFO] Sending provisioning email...");
            bool emailSent = SendProvisioningEmail(username, password, totpUrl, passkeyUrl);

            if (emailSent)
            {
                AdminLogger.Log("[SUCCESS] Welcome email sent successfully.");
            }
            else
            {
                AdminLogger.Warn("[WARNING] Failed to send email. Credentials printed to console only (not logged).");
                Console.WriteLine($"Password:     {password}");
                Console.WriteLine($"TOTP Link:    {totpUrl}");
                Console.WriteLine($"Passkey Link: {passkeyUrl}");
            }

            AuditNotify("USER CREATED", $"User '{username}' was provisioned. Setup links expire in 60 minutes.");
        }

        // --- NEW HELPER METHODS ---

        static string GenerateRandomPassword(int length)
        {
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

            return RandomNumberGenerator.GetString(validChars, length);
        }
        // Reads a required Smtp:* setting. Without this a missing key surfaced as an opaque
        // null-reference from inside MailKit rather than naming the setting that was absent.
        static string SmtpRequired(string key)
        {
            string? v = Config[$"Smtp:{key}"];
            if (string.IsNullOrWhiteSpace(v))
                throw new InvalidOperationException($"Smtp:{key} is not configured in appsettings.json.");
            return v;
        }

        // An ABSENT key takes the documented default; a PRESENT but unparseable value is an
        // error. The distinction matters most for UseSsl: silently reading garbage as `false`
        // would downgrade the provisioning email (temp password + setup tokens) to cleartext
        // SMTP. A typo must fail the send, never weaken it.
        static int SmtpPort()
        {
            string? v = Config["Smtp:Port"];
            if (string.IsNullOrWhiteSpace(v)) return 25;
            if (int.TryParse(v, out var p) && p >= 1 && p <= 65535) return p;
            throw new InvalidOperationException($"Smtp:Port value '{v}' is not a valid port (1-65535).");
        }

        static bool SmtpUseSsl(string host) => SmtpTransportPolicy.GetUseSsl(Config, host);

        static bool SendProvisioningEmail(string userEmail, string tempPassword, string totpUrl, string passkeyUrl)
        {
            // Config problems must land in the same return-false path as network problems:
            // the callers' fallback (print the credentials to the console) is the only way the
            // operator ever sees them, and an exception thrown here after the DB write would
            // skip it -- for reprovision that means a locked-out user and a lost password.
            string host, fromAddress; int port; bool useSsl;
            string? smtpUsername, smtpPassword;
            MailboxAddress fromMailbox;
            try
            {
                host = SmtpRequired("Host");
                port = SmtpPort();
                useSsl = SmtpUseSsl(host);
                smtpUsername = Config["Smtp:Username"];
                smtpPassword = Config["Smtp:Password"];
                fromAddress = SmtpRequired("FromAddress");
                fromMailbox = new MailboxAddress($"{SiteName} Support", fromAddress);
            }
            catch (Exception ex)
            {
                AdminLogger.Error($"[EMAIL ERROR]: {ex.Message}");
                return false;
            }

            var message = new MimeMessage();
            message.From.Add(fromMailbox);
            message.To.Add(new MailboxAddress("New User", userEmail));
            message.Subject = $"Secure Setup: {SiteName} Access";

            var builder = new BodyBuilder();
            builder.HtmlBody = $@"
<div style='font-family: Arial, sans-serif; line-height: 1.6; max-width: 580px; color: #222;'>
    <h2 style='color: #333; margin-bottom: 4px;'>Access Provisioned</h2>
    <p>Hello,</p>
    <p>Your secure access account has been created. You have <strong>60 minutes</strong> to complete setup before these links expire.</p>

    <div style='background-color: #f4f4f4; padding: 15px; border-radius: 5px; margin: 20px 0;'>
        <p style='margin: 0;'><strong>Username:</strong> {userEmail}</p>
        <p style='margin: 10px 0 0 0;'><strong>Temporary Password:</strong> <span style='font-family: monospace; font-size: 16px; background-color: #e0e0e0; padding: 2px 6px; border-radius: 4px;'>{tempPassword}</span></p>
    </div>

    <!-- Primary: Passkey -->
    <div style='border: 2px solid #2e7d32; border-radius: 6px; padding: 20px; margin: 20px 0;'>
        <p style='margin: 0 0 4px 0; font-size: 1.15em; color: #2e7d32;'><strong>&#10003; Recommended &mdash; Passkey</strong></p>
        <p style='margin: 0 0 12px 0; font-size: 0.9em; color: #444;'>Uses your device&rsquo;s built-in security &mdash; Face ID, Touch ID, fingerprint reader, or Windows Hello PIN &mdash; to sign you in with a single tap. No codes to type, and it&rsquo;s resistant to phishing. Works on Android, iOS 16+, and any modern desktop browser.</p>
        <a href='{passkeyUrl}' style='display:inline-block; background:#2e7d32; color:#fff; padding:11px 20px; border-radius:4px; text-decoration:none; font-weight:bold;'>Set Up Passkey &rarr;</a>
    </div>

    <!-- Secondary: TOTP. Omitted entirely in passkey-only deployments. -->
    {(string.IsNullOrEmpty(totpUrl) ? "" : $@"
    <p style='font-size: 0.88em; color: #666; margin: 24px 0 6px 0;'>
        <strong>Don&rsquo;t have a compatible device?</strong> You can use an authenticator app instead.
        Google Authenticator, Authy, and Microsoft Authenticator are all supported.
        You&rsquo;ll enter a 6-digit code each time you log in.
    </p>
    <p style='font-size: 0.82em; color: #d9534f; margin: 0 0 8px 0;'><strong>Note:</strong> Have your authenticator app open before clicking &mdash; the QR code is shown only once.</p>
    <a href='{totpUrl}' style='display:inline-block; background:#555; color:#fff; padding:9px 16px; border-radius:4px; text-decoration:none; font-size:0.88em;'>Set Up Authenticator App &rarr;</a>")}

    <p style='font-size: 0.82em; color: #888; margin-top: 28px;'>You&rsquo;ll be asked to enter your temporary password on the setup page to confirm your identity.</p>

    <p style='margin-top: 24px;'>Thank you,<br>{SiteName} IT Support</p>
</div>";

            message.Body = builder.ToMessageBody();

            using var client = new MailKit.Net.Smtp.SmtpClient();
            try
            {
                var secureOption = useSsl ? MailKit.Security.SecureSocketOptions.StartTls : MailKit.Security.SecureSocketOptions.None;
                client.Connect(host, port, secureOption);

                if (!string.IsNullOrWhiteSpace(smtpUsername) && !string.IsNullOrWhiteSpace(smtpPassword))
                {
                    client.Authenticate(smtpUsername, smtpPassword);
                }

                client.Send(message);
                client.Disconnect(true);
                return true;
            }
            catch (Exception ex)
            {
                AdminLogger.Error($"[EMAIL ERROR]: {ex.Message}");
                return false;
            }
        }
        // Clears stored TOTP secrets after a deployment switches to passkey-only.
        // Building without AllowTotp stops new secrets being minted but does not remove secrets
        // already in users.dat — without this, a "passkey-only" deployment can still be sitting
        // on a database full of live, recoverable shared secrets.
        //
        // Refuses to strand anyone: an account with no passkey enrolled keeps its secret, since
        // clearing it would leave that user with no way to authenticate at all.
        static void PurgeTotpSecrets()
        {
            int cleared = 0, skipped = 0, alreadyClear = 0;
            var strandedUsers = new List<string>();

            using (AcquireDbLock())
            {
                var users = LoadUsers();

                foreach (var u in users)
                {
                    if (string.IsNullOrEmpty(u.TotpSecret) && !u.TotpConfirmed) { alreadyClear++; continue; }

                    if (u.PasskeyCredentials.Count == 0)
                    {
                        skipped++;
                        strandedUsers.Add(u.Username);
                        continue;
                    }

                    u.TotpSecret    = "";
                    u.TotpConfirmed = false;
                    u.LastAcceptedTotpTimeStep = null;
                    cleared++;
                }

                if (cleared > 0)
                {
                    UnlockDatabase();
                    SaveUsers(users);
                }
            }

            AdminLogger.Log($"[SUCCESS] TOTP purge complete: {cleared} secret(s) cleared, {alreadyClear} already clear, {skipped} skipped.");

            if (skipped > 0)
            {
                AdminLogger.Warn($"[WARN] {skipped} account(s) kept their TOTP secret because no passkey is enrolled - " +
                                 "clearing it would lock them out entirely:");
                foreach (var name in strandedUsers)
                    AdminLogger.Warn($"        {name}");
                AdminLogger.Warn("[WARN] Have these users enroll a passkey, or run 'reprovision <email>' for each, then re-run purge-totp.");
            }
        }

        static void ReprovisionUser(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                Console.Write("Enter User Email to reprovision: ");
                username = Console.ReadLine()?.Trim() ?? "";
            }

            if (string.IsNullOrEmpty(username)) return;

            // Generate credentials outside the lock — BCrypt hashing is expensive
            string newPassword     = GenerateRandomPassword(12);
            // Passkey-only deployments mint no TOTP secret; reprovisioning also clears any
            // secret an account picked up before the mode was enabled.
            string newBase32Secret = TotpEnabled
                ? Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(32))
                : "";
            string newTotpToken    = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
            string newPasskeyToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
            DateTime expiresUtc    = DateTime.UtcNow.AddMinutes(60);
            string newPasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);
            string reprovisioned   = "";

            using (AcquireDbLock())
            {
                var users = LoadUsers();
                var user = users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
                if (user == null)
                {
                    AdminLogger.Error($"[ERROR] User '{username}' not found in the database. Use 'add' to create them.");
                    return;
                }

                user.PasswordHash              = newPasswordHash;
                user.TotpSecret                = newBase32Secret;
                user.TotpConfirmed             = false;
                user.LastAcceptedTotpTimeStep   = null;
                user.ProvisioningToken         = TotpEnabled ? newTotpToken : null;
                user.ProvisioningExpiresUtc    = TotpEnabled ? expiresUtc : (DateTime?)null;
                user.PasskeyCredentials        = new();
                user.PasskeyProvisioningToken  = newPasskeyToken;
                user.PasskeyProvisioningExpiresUtc = expiresUtc;
                user.PasskeyRegistrationReady  = false;   // reset: emailed token must pass the password gate first

                UnlockDatabase();
                SaveUsers(users);
                reprovisioned = user.Username;
            }

            AdminLogger.Log($"[SUCCESS] User {reprovisioned} reprovisioned.");
            AdminLogger.Log($"[INFO] New setup links expire at: {expiresUtc.ToLocalTime():HH:mm} (Local Time)");

            // Construct URLs and send email
            string baseUrl    = Config["BouncerUrl"] ?? "";
            string totpUrl    = TotpEnabled ? $"{baseUrl.TrimEnd('/')}/setup/{newTotpToken}" : "";
            string passkeyUrl = $"{baseUrl.TrimEnd('/')}/setup-passkey/{newPasskeyToken}";

            AdminLogger.Log("[INFO] Sending reprovisioning email...");
            bool emailSent = SendProvisioningEmail(reprovisioned, newPassword, totpUrl, passkeyUrl);

            if (emailSent)
            {
                AdminLogger.Log("[SUCCESS] Reprovisioning email sent successfully.");
            }
            else
            {
                AdminLogger.Warn("[WARNING] Failed to send email. Credentials printed to console only (not logged).");
                Console.WriteLine($"New Password:     {newPassword}");
                Console.WriteLine($"TOTP Link:        {totpUrl}");
                Console.WriteLine($"Passkey Link:     {passkeyUrl}");
            }

            AuditNotify("USER REPROVISIONED", $"User '{reprovisioned}' was issued a new password, MFA secret, and setup links. Existing passkeys cleared.");
        }



        static void ExportUsers(string outputPath)
        {
            if (string.IsNullOrEmpty(outputPath))
                outputPath = $"mfa_export_{DateTime.UtcNow:yyyy-MM-dd}.json";

            Console.WriteLine($"\n[WARNING] The export file will contain unencrypted data:");
            Console.WriteLine("  - Password hashes");
            Console.WriteLine("  - TOTP secrets");
            Console.WriteLine("  - Passkey public keys and credential IDs");
            Console.WriteLine($"\nOutput path: {Path.GetFullPath(outputPath)}");
            Console.Write("\nContinue? (Y/N): ");
            var confirm = Console.ReadLine()?.Trim().ToUpper() ?? "";
            if (confirm != "Y" && confirm != "YES")
            {
                Console.WriteLine("Export cancelled.");
                return;
            }

            try
            {
                List<UserEntry> users;
                using (AcquireDbLock()) { users = LoadUsers(); }

                string json = JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true });

                // This file holds password hashes, TOTP secrets, and any live provisioning tokens
                // in the clear -- restrict it from the instant it exists rather than tightening it
                // afterward. FileMode.CreateNew also refuses to follow an existing file or symlink
                // at this path instead of silently overwriting it.
                using (var stream = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    // The handle overload, not the path overload: it chmods the descriptor already
                    // open above instead of re-resolving outputPath on disk, which would reopen a
                    // symlink-race window between CreateNew and the chmod.
                    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        File.SetUnixFileMode(stream.SafeFileHandle, UnixFileMode.UserRead | UnixFileMode.UserWrite); // 600
                    else
                    {
                        // FileInfo.SetAccessControl, not the handle-based FileStream overload: the
                        // stream above was opened without WRITE_DAC, so SetSecurityInfo on that
                        // handle fails even when elevated. FileInfo opens its own handle instead.
                        var security = new FileSecurity();
                        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                        security.AddAccessRule(new FileSystemAccessRule(
                            WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));
                        new FileInfo(outputPath).SetAccessControl(security);
                    }

                    byte[] bytes = Encoding.UTF8.GetBytes(json);
                    stream.Write(bytes, 0, bytes.Length);
                }

                AdminLogger.Log($"[SUCCESS] Exported {users.Count} user(s) to '{Path.GetFullPath(outputPath)}'");
            }
            catch (IOException) when (File.Exists(outputPath))
            {
                AdminLogger.Error($"[ERROR] Export failed: '{Path.GetFullPath(outputPath)}' already exists. " +
                    "Remove it or choose a different path -- export refuses to write through an existing file.");
            }
            catch (Exception ex)
            {
                AdminLogger.Error($"[ERROR] Export failed: {ex.Message}");
            }
        }

        static void ImportUsers(string inputPath)
        {
            if (string.IsNullOrEmpty(inputPath))
            {
                Console.Write("Enter path to import file: ");
                inputPath = Console.ReadLine()?.Trim() ?? "";
            }

            if (string.IsNullOrEmpty(inputPath) || !File.Exists(inputPath))
            {
                AdminLogger.Error($"[ERROR] File not found: {inputPath}");
                return;
            }

            List<UserEntry> imported;
            try
            {
                string json = File.ReadAllText(inputPath, Encoding.UTF8);
                imported = JsonSerializer.Deserialize<List<UserEntry>>(json) ?? new List<UserEntry>();
            }
            catch (Exception ex)
            {
                AdminLogger.Error($"[ERROR] Failed to parse import file: {ex.Message}");
                return;
            }

            // An imported file is untrusted input -- a tampered or hand-edited one could set
            // PasskeyRegistrationReady=true directly, paired with any token, and skip the password
            // gate at the next registration attempt. Force it false unconditionally on import; a
            // legitimate pending registration just re-does the password step.
            int strippedReady = imported.Count(u => u.PasskeyRegistrationReady);
            foreach (var u in imported) u.PasskeyRegistrationReady = false;
            if (strippedReady > 0)
                Console.WriteLine($"  Note: cleared PasskeyRegistrationReady on {strippedReady} record(s) -- " +
                    "imported data cannot claim that state directly.");

            // Not refused: import is how a backup is restored, and an older database may hold such
            // an account. MFAService rejects its firewall requests, so it fails closed; say so here.
            var nonPlain = imported.Where(u => !PlainEmailPattern.IsMatch(u.Username)).Select(u => u.Username).ToList();
            if (nonPlain.Count > 0)
                Console.WriteLine($"  Warning: {nonPlain.Count} account(s) do not have a plain email address and will not " +
                    $"be able to open the firewall: {string.Join(", ", nonPlain)}");

            int existingCount;
            using (AcquireDbLock()) { existingCount = LoadUsers().Count; }

            Console.WriteLine($"\nImport file : {Path.GetFullPath(inputPath)}");
            Console.WriteLine($"  Users in file    : {imported.Count}");
            Console.WriteLine($"  Users in database: {existingCount}");
            Console.WriteLine("\n[WARNING] This will OVERWRITE the entire current database.");
            Console.Write("\nContinue? (Y/N): ");
            var confirm = Console.ReadLine()?.Trim().ToUpper() ?? "";
            if (confirm != "Y" && confirm != "YES")
            {
                Console.WriteLine("Import cancelled.");
                return;
            }

            try
            {
                using (AcquireDbLock())
                {
                    UnlockDatabase();
                    SaveUsers(imported);
                }
                AdminLogger.Log($"[SUCCESS] Imported {imported.Count} user(s) from '{Path.GetFullPath(inputPath)}'");
                AuditNotify("DATABASE IMPORTED", $"Database replaced via import from '{inputPath}'. {imported.Count} user(s) loaded, replacing {existingCount} previous record(s).");
            }
            catch (Exception ex)
            {
                AdminLogger.Error($"[ERROR] Import failed: {ex.Message}");
            }
        }

        static void ListUsers()
        {
            List<UserEntry> users;
            using (AcquireDbLock()) { users = LoadUsers(); }

            Console.WriteLine($"\n{"Username",-30} | {"MFA Status",-38} | {"Passkeys",-20}");
            Console.WriteLine(new string('-', 95));

            foreach (var u in users)
            {
                // Passkey state is independent of TOTP state, so report it unconditionally.
                // The previous version hard-coded "N/A" here whenever a TOTP provisioning token
                // existed, which hid real registrations. In a passkey-only build that was
                // permanent: BurnTotpToken (the only thing that clears ProvisioningToken) is
                // compiled out, so every enrolled user showed "Setup Link EXPIRED / N/A" forever.
                string passkeyStatus;
                if (u.PasskeyCredentials.Count > 0)
                {
                    passkeyStatus = $"{u.PasskeyCredentials.Count} registered";
                }
                else if (!string.IsNullOrEmpty(u.PasskeyProvisioningToken))
                {
                    passkeyStatus = u.PasskeyProvisioningExpiresUtc.HasValue
                                    && DateTime.UtcNow > u.PasskeyProvisioningExpiresUtc.Value
                        ? "Setup link EXPIRED"
                        : $"Pending (Exp: {u.PasskeyProvisioningExpiresUtc?.ToLocalTime():MM/dd HH:mm})";
                }
                else
                {
                    passkeyStatus = "None";
                }

                string status;
#if ALLOW_TOTP
                if (!string.IsNullOrEmpty(u.ProvisioningToken))
                {
                    status = u.ProvisioningExpiresUtc.HasValue && DateTime.UtcNow > u.ProvisioningExpiresUtc.Value
                        ? "TOTP setup link EXPIRED"
                        : $"TOTP pending (Exp: {u.ProvisioningExpiresUtc?.ToLocalTime():MM/dd HH:mm})";
                }
                else
                {
                    status = u.TotpConfirmed ? "Active / TOTP + passkey" : "Active / passkey only";
                }
#else
                // Passkey-only build: enrollment is entirely a function of passkey state.
                status = u.PasskeyCredentials.Count > 0 ? "Active" : "Awaiting passkey registration";
#endif

                Console.WriteLine($"{u.Username,-30} | {status,-38} | {passkeyStatus,-20}");
            }

            Console.WriteLine($"\nTotal Users: {users.Count}");
        }

        static void DeleteUser(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                Console.Write("Enter User Email to delete: ");
                username = Console.ReadLine()?.Trim() ?? "";
            }

            if (string.IsNullOrEmpty(username))
            {
                Console.WriteLine("Delete operation cancelled.");
                return;
            }

            int removed;
            using (AcquireDbLock())
            {
                var users = LoadUsers();
                removed = users.RemoveAll(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
                if (removed > 0) SaveUsers(users);
            }

            if (removed > 0)
            {
                AdminLogger.Log($"[SUCCESS] User '{username}' deleted.");

                // Deleting the account doesn't touch a firewall rule already open for this user --
                // it persists until it naturally expires. Say only what actually happened.
                string revocationNote;
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    int revoked = RevokeWindowsRulesForUser(username);
                    revocationNote = revoked > 0
                        ? $"{revoked} active firewall rule(s) for this user were also removed."
                        : "No active firewall rule was found for this user to remove.";
                }
                else
                {
                    // Unlike Windows, the Linux iptables comment carries no username (see
                    // OpenFirewallPort), so there's no way to find "this user's rules" here.
                    revocationNote = "Any active firewall rule for this user was NOT removed -- " +
                        "Linux rules are not tracked by username. It will expire naturally " +
                        "(within ExpirationHours) or can be found and removed by IP via 'diag'.";
                }
                // Closing the firewall only blocks *new* connections -- it doesn't end a session
                // this user already has established (see README.md's "Revoking access does not
                // end active sessions").
                const string sessionCaveat = "This closes the firewall to new connections. It does " +
                    "NOT end any session, tunnel, or process this user already has running. If " +
                    "removing them needs to be immediate and complete, separately verify -- and if " +
                    "necessary terminate -- their existing sessions on every system they could reach.";
                AdminLogger.Log($"[INFO] {revocationNote} {sessionCaveat}");
                AuditNotify("USER DELETED",
                    $"User '{username}' was removed from the database. {revocationNote} {sessionCaveat}");
            }
            else
            {
                AdminLogger.Error($"[ERROR] User '{username}' not found.");
            }
        }

        // Windows only: MFAService writes each rule's Description as "User: <email> Exp: <time>"
        // (see OpenFirewallPort), so a targeted per-user revocation is possible there in a way
        // it currently is not on Linux. Returns the number of rules removed.
        static int RevokeWindowsRulesForUser(string username)
        {
            string psQuery = $"-NoProfile -Command \"Get-NetFirewallRule -DisplayName '{RulePrefixPsEscaped}*' " +
                "-ErrorAction SilentlyContinue | ForEach-Object { $_.Name + '||' + $_.Description }\"";
            var queryPsi = new ProcessStartInfo("powershell", psQuery)
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var queryProc = Process.Start(queryPsi);
            if (queryProc is null) return 0;
            string output = queryProc.StandardOutput.ReadToEnd();
            queryProc.WaitForExit();

            int removed = 0;
            foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Split("||", 2);
                if (parts.Length != 2) continue;
                string ruleName = parts[0].Trim();
                // Same shape diag already parses: "User: someone@example.com Exp: ...".
                var match = Regex.Match(parts[1], @"User:\s*(?<user>\S+)\s+Exp:");
                if (!match.Success || !match.Groups["user"].Value.Equals(username, StringComparison.OrdinalIgnoreCase))
                    continue;

                var removePsi = new ProcessStartInfo("powershell",
                    $"-NoProfile -Command \"Remove-NetFirewallRule -Name '{ruleName}' -ErrorAction SilentlyContinue\"")
                {
                    CreateNoWindow = true, UseShellExecute = false
                };
                using var removeProc = Process.Start(removePsi);
                removeProc?.WaitForExit();
                removed++;
            }
            return removed;
        }

        // --- Core Security & OS-Aware IO ---

        static IDisposable AcquireDbLock()
        {
            try
            {
                if (!_dbMutex.WaitOne(TimeSpan.FromSeconds(10)))
                {
                    AdminLogger.Error("[DB LOCK] Timed out waiting for database lock.");
                    Environment.Exit(1);
                }
            }
            catch (AbandonedMutexException)
            {
                // A prior process crashed while holding the lock; Windows transferred ownership to us.
                AdminLogger.Warn("[DB LOCK] Mutex was abandoned by a prior process - ownership transferred, proceeding.");
            }
            return new DbLock(_dbMutex);
        }

        private sealed class DbLock : IDisposable
        {
            readonly Mutex _m;
            internal DbLock(Mutex m) => _m = m;
            public void Dispose() => _m.ReleaseMutex();
        }

        static List<UserEntry> LoadUsers()
        {
            if (!File.Exists(DbPath)) return new List<UserEntry>();

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // Windows: Decrypt using DPAPI Machine Key
                    byte[] encryptedBytes = File.ReadAllBytes(DbPath);
                    byte[] jsonBytes = ProtectedData.Unprotect(encryptedBytes, Entropy, DataProtectionScope.LocalMachine);
                    string json = Encoding.UTF8.GetString(jsonBytes);
                    return JsonSerializer.Deserialize<List<UserEntry>>(json) ?? new List<UserEntry>();
                }
                else
                {
                    // Linux: Plain text (Protected by file permissions/sudo)
                    string json = File.ReadAllText(DbPath);
                    return JsonSerializer.Deserialize<List<UserEntry>>(json) ?? new List<UserEntry>();
                }
            }
            catch (Exception ex)
            {
                AdminLogger.Error($"[CRITICAL ERROR] Failed to read the database: {ex.Message}");
                AdminLogger.Log("If on Windows, ensure you are on the machine that created the file.");
                Environment.Exit(1);
                return new();
            }
        }

        static void UnlockDatabase()
        {
            // If MFAService has applied the ReadOnly lock, remove it immediately so
            // the web process can write without waiting for the next 5-minute sweep.
            if (File.Exists(DbPath))
            {
                var attrs = File.GetAttributes(DbPath);
                if ((attrs & FileAttributes.ReadOnly) != 0)
                    File.SetAttributes(DbPath, attrs & ~FileAttributes.ReadOnly);
            }
        }

        static void SaveUsers(List<UserEntry> users)
        {
            // Clear ReadOnly here rather than relying on every caller to call UnlockDatabase()
            // first -- DeleteUser did not, and MFAService re-applies ReadOnly after each of its
            // writes, so that path failed against a live database. File.Replace throws on a
            // ReadOnly destination, so this is now a hard requirement, not a nicety.
            UnlockDatabase();

            string json = JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true });

            // Windows: DPAPI machine key. Linux: plain text (admin tool runs as root).
            byte[] payload = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? ProtectedData.Protect(Encoding.UTF8.GetBytes(json), Entropy, DataProtectionScope.LocalMachine)
                : Encoding.UTF8.GetBytes(json);

            // Temp file + flush + atomic swap, matching MFAService.SaveUsers. Writing over the
            // live file means a crash mid-write leaves users.dat truncated, LoadUsers then fails
            // to decrypt and returns an empty list, and every user is locked out with nothing on
            // disk to recover from. File.Replace keeps the prior contents as .bak.
            string tempPath   = DbPath + ".tmp";
            string backupPath = DbPath + ".bak";

            try
            {
                using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    fs.Write(payload, 0, payload.Length);
                    fs.Flush(flushToDisk: true);
                }

                // Tighten before the swap so users.dat never exists with a permissive umask mode.
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    File.SetUnixFileMode(tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                                                   UnixFileMode.GroupRead);   // 640

                if (File.Exists(DbPath))
                {
                    File.Replace(tempPath, DbPath, backupPath, ignoreMetadataErrors: true);
                    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        File.SetUnixFileMode(backupPath, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                                                         UnixFileMode.GroupRead);   // 640
                }
                else
                {
                    File.Move(tempPath, DbPath);
                }
            }
            finally
            {
                // A failed write leaves users.dat.tmp holding a full copy of the database.
                // Remove it rather than leaving credential material lying around.
                try
                {
                    if (File.Exists(tempPath)) File.Delete(tempPath);
                }
                catch (Exception ex)
                {
                    // Never let cleanup mask the original exception.
                    AdminLogger.Warn($"[WARN] Could not remove {tempPath}: {ex.Message}");
                }
            }
        }

        // --- Utilities ---

        static void AuditNotify(string action, string details)
        {
            // The audit email is best-effort and this method must NEVER throw: it is called
            // after the real work (user created, firewall reset) has already succeeded, and an
            // exception here would either crash the CLI or -- inside ResetFirewall's try --
            // report a successful reset as "[ERROR] Failed to reset firewall".
            string host, fromAddress, notifyAddress; int port; bool useSsl;
            string? username, password;
            MailboxAddress fromMailbox, toMailbox;
            try
            {
                host = SmtpRequired("Host");
                port = SmtpPort();
                useSsl = SmtpUseSsl(host);
                username = Config["Smtp:Username"];
                password = Config["Smtp:Password"];
                fromAddress = SmtpRequired("FromAddress");
                notifyAddress = SmtpRequired("NotifyAddress");
                fromMailbox = new MailboxAddress($"{SiteName} Admin Tool", fromAddress);
                toMailbox = new MailboxAddress("Server Admins", notifyAddress);
            }
            catch (Exception ex)
            {
                AdminLogger.Warn($"[ALERT] Audit email not sent: {ex.Message}");
                return;
            }

            var message = new MimeMessage();
            message.From.Add(fromMailbox);
            message.To.Add(toMailbox);
            message.Subject = $"[AUDIT] {action} - {DateTime.Now:yyyy-MM-dd HH:mm}";

            message.Body = new TextPart("plain")
            {
                Text = $"Action: {action}\nTimestamp: {DateTime.Now}\nDetails: {details}\n\nThis is an automated notification from the {SiteName} MFA Provisioning Tool."
            };

            using var client = new MailKit.Net.Smtp.SmtpClient();
            try
            {
                // Determine SSL requirement (StartTLS is usually best for port 587)
                var secureOption = useSsl
                    ? MailKit.Security.SecureSocketOptions.StartTls
                    : MailKit.Security.SecureSocketOptions.None;

                client.Connect(host, port, secureOption);

                // Conditionally Authenticate only if credentials are provided in the JSON
                if (!string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password))
                {
                    client.Authenticate(username, password);
                }

                client.Send(message);
                client.Disconnect(true);
            }
            catch (Exception ex)
            {
                AdminLogger.Warn($"[ALERT] Failed to send audit email: {ex.Message}");
            }
        }

        static string ReadPasswordHidden()
        {
            string pass = "";
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    pass += key.KeyChar;
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    pass = pass.Substring(0, (pass.Length - 1));
                    Console.Write("\b \b");
                }
            }
            while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return pass;
        }

        static void ShowDiagnostics()
        {
            Console.WriteLine("\n===========================================================");
            Console.WriteLine("                ACTIVE FIREWALL RULES                      ");
            Console.WriteLine("===========================================================\n");

            // Surface the auth posture. Baked in at build time, so it cannot drift from MFAWeb
            // at runtime -- but the two binaries do need to have been built the same way.
            Console.WriteLine(TotpEnabled
                ? "Auth mode: TOTP ENABLED (built with AllowTotp).\n"
                : "Auth mode: PASSKEY-ONLY (built without AllowTotp).\n");

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // WINDOWS LOGIC: Query PowerShell for our custom tagged rules
                Console.WriteLine($"{"Source",-43} | {"Port",-6} | {"User",-25} | {"Expires (Local)",-20}");
                Console.WriteLine(new string('-', 103));

                // The rule's own RemoteAddress is read as well as its name: the name carries the
                // client's exact address, but a grant widened by Ipv6GrantPrefixLength covers that
                // address's network, and only the address filter says so.
                string psCommand = $"-NoProfile -Command \"Get-NetFirewallRule -DisplayName '{RulePrefixPsEscaped}*' -ErrorAction SilentlyContinue | ForEach-Object {{ $_.DisplayName + '||' + $_.Description + '||' + ((($_ | Get-NetFirewallAddressFilter).RemoteAddress) -join ',') }}\"";

                var psi = new ProcessStartInfo("powershell", psCommand)
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc is null) { Console.WriteLine("Could not start the query process."); return; }
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                if (string.IsNullOrWhiteSpace(output))
                {
                    Console.WriteLine("No active temporary rules found.");
                    return;
                }

                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    try
                    {
                        var parts = line.Split("||");
                        // Name is "<RulePrefix><ip>_<port>_<protocol>". Strip the prefix before
                        // splitting: it may contain any number of underscores (or none).
                        string name = parts[0].Trim();
                        if (!name.StartsWith(RulePrefix, StringComparison.Ordinal)) continue;
                        var nameParts = name.Substring(RulePrefix.Length).Split('_');
                        string ip = nameParts[0];
                        string port = nameParts.Length > 1 ? nameParts[1].Trim() : "?";

                        string remote = parts.Length > 2 ? parts[2].Trim() : "";
                        if (remote.Length > 0) ip = remote;

                        string desc = parts.Length > 1 ? parts[1] : "";
                        string user = "Unknown";
                        string expires = "Unknown";

                        // MFAService writes the description as:
                        //   "User: someone@example.com Exp: 2026-03-24 18:00 UTC"
                        // (see OpenFirewallPort). Parse that exact shape -- an earlier version
                        // of this parser split on '|', a format the service never produced, so
                        // every row rendered as "Unknown".
                        var descMatch = Regex.Match(desc, @"User:\s*(?<user>\S+)\s+Exp:\s*(?<exp>.+?)\s*$");
                        if (descMatch.Success)
                        {
                            user = descMatch.Groups["user"].Value.Trim();

                            string expireString = descMatch.Groups["exp"].Value.Trim();
                            string noTz = expireString.EndsWith(" UTC", StringComparison.OrdinalIgnoreCase)
                                ? expireString.Substring(0, expireString.Length - 4)
                                : expireString;

                            expires = DateTime.TryParse(noTz, CultureInfo.InvariantCulture,
                                          DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                                          out DateTime expireUtc)
                                ? expireUtc.ToLocalTime().ToString("MM/dd/yyyy HH:mm")
                                : expireString;
                        }

                        Console.WriteLine($"{ip,-43} | {port,-6} | {user,-25} | {expires,-20}");
                    }
                    catch
                    {
                        // Silently skip unparseable rules to avoid crashing the diag tool
                    }
                }
            }
            else
            {
                // LINUX: read the iptables (IPv4) and ip6tables (IPv6) rules MFAService actually
                // writes -- a grant can land in either table depending on the client's address
                // family. An earlier version queried 'ipset list', which this service never
                // populates, so diag always showed nothing regardless of how many sessions were
                // open. The Linux rule comment carries only "<RulePrefix><ip>_<port> exp:<epoch>"
                // -- no username -- so that column is unavailable here, unlike on Windows.
                Console.WriteLine("Querying iptables/ip6tables for active MFA sessions...\n");

                string rules = RunBash("iptables -S INPUT 2>/dev/null", out _)
                             + "\n" + RunBash("ip6tables -S INPUT 2>/dev/null", out _);
                var mine = rules.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                                .Where(IsManagedRule)
                                .ToList();

                if (mine.Count == 0)
                {
                    Console.WriteLine("No active MFA firewall rules found.");
                }
                else
                {
                    Console.WriteLine($"{"Source",-43} | {"Port",-6} | {"Expires",-20}");
                    Console.WriteLine(new string('-', 77));

                    foreach (string line in mine)
                    {
                        // Keep the prefix length when the grant covers a network (Ipv6GrantPrefixLength
                        // below 128); drop it only for a single host (/32, /128), as before.
                        string ip   = Regex.Match(line, @"-s\s+(\S+)").Groups[1].Value;
                        if (ip.EndsWith("/32") || ip.EndsWith("/128")) ip = ip[..ip.LastIndexOf('/')];
                        string port = Regex.Match(line, @"--dport\s+(\d+)").Groups[1].Value;

                        string expires = "Unknown";
                        var exp = Regex.Match(line, @"exp:(\d+)");
                        if (exp.Success && long.TryParse(exp.Groups[1].Value, out long epoch))
                            expires = DateTimeOffset.FromUnixTimeSeconds(epoch)
                                        .ToLocalTime().ToString("MM/dd/yyyy HH:mm");

                        Console.WriteLine($"{(ip.Length   == 0 ? "?" : ip),-43} | " +
                                          $"{(port.Length == 0 ? "?" : port),-6} | {expires,-20}");
                    }

                    Console.WriteLine($"\n{mine.Count} active rule(s). Usernames are not recorded in iptables comments.");
                }
            }
            Console.WriteLine();
        }

#pragma warning disable CA1416 // Validate platform compatibility
        static bool IsWindowsAdministrator()
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
#pragma warning restore CA1416

        // Runs a bash command and returns trimmed stdout, with the exit code so callers can
        // tell a real failure from empty output. ArgumentList avoids shell-quoting pitfalls.
        // Mirrors MFAService.RunBash. Linux paths only.
        static string RunBash(string script, out int exitCode)
        {
            exitCode = -1;

            var psi = new ProcessStartInfo("/bin/bash");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(script);
            psi.CreateNoWindow         = true;
            psi.UseShellExecute        = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError  = true;

            using var proc = Process.Start(psi);
            if (proc == null) return string.Empty;

            string output = proc.StandardOutput.ReadToEnd().Trim();
            string error  = proc.StandardError.ReadToEnd().Trim();
            proc.WaitForExit();
            exitCode = proc.ExitCode;

            if (!string.IsNullOrWhiteSpace(error))
                AdminLogger.Debug($"[BASH] {error}");

            return output;
        }

        // Matches MFAService's own parsing exactly: the rule name is whatever the quoted comment
        // says, not any text elsewhere on the line. A prior substring match against RulePrefix
        // could delete an unrelated operator rule whose IP, port, or comment contained that text.
        static readonly Regex ManagedRuleComment =
            new(@"(?:^|\s)--comment ""(?<name>[^""]+) exp:\d+""(?:\s|$)", RegexOptions.Compiled);

        static bool IsManagedRule(string iptablesLine)
        {
            var match = ManagedRuleComment.Match(iptablesLine);
            return match.Success && match.Groups["name"].Value.StartsWith(RulePrefix, StringComparison.Ordinal);
        }

        static void ResetFirewall()
        {
            Console.WriteLine("\n[WARNING] This removes every MFA-granted firewall rule.");
            Console.WriteLine("Users will have to re-authenticate before they can open access again.");
            Console.WriteLine();
            Console.WriteLine("This closes the firewall to new connections. It does not necessarily end");
            Console.WriteLine("sessions that are already connected, and any client reaching the port");
            Console.WriteLine("through a separate rule is unaffected.");
            Console.Write("\nAre you sure you want to continue? (Y/N): ");

            var confirm = Console.ReadLine()?.Trim().ToUpper() ?? "";
            if (confirm != "Y" && confirm != "YES")
            {
                Console.WriteLine("Reset aborted.");
                return;
            }

            AdminLogger.Log("[INFO] Resetting firewall rules...");

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // WINDOWS: Delete all temporary Web API rules
                    string psCommand = $"-NoProfile -Command \"Remove-NetFirewallRule -DisplayName '{RulePrefixPsEscaped}*' -ErrorAction SilentlyContinue\"";

                    var psi = new ProcessStartInfo("powershell", psCommand)
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };

                    using var proc = Process.Start(psi);
                    proc?.WaitForExit();

                    AdminLogger.Log($"[SUCCESS] Removed Windows firewall rules matching '{RulePrefix}*'. " +
                        "Established connections are not terminated by this.");
                }
                else
                {
                    // LINUX: MFAService writes plain iptables (IPv4) / ip6tables (IPv6) rules
                    // tagged with RulePrefix -- it never creates ipsets. An earlier version of
                    // this flushed 'auth_*' ipsets and reported success unconditionally, so
                    // emergency revocation silently removed nothing while telling the operator
                    // access was closed.
                    //
                    // Mirror MFAService's sweeper: enumerate '<table> -S INPUT' for both tables
                    // and delete each matching rule by replaying it with -D instead of -A. Then
                    // RE-READ each chain and report what actually happened rather than assuming
                    // it worked.
                    int attempted = 0, failed = 0, remaining = 0;

                    foreach (string table in new[] { "iptables", "ip6tables" })
                    {
                        string rules = RunBash($"{table} -S INPUT 2>/dev/null", out _);

                        foreach (string line in rules.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                        {
                            if (!line.TrimStart().StartsWith("-A INPUT")) continue;
                            if (!IsManagedRule(line)) continue;

                            attempted++;
                            RunBash($"{table} " + line.TrimStart().Replace("-A INPUT", "-D INPUT"), out int rc);
                            if (rc != 0) failed++;
                        }

                        string after = RunBash($"{table} -S INPUT 2>/dev/null", out _);
                        remaining += after.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                                          .Count(IsManagedRule);
                    }

                    if (remaining > 0)
                        AdminLogger.Error(
                            $"[ERROR] {remaining} MFA-managed iptables/ip6tables rule(s) REMAIN after reset ({failed} delete(s) failed). " +
                            "Access is still open. Remove them manually: iptables -S INPUT | grep " + RulePrefix +
                            " (and ip6tables -S INPUT for IPv6).");
                    else if (attempted == 0)
                        AdminLogger.Log("[INFO] No MFA-managed iptables/ip6tables rules were present. Nothing to remove.");
                    else
                        AdminLogger.Log($"[SUCCESS] Removed {attempted} MFA-managed iptables/ip6tables rule(s); chains verified clear.");
                }

                // Optional: Send an Audit Email that a global reset was triggered
                AuditNotify("GLOBAL FIREWALL RESET", string.Join(Environment.NewLine, new[]
                {
                    "An administrator removed all MFA-granted firewall rules via the Admin Tool.",
                    "",
                    "The firewall is now closed to new connections on those rules.",
                    "",
                    "This does not necessarily end sessions that are already connected, and any",
                    "client reaching the port through a separate rule is unaffected. If a session",
                    "must actually be cut off, confirm that separately.",
                }));
            }
            catch (Exception ex)
            {
                AdminLogger.Error($"[ERROR] Failed to reset firewall: {ex.Message}");
            }
        }
    }
}
