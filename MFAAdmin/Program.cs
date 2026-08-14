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
using System.Reflection;
using System.Text.Json;
using static Org.BouncyCastle.Math.EC.ECCurve;

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
    }

    public class UserEntry
    {
        public string Username { get; set; }
        public string PasswordHash { get; set; }
        public string TotpSecret { get; set; }
        // True once the user has visited the setup page and scanned their QR code.
        // MFAAdmin sets this to false on add/reprovision; BurnTotpToken sets it to true.
        public bool TotpConfirmed { get; set; } = false;
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
        // Cross-process mutex — shared by MFAWeb, MFAService, and MFAAdmin to serialize all DB reads/writes.
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

        private static string RulePrefix => Config?["RulePrefix"] ?? "MFA_Temp_";

        // DPAPI Entropy (Windows Only) — loaded from config in Main()
        private static byte[] Entropy = Array.Empty<byte>();

        private static IConfigurationRoot Config;

        static void Main(string[] args)
        {
            Config = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            AdminLogger.SetMinLevel(Config["Logging:AppMinLevel"]);
            string? entropyStr = Config["DpapiEntropy"];
            if (string.IsNullOrWhiteSpace(entropyStr))
                throw new InvalidOperationException("DpapiEntropy must be configured in appsettings.json. Set it to a unique random string for your deployment.");
            Entropy = Encoding.UTF8.GetBytes(entropyStr);

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

            if (cleanArgs.Length == 0)
            {
                var _asm = Assembly.GetExecutingAssembly();
                var _ver = _asm.GetName().Version?.ToString(3) ?? "unknown";
                var _built = _asm.GetCustomAttributes<AssemblyMetadataAttribute>()
                    .FirstOrDefault(a => a.Key == "BuildDate")?.Value ?? "unknown";
                Console.WriteLine("========================================");
                Console.WriteLine($"       {SiteName} MFA Admin Tool          ");
                Console.WriteLine($"       v{_ver}  |  Built {_built} UTC");
                Console.WriteLine("========================================");
                Console.WriteLine("Usage: MFAAdmin [add|list|delete|diag|reset|reprovision|export|import] [username|filepath]");
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
                default:
                    AdminLogger.Log("Unknown command. Use: add, list, delete, diag, reset, reprovision, export, import");
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
                username = Console.ReadLine()?.Trim();
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

            // Credentials generated outside the lock — BCrypt hashing is expensive
            string password = GenerateRandomPassword(12);
            byte[] secretBytes = KeyGeneration.GenerateRandomKey(32);
            string base32Secret = Base32Encoding.ToString(secretBytes);
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
                    ProvisioningToken = provisioningToken,
                    ProvisioningExpiresUtc = expiresUtc,
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
            string totpUrl    = $"{baseUrl.TrimEnd('/')}/setup/{provisioningToken}";
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
        static bool SendProvisioningEmail(string userEmail, string tempPassword, string totpUrl, string passkeyUrl)
        {
            var host = Config["Smtp:Host"];
            var port = int.Parse(Config["Smtp:Port"]);
            var useSsl = bool.Parse(Config["Smtp:UseSsl"]);
            var smtpUsername = Config["Smtp:Username"];
            var smtpPassword = Config["Smtp:Password"];
            var fromAddress = Config["Smtp:FromAddress"];

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress($"{SiteName} Support", fromAddress));
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

    <!-- Secondary: TOTP -->
    <p style='font-size: 0.88em; color: #666; margin: 24px 0 6px 0;'>
        <strong>Don&rsquo;t have a compatible device?</strong> You can use an authenticator app instead.
        Google Authenticator, Authy, and Microsoft Authenticator are all supported.
        You&rsquo;ll enter a 6-digit code each time you log in.
    </p>
    <p style='font-size: 0.82em; color: #d9534f; margin: 0 0 8px 0;'><strong>Note:</strong> Have your authenticator app open before clicking &mdash; the QR code is shown only once.</p>
    <a href='{totpUrl}' style='display:inline-block; background:#555; color:#fff; padding:9px 16px; border-radius:4px; text-decoration:none; font-size:0.88em;'>Set Up Authenticator App &rarr;</a>

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
        static void ReprovisionUser(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                Console.Write("Enter User Email to reprovision: ");
                username = Console.ReadLine()?.Trim();
            }

            if (string.IsNullOrEmpty(username)) return;

            // Generate credentials outside the lock — BCrypt hashing is expensive
            string newPassword     = GenerateRandomPassword(12);
            byte[] secretBytes     = KeyGeneration.GenerateRandomKey(32);
            string newBase32Secret = Base32Encoding.ToString(secretBytes);
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
                user.ProvisioningToken         = newTotpToken;
                user.ProvisioningExpiresUtc    = expiresUtc;
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
            string totpUrl    = $"{baseUrl.TrimEnd('/')}/setup/{newTotpToken}";
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
            var confirm = Console.ReadLine()?.Trim().ToUpper();
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
                File.WriteAllText(outputPath, json, Encoding.UTF8);
                AdminLogger.Log($"[SUCCESS] Exported {users.Count} user(s) to '{Path.GetFullPath(outputPath)}'");
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

            int existingCount;
            using (AcquireDbLock()) { existingCount = LoadUsers().Count; }

            Console.WriteLine($"\nImport file : {Path.GetFullPath(inputPath)}");
            Console.WriteLine($"  Users in file    : {imported.Count}");
            Console.WriteLine($"  Users in database: {existingCount}");
            Console.WriteLine("\n[WARNING] This will OVERWRITE the entire current database.");
            Console.Write("\nContinue? (Y/N): ");
            var confirm = Console.ReadLine()?.Trim().ToUpper();
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
                string status;
                string passkeyStatus;

                // If a TOTP provisioning token exists, the user hasn't scanned their QR code yet
                if (!string.IsNullOrEmpty(u.ProvisioningToken))
                {
                    if (u.ProvisioningExpiresUtc.HasValue && DateTime.UtcNow > u.ProvisioningExpiresUtc.Value)
                    {
                        status = "Setup Link EXPIRED";
                    }
                    else
                    {
                        status = $"Pending Setup (Expires: {u.ProvisioningExpiresUtc?.ToLocalTime():MM/dd HH:mm})";
                    }
                    passkeyStatus = "N/A";
                }
                else
                {
                    // TOTP setup is complete
                    status = "Active / Provisioned";

                    if (u.PasskeyCredentials.Count > 0)
                    {
                        passkeyStatus = $"{u.PasskeyCredentials.Count} registered";
                    }
                    else if (!string.IsNullOrEmpty(u.PasskeyProvisioningToken))
                    {
                        if (u.PasskeyProvisioningExpiresUtc.HasValue && DateTime.UtcNow > u.PasskeyProvisioningExpiresUtc.Value)
                        {
                            passkeyStatus = "Setup Link EXPIRED";
                        }
                        else
                        {
                            passkeyStatus = $"Pending (Exp: {u.PasskeyProvisioningExpiresUtc?.ToLocalTime():MM/dd HH:mm})";
                        }
                    }
                    else
                    {
                        passkeyStatus = "None";
                    }
                }

                Console.WriteLine($"{u.Username,-30} | {status,-38} | {passkeyStatus,-20}");
            }

            Console.WriteLine($"\nTotal Users: {users.Count}");
        }

        static void DeleteUser(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                Console.Write("Enter User Email to delete: ");
                username = Console.ReadLine()?.Trim();
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
                AuditNotify("USER DELETED", $"User '{username}' was removed. All VPN/SSH access revoked.");
            }
            else
            {
                AdminLogger.Error($"[ERROR] User '{username}' not found.");
            }
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
                AdminLogger.Warn("[DB LOCK] Mutex was abandoned by a prior process — ownership transferred, proceeding.");
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
            string json = JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true });

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Windows: Encrypt using DPAPI Machine Key
                byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
                byte[] encryptedBytes = ProtectedData.Protect(jsonBytes, Entropy, DataProtectionScope.LocalMachine);
                File.WriteAllBytes(DbPath, encryptedBytes);
            }
            else
            {
                // Linux: Plain text (Requires sudo to execute the Admin Tool)
                File.WriteAllText(DbPath, json);
            }
        }

        // --- Utilities ---

        static void AuditNotify(string action, string details)
        {
            // Read settings from appsettings.json
            var host = Config["Smtp:Host"];
            var port = int.Parse(Config["Smtp:Port"]);
            var useSsl = bool.Parse(Config["Smtp:UseSsl"]);
            var username = Config["Smtp:Username"];
            var password = Config["Smtp:Password"];
            var fromAddress = Config["Smtp:FromAddress"];
            var notifyAddress = Config["Smtp:NotifyAddress"];

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress($"{SiteName} Admin Tool", fromAddress));
            message.To.Add(new MailboxAddress("Server Admins", notifyAddress));
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

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // WINDOWS LOGIC: Query PowerShell for our custom tagged rules
                Console.WriteLine($"{"IP Address",-15} | {"Port",-6} | {"User",-25} | {"Expires (Local)",-20}");
                Console.WriteLine(new string('-', 75));

                string psCommand = $"-NoProfile -Command \"Get-NetFirewallRule -DisplayName '{RulePrefix}*' -ErrorAction SilentlyContinue | ForEach-Object {{ $_.DisplayName + '||' + $_.Description }}\"";

                var psi = new ProcessStartInfo("powershell", psCommand)
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
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
                        var nameParts = parts[0].Split('_'); // e.g. MFA_Temp_192.168.1.50_22
                        string ip = nameParts[2];
                        string port = nameParts[3].Trim();

                        string desc = parts.Length > 1 ? parts[1] : "";
                        string user = "Unknown";
                        string expires = "Unknown";

                        // Parse the Description: "User: user@example.com | Expires: 2026-03-24 18:00 UTC"
                        if (desc.Contains("|"))
                        {
                            var descParts = desc.Split('|');
                            user = descParts[0].Replace("User:", "").Trim();

                            string expireString = descParts[1].Replace("Expires:", "").Trim();
                            if (DateTime.TryParse(expireString, out DateTime expireUtc))
                            {
                                expires = expireUtc.ToLocalTime().ToString("MM/dd/yyyy HH:mm");
                            }
                        }

                        Console.WriteLine($"{ip,-15} | {port,-6} | {user,-25} | {expires,-20}");
                    }
                    catch
                    {
                        // Silently skip unparseable rules to avoid crashing the diag tool
                    }
                }
            }
            else
            {
                // LINUX LOGIC: Query ipset for active countdown timers
                // Note: The Linux kernel 'ipset' does not store strings like 'Username', so we only get IP and Time Remaining.
                Console.WriteLine("Querying Linux kernel ipset for active sessions...\n");

                var psi = new ProcessStartInfo("sudo", "ipset list")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                if (string.IsNullOrWhiteSpace(output))
                {
                    Console.WriteLine("No active ipsets found.");
                }
                else
                {
                    // Just print the raw ipset output, as it is already highly readable for sysadmins
                    Console.WriteLine(output);
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

        static void ResetFirewall()
        {
            Console.WriteLine("\n[WARNING] This will remove all firewall access.");
            Console.WriteLine("You may need to re-authenticate to the MFA system to regain access.");
            Console.WriteLine("Make sure you have a valid setup.");
            Console.Write("\nAre you sure you want to continue? (Y/N): ");

            var confirm = Console.ReadLine()?.Trim().ToUpper();
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
                    string psCommand = $"-NoProfile -Command \"Remove-NetFirewallRule -DisplayName '{RulePrefix}*' -ErrorAction SilentlyContinue\"";

                    var psi = new ProcessStartInfo("powershell", psCommand)
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };

                    using var proc = Process.Start(psi);
                    proc.WaitForExit();

                    AdminLogger.Log("[SUCCESS] All temporary Windows SSH firewall rules have been cleared.");
                }
                else
                {
                    // LINUX: Find all ipsets starting with 'auth_' and flush their contents
                    string bashCommand = "-c \"for set in $(sudo ipset list -n | grep '^auth_'); do sudo ipset flush $set; done\"";

                    var psi = new ProcessStartInfo("bash", bashCommand)
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };

                    using var proc = Process.Start(psi);
                    proc.WaitForExit();

                    AdminLogger.Log("[SUCCESS] All active Linux WireGuard ipsets have been flushed.");
                }

                // Optional: Send an Audit Email that a global reset was triggered
                AuditNotify("GLOBAL FIREWALL RESET", "An administrator manually flushed all temporary firewall rules via the Admin Tool. All active sessions were terminated.");
            }
            catch (Exception ex)
            {
                AdminLogger.Error($"[ERROR] Failed to reset firewall: {ex.Message}");
            }
        }
    }
}