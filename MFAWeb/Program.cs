// Copyright (c) 2026 Pacific Northwest Software, Inc.
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

using BCrypt.Net;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OtpNet;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Antiforgery;
using System.Reflection;

Directory.SetCurrentDirectory(AppContext.BaseDirectory);

var builder = WebApplication.CreateBuilder(args);

// --- Security: Rate Limiting ---
int rateLimitPerWindow = builder.Configuration.GetValue<int>("RateLimitPerWindow", 20);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy("LoginRateLimit", httpContext =>
    {
        // Always use the TCP connection's remote address — never X-Forwarded-For or
        // X-Real-IP headers.  Trusting proxy headers would allow an attacker to spoof
        // their IP and bypass rate limiting and the public-IP enforcement below.
        // By design, MFAWeb is deployed directly on the internet without a reverse
        // proxy so that Connection.RemoteIpAddress is always the true client address.
        string clientIp = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        return RateLimitPartition.GetFixedWindowLimiter(clientIp, _ =>
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = rateLimitPerWindow,
                Window = TimeSpan.FromMinutes(5),
                QueueLimit = 0
            });
    });
});
builder.Services.AddAntiforgery();
// Required for systemd units declaring Type=notify -- see the note in MFAService.
builder.Services.AddSystemd();
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "MFA Firewall Knocker";
});
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
});

// --- TLS ---
// MFAWeb is HTTPS-only and binds no cleartext listener at all. Certificates are obtained
// out of band by a dedicated ACME client (certbot on Linux, win-acme on Windows) rather
// than by this process, so the internet-facing service is not also an ACME client.
//
// A built-in LettuceEncrypt path used to live here. It was removed because it never worked:
// on Linux it reported "Timeout during connect (likely firewall problem)" for every HTTP-01
// attempt while certbot obtained a certificate for the same host, port and challenge type
// minutes later; on Windows it was never used at all, since port 80 was already taken. It
// also bound port 80 and served the ENTIRE application in cleartext there, not just the
// ACME challenge, and it pulled four packages (one NuGet-deprecated, one legacy BouncyCastle)
// into the most exposed component. Do not reintroduce an in-process ACME client.
if (!OperatingSystem.IsWindows())
{
    // --- Linux/macOS: PEM certificate, reloaded from disk without a restart ---
    //
    // The certificate lives at Kestrel:Endpoints:Https:Certificate:{Path,KeyPath}. Kestrel
    // would load that once at startup, which is a trap for a passkey gate: certbot renews on
    // schedule, but MFAWeb keeps serving the OLD certificate until something restarts it. When
    // it finally expires, browsers refuse the secure context, WebAuthn will not run, and in a
    // passkey-only build there is no other way in -- if SSH is itself gated, that is a remote
    // lockout caused by a *successful* renewal.
    //
    // So mirror the Windows behaviour: a selector that re-reads the file, keeps the last good
    // certificate if a read fails, and never hard-fails at startup. certbot's live/ directory
    // is a symlink to the current version, so re-reading the same path is all that is needed.
    //
    // NOTE: a selector overrides the certificate Kestrel loaded from configuration. That is
    // fine here because we load the same files ourselves. Do NOT install the Windows
    // store-scanning selector on this platform -- it can only return null ("Unix LocalMachine
    // X509Store is limited to the Root and CertificateAuthority stores") and that silently
    // replaced a perfectly good PEM with nothing, breaking TLS entirely. Verified on Ubuntu 24.04.
    string? pemCertPath = builder.Configuration["Kestrel:Endpoints:Https:Certificate:Path"];
    string? pemKeyPath  = builder.Configuration["Kestrel:Endpoints:Https:Certificate:KeyPath"];
    int pemWarnDays     = builder.Configuration.GetValue<int>("CertAlert:WarnDays", 20);

    if (string.IsNullOrWhiteSpace(pemCertPath) || string.IsNullOrWhiteSpace(pemKeyPath))
    {
        AuditLogger.Error("[CERT] Kestrel:Endpoints:Https:Certificate:Path and :KeyPath are not both " +
                          "configured, and there is no Windows certificate store on this platform. " +
                          "HTTPS will fail. See INSTALL.md.");
    }
    else
    {
        X509Certificate2? pemCached = null;
        DateTime pemNextCheck = DateTime.MinValue;
        object pemLock = new();

        X509Certificate2? LoadPem()
        {
            try
            {
                // Ephemeral key material; fine for Kestrel on Unix.
                var fresh = X509Certificate2.CreateFromPemFile(pemCertPath!, pemKeyPath!);
                if (DateTime.Now > fresh.NotAfter)
                    AuditLogger.Error($"[CERT] PEM certificate for '{fresh.Subject}' EXPIRED on " +
                                      $"{fresh.NotAfter:yyyy-MM-dd}. Passkey sign-in will fail: browsers " +
                                      "refuse WebAuthn on an invalid certificate. Renew immediately.");
                return fresh;
            }
            catch (Exception ex)
            {
                AuditLogger.Error($"[CERT] Could not load PEM certificate: {ex.Message}");
                return null;
            }
        }

        X509Certificate2? GetCurrentPem()
        {
            lock (pemLock)
            {
                if (pemCached is not null && DateTime.Now < pemNextCheck) return pemCached;
                pemNextCheck = DateTime.Now.AddMinutes(1);

                // Re-read the file once a minute and compare thumbprints. An earlier version
                // tried to skip the read unless the file's mtime changed, but the configured
                // path is normally a symlink (certbot's live/ -> archive/) and stat'ing the link
                // does not reliably reflect a rewritten target, so renewals were missed. Parsing
                // a PEM once a minute costs nothing; the mtime shortcut bought nothing and was
                // wrong. Verified on Ubuntu 24.04 against a certbot layout.
                var fresh = LoadPem();
                if (fresh is not null)
                {
                    bool changed = pemCached is null || fresh.Thumbprint != pemCached.Thumbprint;
                    if (changed && pemCached is not null)
                        AuditLogger.Log($"[CERT] Reloaded PEM certificate: now '{fresh.Subject}', " +
                                        $"expires {fresh.NotAfter:yyyy-MM-dd} (thumbprint {fresh.Thumbprint}).");

                    if (changed)
                    {
                        // Deliberately do NOT dispose the previous instance. The selector runs per
                        // TLS handshake, so a connection may still be completing with the object we
                        // just replaced; disposing frees its ephemeral private key and would fail
                        // that handshake. Let GC reclaim it. Matches the Windows path, which also
                        // never disposes the outgoing certificate.
                        pemCached = fresh;
                        CertStatus.Update(pemCached, pemWarnDays);
                    }
                    else
                    {
                        fresh.Dispose();   // unchanged; keep the instance already in use
                    }
                }
                else if (pemCached is not null)
                {
                    // Keep serving the last good certificate rather than dropping TLS.
                    AuditLogger.Warn("[CERT] Reload failed; continuing with the previously loaded certificate.");
                }
                return pemCached;
            }
        }

        var initial = GetCurrentPem();
        if (initial is null)
            AuditLogger.Error("[CERT] No usable PEM certificate at startup. HTTPS will fail until one exists.");
        else
            AuditLogger.Log($"[CERT] PEM certificate loaded for '{initial.Subject}', expires " +
                            $"{initial.NotAfter:yyyy-MM-dd}. Renewals are picked up without a restart.");

        builder.WebHost.ConfigureKestrel(kestrel =>
            kestrel.ConfigureHttpsDefaults(https => https.ServerCertificateSelector = (_, _) => GetCurrentPem()));
    }
}
else
{
    // --- HTTPS via a certificate from the Windows certificate store ---
    // The endpoint URL/port lives in appsettings under Kestrel:Endpoints:Https,
    // but the certificate is chosen here rather than bound by subject in config.
    // Binding a single cert by subject crashes the service at startup the moment
    // that specific cert expires or is removed (Kestrel throws in BindAsync).
    // Instead we scan the store and pick the newest, currently-valid certificate
    // whose subject matches the hostname, and re-evaluate periodically so a
    // renewed cert is picked up without restarting the service.
    string certSubject = builder.Configuration["HttpsCert:Subject"]
        ?? new Uri(builder.Configuration["AppUrl"] ?? "https://localhost").Host;
    var certStoreName = Enum.TryParse<StoreName>(
        builder.Configuration["HttpsCert:Store"], ignoreCase: true, out var sn) ? sn : StoreName.My;
    var certStoreLocation = Enum.TryParse<StoreLocation>(
        builder.Configuration["HttpsCert:Location"], ignoreCase: true, out var sl) ? sl : StoreLocation.LocalMachine;

    // Warn window for the post-login banner. The push (email) alert is owned by
    // MFAService, which stays healthy even when no usable cert exists.
    int certWarnDays = builder.Configuration.GetValue<int>("CertAlert:WarnDays", 20);

    // Cache the selected cert and refresh at most once a minute, so an expiring
    // cert is swapped for a freshly-issued replacement without a restart.
    X509Certificate2? cachedCert = SelectBestCertificate(certSubject, certStoreName, certStoreLocation);
    DateTime cacheExpiry = DateTime.Now.AddMinutes(1);
    object certLock = new();
    if (cachedCert is null)
        AuditLogger.Warn($"No currently-valid certificate for '{certSubject}' found in " +
            $"{certStoreLocation}/{certStoreName}. HTTPS will fail until one is installed.");
    CertStatus.Update(cachedCert, certWarnDays);

    X509Certificate2? GetCurrentCertificate()
    {
        lock (certLock)
        {
            // X509 NotBefore/NotAfter are local time, so compare against DateTime.Now.
            bool stale = cachedCert is null
                || DateTime.Now >= cacheExpiry
                || DateTime.Now > cachedCert.NotAfter
                || DateTime.Now < cachedCert.NotBefore;
            if (stale)
            {
                var picked = SelectBestCertificate(certSubject, certStoreName, certStoreLocation);
                if (picked is not null) cachedCert = picked; // keep last good cert if the store momentarily has none
                cacheExpiry = DateTime.Now.AddMinutes(1);
                CertStatus.Update(cachedCert, certWarnDays);
            }
            return cachedCert;
        }
    }

    builder.WebHost.ConfigureKestrel(kestrel =>
    {
        kestrel.ConfigureHttpsDefaults(https =>
        {
            https.ServerCertificateSelector = (_, _) => GetCurrentCertificate();
        });
    });
}

// Selects the newest, currently-valid certificate with a private key that is
// valid for the requested hostname. Matches against the Subject CN *and* the
// Subject Alternative Name entries — Let's Encrypt certs often carry the host
// only in the SAN with an empty Subject, so a CN-only lookup misses them.
// Returns null if none qualifies.
static X509Certificate2? SelectBestCertificate(string hostname, StoreName storeName, StoreLocation storeLocation)
{
    try
    {
        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
        var now = DateTime.Now;
        var match = store.Certificates
            .OfType<X509Certificate2>()
            .Where(c => c.HasPrivateKey
                && c.NotBefore <= now && c.NotAfter >= now
                && c.MatchesHostname(hostname))
            .OrderByDescending(c => c.NotAfter)
            .FirstOrDefault();
        if (match is not null)
            AuditLogger.Log($"TLS certificate selected for '{hostname}': subject '{match.Subject}', thumbprint {match.Thumbprint}, expires {match.NotAfter:u}");
        return match;
    }
    catch (Exception ex)
    {
        AuditLogger.Error($"Failed to select TLS certificate for '{hostname}': {ex.Message}");
        return null;
    }
}

// --- FIDO2/Passkey Configuration ---
string appUrl = builder.Configuration["AppUrl"] ?? "https://localhost";
var fido2 = new Fido2(new Fido2Configuration
{
    ServerDomain = new Uri(appUrl).Host,
    ServerName = builder.Configuration["SiteName"] ?? "MFA Secure Access",
    Origins = new HashSet<string> { appUrl }
});

var app = builder.Build();
AuditLogger.SetMinLevel(app.Configuration["Logging:AppMinLevel"]);
AuditLogger.LogDirectory = app.Configuration["LogPath"] ?? AuditLogger.LogDirectory;
LoginFailureMonitor.Configure(app.Configuration);

var _asm = Assembly.GetExecutingAssembly();
var _ver = _asm.GetName().Version?.ToString(3) ?? "unknown";
var _built = _asm.GetCustomAttributes<AssemblyMetadataAttribute>()
    .FirstOrDefault(a => a.Key == "BuildDate")?.Value ?? "unknown";
AuditLogger.Log($"MFAWeb v{_ver} (built {_built} UTC) starting...");

string siteName = app.Configuration["SiteName"] ?? "MFA Secure Access";
// HTML-escaped form for interpolation into the inline markup below. Operator-controlled
// config rather than user input, and the CSP would block injected script anyway, but this
// page is hand-assembled from strings so escaping every interpolated value is the habit
// worth keeping. Use `siteName` (unescaped) for non-HTML contexts such as the TOTP issuer.
string siteNameHtml = System.Net.WebUtility.HtmlEncode(siteName);
string logoUrl = app.Configuration["LogoUrl"] ?? "";
string imgSrcDirective = string.IsNullOrEmpty(logoUrl) || !Uri.TryCreate(logoUrl, UriKind.Absolute, out var logoUri)
    ? "img-src 'self'; "
    : $"img-src 'self' {logoUri.GetLeftPart(UriPartial.Authority)}; ";
app.UseHsts();
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'none'; " +
        "script-src 'self'; " +
        "style-src 'unsafe-inline'; " +
        imgSrcDirective +
        "connect-src 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'");
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");
    context.Response.Headers.Append("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()");
    await next();
});
app.UseRateLimiter();
app.UseStaticFiles();

// --- Passkey challenge store (in-memory, 2-minute expiry) ---
var passkeyStore = new ConcurrentDictionary<string, (string OptionsJson, string Username, DateTime Expiry)>();

// --- Configuration & OS Detection ---
string DbPath = app.Configuration["DbPath"] ?? (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
    ? @"C:\ProgramData\MFAAuth\users.dat"
    : @"/etc/mfa-auth/users.json");

// DpapiEntropy must be a real per-deployment secret. DPAPI here is LocalMachine scope,
// so this value is the only thing stopping another process on the same host from
// decrypting users.dat — and the placeholder in appsettings.example.json is published
// in the public source repository. Refuse to start rather than run with a known value.
string? dpapiEntropyStr = app.Configuration["DpapiEntropy"];
if (string.IsNullOrWhiteSpace(dpapiEntropyStr))
    throw new InvalidOperationException("DpapiEntropy must be configured in appsettings.json. Set it to a unique random string for your deployment.");
if (dpapiEntropyStr.Contains("REPLACE-WITH", StringComparison.OrdinalIgnoreCase))
    throw new InvalidOperationException("DpapiEntropy is still set to the placeholder from appsettings.example.json. That value is public and offers no protection. Generate a unique random string for this deployment.");
if (dpapiEntropyStr.Trim().Length < 16)
    throw new InvalidOperationException("DpapiEntropy must be at least 16 characters. Generate a unique random string for this deployment (e.g. 32 random bytes, base64-encoded).");
byte[] Entropy = Encoding.UTF8.GetBytes(dpapiEntropyStr);

// TOTP support is a COMPILE-TIME decision (-p:AllowTotp=true), not a runtime setting.
// Without the flag there is no TOTP login route, no TOTP enrollment route, and no TOTP form
// on the login page — the weaker method is absent from the binary rather than switched off,
// so it cannot be re-enabled by editing config or by a mistake in a conditional.
#if ALLOW_TOTP
AuditLogger.Warn("TOTP is ENABLED (built with AllowTotp). Password + authenticator login is accepted " +
                 "alongside passkeys. Ensure MFAAdmin was built with the same flag.");
#else
AuditLogger.Log("TOTP is not enabled (built without AllowTotp). Passkey-only.");
#endif

// --- Serve the Login UI ---
app.MapGet("/", async (HttpContext context, IAntiforgery antiforgery) =>
{
    // Use TCP connection address directly — see rate-limiter comment for why
    // X-Forwarded-For is intentionally ignored throughout this application.
    string clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    if (clientIp.StartsWith("::ffff:")) clientIp = clientIp.Substring(7); // Clean up IPv4-mapped IPv6

    AuditLogger.Debug($"Connection from {clientIp}");

    if (!IsPublicIpAddress(clientIp))
    {
        AuditLogger.Warn($"[SECURITY] Blocked authorization attempt from internal/private IP: {clientIp}");
        context.Response.StatusCode = 403; // Forbidden
        await context.Response.WriteAsync($"Error: Authorization is only permitted from external internet addresses ({clientIp})");
        return;
    }

    var csrfTokens = antiforgery.GetAndStoreTokens(context);

    // Built without AllowTotp this is the empty string, so no TOTP form is emitted at all --
    // and there is no /auth route for one to post to either.
#if ALLOW_TOTP
    string totpFormHtml = $@"
                <div class='try-another'>
                    <button type='button' id='toggleTotpBtn' class='try-another-btn'>Try another way&hellip;</button>
                </div>

                <div class='totp-section' id='totpSection'>
                    <form id='authForm' action='/auth' method='post'>
                        <input type='hidden' name='{csrfTokens.FormFieldName}' value='{csrfTokens.RequestToken}'/>
                        <input type='email' id='totpUsernameField' name='username' placeholder='Email Address' required autocomplete='username' />
                        <input type='password' name='password' placeholder='Password' required />
                        <input type='text' name='totp' placeholder='6-Digit Authenticator Code'
                               required autocomplete='one-time-code' maxlength='6' />
                        <button type='submit'>Authorize My IP</button>
                    </form>
                </div>";
#else
    string totpFormHtml = "";
#endif

    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0' />
            <title>{siteNameHtml}</title>
            <link rel='icon' type='image/x-icon' href='/favicon.ico' />
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #121212; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
                .login-box {{ background: #1e1e1e; padding: 40px; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); width: 90%; max-width: 320px; box-sizing: border-box; }}
                .logo {{ display: block; margin: 0 auto 20px auto; max-width: 240px; width: 100%; }}
                .ip-display {{ text-align: center; color: #aaa; font-size: 0.9em; margin-bottom: 20px; padding: 8px; background: #252525; border-radius: 4px; border: 1px solid #333; }}
                .ip-display strong {{ color: #007acc; letter-spacing: 1px; }}
                input {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #333; border-radius: 4px; box-sizing: border-box; background: #2d2d2d; color: #fff; }}
                input:focus {{ outline: none; border-color: #007acc; }}
                button {{ width: 100%; padding: 12px; background: #007acc; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; margin-top: 10px; transition: background 0.2s; }}
                button:hover {{ background: #005999; }}
                .passkey-error {{ color: #ff6b6b; font-size: 0.85em; margin-top: 10px; text-align: center; display: none; }}
                .try-another {{ text-align: center; margin-top: 18px; }}
                .try-another-btn {{ background: none; border: none; color: #007acc; font-size: 0.88em; cursor: pointer; padding: 0; width: auto; text-decoration: underline; font-weight: normal; margin: 0; }}
                .try-another-btn:hover {{ background: none; color: #66b2e8; }}
                .totp-section {{ display: none; margin-top: 14px; border-top: 1px solid #2a2a2a; padding-top: 14px; }}
                .disclaimer {{ text-align: center; color: #555; font-size: 0.75em; margin-top: 25px; text-transform: uppercase; letter-spacing: 1px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class='login-box'>
                <img src='{(string.IsNullOrEmpty(logoUrl) ? "/knocker.png" : logoUrl)}' alt='Logo' class='logo' />
                <div class='ip-display'>Connecting IP: <strong>{clientIp}</strong></div>

                <input type='email' id='usernameField' placeholder='Email Address' autocomplete='username webauthn' />
                <button type='button' id='passkeyBtn'>Sign in with Passkey</button>
                <div class='passkey-error' id='passkeyError'></div>

                {totpFormHtml}

                <div class='disclaimer'>Authorized Use Only</div>
            </div>
            <script src='/login.js'></script>
        </body>
        </html>");
}).RequireRateLimiting("LoginRateLimit");

// --- Handle the Login POST ---
// ===========================================================================
// TOTP ROUTES — compiled in ONLY with -p:AllowTotp=true.
// Without that flag these endpoints do not exist: /auth, /setup/{token} and
// /setup return 404, because there is no handler rather than a handler that
// declines. Nothing to misconfigure and nothing to bypass.
// ===========================================================================
#if ALLOW_TOTP
app.MapPost("/auth", async (HttpContext context, IAntiforgery antiforgery, IConfiguration config) =>
{
    try { await antiforgery.ValidateRequestAsync(context); }
    catch { context.Response.StatusCode = 400; await context.Response.WriteAsync("Invalid request."); return; }

    var form = await context.Request.ReadFormAsync();
    string rawEmail = form["username"].ToString().Trim();
    string password = form["password"].ToString();
    string totpCode = form["totp"].ToString().Trim();

    AuditLogger.Log($"Login attempt from '{rawEmail}'");

    // 1. Validate Email Format and Domain
    var allowedDomains = app.Configuration.GetSection("AllowedDomains").Get<string[]>() ?? Array.Empty<string>();

    if (!MailAddress.TryCreate(rawEmail, out var mailAddress) ||
        !allowedDomains.Any(d => d.Equals(mailAddress.Host, StringComparison.OrdinalIgnoreCase)))
    {
        AuditLogger.Warn("Denied - invalid account domain");
        await SendDenyResponse(context, "Invalid account domain.");
        return;
    }

    string username = mailAddress.Address;

    // 2. Get Client IP Address — TCP connection only, no proxy headers (by design)
    string clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "";
    if (clientIp.StartsWith("::ffff:")) clientIp = clientIp.Substring(7); // Clean up IPv4-mapped IPv6 addresses

    if (!IsPublicIpAddress(clientIp))
    {
        AuditLogger.Warn($"[SECURITY] Blocked auth attempt from internal IP: {clientIp}");
        await SendDenyResponse(context, "Authorization is only permitted from external internet addresses.");
        return;
    }

    // 3. Validate credentials (read-only — MFAWeb never writes the DB)
    bool credentialsValid = false;
    bool hadNoPasskeys = false;
    string authedUsername = "";

    {
        var users = LoadUsers(DbPath, Entropy);
        var user = users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        // The empty-secret check is defence in depth. Passkey-only accounts store
        // TotpSecret = "" and TotpConfirmed = false, so TotpConfirmed alone already blocks
        // them — but if that pairing is ever broken (a crafted 'import', DB tampering, a
        // future refactor), Base32Encoding.ToBytes("") throws and a valid password would
        // surface as a 500 instead of a clean denial. Treat an empty secret as invalid.
        if (user != null && user.TotpConfirmed && !string.IsNullOrWhiteSpace(user.TotpSecret)
            && BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
        {
            var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
            if (totp.VerifyTotp(totpCode, out _, new VerificationWindow(1, 1)))
            {
                credentialsValid = true;
                hadNoPasskeys = user.PasskeyCredentials.Count == 0;
                authedUsername = user.Username;
            }
        }
    }

    if (!credentialsValid)
    {
        LoginFailureMonitor.RecordFailure(username, clientIp);
        AuditLogger.Warn("Failed - Invalid credentials or expired code");
        await SendDenyResponse(context, "Invalid credentials or expired code.");
        return;
    }

    LoginFailureMonitor.RecordSuccess(username);
    AuditLogger.Log("Valid, opening port(s)...");

    // 4. IPC call (async — lock must not be held here)
    // The Web App no longer reads ports/expirations. It simply tells the Worker who authenticated.
    bool successfullyOpened = await IpcFirewallClient.OpenPortAsync(clientIp, authedUsername);

    if (!successfullyOpened)
    {
        AuditLogger.Error($"[IPC] Firewall worker unreachable or rejected request for {clientIp}");
        await SendDenyResponse(context, "Firewall service is temporarily unavailable. Please try again shortly.");
        return;
    }

    // 5. Offer passkey registration — delegate the DB write to MFAService via IPC
    string passkeyRegHtml = "";
    if (hadNoPasskeys)
    {
        string pkToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var pkExpiry = DateTime.UtcNow.AddMinutes(10);
        if (await IpcFirewallClient.SetPasskeyProvisionTokenAsync(authedUsername, pkToken, pkExpiry))
        {
            passkeyRegHtml = $@"
                        <div style='margin-top:20px; padding-top:16px; border-top:1px solid #1e3a4a;'>
                            <p style='color:#556; font-size:0.8em; margin:0 0 8px 0;'>Skip the code next time?</p>
                            <a href='/register-passkey/{pkToken}' style='color:#007acc; font-size:0.85em; text-decoration:none; font-family:""Segoe UI"",sans-serif;'>Register a Passkey (fingerprint/PIN) &rarr;</a>
                        </div>";
        }
    }

    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
                <!DOCTYPE html>
                <html>
                <head>
                    <meta name='viewport' content='width=device-width, initial-scale=1.0' />
                    <title>Access Granted</title>
                    <script src='/timer.js'></script>
                </head>
                <body style='background:#121212; display:flex; justify-content:center; align-items:center; height:100vh; margin:0;'>
                    <div style='background:#1e1e1e; color:#0f0; font-family:monospace; padding:40px; text-align:center; border-radius:8px; border:1px solid #333; width: 90%; max-width: 400px; box-sizing: border-box;'>
                        <h2>[ ACCESS GRANTED ]</h2>
                        <p>Firewall doorway opened for IP:<br/><strong>{clientIp}</strong></p>
                        <p>Authorized Services:<br/><strong>Server Default Policies Applied</strong></p>
                        <p style='color:#aaa; font-size:0.9em; margin-top:20px;'>You may now connect. This session will expire according to server policy.</p>
                        {passkeyRegHtml}
                        <div style='margin-top: 20px; border-top: 1px solid #333; padding-top: 20px;'>
                            <p style='color:#777; font-size:0.85em; margin-bottom: 15px;'>Returning to login in <span id='timer'>60</span>s...</p>
                            <a href='/' style='color:#fff; text-decoration:none; background:#007acc; padding:10px 20px; border-radius:4px; display:inline-block; font-family:""Segoe UI"", Tahoma, sans-serif; font-weight:bold;'>Return to Login</a>
                        </div>
                    </div>
                </body>
                </html>");
    }).RequireRateLimiting("LoginRateLimit");

// --- GET: Display the Provisioning Login Page ---
app.MapGet("/setup/{token}", async (HttpContext context, string token, IAntiforgery antiforgery) =>
{
    AuditLogger.Debug("TOTP setup page requested");   // never log the provisioning token

    string? provisionUsername = null;
    {
        var users = LoadUsers(DbPath, Entropy);
        var user = users.FirstOrDefault(u => TokenEquals(u.ProvisioningToken, token));
        if (user != null && user.ProvisioningExpiresUtc != null && DateTime.UtcNow <= user.ProvisioningExpiresUtc)
            provisionUsername = user.Username;
    }

    if (provisionUsername == null)
    {
        AuditLogger.Warn("Provisioning link is invalid or has expired.");
        await SendDenyResponse(context, "Provisioning link is invalid or has expired.");
        return;
    }

    var csrfTokens = antiforgery.GetAndStoreTokens(context);
    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0' />
            <title>{siteNameHtml} - Setup 2FA</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background: #121212; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
                .login-box {{ background: #1e1e1e; padding: 40px; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); width: 90%; max-width: 320px; box-sizing: border-box; text-align: center; }}
                input {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #333; border-radius: 4px; box-sizing: border-box; background: #2d2d2d; color: #fff; }}
                button {{ width: 100%; padding: 12px; background: #007acc; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; margin-top: 10px; }}
                button:hover {{ background: #005999; }}
            </style>
        </head>
        <body>
            <div class='login-box'>
                <h2>Set Up Authenticator</h2>
                <p style='color:#aaa; font-size:0.9em;'>Verify your password to reveal your 2FA setup code.</p>
                <form action='/setup' method='post'>
                    <input type='hidden' name='{csrfTokens.FormFieldName}' value='{csrfTokens.RequestToken}'/>
                    <input type='hidden' name='token' value='{token}' />
                    <input type='hidden' name='username' value='{System.Net.WebUtility.HtmlEncode(provisionUsername)}' />
                    <input type='password' name='password' placeholder='Enter your password' required />
                    <button type='submit'>Reveal Secret</button>
                </form>
            </div>
        </body>
        </html>");
}).RequireRateLimiting("LoginRateLimit");

// --- POST: Verify Password and Display QR Code ---
app.MapPost("/setup", async (HttpContext context, IAntiforgery antiforgery) =>
{
    // Passkey-only: refuse at the endpoint, not just by hiding the page.
    try { await antiforgery.ValidateRequestAsync(context); }
    catch { context.Response.StatusCode = 400; await context.Response.WriteAsync("Invalid request."); return; }

    var form = await context.Request.ReadFormAsync();
    string token = form["token"].ToString();
    string username = form["username"].ToString();
    string password = form["password"].ToString();

    // Load and validate (read-only); token burn delegated to MFAService via IPC
    string? totpSecret = null;
    string? authedUsername = null;
    bool setupInvalid = false;
    bool setupBadPassword = false;
    bool setupNoSecret = false;
    {
        var users = LoadUsers(DbPath, Entropy);
        var user = users.FirstOrDefault(u => TokenEquals(u.ProvisioningToken, token) && u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));

        if (user == null || user.ProvisioningExpiresUtc == null || DateTime.UtcNow > user.ProvisioningExpiresUtc)
        {
            setupInvalid = true;
        }
        else if (!BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
        {
            setupBadPassword = true;
        }
        else if (string.IsNullOrWhiteSpace(user.TotpSecret))
        {
            // No secret to enroll — the account was provisioned in passkey-only mode.
            // Refuse rather than burn the token and confirm an unusable empty secret.
            setupNoSecret = true;
        }
        else
        {
            totpSecret = user.TotpSecret;
            authedUsername = user.Username;
        }
    }

    if (setupInvalid)
    {
        AuditLogger.Warn("Provisioning link is invalid or has expired.");
        await SendDenyResponse(context, "Provisioning link is invalid or has expired.");
        return;
    }
    if (setupBadPassword)
    {
        AuditLogger.Warn("Provisioning - Invalid password");
        await SendDenyResponse(context, "Invalid password.");
        return;
    }
    if (setupNoSecret)
    {
        AuditLogger.Warn("Provisioning - account has no TOTP secret (provisioned in passkey-only mode)");
        await SendDenyResponse(context, "This account has no authenticator secret. Use your passkey setup link instead.");
        return;
    }

    // Burn the token via IPC — MFAService is the sole DB writer
    if (!await IpcFirewallClient.BurnTotpTokenAsync(token))
    {
        AuditLogger.Warn($"[IPC] Failed to burn TOTP provisioning token for '{authedUsername}'");
        await SendDenyResponse(context, "Service temporarily unavailable. Please try again.");
        return;
    }

    AuditLogger.Log($"Provision request is valid for '{authedUsername}'");

    // Generate the Auth URI
    string issuer = siteName;
    string encodedIssuer = Uri.EscapeDataString(issuer);
    string encodedUser = Uri.EscapeDataString(authedUsername!);
    string authUri = $"otpauth://totp/{encodedIssuer}:{encodedUser}?secret={totpSecret}&issuer={encodedIssuer}";

    // Display the QR Code (rendered client-side via locally hosted qrious.min.js)
    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
            <!DOCTYPE html>
            <html>
            <head>
                <meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0' />
                <title>{siteNameHtml} - MFA Secret</title>
                <style>
                    body {{ font-family: monospace; background: #121212; color: #fff; text-align: center; padding-top: 50px; margin: 0; }}
                    .container {{ background: #1e1e1e; padding: 40px; border-radius: 8px; display: inline-block; border: 1px solid #333; width: 90%; max-width: 400px; box-sizing: border-box; margin: 20px auto; }}
                    .secret-text {{ font-size: 1.2em; color: #0f0; letter-spacing: 2px; margin: 20px 0; background: #000; padding: 10px; border-radius: 4px; word-break: break-all; }}
                    .warning {{ color: #ff4444; font-size: 0.85em; margin: 20px auto; line-height: 1.4; }}
                </style>
            </head>
            <body>
                <div class='container'>
                    <h2>Scan this QR Code</h2>
                    <p style='color:#aaa;'>Open Google Authenticator, Authy, or Apple Passwords.</p>

                    <canvas id='qr' data-uri='{authUri}' style='max-width: 100%; height: auto;'></canvas>

                    <div class='secret-text'>{totpSecret}</div>

                    <div class='warning'>
                        <strong>WARNING:</strong> This page will only display once.
                        Once you leave this page, the provisioning link will permanently expire.
                    </div>

                    <a href='/' style='display:inline-block; margin-top:20px; padding:10px 20px; background:#007acc; color:#fff; text-decoration:none; border-radius:4px;'>Go to Login</a>
                </div>
                <script src='/qrious.min.js'></script>
                <script src='/qr-setup.js'></script>
            </body>
            </html>");
}).RequireRateLimiting("LoginRateLimit");
#endif  // ALLOW_TOTP — end of the TOTP route block

// -----------------------------------------------------------------------
// PASSKEY PROVISIONING: Password gate (for admin-issued setup links)
// The admin tool sets PasskeyProvisioningToken (random, unguessable) and
// PasskeyProvisioningExpiresUtc (e.g. UtcNow + 60 minutes) on the user.
// -----------------------------------------------------------------------
app.MapGet("/setup-passkey/{token}", async (HttpContext context, string token, IAntiforgery antiforgery) =>
{
    AuditLogger.Debug("Passkey setup page requested");   // never log the provisioning token

    string? passkeyProvisionUsername = null;
    {
        var users = LoadUsers(DbPath, Entropy);
        var user = users.FirstOrDefault(u => TokenEquals(u.PasskeyProvisioningToken, token));
        if (user != null && user.PasskeyProvisioningExpiresUtc != null && DateTime.UtcNow <= user.PasskeyProvisioningExpiresUtc)
            passkeyProvisionUsername = user.Username;
    }

    if (passkeyProvisionUsername == null)
    {
        AuditLogger.Warn("Passkey provisioning link is invalid or has expired.");
        await SendDenyResponse(context, "Provisioning link is invalid or has expired.");
        return;
    }

    var csrfTokens = antiforgery.GetAndStoreTokens(context);
    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0' />
            <title>{siteNameHtml} - Register Passkey</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background: #121212; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
                .login-box {{ background: #1e1e1e; padding: 40px; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); width: 90%; max-width: 320px; box-sizing: border-box; text-align: center; }}
                input {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #333; border-radius: 4px; box-sizing: border-box; background: #2d2d2d; color: #fff; }}
                button {{ width: 100%; padding: 12px; background: #007acc; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; margin-top: 10px; }}
                button:hover {{ background: #005999; }}
            </style>
        </head>
        <body>
            <div class='login-box'>
                <h2>Register a Passkey</h2>
                <p style='color:#aaa; font-size:0.9em;'>Verify your password to continue.</p>
                <form action='/setup-passkey' method='post'>
                    <input type='hidden' name='{csrfTokens.FormFieldName}' value='{csrfTokens.RequestToken}'/>
                    <input type='hidden' name='token' value='{token}' />
                    <input type='hidden' name='username' value='{System.Net.WebUtility.HtmlEncode(passkeyProvisionUsername)}' />
                    <input type='password' name='password' placeholder='Enter your password' required autocomplete='current-password' />
                    <button type='submit'>Continue</button>
                </form>
            </div>
        </body>
        </html>");
}).RequireRateLimiting("LoginRateLimit");

app.MapPost("/setup-passkey", async (HttpContext context, IAntiforgery antiforgery) =>
{
    try { await antiforgery.ValidateRequestAsync(context); }
    catch { context.Response.StatusCode = 400; await context.Response.WriteAsync("Invalid request."); return; }

    var form = await context.Request.ReadFormAsync();
    string token    = form["token"].ToString();
    string username = form["username"].ToString();
    string password = form["password"].ToString();

    bool pkInvalid = false;
    bool pkBadPassword = false;
    {
        var users = LoadUsers(DbPath, Entropy);
        var user = users.FirstOrDefault(u => TokenEquals(u.PasskeyProvisioningToken, token)
                                         && u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));

        if (user == null || user.PasskeyProvisioningExpiresUtc == null || DateTime.UtcNow > user.PasskeyProvisioningExpiresUtc)
            pkInvalid = true;
        else if (!BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            pkBadPassword = true;
    }

    if (pkInvalid)
    {
        AuditLogger.Warn("Passkey provisioning link is invalid or has expired.");
        await SendDenyResponse(context, "Provisioning link is invalid or has expired.");
        return;
    }
    if (pkBadPassword)
    {
        AuditLogger.Warn($"Passkey provisioning - invalid password for '{username}'");
        await SendDenyResponse(context, "Invalid password.");
        return;
    }

    AuditLogger.Log($"Passkey provisioning password verified for '{username}'");

    // Burn the email-link token immediately and replace it with a fresh 5-minute token.
    // This ensures the intercepted provisioning link cannot be used to register an
    // attacker-controlled device after the legitimate user has verified their password.
    string? registrationToken = await IpcFirewallClient.RenewPasskeyTokenAsync(token);
    if (registrationToken == null)
    {
        AuditLogger.Warn($"[IPC] Failed to renew passkey token for '{username}'");
        await SendDenyResponse(context, "Service temporarily unavailable. Please try again.");
        return;
    }

    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0' />
            <title>{siteNameHtml} - Register Passkey</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background: #121212; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
                .box {{ background: #1e1e1e; padding: 40px; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); width: 90%; max-width: 360px; box-sizing: border-box; text-align: center; }}
                button {{ width: 100%; padding: 13px; background: #007acc; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 1em; margin-top: 10px; }}
                button:hover {{ background: #005999; }}
                button:disabled {{ background: #333; color: #666; cursor: default; }}
                #status {{ margin-top: 16px; font-size: 0.9em; color: #aaa; min-height: 1.4em; }}
                .success {{ color: #0f0 !important; }}
                .error   {{ color: #f66 !important; }}
            </style>
        </head>
        <body>
            <div class='box'>
                <h2 style='margin-top:0;'>Register a Passkey</h2>
                <p style='color:#aaa; font-size:0.9em;'>Your device will ask for your fingerprint, face, or PIN. This passkey lets you sign in without a 6-digit code.</p>
                <button id='registerBtn' data-token='{registrationToken}'>Register This Device</button>
                <div id='status'></div>
                <a href='/' style='display:inline-block; margin-top:24px; color:#555; font-size:0.85em;'>Back to Login</a>
            </div>
            <script src='/passkey-register.js'></script>
        </body>
        </html>");
}).RequireRateLimiting("LoginRateLimit");

// -----------------------------------------------------------------------
// PASSKEY: Step 1 â€" Return an assertion challenge for the given username
// -----------------------------------------------------------------------
app.MapPost("/passkey/challenge", async (HttpContext context) =>
{
    string? body = await ReadBodyWithLimitAsync(context.Request);
    if (body == null) { context.Response.StatusCode = 413; await context.Response.WriteAsync("Request too large."); return; }
    JsonDocument doc;
    try { doc = JsonDocument.Parse(body); }
    catch { context.Response.StatusCode = 400; await context.Response.WriteAsync("Invalid JSON."); return; }
    string rawEmail;
    using (doc) rawEmail = doc.RootElement.TryGetProperty("username", out var uProp) ? uProp.GetString() ?? "" : "";

    var allowedDomains = app.Configuration.GetSection("AllowedDomains").Get<string[]>() ?? Array.Empty<string>();
    if (!MailAddress.TryCreate(rawEmail, out var mail) ||
        !allowedDomains.Any(d => d.Equals(mail.Host, StringComparison.OrdinalIgnoreCase)))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Invalid account domain.");
        return;
    }

    List<PublicKeyCredentialDescriptor>? allowedKeys = null;
    {
        var users = LoadUsers(DbPath, Entropy);
        var user = users.FirstOrDefault(u => u.Username.Equals(mail.Address, StringComparison.OrdinalIgnoreCase));
        if (user != null && user.PasskeyCredentials.Count > 0)
            allowedKeys = user.PasskeyCredentials
                .Select(c => new PublicKeyCredentialDescriptor(FromBase64Url(c.CredentialId)))
                .ToList();
    }

    if (allowedKeys == null)
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("No passkey registered for this account.");
        return;
    }

    var options = fido2.GetAssertionOptions(allowedKeys, UserVerificationRequirement.Required);
    string optionsJson = options.ToJson();

    // Prune old challenges then store the new one
    var now = DateTime.UtcNow;
    foreach (var k in passkeyStore.Keys.ToList())
        if (passkeyStore.TryGetValue(k, out var e) && e.Expiry < now) passkeyStore.TryRemove(k, out _);

    string key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    passkeyStore[key] = (optionsJson, mail.Address, DateTime.UtcNow.AddMinutes(2));

    using var optDoc = JsonDocument.Parse(optionsJson);
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsJsonAsync(new { challengeKey = key, options = optDoc.RootElement.Clone() });
}).RequireRateLimiting("LoginRateLimit");

// -----------------------------------------------------------------------
// PASSKEY: Step 2 â€" Verify the assertion and open the firewall
// -----------------------------------------------------------------------
app.MapPost("/passkey/verify", async (HttpContext context, IConfiguration config) =>
{
    string? body = await ReadBodyWithLimitAsync(context.Request);
    if (body == null) { context.Response.StatusCode = 413; await context.Response.WriteAsync("Request too large."); return; }
    JsonDocument doc;
    try { doc = JsonDocument.Parse(body); }
    catch { context.Response.StatusCode = 400; await context.Response.WriteAsync("Invalid JSON."); return; }
    string rawEmail, challengeKey, assertionJson;
    using (doc)
    {
        rawEmail     = doc.RootElement.TryGetProperty("username",     out var uP) ? uP.GetString() ?? "" : "";
        challengeKey = doc.RootElement.TryGetProperty("challengeKey", out var cP) ? cP.GetString() ?? "" : "";
        assertionJson = doc.RootElement.TryGetProperty("assertion",   out var aP) ? aP.GetRawText() : "{}";
    }

    AuditLogger.Log($"Passkey verify attempt from '{rawEmail}'");

    var allowedDomains = app.Configuration.GetSection("AllowedDomains").Get<string[]>() ?? Array.Empty<string>();
    if (!MailAddress.TryCreate(rawEmail, out var mail) ||
        !allowedDomains.Any(d => d.Equals(mail.Host, StringComparison.OrdinalIgnoreCase)))
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Invalid credentials.");
        return;
    }

    string username = mail.Address;

    if (!passkeyStore.TryRemove(challengeKey, out var stored) || stored.Expiry < DateTime.UtcNow)
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Challenge expired. Please try again.");
        return;
    }

    if (!stored.Username.Equals(username, StringComparison.OrdinalIgnoreCase))
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Invalid credentials.");
        return;
    }

    AuthenticatorAssertionRawResponse? clientAssertion;
    try { clientAssertion = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(assertionJson); }
    catch { context.Response.StatusCode = 400; await context.Response.WriteAsync("Malformed assertion."); return; }

    if (clientAssertion == null)
    {
        context.Response.StatusCode = 400; await context.Response.WriteAsync("Malformed assertion."); return;
    }

    // Phase 1: load credential data (read-only)
    string? credPublicKey = null;
    uint credSignCount = 0;
    string? matchedCredId = null;
    {
        var users = LoadUsers(DbPath, Entropy);
        var user = users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (user == null || user.PasskeyCredentials.Count == 0)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Invalid credentials.");
            return;
        }

        var cred = user.PasskeyCredentials
            .FirstOrDefault(c => FromBase64Url(c.CredentialId).SequenceEqual(clientAssertion.Id ?? clientAssertion.RawId ?? Array.Empty<byte>()));
        if (cred == null)
        {
            AuditLogger.Warn("Passkey verify - credential not found");
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Invalid credentials.");
            return;
        }

        credPublicKey = cred.PublicKey;
        credSignCount = cred.SignCount;
        matchedCredId = cred.CredentialId;
    }

    // Async FIDO2 verification (lock not held)
    uint newSignCount;
    try
    {
        var storedOptions = AssertionOptions.FromJson(stored.OptionsJson);
        var result = await fido2.MakeAssertionAsync(
            assertionResponse: clientAssertion,
            originalOptions: storedOptions,
            storedPublicKey: FromBase64Url(credPublicKey!),
            storedSignatureCounter: credSignCount,
            isUserHandleOwnerOfCredentialIdCallback: (args, _) =>
            {
                string handleUser = Encoding.UTF8.GetString(args.UserHandle);
                return Task.FromResult(handleUser.Equals(username, StringComparison.OrdinalIgnoreCase));
            });
        newSignCount = result.Counter;
    }
    catch (Exception ex)
    {
        // Sign-count regression means the credential counter went backwards — a strong indicator
        // of a cloned authenticator.  Log at ERROR so it surfaces in monitoring.
        bool isCounterAnomaly = ex.Message.Contains("counter", StringComparison.OrdinalIgnoreCase)
                             || ex.Message.Contains("sign count", StringComparison.OrdinalIgnoreCase);
        if (isCounterAnomaly)
            AuditLogger.Error($"[SECURITY ALERT] Possible credential clone for '{username}' - sign count anomaly: {ex.Message}");
        else
            AuditLogger.Warn($"Passkey assertion failed for '{username}': {ex.Message}");
        context.Response.StatusCode = 401; await context.Response.WriteAsync("Passkey verification failed."); return;
    }

    // Defense-in-depth: if the library somehow allowed a non-increasing counter, flag it.
    if (credSignCount > 0 && newSignCount <= credSignCount)
        AuditLogger.Error($"[SECURITY ALERT] Sign count did not increase for '{username}' credential '{matchedCredId}': stored={credSignCount}, received={newSignCount} - possible credential clone.");

    // Phase 2: update sign counter via IPC (best-effort — don't block login on failure)
    if (!await IpcFirewallClient.UpdateSignCountAsync(matchedCredId!, newSignCount))
        AuditLogger.Warn($"[IPC] Failed to update sign count for credential '{matchedCredId}'");

    // ---- Open firewall (Delegating authority to MFAService worker) ----
    // TCP connection address only — no proxy headers (by design)
    string clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "";
    if (clientIp.StartsWith("::ffff:")) clientIp = clientIp.Substring(7);

    if (!IsPublicIpAddress(clientIp))
    {
        AuditLogger.Warn($"[SECURITY] Blocked passkey auth from internal IP: {clientIp}");
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Authorization is only permitted from external internet addresses.");
        return;
    }

    AuditLogger.Log($"Passkey valid for '{username}', requesting firewall open for {clientIp}...");

    bool successfullyOpened = await IpcFirewallClient.OpenPortAsync(clientIp, username);

    if (!successfullyOpened)
    {
        AuditLogger.Error($"[IPC] Firewall worker unreachable or rejected request for {clientIp}");
        context.Response.StatusCode = 503;
        await context.Response.WriteAsync("Firewall service is temporarily unavailable. Please try again shortly.");
        return;
    }

    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name='viewport' content='width=device-width, initial-scale=1.0' />
            <title>Access Granted</title>
            <script src='/timer.js'></script>
        </head>
        <body style='background:#121212; display:flex; justify-content:center; align-items:center; height:100vh; margin:0;'>
            <div style='background:#1e1e1e; color:#0f0; font-family:monospace; padding:40px; text-align:center; border-radius:8px; border:1px solid #333; width:90%; max-width:400px; box-sizing:border-box;'>
                <h2>[ ACCESS GRANTED ]</h2>
                <p>Firewall doorway opened for IP:<br/><strong>{clientIp}</strong></p>
                <p>Authorized Services:<br/><strong>Server Default Policies Applied</strong></p>
                <p style='color:#aaa; font-size:0.9em; margin-top:20px;'>You may now connect. This session will expire according to server policy.</p>
                <div style='margin-top:20px; border-top:1px solid #333; padding-top:20px;'>
                    <p style='color:#777; font-size:0.85em; margin-bottom:15px;'>Returning to login in <span id='timer'>60</span>s...</p>
                    <a href='/' style='color:#fff; text-decoration:none; background:#007acc; padding:10px 20px; border-radius:4px; display:inline-block; font-family:""Segoe UI"",Tahoma,sans-serif; font-weight:bold;'>Return to Login</a>
                </div>
            </div>
        </body>
        </html>");
}).RequireRateLimiting("LoginRateLimit");

// -----------------------------------------------------------------------
// PASSKEY REGISTRATION: Page (linked from TOTP success screen)
// -----------------------------------------------------------------------
app.MapGet("/register-passkey/{token}", async (HttpContext context, string token) =>
{
    bool regLinkValid = false;
    {
        var users = LoadUsers(DbPath, Entropy);
        var user = users.FirstOrDefault(u => TokenEquals(u.PasskeyProvisioningToken, token));
        regLinkValid = user != null && user.PasskeyProvisioningExpiresUtc != null && DateTime.UtcNow <= user.PasskeyProvisioningExpiresUtc
                       && user.PasskeyRegistrationReady;
    }

    if (!regLinkValid)
    {
        await SendDenyResponse(context, "Registration link is invalid or has expired.");
        return;
    }

    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0' />
            <title>{siteNameHtml} - Register Passkey</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background: #121212; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
                .box {{ background: #1e1e1e; padding: 40px; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); width: 90%; max-width: 360px; box-sizing: border-box; text-align: center; }}
                button {{ width: 100%; padding: 13px; background: #007acc; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 1em; margin-top: 10px; }}
                button:hover {{ background: #005999; }}
                button:disabled {{ background: #333; color: #666; cursor: default; }}
                #status {{ margin-top: 16px; font-size: 0.9em; color: #aaa; min-height: 1.4em; }}
                .success {{ color: #0f0 !important; }}
                .error   {{ color: #f66 !important; }}
            </style>
        </head>
        <body>
            <div class='box'>
                <h2 style='margin-top:0;'>Register a Passkey</h2>
                <p style='color:#aaa; font-size:0.9em;'>Your device will ask you for your fingerprint, face, or PIN. This passkey lets you sign in without a 6-digit code.</p>
                <button id='registerBtn' data-token='{token}'>Register This Device</button>
                <div id='status'></div>
                <a href='/' style='display:inline-block; margin-top:24px; color:#555; font-size:0.85em;'>Back to Login</a>
            </div>
            <script src='/passkey-register.js'></script>
        </body>
        </html>");
}).RequireRateLimiting("LoginRateLimit");

// -----------------------------------------------------------------------
// PASSKEY REGISTRATION: Begin (generate attestation options)
// -----------------------------------------------------------------------
app.MapPost("/passkey/register/begin", async (HttpContext context) =>
{
    string? body = await ReadBodyWithLimitAsync(context.Request);
    if (body == null) { context.Response.StatusCode = 413; await context.Response.WriteAsync("Request too large."); return; }
    JsonDocument doc;
    try { doc = JsonDocument.Parse(body); }
    catch { context.Response.StatusCode = 400; await context.Response.WriteAsync("Invalid JSON."); return; }
    string token;
    using (doc) token = doc.RootElement.TryGetProperty("token", out var tP) ? tP.GetString() ?? "" : "";

    Fido2User? fidoUser = null;
    List<PublicKeyCredentialDescriptor>? existingCreds = null;
    {
        var users = LoadUsers(DbPath, Entropy);
        var user = users.FirstOrDefault(u => TokenEquals(u.PasskeyProvisioningToken, token));

        if (user == null || user.PasskeyProvisioningExpiresUtc == null || DateTime.UtcNow > user.PasskeyProvisioningExpiresUtc
            || !user.PasskeyRegistrationReady)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Registration link is invalid or has expired.");
            return;
        }

        fidoUser = new Fido2User
        {
            Id = Encoding.UTF8.GetBytes(user.Username),
            Name = user.Username,
            DisplayName = user.Username
        };
        existingCreds = user.PasskeyCredentials
            .Select(c => new PublicKeyCredentialDescriptor(FromBase64Url(c.CredentialId)))
            .ToList();
    }

    var options = fido2.RequestNewCredential(
        user: fidoUser!,
        excludeCredentials: existingCreds!,
        authenticatorSelection: new AuthenticatorSelection
        {
            AuthenticatorAttachment = AuthenticatorAttachment.Platform,
            RequireResidentKey = false,
            UserVerification = UserVerificationRequirement.Required
        },
        attestationPreference: AttestationConveyancePreference.None);

    string optionsJson = options.ToJson();

    var now = DateTime.UtcNow;
    foreach (var k in passkeyStore.Keys.ToList())
        if (passkeyStore.TryGetValue(k, out var e) && e.Expiry < now) passkeyStore.TryRemove(k, out _);

    string key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    passkeyStore[key] = (optionsJson, fidoUser!.Name, DateTime.UtcNow.AddMinutes(2));

    using var optDoc = JsonDocument.Parse(optionsJson);
    await context.Response.WriteAsJsonAsync(new { challengeKey = key, options = optDoc.RootElement.Clone() });
}).RequireRateLimiting("LoginRateLimit");

// -----------------------------------------------------------------------
// PASSKEY REGISTRATION: Complete (verify attestation, save credential)
// -----------------------------------------------------------------------
#pragma warning disable ASP0016
app.MapPost("/passkey/register/complete", async (HttpContext context) =>
{
    string? body = await ReadBodyWithLimitAsync(context.Request);
    if (body == null) { context.Response.StatusCode = 413; await context.Response.WriteAsync("Request too large."); return; }
    JsonDocument doc;
    try { doc = JsonDocument.Parse(body); }
    catch { context.Response.StatusCode = 400; await context.Response.WriteAsync("Invalid JSON."); return; }
    string token, challengeKey, attestJson;
    using (doc)
    {
        token        = doc.RootElement.TryGetProperty("token",        out var tP) ? tP.GetString() ?? "" : "";
        challengeKey = doc.RootElement.TryGetProperty("challengeKey", out var cP) ? cP.GetString() ?? "" : "";
        attestJson   = doc.RootElement.TryGetProperty("attestation",  out var aP) ? aP.GetRawText() : "{}";
    }

    if (!passkeyStore.TryRemove(challengeKey, out var stored) || stored.Expiry < DateTime.UtcNow)
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Challenge expired. Please start over.");
        return;
    }

    AuthenticatorAttestationRawResponse? clientAttestation;
    try { clientAttestation = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(attestJson); }
    catch { context.Response.StatusCode = 400; await context.Response.WriteAsync("Malformed attestation."); return; }

    if (clientAttestation == null)
    {
        context.Response.StatusCode = 400; await context.Response.WriteAsync("Malformed attestation."); return;
    }

    // Phase 1: validate token and capture existing credential IDs (read-only)
    string? regUsername = null;
    HashSet<string>? existingCredIds = null;
    {
        var users = LoadUsers(DbPath, Entropy);
        var user = users.FirstOrDefault(u => TokenEquals(u.PasskeyProvisioningToken, token));

        if (user == null || user.PasskeyProvisioningExpiresUtc == null || DateTime.UtcNow > user.PasskeyProvisioningExpiresUtc
            || !user.PasskeyRegistrationReady)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Registration link is invalid or has expired.");
            return;
        }

        regUsername = user.Username;
        existingCredIds = new HashSet<string>(
            users.SelectMany(u => u.PasskeyCredentials.Select(c => c.CredentialId)));
    }

    // Async FIDO2 attestation verification (lock not held)
    // Use the captured existingCredIds list — no nested LoadUsers call
    StoredPasskeyCredential? newCred = null;
    try
    {
        var storedOptions = CredentialCreateOptions.FromJson(stored.OptionsJson);
        var result = await fido2.MakeNewCredentialAsync(
            attestationResponse: clientAttestation,
            origChallenge: storedOptions,
            isCredentialIdUniqueToUser: (args, _) =>
            {
                string b64 = ToBase64Url(args.CredentialId);
                return Task.FromResult(!existingCredIds!.Contains(b64));
            });

        var cred = result.Result ?? throw new Exception("Attestation result was null.");
        newCred = new StoredPasskeyCredential
        {
            CredentialId  = ToBase64Url(cred.CredentialId),
            PublicKey     = ToBase64Url(cred.PublicKey),
            SignCount     = cred.Counter,
            RegisteredUtc = DateTime.UtcNow
        };
    }
    catch (Exception ex)
    {
        AuditLogger.Warn($"Passkey registration failed for '{regUsername}': {ex.Message}");
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Passkey registration failed.");
        return;
    }

    // Phase 2: add credential and burn token via IPC — MFAService is the sole DB writer
    if (!await IpcFirewallClient.AddPasskeyAsync(token, newCred!.CredentialId, newCred!.PublicKey, newCred!.SignCount))
    {
        AuditLogger.Warn($"[IPC] Failed to save passkey credential for '{regUsername}'");
        context.Response.StatusCode = 500;
        await context.Response.WriteAsync("Failed to save passkey. Please try again.");
        return;
    }

    AuditLogger.Log($"Passkey registered for '{regUsername}'");
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync("{\"ok\":true}");
}).RequireRateLimiting("LoginRateLimit");
#pragma warning restore ASP0016

// -----------------------------------------------------------------------
// ACCESS GRANTED: Landing page after successful passkey authentication
// -----------------------------------------------------------------------
app.MapGet("/access-granted", async context =>
{
    string clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    if (clientIp.StartsWith("::ffff:")) clientIp = clientIp.Substring(7);
    context.Response.ContentType = "text/html";
    // Surface an impending TLS-certificate expiry to whoever just authenticated.
    string certBanner = CertStatus.ShowWarning
        ? $"<p style='background:#3a2f00; color:#ffcc00; border:1px solid #665500; border-radius:4px; padding:10px; margin:0 0 20px; font-size:0.85em;'>&#9888; {System.Net.WebUtility.HtmlEncode(CertStatus.Message)}</p>"
        : "";
    await context.Response.WriteAsync(@"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name='viewport' content='width=device-width, initial-scale=1.0' />
            <title>Access Granted</title>
            <script src='/timer.js'></script>
        </head>
        <body style='background:#121212; display:flex; justify-content:center; align-items:center; height:100vh; margin:0;'>
            <div style='background:#1e1e1e; color:#0f0; font-family:monospace; padding:40px; text-align:center; border-radius:8px; border:1px solid #333; width:90%; max-width:400px; box-sizing:border-box;'>
                " + certBanner + @"
                <h2>[ ACCESS GRANTED ]</h2>
                <p>Firewall doorway opened. You may now connect.</p>
                <p style='color:#aaa; font-size:0.9em; margin-top:20px;'>This session will automatically expire per your account settings.</p>
                <div style='margin-top:20px; border-top:1px solid #333; padding-top:20px;'>
                    <p style='color:#777; font-size:0.85em; margin-bottom:15px;'>Returning to login in <span id='timer'>60</span>s...</p>
                    <a href='/' style='color:#fff; text-decoration:none; background:#007acc; padding:10px 20px; border-radius:4px; display:inline-block; font-family:""Segoe UI"",Tahoma,sans-serif; font-weight:bold;'>Return to Login</a>
                </div>
            </div>
        </body>
        </html>");
}).RequireRateLimiting("LoginRateLimit");

app.Run();

// --- Helper Methods ---

// Reads the request body up to maxBytes. Returns null if the body exceeds the limit.
static async Task<string?> ReadBodyWithLimitAsync(HttpRequest request, int maxBytes = 65_536)
{
    if (request.ContentLength.HasValue && request.ContentLength > maxBytes)
        return null;

    using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
    char[] buf = new char[maxBytes + 1];
    int read = await reader.ReadBlockAsync(buf, 0, buf.Length);
    return read > maxBytes ? null : new string(buf, 0, read);
}

static async Task SendDenyResponse(HttpContext context, string reason)
{
    context.Response.StatusCode = 401;
    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name='viewport' content='width=device-width, initial-scale=1.0' />
            <title>Access Denied</title>
        </head>
        <body style='background:#121212; display:flex; justify-content:center; align-items:center; height:100vh; margin:0;'>
            <div style='background:#1e1e1e; color:#f00; font-family:monospace; padding:30px; text-align:center; border-radius:8px; border:1px solid #333; width: 90%; max-width: 400px; box-sizing: border-box;'>
                <h2>[ ACCESS DENIED ]</h2>
                <p>{reason}</p>
                <br/>
                <a href='/' style='color:#fff; text-decoration:none; background:#333; padding:10px 20px; border-radius:4px; display:inline-block; margin-top:15px;'>Return</a>
            </div>
        </body>
        </html>");
}


static List<UserEntry> LoadUsers(string dbPath, byte[] entropy)
{
    if (!File.Exists(dbPath)) return new List<UserEntry>();

    try
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            byte[] encryptedBytes = File.ReadAllBytes(dbPath);
            byte[] jsonBytes = ProtectedData.Unprotect(encryptedBytes, entropy, DataProtectionScope.LocalMachine);
            return JsonSerializer.Deserialize<List<UserEntry>>(Encoding.UTF8.GetString(jsonBytes)) ?? new List<UserEntry>();
        }
        else
        {
            return JsonSerializer.Deserialize<List<UserEntry>>(File.ReadAllText(dbPath)) ?? new List<UserEntry>();
        }
    }
    catch (Exception ex)
    {
        AuditLogger.Error($"[CRITICAL ERROR] Failed to load database: {ex.Message}");
        return new List<UserEntry>();
    }
}

// Constant-time comparison for provisioning tokens. These are 256 bits of CSPRNG output and
// short-lived, so a practical remote timing attack is not realistic -- but secrets compared
// with '==' short-circuit on the first differing byte, and this costs nothing. Length is not
// secret (all tokens are the same length), so an early length mismatch is fine.
static bool TokenEquals(string? a, string? b)
{
    if (a is null || b is null) return false;
    return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}

static byte[] FromBase64Url(string b64url)
{
    string padded = b64url.Replace('-', '+').Replace('_', '/');
    switch (padded.Length % 4) { case 2: padded += "=="; break; case 3: padded += "="; break; }
    return Convert.FromBase64String(padded);
}

static string ToBase64Url(byte[] bytes) =>
    Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

static bool IsPublicIpAddress(string ipString)
{
    if (!System.Net.IPAddress.TryParse(ipString, out var ip))
        return false;

    // Normalize IPv4-mapped IPv6 (e.g. ::ffff:10.0.0.1) so it's judged by its IPv4 value.
    if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

    // Handle IPv4
    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
    {
        byte[] bytes = ip.GetAddressBytes();

        // 10.0.0.0/8 (Private)
        if (bytes[0] == 10) return false;

        // 172.16.0.0/12 (Private)
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;

        // 192.168.0.0/16 (Private)
        if (bytes[0] == 192 && bytes[1] == 168) return false;

        // 127.0.0.0/8 (Loopback / Localhost)
        if (bytes[0] == 127) return false;

        // 169.254.0.0/16 (Link-local / APIPA)
        if (bytes[0] == 169 && bytes[1] == 254) return false;

        // 100.64.0.0/10 (RFC 6598 — Carrier-Grade NAT shared space)
        if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) return false;

        // 0.0.0.0/8 (unspecified)
        if (bytes[0] == 0) return false;
    }
    // Handle IPv6
    else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
    {
        if (ip.IsIPv6SiteLocal || ip.IsIPv6LinkLocal || System.Net.IPAddress.IsLoopback(ip)
            || ip.Equals(System.Net.IPAddress.IPv6Any))   // :: (unspecified)
            return false;

        // fc00::/7 — Unique Local Addresses (IPv6 private, covers fc00:: and fd00::)
        byte[] bytes = ip.GetAddressBytes();
        if ((bytes[0] & 0xFE) == 0xFC) return false;
    }

    // If it passed all the traps, it's a real public internet IP
    return true;
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
    // Set true only after the password gate (RenewPasskeyToken) or a post-login
    // token (SetPasskeyToken). The emailed provisioning token stays false, so it
    // cannot drive passkey registration without verifying the password first.
    public bool PasskeyRegistrationReady { get; set; } = false;
}

public class StoredPasskeyCredential
{
    public string CredentialId { get; set; } = string.Empty;   // base64url
    public string PublicKey { get; set; } = string.Empty;      // base64url (COSE)
    public uint SignCount { get; set; }
    public DateTime RegisteredUtc { get; set; }
}



// -----------------------------------------------------------------------
// IPC FIREWALL CLIENT
// Sends firewall open requests to the privileged PNWMfaWorker over IPC.
// Uses a named pipe on Windows and a Unix domain socket on Linux.
// Awaits SUCCESS before the caller renders the Access Granted page.
// -----------------------------------------------------------------------
public static class IpcFirewallClient
{
    private const int    TimeoutMs      = 30000;
    private const string PipeName       = "MFAFirewallPipe";
    private const string UnixSocketPath = "/run/mfafirewall.sock";

    // Returns true only when the worker confirms the rules were applied.
    public static async Task<bool> OpenPortAsync(string ip, string username)
    {
        string request = $"{ip}|{username}"; // STRICT 2-PART FORMAT
        try
        {
            string? response = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? await SendViaPipeAsync(request)
                : await SendViaUnixSocketAsync(request);

            if (response == "SUCCESS") return true;

            AuditLogger.Warn($"[IPC] Worker responded: {response ?? "(no response)"}");
            return false;
        }
        catch (Exception ex)
        {
            AuditLogger.Error($"[IPC] Could not reach firewall worker: {ex.Message}");
            return false;
        }
    }

    public static async Task<bool> BurnTotpTokenAsync(string token)
        => await SendDbCommandAsync($"DB:BURN_TOTP_TOKEN|{token}");

    /// <summary>
    /// Atomically replaces the old passkey provisioning token with a new short-lived one.
    /// Returns the new token on success, or null on failure.
    /// </summary>
    public static async Task<string?> RenewPasskeyTokenAsync(string oldToken)
    {
        string request = $"DB:RENEW_PASSKEY_TOKEN|{oldToken}";
        try
        {
            string? response = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? await SendViaPipeAsync(request)
                : await SendViaUnixSocketAsync(request);
            if (response != null && !response.StartsWith("ERROR:"))
                return response;
            AuditLogger.Warn($"[IPC] RenewPasskeyToken failed: {response ?? "(no response)"}");
            return null;
        }
        catch (Exception ex)
        {
            AuditLogger.Error($"[IPC] RenewPasskeyToken failed: {ex.Message}");
            return null;
        }
    }

    public static async Task<bool> SetPasskeyProvisionTokenAsync(string username, string pkToken, DateTime expiresUtc)
        => await SendDbCommandAsync($"DB:SET_PASSKEY_TOKEN|{username}|{pkToken}|{expiresUtc:O}");

    public static async Task<bool> UpdateSignCountAsync(string credentialId, uint newCount)
        => await SendDbCommandAsync($"DB:UPDATE_SIGN_COUNT|{credentialId}|{newCount}");

    public static async Task<bool> AddPasskeyAsync(string provToken, string credentialId, string publicKey, uint signCount)
        => await SendDbCommandAsync($"DB:ADD_PASSKEY|{provToken}|{credentialId}|{publicKey}|{signCount}");

    private static async Task<bool> SendDbCommandAsync(string request)
    {
        try
        {
            string? response = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? await SendViaPipeAsync(request)
                : await SendViaUnixSocketAsync(request);
            if (response == "SUCCESS") return true;
            AuditLogger.Warn($"[IPC] DB command failed: {response ?? "(no response)"}");
            return false;
        }
        catch (Exception ex)
        {
            AuditLogger.Error($"[IPC] DB command failed: {ex.Message}");
            return false;
        }
    }

    private static async Task<string?> SendViaPipeAsync(string request)
    {
        using var cts  = new CancellationTokenSource(TimeoutMs);
        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        AuditLogger.Debug($"[IPC] Connecting to pipe...");
        await pipe.ConnectAsync(TimeoutMs, cts.Token);
        AuditLogger.Debug($"[IPC] Connected. Sending request...");

        // Direct byte I/O — avoids StreamReader/StreamWriter BOM and buffering issues on pipes
        byte[] requestBytes = Encoding.UTF8.GetBytes(request + "\n");
        await pipe.WriteAsync(requestBytes, cts.Token);
        await pipe.FlushAsync(cts.Token);
        AuditLogger.Debug($"[IPC] Request sent. Waiting for response...");

        const int MaxResponseBytes = 1024;
        var buffer = new List<byte>(256);
        var singleByte = new byte[1];
        while (buffer.Count < MaxResponseBytes)
        {
            int n = await pipe.ReadAsync(singleByte, cts.Token);
            if (n == 0 || singleByte[0] == (byte)'\n') break;
            if (singleByte[0] != (byte)'\r') buffer.Add(singleByte[0]);
        }

        string response = Encoding.UTF8.GetString(buffer.ToArray());
        // A response may be a freshly-minted token (e.g. RENEW_PASSKEY_TOKEN), so log
        // only status responses verbatim and redact anything else.
        string respLog = string.IsNullOrEmpty(response) ? "(none)"
            : (response == "SUCCESS" || response.StartsWith("ERROR", StringComparison.OrdinalIgnoreCase)) ? response
            : "<redacted>";
        AuditLogger.Debug($"[IPC] Response received: '{respLog}'");
        return response;
    }

    private static async Task<string?> SendViaUnixSocketAsync(string request)
    {
        using var cts    = new CancellationTokenSource(TimeoutMs);
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);

        await socket.ConnectAsync(new UnixDomainSocketEndPoint(UnixSocketPath), cts.Token);

        using var stream = new NetworkStream(socket, ownsSocket: false);

        // Direct byte I/O, matching SendViaPipeAsync. A StreamWriter over Encoding.UTF8 prepends
        // a BOM to the first write; the service reads raw bytes, so that BOM ends up inside the
        // first field and every request fails to parse ("ERROR: Invalid IP address"). The old
        // StreamReader on the service side used to strip it silently, which hid the problem.
        byte[] requestBytes = Encoding.UTF8.GetBytes(request + "\n");
        await stream.WriteAsync(requestBytes, cts.Token);
        await stream.FlushAsync(cts.Token);

        const int MaxResponseBytes = 1024;
        var buffer = new List<byte>(256);
        var singleByte = new byte[1];
        while (buffer.Count < MaxResponseBytes)
        {
            int n = await stream.ReadAsync(singleByte, cts.Token);
            if (n == 0 || singleByte[0] == (byte)'\n') break;
            if (singleByte[0] != (byte)'\r') buffer.Add(singleByte[0]);
        }

        // Tolerate a BOM from an older service build.
        if (buffer.Count >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
            buffer.RemoveRange(0, 3);

        return buffer.Count == 0 ? null : Encoding.UTF8.GetString(buffer.ToArray());
    }
}
// Tracks the currently-served TLS certificate's expiry so the post-login page
// can warn an operator before it lapses. Populated by the cert selector; the
// push (email) alert lives in MFAService so it fires even if the web tier is down.
public static class CertStatus
{
    private static volatile bool _showWarning;
    private static string _message = "";
    public static bool ShowWarning => _showWarning;
    public static string Message => _message;

    public static void Update(X509Certificate2? cert, int warnDays)
    {
        if (cert is null)
        {
            _message = "No valid TLS certificate is installed for this site.";
            _showWarning = true;
            return;
        }
        // X509 NotAfter is local time.
        int days = (int)Math.Floor((cert.NotAfter - DateTime.Now).TotalDays);
        if (days < 0)
        {
            _message = $"TLS certificate expired on {cert.NotAfter:yyyy-MM-dd}.";
            _showWarning = true;
        }
        else if (days <= warnDays)
        {
            _message = $"TLS certificate expires in {days} day{(days == 1 ? "" : "s")} (on {cert.NotAfter:yyyy-MM-dd}).";
            _showWarning = true;
        }
        else
        {
            _message = "";
            _showWarning = false;
        }
    }
}

// Per-account failed-login monitor. It deliberately does NOT lock accounts —
// that would let anyone DoS a user by guessing their (email) username. Instead it
// logs a [SECURITY] warning when an account crosses the failure threshold within
// the window, and optionally emails an alert when AccountAlert:SendEmail is true.
// Detection, not prevention; the per-IP rate limiter remains the throttle.
public static class LoginFailureMonitor
{
    private static readonly ConcurrentDictionary<string, (int Failures, DateTime WindowStartUtc, bool Alerted)> _state = new();
    private static int _threshold = 10;
    private static TimeSpan _window = TimeSpan.FromMinutes(15);
    private static bool _sendEmail = false;
    private static IConfiguration? _config;

    public static void Configure(IConfiguration config)
    {
        _config = config;
        int t = config.GetValue<int>("AccountAlert:Threshold", 10);
        int w = config.GetValue<int>("AccountAlert:WindowMinutes", 15);
        _sendEmail = config.GetValue<bool>("AccountAlert:SendEmail", false);
        if (t > 0) _threshold = t;
        if (w > 0) _window = TimeSpan.FromMinutes(w);
    }

    public static void RecordSuccess(string username) => _state.TryRemove(username.ToLowerInvariant(), out _);

    public static void RecordFailure(string username, string clientIp)
    {
        string key = username.ToLowerInvariant();
        var now = DateTime.UtcNow;

        // Prune entries whose window has elapsed so a username-cycling attacker can't
        // grow the map without bound. Cheap at auth-failure rates (per-IP rate limited).
        foreach (var kv in _state)
            if (now - kv.Value.WindowStartUtc >= _window)
                _state.TryRemove(kv.Key, out _);

        var result = _state.AddOrUpdate(key,
            _ => (1, now, false),
            (_, s) => (now - s.WindowStartUtc >= _window)
                ? (1, now, false)                                   // window elapsed → reset
                : (s.Failures + 1, s.WindowStartUtc, s.Alerted));   // same window → increment

        // Fire exactly once per window when the threshold is first crossed.
        if (result.Failures >= _threshold && !result.Alerted
            && _state.TryUpdate(key, (result.Failures, result.WindowStartUtc, true), result))
        {
            AuditLogger.Warn($"[SECURITY] {result.Failures} failed logins for '{username}' within {_window.TotalMinutes:0} min (latest from {clientIp})");
            if (_sendEmail)
                _ = Task.Run(() => TrySendAlert(username, result.Failures, clientIp)); // don't block the auth response
        }
    }

    private static void TrySendAlert(string username, int failures, string clientIp)
    {
        var cfg = _config;
        if (cfg == null) return;
        string? host = cfg["Smtp:Host"], from = cfg["Smtp:FromAddress"], notify = cfg["Smtp:NotifyAddress"];
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(from) || string.IsNullOrWhiteSpace(notify))
        {
            AuditLogger.Warn("[SECURITY] AccountAlert:SendEmail is enabled but Smtp Host/FromAddress/NotifyAddress is not fully configured.");
            return;
        }
        int  port   = int.TryParse(cfg["Smtp:Port"], out var p) ? p : 25;
        bool useSsl = bool.TryParse(cfg["Smtp:UseSsl"], out var s) && s;
        string? user = cfg["Smtp:Username"], pass = cfg["Smtp:Password"];
        try
        {
            using var msg = new MailMessage(from, notify)
            {
                Subject = $"[MFA] {failures} failed logins for {username}",
                Body    = $"{failures} failed login attempts for '{username}' within {_window.TotalMinutes:0} minutes.\n" +
                          $"Most recent attempt from {clientIp}.\n\n" +
                          "This is a detection alert only — the account is NOT locked.\n\n-- MFAWeb login monitor"
            };
            using var client = new SmtpClient(host, port) { EnableSsl = useSsl };
            if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(pass))
                client.Credentials = new System.Net.NetworkCredential(user, pass);
            client.Send(msg);
            AuditLogger.Log($"[SECURITY] Failed-login alert emailed to {notify} for '{username}'");
        }
        catch (Exception ex)
        {
            AuditLogger.Error($"[SECURITY] Failed to send login-alert email: {ex.Message}");
        }
    }
}

public enum LogSeverity { Debug, Info, Warning, Error }

public static class AuditLogger
{
    public static string LogDirectory = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
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

        // Scrub the message of all malicious payloads before formatting
        string safeMessage = SanitizeForLog(message);

        string tag = level switch
        {
            LogSeverity.Debug   => "DBG",
            LogSeverity.Warning => "WRN",
            LogSeverity.Error   => "ERR",
            _                   => "INF"
        };

        string logEntry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC] [{tag}] {safeMessage}";

        Console.WriteLine(logEntry);

        try
        {
            if (!Directory.Exists(LogDirectory))
            {
                Directory.CreateDirectory(LogDirectory);
            }

            string dailyFileName = $"mfaweb_{DateTime.UtcNow:yyyy-MM-dd}.log";
            string fullPath = Path.Combine(LogDirectory, dailyFileName);

            lock (_lock)
            {
                File.AppendAllText(fullPath, logEntry + Environment.NewLine);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[LOG ERROR] Could not write to log file: {ex.Message}");
        }
    }

    // --- NEW: The Zero-Trust Sanitizer ---
    private static string SanitizeForLog(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "[EMPTY]";

        // 1. Length Truncation (Prevents Log Flooding / Disk Exhaustion DoS)
        // Set to 512 to ensure it easily fits our longest legitimate log entries, 
        // while stopping attackers from dumping 10MB payloads into the username field.
        if (raw.Length > 512)
        {
            raw = raw.Substring(0, 512) + "...[TRUNCATED]";
        }

        // 2. Strict Character Whitelisting
        var safeString = new StringBuilder(raw.Length);
        foreach (char c in raw)
        {
            // Only allow standard, printable ASCII characters (Decimal 32 to 126).
            // This instantly destroys:
            // - Newlines (\n) and Carriage Returns (\r)
            // - Tabs (\t)
            // - Null Bytes (\0)
            // - Terminal Escape Sequences (e.g., ANSI color codes / screen clears)
            // - Unicode composed characters, zero-width spaces, and emojis
            if (c >= 32 && c <= 126)
            {
                safeString.Append(c);
            }
            else
            {
                // Visually flag that a malicious or weird character was stripped
                safeString.Append('?');
            }
        }

        return safeString.ToString();
    }
}


