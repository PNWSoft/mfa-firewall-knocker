# CLAUDE.md

Guidance for working in this repository.

## What this is

An MFA gate that opens firewall ports on demand after strong auth.

- **MFAWeb** — internet-facing ASP.NET Core minimal API (runs as a gMSA on Windows, a dedicated
  unprivileged user on Linux). WebAuthn/passkey + TOTP login. Read-only to the user database;
  all writes go out over IPC. Serves HTTPS on `:8443` by default.
- **MFAService** — privileged service (LocalSystem on Windows, root on Linux). Sole writer of
  `users.dat`; opens/sweeps firewall rules; hosts the IPC server. Also the always-on watchdog for
  infrastructure concerns (cert expiry alerts).
- **MFAAdmin** — elevated console tool for provisioning users.

Data flow: `MFAWeb → named pipe (Windows) / Unix socket (Linux) → MFAService`. IPC protocol:
`"IP|Username"` to open the firewall; `"DB:COMMAND|..."` for DB ops. `users.dat` is DPAPI-encrypted
(LocalMachine) and guarded by the cross-process mutex `Global\MFA_DB_LOCK`.

Firewall backends: PowerShell `NetSecurity` on Windows, `iptables` on Linux. If your distro uses
`nftables`, `ufw`, or `firewalld`, edit the marked sections in `OpenFirewallPort` and
`SweepExpiredRules` in `MFAService/Program.cs`.

## Build / publish / deploy

- Build: `dotnet build <Project>/<Project>.csproj -c Debug`
- Publish: `dotnet publish <Project>/<Project>.csproj -c Release -p:PublishProfile=FolderProfile`
  - The bundled profiles target **win-x64, self-contained**. MFAService/MFAAdmin are single-file;
    MFAWeb is a multi-file folder. `MFAAdmin/Properties/PublishProfiles/FolderProfile1.pubxml`
    targets linux-x64.
- **Incremental deploys:** copying only `MFAWeb.dll` is not enough when dependencies change (e.g.
  the LettuceEncrypt chain: `LettuceEncrypt.dll`, `Certes.dll`, `BouncyCastle.Crypto.dll`,
  `McMaster.AspNetCore.Kestrel.Certificates.dll`, plus `MFAWeb.deps.json`). Copy the whole publish
  directory but exclude `appsettings.json` so the DLL set + `deps.json` stay consistent and server
  config isn't clobbered — e.g. `robocopy <publish> <dest> /E /XF appsettings.json`.
- `appsettings.json` for all three is **gitignored** — it holds secrets (`DpapiEntropy`, SMTP
  credentials). `appsettings.example.json` are the templates; copy and fill them in per deployment.
- All three share the `users.dat` schema, so **deploy all three together** when `UserEntry` changes.

## TLS certificate handling (store-cert path, `UseLettuceEncrypt=false`)

This is the primary path. LettuceEncrypt is wired in as an optional alternative, but its HTTP-01
challenge needs port 80 and it stores certs in a directory rather than the Windows store.

### MFAWeb — resilient selection + banner
- Kestrel's HTTPS endpoint in `appsettings.json` declares only the **URL**
  (`Kestrel:Endpoints:Https:Url`). The certificate is chosen in code, **not** bound by subject in
  config.
  - Rationale: a `Kestrel:...:Certificate` subject binding does a CN-only `FindBySubjectName` with
    `AllowInvalid:false`, which **crashes Kestrel at startup** the moment the cert expires or when
    the CA issues an empty-CN / SAN-only replacement.
- `SelectBestCertificate(hostname, store, location)` scans `LocalMachine\My`, matches the hostname
  against **CN *and* SAN** (`X509Certificate2.MatchesHostname`), keeps only currently-valid certs
  with a private key, and picks the **newest expiry**.
- Wired via `ConfigureHttpsDefaults` → `ServerCertificateSelector`, with a 1-minute cache
  (`GetCurrentCertificate`) so a renewed cert is picked up **without a restart**; keeps the
  last-good cert if the store is briefly empty. Never hard-crashes on a missing cert.
- `CertStatus` (static) is updated by the selector and drives a **post-login warning banner** on
  `/access-granted` when the cert is within `CertAlert:WarnDays` (shown to all authenticated users
  by design).

### MFAService — expiry email watchdog
- `CertificateMonitorService` (a `BackgroundService`, Windows-only) scans the store every
  `CertAlert:CheckIntervalHours` for the newest cert matching the hostname (including expired, so it
  can report it), and **emails `Smtp:NotifyAddress`** when the cert is missing / expired / within
  `WarnDays`. Throttled to once per 24h; resets when healthy.
- Deliberately in MFAService (always-on, no TLS dependency) rather than MFAWeb, so the alert still
  fires in the exact failure mode that matters — when no usable cert exists and MFAWeb can't serve
  HTTPS. Uses BCL `System.Net.Mail`, so no MailKit dependency is pulled into MFAWeb/MFAService.

### Renewal notes
- Any ACME client that installs into `LocalMachine\My` works. If port 80 is unavailable on the host,
  **TLS-ALPN-01 on port 443** or **DNS-01** are the workable challenge types; HTTP-01 is not.
- **The service account must have read access to the certificate's private key**, or the cert
  selects fine but the TLS handshake fails (SChannel can't open the key → the client sees an EOF).
  Grant it on every renewal — most ACME clients have a flag for this (win-acme:
  `--acl-read "DOMAIN\MFA_Service$"`). The `MatchesHostname`/`HasPrivateKey` filter alone is **not**
  sufficient, because `HasPrivateKey` is true even when the current account can't access the key.

## Config keys

- **MFAWeb:** `AppUrl`, `SiteName`, `LogoUrl`, `DpapiEntropy` (required), `RateLimitPerWindow`,
  `AllowedDomains`, `Kestrel:Endpoints:Https:Url`, `HttpsCert:{Subject,Store,Location}`,
  `CertAlert:WarnDays`, `AccountAlert:{Threshold,WindowMinutes,SendEmail}`, `Smtp:*` (for account
  alerts), `UseLettuceEncrypt` (+ `LettuceEncrypt:*` when true).
- **MFAService:** `DpapiEntropy` (required), `BouncerConfig:{AllowedPorts,ExpirationHours,RulePrefix}`,
  `FirewallService:GmsaAccount`, `HttpsCert:{Subject,Store,Location}` (must match MFAWeb),
  `CertAlert:{WarnDays,CheckIntervalHours}`,
  `Smtp:{Host,Port,UseSsl,Username,Password,FromAddress,NotifyAddress}`.
- **MFAAdmin:** `DpapiEntropy` (required), `SiteName`, `RulePrefix`, `BouncerUrl`, `AllowedDomains`,
  `FirewallService:GmsaAccount`, `Smtp:*`.

## Security invariants (do not regress)

- **Passkey registration requires password proof.** A user's `PasskeyRegistrationReady` flag gates
  passkey registration and is set `true` **only** by `RenewPasskeyToken` (after the `/setup-passkey`
  password check) or `SetPasskeyToken` (a token minted post-login). The emailed provisioning token
  from MFAAdmin is set `false`. The authoritative gate is `AddPasskey` in MFAService (the sole DB
  writer) — it rejects any registration whose token isn't registration-ready, so bypassing MFAWeb's
  routes doesn't help. `/register-passkey`, `/passkey/register/begin`, `/passkey/register/complete`
  also check the flag. **Never** let the register routes or `AddPasskey` accept a bare
  `PasskeyProvisioningToken` without this flag — that reintroduces the emailed-link bypass. The
  field lives in all three `UserEntry` classes and must stay in sync (shared `users.dat` schema →
  deploy all three together).
- **The privilege boundary re-validates, it does not trust MFAWeb.** MFAService independently
  re-checks `IsPublicIpAddress` before opening a firewall rule and strictly validates every IPC
  request. Keep policy checks (public-IP-only, input validation) on the privileged side even though
  MFAWeb also does them.
- **No account lockout.** Failed-login handling is detection-only (`LoginFailureMonitor`, logs +
  optional email). Do **not** add per-account lockout — usernames are guessable emails, so lockout
  enables a trivial DoS. Per-IP rate limiting is the throttle.
- **Don't log secrets.** MFAService redacts `DB:` command arguments before logging (`RedactRequest`)
  and both loggers sanitize control characters. Don't log raw IPC requests, tokens, or credential
  material.
- Command construction into PowerShell/iptables relies on prior validation: IP via
  `IPAddress.TryParse`, port via `int.TryParse`, username single-quote-escaped **and** passed via
  `-EncodedCommand`. Preserve that validation-before-use ordering.

## Conventions / gotchas

- `X509Certificate2.NotBefore/NotAfter` are **local time** — compare against `DateTime.Now`, not
  `UtcNow`.
- MFAWeb intentionally ignores `X-Forwarded-For`; it uses the TCP connection address (rate limiting,
  IP checks). Do not put a reverse proxy in front of it.
- `HttpsCert:Subject`/`Store`/`Location` must be identical in MFAWeb and MFAService.
- LettuceEncrypt is pinned at **1.3.3** (1.3.4 does not exist on NuGet).
- The login page falls back to the bundled `wwwroot/knocker.png` when `LogoUrl` is empty. The CSP
  `img-src` directive is widened to the logo's origin only when `LogoUrl` is an absolute URL.
