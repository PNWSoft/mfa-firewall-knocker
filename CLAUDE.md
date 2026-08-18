# CLAUDE.md

Guidance for working in this repository.

## What this is

An MFA gate that opens firewall ports on demand after strong auth.

- **MFAWeb** — internet-facing ASP.NET Core minimal API (runs as a gMSA on Windows, a dedicated
  unprivileged user on Linux). WebAuthn/passkey login; TOTP only in an `AllowTotp` build.
  Read-only to the user database;
  all writes go out over IPC. Serves HTTPS on `:8443` by default.
- **MFAService** — privileged service (LocalSystem on Windows, root on Linux). The only writer of
  `users.dat` **on the request path**; opens/sweeps firewall rules; hosts the IPC server. Also the
  always-on watchdog for infrastructure concerns (cert expiry alerts). (MFAAdmin also writes the
  DB directly when an administrator runs it, under the same mutex — the invariant that matters is
  that **MFAWeb never writes**, not that MFAService is the only writer in the whole system.)
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
  - The bundled profiles target win-x64 (MFAAdmin's `FolderProfile1.pubxml` targets linux-x64).
    MFAService's profile is **self-contained single-file**; MFAAdmin's profiles are
    **framework-dependent** single-file; MFAWeb's is a self-contained multi-file folder. For
    deployment, INSTALL.md passes `-r win-x64 --self-contained` explicitly rather than relying
    on the profiles, which is why the MFAAdmin profile's `SelfContained=false` doesn't bite.
- **Incremental deploys:** copying only `MFAWeb.dll` is not enough when the dependency set
  changes — `MFAWeb.deps.json` must stay consistent with the DLLs beside it. Copy the whole
  publish directory but exclude `appsettings.json` so the DLL set + `deps.json` stay consistent and server
  config isn't clobbered — e.g. `robocopy <publish> <dest> /E /XF appsettings.json`.
- `appsettings.json` for all three is **gitignored** — it holds secrets (`DpapiEntropy`, SMTP
  credentials). `appsettings.example.json` are the templates; copy and fill them in per deployment.
- All three share the `users.dat` schema, so **deploy all three together** when `UserEntry` changes.

## TLS certificate handling

MFAWeb is HTTPS-only and binds no cleartext listener. Certificates come from an external ACME
client: the Windows store (win-acme) on Windows, PEM files from certbot on Linux. There is
deliberately no in-process ACME client — see the note at the top of the TLS block in
`MFAWeb/Program.cs` for why the LettuceEncrypt integration was removed.

### MFAWeb — resilient selection + banner (Windows)
- On Windows the HTTPS endpoint declares only the **URL** (`Kestrel:Endpoints:Https:Url`) and the
  certificate is chosen in code from the store. Never add a `Kestrel:...:Certificate:Subject`
  binding: it does a CN-only `FindBySubjectName` with `AllowInvalid:false` and **crashes Kestrel
  at startup** the moment the cert expires or the CA issues an empty-CN / SAN-only replacement.
  - This is about the *Subject* binding specifically. On **Linux** the certificate legitimately
    comes from `Kestrel:...:Certificate:{Path,KeyPath}` (PEM). The **store-scanning** selector must
    not be installed there — it can only return null and silently overrode a good PEM with nothing,
    breaking TLS entirely. A separate **PEM** selector is installed instead (see the platform guard
    in `Program.cs`): it re-reads on mtime change, keeps the last good cert on a failed read, and
    populates `CertStatus`, giving Linux the same restart-free renewal and banner as Windows.
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
- `CertificateMonitorService` runs on **both** platforms: it scans the Windows store, or stats
  `HttpsCert:PemPath` on Linux. It used to return immediately off Windows, which meant a Linux
  deployment got no warning at all before a certificate lapsed.
- On Windows it scans the store every
  `CertAlert:CheckIntervalHours` for the newest cert matching the hostname (including expired, so it
  can report it), and **emails `Smtp:NotifyAddress`** when the cert is missing / expired / within
  `WarnDays`. Throttled to once per 24h; resets when healthy.
- Deliberately in MFAService (always-on, no TLS dependency) rather than MFAWeb, so the alert still
  fires in the exact failure mode that matters — when no usable cert exists and MFAWeb can't serve
  HTTPS. Uses BCL `System.Net.Mail`, so no MailKit dependency is pulled into MFAWeb/MFAService.

### Renewal notes
- **Windows:** any ACME client that installs into `LocalMachine\My` works. HTTP-01 needs port 80
  free on the host; where it isn't, **TLS-ALPN-01 on 443** or **DNS-01** are the alternatives.
- **Linux:** certbot `--standalone` works because MFAWeb never binds port 80 — so never give
  certbot a `--pre-hook` that stops MFAWeb (it would be pure downtime, and certbot persists the
  hook into the renewal config). MFAWeb re-loads the PEM once a minute and swaps on a thumbprint
  change, so renewal is picked up **without a restart**; verified against a forced renewal with
  the served certificate changing under a constant PID. The deploy hook re-applies the group
  grant and is belt-and-braces, not load-bearing.
- The `mfaweb` unit uses `Wants=mfaservice.service`, **not** `Requires=`. `Requires=` propagates
  *stop*: restarting MFAService would take MFAWeb down and leave it down.
- **The service account must have read access to the certificate's private key**, or the cert
  selects fine but the TLS handshake fails (SChannel can't open the key → the client sees an EOF).
  Grant it on every renewal — most ACME clients have a flag for this (win-acme:
  `--acl-read "DOMAIN\MFA_Service$"`). The `MatchesHostname`/`HasPrivateKey` filter alone is **not**
  sufficient, because `HasPrivateKey` is true even when the current account can't access the key.

## Config keys

- **MFAWeb:** `AppUrl`, `SiteName`, `LogoUrl`, `DpapiEntropy` (required), `RateLimitPerWindow`,
  `AllowedDomains`, `Kestrel:Endpoints:Https:Url`, `HttpsCert:{Subject,Store,Location}`,
  `CertAlert:WarnDays`, `AccountAlert:{Threshold,WindowMinutes,SendEmail}`, `Smtp:*` (for account
  alerts). Linux additionally uses `Kestrel:Endpoints:Https:Certificate:{Path,KeyPath}`.
- **MFAService:** `DpapiEntropy` (required), `BouncerConfig:{AllowedPorts,ExpirationHours,RulePrefix}`,
  `FirewallService:GmsaAccount`, `HttpsCert:{Subject,Store,Location}` (must match MFAWeb;
  `HttpsCert:PemPath` instead on Linux, or there are no expiry alerts there),
  `CertAlert:{WarnDays,CheckIntervalHours}`,
  `Smtp:{Host,Port,UseSsl,Username,Password,FromAddress,NotifyAddress}`.
- **MFAAdmin:** `DpapiEntropy` (required), `SiteName`, `RulePrefix`, `BouncerUrl`,
  `AllowedDomains`, `FirewallService:GmsaAccount`, `Smtp:*`.

## Design principle: prefer deletion to configuration

For a security tool, **removing a capability beats adding a switch to disable it.** A switch can
be mis-set, mis-defaulted, or drift between components; an absent code path cannot, and a
reviewer never has to reason about it. Several decisions here follow from that and should not be
casually reversed:

- TOTP is compiled out, not config-disabled (`-p:AllowTotp=true` to include it).
- LettuceEncrypt was deleted rather than repaired: it removed four dependencies and made the
  cleartext port-80 listener *unreachable* instead of merely fixed.
- `RequirePasskey` as a runtime setting was abandoned mid-implementation once it became clear it
  needed a new IPC verb, a cached accessor, a refresh loop, and a widened named-pipe ACL just to
  keep two components in agreement.

When a feature is unused, untested, or only reachable via a flag nobody sets, deleting it is
usually the security fix. Adding surface needs to earn its place.

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
- **TOTP is a compile-time decision, not a config value.** It is excluded unless built with
  `-p:AllowTotp=true` (`ALLOW_TOTP`). In the default build `/auth`, `/setup/{token}` and `/setup`
  do not exist (404 — no handler, rather than a handler that declines), the login page emits no
  TOTP form, MFAService omits the `BURN_TOTP_TOKEN` IPC verb, and MFAAdmin mints no TOTP secret,
  so `users.dat` holds no recoverable shared secret. **Do not reintroduce this as a runtime
  setting.** A config switch can be flipped, mis-defaulted, or drift between components; an
  absent code path cannot. The flag must match across all three components, which are deployed
  together anyway.
- **One passkey per account is enforced on the privileged side, and relaxing it is a trap.**
  `RenewPasskeyToken` and `SetPasskeyToken` both refuse when `PasskeyCredentials.Count > 0`.
  This is what makes a phished password worthless against an enrolled account: the only
  registration gates are the password and a post-login token, and the password is the phishable
  one. If multi-device enrollment is ever added, do **not** do it by dropping these checks —
  authorize adding a credential with an assertion from an *existing* passkey, never with the
  password alone. Until then, per-admin redundancy is a synced passkey or a second account
  (documented in the README's redundancy section).
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
- **Config values that reach a firewall command are bounded on the privileged side.**
  `ExpirationHours` is clamped to 1-48 (`MaxExpirationHours`), the port must be 1-65535, and the
  protocol must be TCP or UDP; anything else is skipped with a `[CONFIG]` warning. The upper cap
  matters most: without it a slipped digit turns time-limited access into a standing grant that
  the sweeper will not clear for weeks. Keep these checks in MFAService, not only in the docs.
- Command construction into PowerShell/iptables relies on prior validation: IP via
  `IPAddress.TryParse`, port via `int.TryParse`, username single-quote-escaped **and** passed via
  `-EncodedCommand`. Preserve that validation-before-use ordering.

## Conventions / gotchas

- `X509Certificate2.NotBefore/NotAfter` are **local time** — compare against `DateTime.Now`, not
  `UtcNow`.
- MFAWeb intentionally ignores `X-Forwarded-For`; it uses the TCP connection address (rate limiting,
  IP checks). Do not put a reverse proxy in front of it.
- `HttpsCert:Subject`/`Store`/`Location` must be identical in MFAWeb and MFAService.
- **IPC uses raw byte I/O on both transports — never `StreamWriter`/`StreamReader`.** A
  `StreamWriter` over `Encoding.UTF8` prepends a BOM to its first write, and both IPC readers
  parse raw bytes, so the BOM lands inside the first field and every request fails with
  `ERROR: Invalid IP address`. This was live on the Unix socket path and invisible on Windows
  (which already used raw bytes) until a real Linux deployment surfaced it. Both sides now use
  `Encoding.UTF8.GetBytes` (no BOM) and defensively strip a leading `EF BB BF` on read. If you
  reintroduce a `StreamWriter` here, use `new UTF8Encoding(false)`.
- **Both hosts call `AddSystemd()` as well as `AddWindowsService()`.** The documented systemd
  units declare `Type=notify`; without `AddSystemd()` the service never sends `READY=1`, so
  systemd waits out the full start timeout and marks the unit failed. Each call is a no-op off
  its own platform. Don't remove either.
- **`Microsoft.IdentityModel.JsonWebTokens` / `System.IdentityModel.Tokens.Jwt` 6.34.0 in
  MFAWeb are unused by our code on purpose.** They are transitive version overrides: Fido2
  3.0.1 otherwise resolves them to 6.17.0, which carries GHSA-59j7-ghrg-fj52. Deleting them
  as "unused" reintroduces the advisory. Always run `dotnet list package --vulnerable
  --include-transitive` after touching MFAWeb's dependencies. The real fix is Fido2 4.x,
  which needs the passkey ceremonies re-tested.
- `SaveUsers` in **both** MFAService and MFAAdmin writes to `users.dat.tmp`, flushes to disk,
  then `File.Replace`s into place, leaving the previous contents as `users.dat.bak`. Don't
  revert to writing the live file directly — a torn write makes `LoadUsers` fail to decrypt
  and return an empty list, which locks out every user. `.bak` holds the same secrets as the
  DB, so it must stay inside the ACL-restricted data directory.
- **Passkeys are platform-authenticator-only with user verification required.** Registration
  options set `AuthenticatorAttachment = Platform`, `UserVerification = Required`,
  `RequireResidentKey = false`, `attestation = None`; assertion options also require UV. So
  roaming security keys are rejected at registration, credentials are non-discoverable (the
  user types their email first), and every ceremony needs a biometric or device PIN. UV is
  enforced server-side on each assertion; `Platform` is only browser-enforced at registration
  (attestation is `None`, so authenticator type is not verified afterward). Relaxing
  `AuthenticatorAttachment` to `CrossPlatform` enables security keys — do **not** relax
  `UserVerification` at the same time, or the second factor degrades to mere possession.
- The login page falls back to the bundled `wwwroot/knocker.png` when `LogoUrl` is empty. The CSP
  `img-src` directive is widened to the logo's origin only when `LogoUrl` is an absolute URL.
