<div align="center">
  <img src="MFAWeb/wwwroot/knocker.png" alt="MFA Firewall Knocker" width="160" />
  <h1>MFA Firewall Knocker</h1>
  <p><strong>Open a firewall port for your IP — but only after real multi-factor authentication.</strong></p>
</div>

---

Exposing SSH, RDP, or any admin port to the internet means exposing it to everyone. Closing it means
you can't reach it either. This is the middle path: the port stays **closed by default**, and a
user who proves who they are with a passkey or TOTP code gets a firewall rule opened **for their
source IP only**, which **expires automatically**.

It's port knocking, except the knock is WebAuthn instead of a magic packet sequence.

## How it works

```
  Browser ──HTTPS──▶  MFAWeb          ──named pipe / unix socket──▶  MFAService
                      (unprivileged)                                 (privileged)
                      passkey / TOTP                                 writes firewall rules
                      read-only to DB                                sole writer of users.dat
```

1. You hit MFAWeb from the machine you want access from. It shows you the IP it sees.
2. You authenticate with a **FIDO2 passkey** (preferred) or a **TOTP** code.
3. MFAWeb hands the request to MFAService over local IPC. It never touches the firewall itself.
4. MFAService **independently re-validates** the request and opens a rule scoped to that single IP
   and the ports you allowed.
5. A sweeper removes the rule once it expires (default: 1 hour).

The split matters. MFAWeb is the part exposed to the internet, so it holds no privileges, cannot
write to the user database, and cannot issue a firewall command directly. MFAService is never
exposed to the network and re-checks every policy decision rather than trusting its caller.

## Features

- **Passkey-only by default.** WebAuthn/FIDO2 with a platform authenticator is the default and
  only login method; TOTP is available but **off by default** (`RequirePasskey`). See
  [Passkey requirements](#passkey-requirements) — the WebAuthn configuration is stricter than
  most deployments and will reject a YubiKey
- **Per-IP, auto-expiring** firewall rules — nothing is left open
- **Public-IP-only enforcement** — requests from RFC-1918, CGNAT, loopback, and link-local ranges
  are rejected, on both sides of the privilege boundary
- **No account lockout by design** — usernames are email addresses and therefore guessable, so
  lockout would be a trivial DoS. Throttling is per-IP; failed logins are detected and alerted on
  instead
- **Encrypted user store** — `users.dat` is DPAPI-encrypted on Windows and guarded by a
  cross-process mutex; MFAService is its only writer
- **TLS cert resilience** — the certificate is selected at runtime from the store by CN *and* SAN,
  picking the newest valid one. A renewal is picked up without a restart, and an expired cert
  degrades to a warning banner instead of a startup crash
- **Cert expiry email alerts** from the always-on privileged service, so the warning still arrives
  in the one failure mode that matters: when no usable cert exists and the web app can't serve HTTPS
- **Ignores `X-Forwarded-For`** — the client IP always comes from the TCP connection, so it can't be
  spoofed with a forged header

## Components

| Component | Role | Runs as |
|-----------|------|---------|
| **MFAWeb** | Internet-facing ASP.NET Core app. Authenticates users, then asks MFAService to open the firewall. | gMSA (Windows) / dedicated user (Linux) |
| **MFAService** | Privileged background service. Owns the user database and issues firewall commands. Never exposed to the internet. | LocalSystem (Windows) / root (Linux) |
| **MFAAdmin** | Command-line tool for provisioning and managing users. | Administrator (Windows) / root (Linux) |

## Passkey requirements

The WebAuthn configuration is deliberately strict. As written it requires a **platform
authenticator with user verification** — the built-in kind, unlocked by biometric or device PIN:

| Setting | Value | Consequence |
|---------|-------|-------------|
| `AuthenticatorAttachment` | `Platform` | Only built-in authenticators: Windows Hello, Touch ID / Face ID, Android biometric. **Roaming security keys — YubiKey, Titan, SoloKeys — are rejected at registration.** |
| `UserVerification` | `Required` | Biometric or device PIN on **every** registration and **every** login. A tap-only key is not enough. Enforced server-side on each assertion. |
| `RequireResidentKey` | `false` | Non-discoverable credential: the user types their email address first. No usernameless "just tap" login. |
| `attestationPreference` | `None` | The server does not verify authenticator make or model. |

Set in `MFAWeb/Program.cs` (registration options and assertion options).

This works out of the box on **iOS/iPadOS, macOS (Touch ID / Face ID), Windows Hello, and
Android**.

Practical consequences to plan for:

- **Whether a passkey survives losing the device depends on the platform.** Apple passkeys
  sync through iCloud Keychain and Google's sync through Google Password Manager, so the
  credential is available on the user's other devices in the same ecosystem. Windows Hello
  passkeys have historically been device-bound (newer Windows 11 builds add sync via Microsoft
  account or a third-party provider). **Plan recovery around the pessimistic case:** an admin
  runs `MFAAdmin reprovision <email>`.
- **Machines without a platform authenticator cannot register a passkey at all.** An older
  desktop with no Hello-capable hardware has no way in unless you enable TOTP by setting
  `RequirePasskey` to `false`.
- **If you want security-key support**, change `AuthenticatorAttachment` to
  `CrossPlatform`, or drop the property entirely to allow both. Keep
  `UserVerification = Required` if you do — a PIN-less key would weaken the factor to
  mere possession.

### Passkey-only mode (`RequirePasskey`, default `true`)

TOTP is phishable, and per the security audit a captured code stays valid for roughly 90
seconds. An account is only as strong as its weakest enrolled method, so leaving TOTP on
means the passkey buys you little. It is therefore **off by default**.

With `RequirePasskey: true`:

- `/auth` (password + authenticator code) returns **403 regardless of credentials** — the form
  is refused at the endpoint, not merely hidden in the UI.
- The TOTP enrollment pages (`/setup/{token}`, `/setup`) are refused the same way.
- `MFAAdmin add` and `reprovision` **mint no TOTP secret at all**, and the provisioning email
  omits the authenticator-app link. `users.dat` therefore holds no recoverable shared secret —
  only passkey public keys and BCrypt hashes.

The key must be set identically in **MFAWeb's and MFAAdmin's** `appsettings.json`.

> **Switching an existing deployment?** Enabling the flag stops new secrets being minted but
> does **not** remove secrets already in the database. Run `MFAAdmin purge-totp` to clear them,
> or you have a "passkey-only" deployment still sitting on live secrets. That command
> deliberately skips accounts with no passkey enrolled — clearing those would lock the user out
> entirely — and lists them so you can reprovision them first.

## Requirements

- .NET 10 (runtime, or publish self-contained)
- **Windows:** Windows Server 2019+, PowerShell 5.1+ with the `NetSecurity` module, and an Active
  Directory domain if you want to run MFAWeb under a gMSA
- **Linux:** systemd, and `iptables` (see the note below)
- An SMTP relay, for user provisioning emails and alerts
- A TLS certificate for MFAWeb, or port 80 reachable if you want Let's Encrypt to handle it

> **Linux firewall backends:** the built-in Linux path uses `iptables`. If your distro uses
> `nftables`, `ufw`, or `firewalld`, adapt the two clearly-marked sections in `OpenFirewallPort` and
> `SweepExpiredRules` in `MFAService/Program.cs`. See the Linux Firewall Commands section of
> [INSTALL.md](INSTALL.md).

## Quick start

```bash
git clone https://github.com/<you>/mfa-firewall-knocker.git
cd mfa-firewall-knocker

# Configure each component from its template
cp MFAWeb/appsettings.example.json     MFAWeb/appsettings.json
cp MFAService/appsettings.example.json MFAService/appsettings.json
cp MFAAdmin/appsettings.example.json   MFAAdmin/appsettings.json
# ...then edit each one: AppUrl, AllowedDomains, DpapiEntropy, Smtp, HttpsCert

dotnet build MFAWeb/MFAWeb.csproj -c Release
dotnet publish MFAService/MFAService.csproj -c Release -p:PublishProfile=FolderProfile
```

Then add your first user:

```
MFAAdmin add you@your-domain.com
```

They get an email with a passkey setup link and a TOTP QR code link, both valid for 60 minutes.

**[INSTALL.md](INSTALL.md) is the real guide** — gMSA creation, service installation, systemd units,
socket permissions, TLS options, and file permissions are all covered there. Read it before
deploying.

## Configuration

Every component reads its own `appsettings.json`, which is **gitignored** because it holds secrets.
Copy the matching `appsettings.example.json` and fill it in. The full key reference is in
[INSTALL.md](INSTALL.md).

A few that are easy to get wrong:

- **`DpapiEntropy`** — a unique random string mixed into the DPAPI key derivation. It must be
  **identical across all three components** and must not be left at the placeholder value.
- **`HttpsCert:Subject` / `Store` / `Location`** — must match between MFAWeb and MFAService, or the
  cert monitor will watch a different certificate than the one being served.
- **`RequirePasskey`** — passkey-only mode, **default `true`**. Must be identical in MFAWeb's
  and MFAAdmin's config. See [Passkey-only mode](#passkey-only-mode-requirepasskey-default-true).
- **`AllowedDomains`** — restricts which email domains can be provisioned.
- **`BouncerConfig:AllowedPorts`** — the only ports MFAService will ever open, e.g. `["22/TCP"]`.
- **`LogoUrl`** — leave empty to use the bundled knocker logo, or point it at your own image.

> **Do not put a reverse proxy in front of MFAWeb.** It deliberately ignores `X-Forwarded-For` and
> `X-Real-IP` and reads the client IP from the TCP connection. Behind a proxy, every request would
> appear to come from the proxy — collapsing rate limiting and opening the firewall for the wrong
> address. Bind it directly to the public interface.

## Security notes

- The user database stores **TOTP secrets in recoverable form** (they have to be, to validate
  codes). Protect the file with the filesystem permissions documented in INSTALL.md. Passkey
  credentials are public keys and are not sensitive — passkeys are the stronger option for this
  reason, among others.
- Firewall rules expire after `ExpirationHours`; the sweeper runs every 5 minutes.
- Passkey registration always requires proof of password or a post-login token. See the security
  invariants in [CLAUDE.md](CLAUDE.md) before changing anything in that path.
- This software is provided as-is under the MIT license, with no warranty. It manipulates firewall
  rules on a privileged host. **Review the code and test in a non-production environment first.**

If you find a security issue, please open an issue describing the impact without a working exploit,
or contact the maintainer privately.

## Contributing

Issues and pull requests are welcome. [CLAUDE.md](CLAUDE.md) documents the architecture, the
invariants that must not regress, and the non-obvious gotchas — it's the fastest way to get oriented,
whether or not you use an AI assistant.

## License

MIT — see [LICENSE](LICENSE).
