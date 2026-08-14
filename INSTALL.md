# MFA Firewall Knocker — Installation Guide

## Overview

Three components work together:

| Component | Role | Runs as |
|-----------|------|---------|
| **MFAWeb** | Internet-facing web app. Authenticates users via WebAuthn (passkey) or TOTP, then asks MFAService to open the firewall. | gMSA (Windows) / dedicated user (Linux) |
| **MFAService** | Privileged background service. Receives IPC requests from MFAWeb and issues firewall commands. Never exposed to the internet. | LocalSystem (Windows) / root (Linux) |
| **MFAAdmin** | Command-line admin tool. Manages the user database — add, delete, reprovision users. | Local Administrator (Windows) / root (Linux) |

Communication between MFAWeb and MFAService uses a **named pipe** (Windows) or **Unix domain socket** (Linux). MFAWeb never touches the firewall or user database directly.

> **Do not place a reverse proxy in front of MFAWeb.** The application intentionally
> ignores `X-Forwarded-For` and `X-Real-IP` headers and reads the client IP exclusively
> from the TCP connection (`Connection.RemoteIpAddress`). This prevents IP spoofing via
> forged proxy headers, which would otherwise bypass rate limiting and the public-IP
> enforcement that blocks internal-network authentication. MFAWeb must be bound directly
> to the public interface.

---

## Prerequisites

### Windows
- Windows Server 2019 or later
- .NET 10 Runtime (or Self-Contained publish)
- Active Directory domain (required for gMSA)
- PowerShell 5.1+ with the `NetSecurity` module (included in Windows Server)
- An SMTP relay accessible from the server
- A TLS certificate for MFAWeb (see [TLS Options](#tls-options))

### Linux
- Ubuntu 22.04 LTS / Debian 12 / RHEL 9 (or equivalent)
- .NET 10 Runtime (or Self-Contained publish)
- `systemd`
- An SMTP relay accessible from the server
- A TLS certificate or Let's Encrypt support (see [TLS Options](#tls-options))

> **Linux firewall backend note:** MFAService has separate Windows (PowerShell /
> `NetSecurity`) and Linux (`iptables`) code paths built in. The default Linux
> implementation uses `iptables`. If your distro uses `nftables`, `ufw`, or `firewalld`
> instead, update the two clearly-marked sections in `OpenFirewallPort` and
> `SweepExpiredRules` in `MFAService/Program.cs`. See [Linux Firewall Commands](#7-linux-firewall-commands).

---

## Configuration Reference

All three components read from their own `appsettings.json`. Copy the
`appsettings.example.json` in each component's directory and fill in the values.

### MFAWeb — `appsettings.json`

```json
{
  "AppUrl":            "https://your.domain.com:8443",
  "SiteName":          "My Organization Secure Access",
  "LogoUrl":           "",
  "DpapiEntropy":      "REPLACE-WITH-A-UNIQUE-RANDOM-STRING",
  "RateLimitPerWindow": 20,
  "AllowedDomains":    [ "your-domain.com" ],
  "FirewallService": {
    "GmsaAccount": "YOURDOMAIN\\MFA_Service$"
  },
  "Smtp": {
    "Host": "your-smtp-server",  "Port": 25,
    "FromAddress": "security@your-domain.com",
    "NotifyAddress": "admins@your-domain.com"
  }
}
```

| Key | Description |
|-----|-------------|
| `AppUrl` | Full public URL of MFAWeb. Must match the TLS certificate's domain. Used for WebAuthn origin validation — any mismatch will break passkey login. |
| `SiteName` | Displayed in page titles, the TOTP issuer name, and provisioning emails. |
| `LogoUrl` | Optional URL of a logo image shown on the login page. Leave empty to use the bundled knocker logo (`wwwroot/knocker.png`). If set to an external URL, that origin is added to the `img-src` CSP directive automatically. |
| `DpapiEntropy` | **Required.** A deployment-specific value mixed into the DPAPI key derivation on Windows. It prevents other processes on the same machine from reading the database without knowing this value — keep it consistent across all three components. Startup fails if it is missing, under 16 characters, or still the placeholder from `appsettings.example.json` (that placeholder is published in the public repository and protects nothing). On Linux it is unused for encryption (the database is plain JSON) but is still validated at startup. See [step 3](#3-configure-appsettingsjson-and-restrict-permissions) for how to generate one. |
| `RateLimitPerWindow` | Maximum requests per IP per 5-minute window across all endpoints. Default: 20. |
| `AllowedDomains` | Email address domains permitted to use the system. Enforced in both MFAWeb (login form rejects other domains) and MFAAdmin (`add` refuses to provision an account outside these domains). |
| `FirewallService:GmsaAccount` | The gMSA account name that MFAWeb runs as (Windows only). Used to set the named pipe ACL so only that account can send IPC requests. |

### MFAService — `appsettings.json`

```json
{
  "DpapiEntropy": "REPLACE-WITH-A-UNIQUE-RANDOM-STRING",
  "BouncerConfig": {
    "AllowedPorts":    [ "22/TCP" ],
    "ExpirationHours": 1,
    "RulePrefix":      "MFA_Temp_"
  },
  "FirewallService": {
    "GmsaAccount": "YOURDOMAIN\\MFA_Service$"
  }
}
```

| Key | Description |
|-----|-------------|
| `DpapiEntropy` | Must match MFAWeb and MFAAdmin exactly. |
| `BouncerConfig:AllowedPorts` | Ports opened for each authenticated IP, in `port/protocol` format. Examples: `"22/TCP"`, `"51820/UDP"`. |
| `BouncerConfig:ExpirationHours` | How long firewall rules stay open. Rules are automatically removed by the sweeper when they expire. |
| `BouncerConfig:RulePrefix` | Prefix applied to every Windows Firewall rule name. Must also match the value in MFAAdmin's config so the `diag` and `reset` commands can find the rules. |

### MFAAdmin — `appsettings.json`

```json
{
  "AllowedDomains": [ "your-domain.com" ],
  "SiteName":       "My Organization",
  "DpapiEntropy":   "REPLACE-WITH-A-UNIQUE-RANDOM-STRING",
  "BouncerUrl":     "https://your.domain.com:8443",
  "RulePrefix":     "MFA_Temp_",
  "FirewallService": {
    "GmsaAccount": "YOURDOMAIN\\MFA_Service$"
  },
  "Smtp": {
    "Host": "your-smtp-server",  "Port": 25,
    "FromAddress": "security@your-domain.com",
    "NotifyAddress": "admins@your-domain.com"
  }
}
```

| Key | Description |
|-----|-------------|
| `BouncerUrl` | Base URL of MFAWeb. Used to generate the provisioning links sent in welcome emails. |
| `RulePrefix` | Must match `BouncerConfig:RulePrefix` in MFAService. Used by `diag` and `reset` commands. |

---

## Windows Installation

### 1. Create the gMSA

Run the following on a domain controller (requires `ActiveDirectory` PowerShell module):

```powershell
# Allow the web server to retrieve the gMSA password
Add-ADComputerServiceAccount -Identity "WEBSERVER$" -ServiceAccount "MFA_Service"

# Create the account (adjust KDS key creation if not done already)
New-ADServiceAccount `
    -Name "MFA_Service" `
    -DNSHostName "mfa-service.yourdomain.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "WEBSERVER$"
```

On the web server, install the gMSA and verify it:

```powershell
Install-ADServiceAccount -Identity "MFA_Service"
Test-ADServiceAccount -Identity "MFA_Service"
```

### 2. Publish the Applications

From the repository root, publish each component as a self-contained Windows executable:

```powershell
dotnet publish MFAService/MFAService.csproj -c Release -r win-x64 --self-contained
dotnet publish MFAWeb/MFAWeb.csproj     -c Release -r win-x64 --self-contained
dotnet publish MFAAdmin/MFAAdmin.csproj -c Release -r win-x64 --self-contained
```

Copy the publish outputs to their installation directories, for example:
- `C:\Services\MFAService\`
- `C:\Services\MFAWeb\`
- `C:\Tools\MFAAdmin\`

### 3. Configure appsettings.json and Restrict Permissions

In each installation directory, copy `appsettings.example.json` to `appsettings.json`
and fill in the values. The `DpapiEntropy` value must be identical in all three files.

Generate a strong entropy string with a cryptographic RNG (works on both Windows
PowerShell 5.1 and PowerShell 7):

```powershell
$b = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[Convert]::ToBase64String($b)
```

> The components refuse to start if `DpapiEntropy` is missing, shorter than 16 characters,
> or still set to the placeholder from `appsettings.example.json`.

**Now restrict access to the secrets.** This step is mandatory, not optional.

On Windows, DPAPI is used at `LocalMachine` scope, so `DpapiEntropy` is the only thing
separating `users.dat` from any other process on the host. `C:\ProgramData` and newly
created folders under `C:\` grant **Authenticated Users** read access by default — which
would let any local non-admin read the entropy out of `appsettings.json`, read `users.dat`,
and call `ProtectedData.Unprotect` to recover the **plaintext TOTP secrets** and password
hashes of every user.

Restrict the data directory and each `appsettings.json` to SYSTEM, Administrators, and the
gMSA only:

> **Note the single quotes** around every grant that names the gMSA. The account name ends
> in `$`, and inside a *double*-quoted PowerShell string `$:` is parsed as a variable
> reference — the command fails to parse. Single quotes keep it literal.

```powershell
# Create both directories up front so the ACLs exist before anything writes to them
New-Item -ItemType Directory -Force -Path "C:\ProgramData\MFAAuth"      | Out-Null
New-Item -ItemType Directory -Force -Path "C:\ProgramData\MFAAuth\Logs" | Out-Null

# Data directory: MFAService (LocalSystem) is the only writer of users.dat.
# MFAWeb only ever reads it, so the gMSA gets read access and nothing more.
icacls "C:\ProgramData\MFAAuth" /inheritance:r `
    /grant 'SYSTEM:(OI)(CI)F' `
    /grant 'Administrators:(OI)(CI)F' `
    /grant 'YOURDOMAIN\MFA_Service$:(OI)(CI)R'

# MFAWeb writes its own log files, so the gMSA needs Modify on Logs specifically.
icacls "C:\ProgramData\MFAAuth\Logs" /grant 'YOURDOMAIN\MFA_Service$:(OI)(CI)M'

# Each appsettings.json holds DpapiEntropy and SMTP credentials.
foreach ($f in @(
    "C:\Services\MFAService\appsettings.json",
    "C:\Services\MFAWeb\appsettings.json",
    "C:\Tools\MFAAdmin\appsettings.json")) {
    icacls $f /inheritance:r /grant 'SYSTEM:F' /grant 'Administrators:F'
}

# Only MFAWeb runs as the gMSA, so only its config needs the extra grant.
icacls "C:\Services\MFAWeb\appsettings.json" /grant 'YOURDOMAIN\MFA_Service$:R'
```


Verify that `Users` and `Authenticated Users` are absent from the result:

```powershell
icacls "C:\ProgramData\MFAAuth"
icacls "C:\Services\MFAWeb\appsettings.json"
```

> MFAAdmin runs elevated, so Administrators access is sufficient for it; it does not need
> a separate grant. The read-only file attribute that `DatabaseLockService` sets on
> `users.dat` is **not** an access control and is trivially cleared — the ACL above is what
> actually protects the file.
>
> Writes are atomic: the database is written to `users.dat.tmp`, flushed, then swapped into
> place, leaving the previous copy as `users.dat.bak`. **`users.dat.bak` contains exactly the
> same secrets as the live database.** It lives in the same directory and is covered by the
> ACL above — keep it there. If you copy it elsewhere as a backup, protect the destination
> the same way, and note that on Windows it is DPAPI-encrypted to *that machine*, so it is
> only restorable on the same host with the same `DpapiEntropy`.

### 4. Install MFAService as a Windows Service

MFAService runs as **LocalSystem** — do not give it the gMSA. It needs local administrative
rights to run `New-NetFirewallRule`/`Remove-NetFirewallRule`, and the named-pipe ACL depends
on the server (SYSTEM) and the client (the gMSA) being *different* identities. `New-Service`
defaults to LocalSystem, so simply omit `-Credential`:

```powershell
New-Service `
    -Name "MFAFirewallService" `
    -BinaryPathName "C:\Services\MFAService\MFAService.exe" `
    -DisplayName "MFA Firewall Service" `
    -StartupType Automatic
```

> If firewall rules fail to open, **do not** "fix" it by adding the gMSA to local
> Administrators — that collapses the privilege boundary this design exists to create.
> Check that MFAService is running as LocalSystem instead.

### 5. Install MFAWeb as a Windows Service

```powershell
New-Service `
    -Name "MFAWebService" `
    -BinaryPathName "C:\Services\MFAWeb\MFAWeb.exe" `
    -DisplayName "MFA Web Service" `
    -StartupType Automatic `
    -Credential "YOURDOMAIN\MFA_Service$"
```

### 6. Configure TLS

Import your TLS certificate into the **Local Machine → Personal** store:

```powershell
Import-PfxCertificate `
    -FilePath "C:\certs\your-cert.pfx" `
    -CertStoreLocation Cert:\LocalMachine\My `
    -Password (Read-Host -AsSecureString "PFX password")
```

Grant the gMSA read access to the private key:

```powershell
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*your.domain.com*" }
$acl  = Get-Acl "Cert:\LocalMachine\My\$($cert.Thumbprint)"
$rule = New-Object Security.AccessControl.FileSystemAccessRule("YOURDOMAIN\MFA_Service$", "Read", "Allow")
$acl.AddAccessRule($rule)
Set-Acl -Path "Cert:\LocalMachine\My\$($cert.Thumbprint)" -AclObject $acl
```

Set `HttpsCert:Subject` in MFAWeb's `appsettings.json` to the certificate's hostname, and
set the **same** `HttpsCert:Subject`/`Store`/`Location` values in MFAService's
`appsettings.json` so its expiry watchdog monitors the certificate that is actually served.

> **Do not add a `Kestrel:Endpoints:Https:Certificate` block.** MFAWeb deliberately selects
> the certificate in code at request time (matching on CN *and* SAN, preferring the newest
> valid one) so that a renewal is picked up without a restart and an expired certificate
> degrades to a warning banner. Kestrel's built-in `Certificate:Subject` binding does a
> CN-only lookup at startup and **crashes the service the moment that certificate expires**
> or is replaced by a SAN-only one. The `Https` endpoint should declare only its `Url`.

Alternatively, use [Let's Encrypt](#option-b-lets-encrypt--lettuce-encrypt) to skip
manual certificate management.

### 7. Open the Firewall Port

Allow inbound traffic on MFAWeb's port (default 8443):

```powershell
New-NetFirewallRule `
    -DisplayName "MFA Web (HTTPS)" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8443 `
    -Action Allow
```

### 8. Start the Services

```powershell
Start-Service MFAFirewallService
Start-Service MFAWebService
```

Check the logs at `C:\ProgramData\MFAAuth\Logs\` to verify startup.

> If a service fails to start and writes **no** log file, the failure happened during
> configuration validation, before file logging was available. Look in the Windows
> **Application** event log instead — a missing, too-short, or still-placeholder
> `DpapiEntropy` is reported there:
>
> ```powershell
> Get-EventLog -LogName Application -Newest 20 -EntryType Error |
>     Where-Object { $_.Message -match 'MFA' } | Format-List TimeGenerated, Message
> ```

---

## Linux Installation

### 1. Create Service Accounts

```bash
# MFAService runs as root (required for firewall management)
# MFAWeb runs as a dedicated low-privilege user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mfaweb

# Create the data directory
sudo mkdir -p /etc/mfa-auth
sudo chown root:mfaweb /etc/mfa-auth
sudo chmod 750 /etc/mfa-auth
```

### 2. Publish the Applications

```bash
dotnet publish MFAService/MFAService.csproj -c Release -r linux-x64 --self-contained
dotnet publish MFAWeb/MFAWeb.csproj     -c Release -r linux-x64 --self-contained
dotnet publish MFAAdmin/MFAAdmin.csproj -c Release -r linux-x64 --self-contained
```

Copy the outputs to:
- `/opt/mfa-service/`
- `/opt/mfa-web/`
- `/usr/local/bin/mfaadmin` (single binary)

### 3. Configure appsettings.json

In each installation directory, copy `appsettings.example.json` to `appsettings.json`.
Generate a strong entropy string:

```bash
openssl rand -base64 32
```

Set the same value for `DpapiEntropy` in all three config files. On Linux, DPAPI is not
used — the user database is stored as plain JSON — but the value is still required by
the application to start.

Remove the `Kestrel:Certificate` block if using Let's Encrypt (see [TLS Options](#tls-options)).

### 4. Set File Permissions

```bash
# Config files should not be world-readable
sudo chmod 640 /opt/mfa-service/appsettings.json
sudo chmod 640 /opt/mfa-web/appsettings.json

# User database (created on first MFAAdmin add — set group ownership now)
# MFAService will enforce mode 640 at runtime, but chown must be done manually
sudo touch /etc/mfa-auth/users.json
sudo chown root:mfaweb /etc/mfa-auth/users.json
sudo chmod 640 /etc/mfa-auth/users.json
```

### 5. Create systemd Service Units

**MFAService** (`/etc/systemd/system/mfa-service.service`):

```ini
[Unit]
Description=MFA Firewall Service
After=network.target

[Service]
Type=notify
ExecStart=/opt/mfa-service/MFAService
WorkingDirectory=/opt/mfa-service
Restart=on-failure
RestartSec=5

# Root is required for firewall rule management
User=root

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mfa-service

[Install]
WantedBy=multi-user.target
```

**MFAWeb** (`/etc/systemd/system/mfa-web.service`):

```ini
[Unit]
Description=MFA Web Service
After=network.target mfa-service.service
Requires=mfa-service.service

[Service]
Type=notify
ExecStart=/opt/mfa-web/MFAWeb
WorkingDirectory=/opt/mfa-web
Restart=on-failure
RestartSec=5
User=mfaweb
Group=mfaweb

# Allow binding to ports below 1024 if using port 443
AmbientCapabilities=CAP_NET_BIND_SERVICE

StandardOutput=journal
StandardError=journal
SyslogIdentifier=mfa-web

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable mfa-service mfa-web
sudo systemctl start mfa-service
sudo systemctl start mfa-web
```

Check startup logs:

```bash
sudo journalctl -u mfa-service -u mfa-web -f
```

### 6. Socket Permissions

MFAService creates the Unix domain socket at `/run/mfafirewall.sock` with mode `0660`,
owned by root, group root by default. Add the `mfaweb` user to the socket's group so
MFAWeb can connect:

The simplest approach is to set the socket group at runtime. In the MFAService source,
the socket is set to mode `0660`. To allow `mfaweb` to connect, either:

- Run MFAService with a supplemental group that `mfaweb` also belongs to, **or**
- Add the `mfaweb` user to the `root` group *(not recommended)*, **or**
- Create a shared group: `sudo groupadd mfaipc`, add both root and mfaweb:
  ```bash
  sudo usermod -aG mfaipc mfaweb
  ```
  Then configure MFAService's service unit to run with that group:
  ```ini
  Group=mfaipc
  SupplementaryGroups=mfaipc
  ```

### 7. Linux Firewall Commands

MFAService contains separate code paths for Windows (PowerShell / `NetSecurity`) and
Linux (`iptables`). The Linux path is active automatically when running on Linux — no
source changes are required for a standard `iptables` setup.

Rules are tracked using an `iptables` comment that embeds the rule name and expiry
timestamp (e.g. `MFA_Temp_1.2.3.4_22 exp:1746000000`). The sweeper reads
`iptables -S INPUT`, finds rules whose expiry has passed, and deletes them.

**If your distro uses a different firewall backend**, replace the `iptables` calls in
the two clearly-commented sections of `MFAService/Program.cs`:

- `OpenFirewallPort` — the `else` branch after the Windows block
- `SweepExpiredRules` — the `else` branch after the Windows block

Example equivalents for common backends:

```bash
# nftables
nft add rule ip filter INPUT ip saddr 1.2.3.4 tcp dport 22 accept comment "MFA_Temp_1.2.3.4_22 exp:1746000000"
nft delete rule ip filter INPUT handle <handle>

# ufw
ufw allow from 1.2.3.4 to any port 22 proto tcp comment "MFA_Temp_1.2.3.4_22 exp:1746000000"
ufw delete allow from 1.2.3.4 to any port 22 proto tcp

# List active MFA rules (iptables)
iptables -S INPUT | grep MFA_Temp
```

---

## TLS Options

MFAWeb serves **HTTPS only** and never binds a cleartext listener. Certificates are obtained by
a dedicated ACME client, not by MFAWeb itself — the internet-facing service is deliberately not
also an ACME client.

### Windows — certificate from the Windows store

Install into `LocalMachine\My` (win-acme, Certify, or an internal CA) and set
`HttpsCert:{Subject,Store,Location}`. Do **not** add a `Kestrel:...:Certificate` block.

MFAWeb selects the certificate at runtime: it matches the hostname against CN **and** SAN, keeps
only currently-valid certificates with a private key, picks the newest expiry, and re-checks once
a minute. A renewal is picked up **without a restart**, and an expired certificate degrades to a
post-login warning banner rather than crashing Kestrel at startup.

> **The service account needs read access to the private key.** Otherwise the certificate selects
> correctly and the TLS handshake still fails — SChannel cannot open the key and the client sees
> an EOF. Re-apply on every renewal; win-acme does this with `--acl-read "DOMAIN\MFA_Service$"`.

### Linux — PEM files from certbot

The Windows certificate store does not exist on Linux, so `HttpsCert` is ignored there and the
certificate comes from Kestrel configuration.

```bash
sudo apt-get install -y certbot

# MFAWeb does not listen on :80, so certbot --standalone can use it for the HTTP-01 challenge.
# Port 80 must be open in the firewall and reachable from the internet.
sudo certbot certonly --standalone --non-interactive --agree-tos     -m admin@your-domain.com -d your.domain.com
```

Point Kestrel at the result in MFAWeb's `appsettings.json`:

```json
"Kestrel": {
  "Endpoints": {
    "Https": {
      "Url": "https://*:8443",
      "Certificate": {
        "Path":    "/etc/letsencrypt/live/your.domain.com/fullchain.pem",
        "KeyPath": "/etc/letsencrypt/live/your.domain.com/privkey.pem"
      }
    }
  }
}
```

MFAWeb runs unprivileged, so it needs read access to the key. Grant it via the shared group:

```bash
sudo chgrp -R mfaipc /etc/letsencrypt/live /etc/letsencrypt/archive
sudo chmod -R g+rX  /etc/letsencrypt/live /etc/letsencrypt/archive
sudo -u mfaweb test -r /etc/letsencrypt/live/your.domain.com/privkey.pem && echo OK
```

MFAWeb re-reads the PEM once a minute and swaps it in when the thumbprint changes, so a renewal
takes effect **without a restart and without downtime** — verified against a real forced renewal:
the served certificate changed while the process ID stayed the same.

**Do not add a `--pre-hook` that stops MFAWeb.** MFAWeb never binds port 80, so certbot
`--standalone` does not conflict with it; stopping the service would be pure downtime, and
certbot persists such hooks into `/etc/letsencrypt/renewal/<domain>.conf` where they silently
run on every future renewal.

The deploy hook below is still worth installing — it re-applies the group grant after certbot
rewrites the files:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/10-restart-mfaweb.sh >/dev/null <<'HOOK'
#!/bin/sh
chgrp -R mfaipc /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
chmod -R g+rX  /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
systemctl restart mfaweb.service
HOOK
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/10-restart-mfaweb.sh
```

Verify from outside the network — `ssl_verify_result` must be `0`:

```bash
curl -s -o /dev/null -w "%{http_code} verify=%{ssl_verify_result}
" https://your.domain.com:8443/
```

> **Port 80 and cleartext.** MFAWeb never serves anything on port 80. Keep 80 open in the
> firewall only so certbot can bind it briefly during renewal; nothing else listens there.

---

## User Provisioning (MFAAdmin)

MFAAdmin must run with elevated privileges (Administrator on Windows, root on Linux).

```
MFAAdmin add <email>           Add a new user and send a provisioning email
MFAAdmin list                  List all users and their credential status
MFAAdmin delete <email>        Permanently remove a user
MFAAdmin reprovision <email>   Resend provisioning links (new password + tokens)
MFAAdmin diag                  Show active firewall rules and user database info
MFAAdmin reset                 Remove all MFA-managed firewall rules
MFAAdmin export <file.json>    Export user database to a JSON file (unencrypted)
MFAAdmin import <file.json>    Import users from a previously exported file
MFAAdmin purge-totp            Clear stored TOTP secrets (see Passkey-Only Mode below)
```

### Passkey-Only Mode

TOTP is a **build-time** decision, not a setting. The default build has no TOTP login or
enrollment route at all, `add` and `reprovision` mint no TOTP secret, and the provisioning
email contains only the passkey link. To include TOTP, build every component with
`-p:AllowTotp=true`.

If you move an existing deployment to a passkey-only build, rebuilding stops new secrets being
minted but does **not** remove secrets already in `users.dat`. Run:

```
MFAAdmin purge-totp
```

This clears the stored secret for every account that has a passkey enrolled. It deliberately
**skips accounts with no passkey** — clearing those would leave the user unable to authenticate
at all — and prints the list so you can have them enroll a passkey, or `reprovision` them, and
then re-run it.

### New User Workflow

1. Run `MFAAdmin add user@your-domain.com`
2. The user receives an email with a **Passkey setup** link. In a build made with
   `-p:AllowTotp=true`, it also contains an **Authenticator app setup** link for TOTP.

> **Passkey registration requires a built-in authenticator with biometric or PIN unlock.**
> The WebAuthn options specify `AuthenticatorAttachment = Platform` and
> `UserVerification = Required`, so Windows Hello, Touch ID / Face ID, and Android biometric
> work, while **roaming security keys such as YubiKeys are rejected**. The credential is
> non-discoverable (`RequireResidentKey = false`), so users type their email address before
> authenticating.
>
> Apple passkeys sync via iCloud Keychain and Google's via Google Password Manager, so the
> credential follows the user across devices in the same ecosystem; Windows Hello passkeys
> have historically been device-bound. Plan recovery around the pessimistic case —
> `MFAAdmin reprovision <email>`.
>
> **A machine with no platform authenticator cannot register a passkey at all**, and in the
> default (passkey-only) build that user has no way in. Rebuild all three components with
> `-p:AllowTotp=true` to allow TOTP. To allow security keys instead, change
> `AuthenticatorAttachment` to `CrossPlatform` (or remove it to permit both) in
> `MFAWeb/Program.cs`, keeping `UserVerification = Required`.
3. Links expire after **60 minutes**. Use `MFAAdmin reprovision` to resend.
4. The user visits MFAWeb and authenticates with their passkey or TOTP code to open
   the firewall for their current IP.

---

## Security Notes

- **`DpapiEntropy`** is a deployment-specific value mixed into the DPAPI key derivation
  on Windows. It prevents other processes on the same machine from reading the database
  without knowing this value. Keep it consistent across all three components and don't
  use the default or a publicly known value. On Linux it is unused for encryption (the
  database is plain JSON) but is still validated at startup — a missing value will
  prevent the service from starting.
- The user database contains **TOTP secrets** (not hashed). A compromised database file
  allows an attacker to generate valid TOTP codes. Protect the file with filesystem
  permissions as documented above. Passkey credentials stored in the database are
  public keys and are not sensitive.
- MFAWeb **only accepts authentication requests from public (internet) IP addresses**.
  Requests from RFC-1918 private ranges are rejected with HTTP 403. This prevents
  internal-only deployments from accidentally being used as a pivot point.
- Firewall rules opened by MFAService expire automatically after `ExpirationHours`.
  MFAService's sweeper runs every 5 minutes to remove expired rules.
