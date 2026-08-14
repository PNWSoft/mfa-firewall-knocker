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
  "UseLettuceEncrypt": false,
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
| `LogoUrl` | Optional URL of a logo image shown on the login page. Leave empty for no logo. If set to an external URL, that origin is added to the `img-src` CSP directive automatically. |
| `DpapiEntropy` | **Required.** A deployment-specific value mixed into the DPAPI key derivation on Windows. It prevents other processes on the same machine from reading the database without knowing this value — keep it consistent across all three components and don't use the default. On Linux it is unused for encryption (the database is plain JSON) but is still validated at startup. Generate with: `[Convert]::ToBase64String((1..32 \| % { Get-Random -Max 256 }))` |
| `RateLimitPerWindow` | Maximum requests per IP per 5-minute window across all endpoints. Default: 20. |
| `AllowedDomains` | Email address domains permitted to use the system. Enforced in both MFAWeb (login form rejects other domains) and MFAAdmin (`add` refuses to provision an account outside these domains). |
| `UseLettuceEncrypt` | Set to `true` to obtain a TLS certificate automatically from Let's Encrypt. See [TLS Options](#tls-options). |
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

### 3. Configure appsettings.json

In each installation directory, copy `appsettings.example.json` to `appsettings.json`
and fill in the values. The `DpapiEntropy` value must be identical in all three files.

Generate a strong entropy string:

```powershell
[Convert]::ToBase64String((1..32 | % { Get-Random -Maximum 256 }))
```

### 4. Install MFAService as a Windows Service

```powershell
New-Service `
    -Name "MFAFirewallService" `
    -BinaryPathName "C:\Services\MFAService\MFAService.exe" `
    -DisplayName "MFA Firewall Service" `
    -StartupType Automatic `
    -Credential "YOURDOMAIN\MFA_Service$"

# Grant the gMSA the "Log on as a service" right
# (easiest via Local Security Policy → User Rights Assignment)
```

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

Set the `Kestrel:Endpoints:Https:Certificate:Subject` in MFAWeb's `appsettings.json` to
match the certificate's Subject name.

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

### Option A: Manual Certificate (Windows cert store or PEM file)

**Windows:** Import to `LocalMachine\My` and set `Kestrel:Endpoints:Https:Certificate:Subject`
in `appsettings.json` (see Step 6 of Windows installation above).

**Linux:** Provide a PEM certificate and key, then configure Kestrel in `appsettings.json`:

```json
"Kestrel": {
  "Endpoints": {
    "Https": {
      "Url": "https://*:8443",
      "Certificate": {
        "Path": "/etc/ssl/certs/your-cert.pem",
        "KeyPath": "/etc/ssl/private/your-cert.key"
      }
    }
  }
}
```

### Option B: Let's Encrypt (LettuceEncrypt)

Automatic certificate provisioning using the ACME HTTP-01 challenge. Requires:
- Port **80** reachable from the internet (for the ACME challenge)
- Port **443** for HTTPS (Let's Encrypt will not issue certs for non-standard ports)

Set `AppUrl` to `https://your.domain.com` (port 443) and update `appsettings.json`:

```json
"Kestrel": {
  "Endpoints": {
    "Https": { "Url": "https://*:443" }
  }
},
"UseLettuceEncrypt": true,
"LettuceEncrypt": {
  "AcceptTermsOfService": true,
  "DomainNames": [ "your.domain.com" ],
  "EmailAddress": "admin@your-domain.com",
  "UseStagingServer": true,
  "CertificateDirectory": "C:\\ProgramData\\MFAAuth\\Certs"
}
```

> Set `UseStagingServer: true` on first deployment to verify everything works without
> consuming Let's Encrypt production rate limits. Switch to `false` once confirmed.

Certificates are stored in `CertificateDirectory` and renewed automatically.

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
```

### New User Workflow

1. Run `MFAAdmin add user@your-domain.com`
2. The user receives an email with two links:
   - **Passkey setup** (recommended) — registers a FIDO2 passkey on their device
   - **Authenticator app setup** — scans a QR code for TOTP
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
