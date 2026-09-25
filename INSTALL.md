# MFA Firewall Knocker — Installation Guide

## Overview

Three components work together:

| Component | Role | Runs as |
|-----------|------|---------|
| **MFAWeb** | Internet-facing web app. Authenticates users via WebAuthn (passkey), or TOTP in a build made with `-p:AllowTotp=true`, then asks MFAService to open the firewall. | gMSA (Windows) / dedicated user (Linux) |
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
- An SMTP relay that supports authenticated STARTTLS, or one running on the server itself
- A TLS certificate for MFAWeb (see [TLS Options](#tls-options))

### Linux
- Ubuntu 22.04 LTS / Debian 12 / RHEL 9 (or equivalent)
- .NET 10 Runtime (or Self-Contained publish)
- `systemd`
- An SMTP relay that supports authenticated STARTTLS, or one running on the server itself
- A TLS certificate, obtained with an external ACME client such as certbot (see [TLS Options](#tls-options))

> **Linux firewall backend note:** MFAService has separate Windows (PowerShell /
> `NetSecurity`) and Linux (`iptables`/`ip6tables`) code paths built in. The default Linux
> implementation uses `iptables` for IPv4 grants and `ip6tables` for IPv6 ones. If your distro
> uses `nftables`, `ufw`, or `firewalld` instead, update the clearly-marked sections in
> `OpenFirewallPort` and `SweepExpiredRules` in `MFAService/Program.cs`, and MFAAdmin's `diag`/
> `reset` — for both address families. See [Linux Firewall Commands](#7-linux-firewall-commands).

> **SDK version note:** `global.json` pins the exact .NET SDK version used to build this
> repo. That's for reproducible builds/testing, not a security requirement — feel free to
> change it to whatever SDK you have installed, and you'll need to once 10.0.400 is no
> longer available (e.g. after it's superseded or deprecated upstream).

---

## Configuration Reference

All three components read from their own `appsettings.json`. Copy the
`appsettings.example.json` in each component's directory and fill in the values.

### MFAWeb — `appsettings.json`

```json
{
  "AppUrl":            "https://your.domain.com:8443",
  "AdditionalOrigins": [],
  "SiteName":          "My Organization Secure Access",
  "LogoUrl":           "",
  "DpapiEntropy":      "REPLACE-WITH-A-UNIQUE-RANDOM-STRING",
  "RateLimitPerWindow": 20,
  "AllowedDomains":    [ "your-domain.com" ],
  "FirewallService": {
    "GmsaAccount": "YOURDOMAIN\\MFA_Service$"
  },
  "Smtp": {
    "Host": "your-smtp-server",  "Port": 587,  "UseSsl": true,
    "FromAddress": "security@your-domain.com",
    "NotifyAddress": "admins@your-domain.com"
  },
  "AccountAlert": {
    "Threshold": 10,  "WindowMinutes": 15,
    "SendEmail": false,  "MaxEmailsPerWindow": 10
  }
}
```

| Key | Description |
|-----|-------------|
| `AppUrl` | Full public URL of MFAWeb. Must match the TLS certificate's domain. Used for WebAuthn origin validation — any mismatch will break passkey login. |
| `AdditionalOrigins` | Optional list of other names for this same server where passkey sign-in should work, as exact origins such as `"https://v6.your.domain.com:8443"`. The usual reason is an IPv6-only name (AAAA record only), so phones on cellular can't choose IPv4 and land behind carrier NAT; see the README's IPv6 notes. Each entry must be `https`, must be `AppUrl`'s host or a name under it, must use `AppUrl`'s port, and must have no path; MFAWeb refuses to start otherwise, and logs the accepted list at startup. The **one** certificate MFAWeb serves must cover every name listed (it selects a single certificate for all names, so a separate certificate for the extra name is never used), and MFAService's expiry alert checks only the main name. Every name listed is trusted exactly as `AppUrl` is: if you remove a name's DNS record, remove it here too. Default: empty. |
| `SiteName` | Displayed in page titles, the TOTP issuer name, and provisioning emails. |
| `LogoUrl` | Optional URL of a logo image shown on the login page. Leave empty to use the bundled knocker logo (`wwwroot/knocker.png`). If set to an external URL, that origin is added to the `img-src` CSP directive automatically. |
| `DpapiEntropy` | **Required.** A deployment-specific value mixed into the DPAPI key derivation on Windows. It prevents other processes on the same machine from reading the database without knowing this value — keep it consistent across all three components. Startup fails if it is missing, under 16 characters, or still the placeholder from `appsettings.example.json` (that placeholder is published in the public repository and protects nothing). On Linux it is unused for encryption (the database is plain JSON) but is still validated at startup. See [step 3](#3-configure-appsettingsjson-and-restrict-permissions) for how to generate one. |
| `RateLimitPerWindow` | Maximum requests per 5-minute window to the login and registration routes, per partition. An IPv4 address is its own partition; an IPv6 address is bucketed by its /56 network prefix, since a single customer allocation commonly spans a /56 or /64 and partitioning on the full address would let anyone inside their own allocation get an effectively fresh bucket per request. Default: 20. |
| `GlobalRateLimitPerWindow` | A single aggregate cap on those routes shared across every partition combined, as a backstop independent of the per-partition key. Default: 200. Only the app's own routes count toward it. Everything else (static files such as the login script, logo and favicon, unknown paths, and requests with the wrong HTTP method) has a fixed per-partition limit of its own instead (120 per 5 minutes), so one source cannot exhaust the shared budget that way and lock everyone out. |
| `AllowedDomains` | Email address domains permitted to use the system. Enforced in both MFAWeb (login form rejects other domains) and MFAAdmin (`add` refuses to provision an account outside these domains). |
| `FirewallService:GmsaAccount` | Required IPC client identity. On Windows, the gMSA account that MFAWeb runs as. On Linux, set this to the local account `mfaweb` in MFAService's config. The service rejects clients whose identity does not match. |
| `AccountAlert:Threshold` | Failed login attempts for one account, within `WindowMinutes`, before a `[SECURITY]` log line fires (and an email, if `SendEmail` is on). Detection only — the account is never locked. Default: 10. |
| `AccountAlert:WindowMinutes` | The window `Threshold` and `MaxEmailsPerWindow` are measured over. Default: 15. |
| `AccountAlert:SendEmail` | Off by default. When on, requires `Smtp:{Host,FromAddress,NotifyAddress}` to be fully configured or nothing is sent (logged as a warning instead). |
| `AccountAlert:MaxEmailsPerWindow` | A cap on alert **emails** sent across every account combined in one window, independent of the per-account threshold. `/passkey/challenge` discloses a target's credential ID by design (non-resident WebAuthn credentials require it), so driving many different accounts past `Threshold` needs no secret — only a list of email addresses. The per-account log line above is never suppressed by this cap; only the email attempt is. Default: 10. |

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
| `BouncerConfig:ExpirationHours` | How long firewall rules stay open. Rules are automatically removed by the sweeper when they expire. **Clamped to 1-48 on the privileged side**, so a larger value is reduced to 48 and logged with a `[CONFIG]` warning — a slipped digit cannot leave a standing grant. Every `AllowedPorts` entry must use a port in 1-65535 and protocol TCP or UDP; an invalid entry fails the grant request instead of returning a partial success. |
| `BouncerConfig:RulePrefix` | Prefix applied to every firewall rule name. Must also match the value in MFAAdmin's config so the `diag` and `reset` commands can find the rules. Letters, digits, space, `_`, `.` and `-` only, 1-64 characters; MFAService refuses to start with anything else, since a quote in the prefix breaks the firewall commands and, on Linux, leaves grants the sweeper can never remove. |
| `BouncerConfig:Ipv6GrantPrefixLength` | How much of an IPv6 client's address a grant covers: `128` (the default) is the exact address, and anything down to `64` widens the grant to that address's network, so a client whose address changes within its `/64` (privacy addresses, cellular carriers) keeps access. Values outside 64-128 are clamped, with a `[CONFIG]` warning. IPv4 grants are never widened. Applies on both platforms: Windows has always handled IPv6 grants, as the exact address only, until 0.4.0; on Linux IPv6 grants are new in 0.4.0. |
| `HttpsCert:PemPath` | **Linux only, and required for expiry alerts there.** Full path to the certificate MFAWeb serves (e.g. `/etc/mfa-auth/tls/current/fullchain.pem`). There is no certificate store on Linux, so without this the expiry watchdog logs `[CERT] Monitor disabled` at startup and never alerts — and an expired certificate means no passkey sign-in at all. |

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
    "Host": "your-smtp-server",  "Port": 587,  "UseSsl": true,
    "FromAddress": "security@your-domain.com",
    "NotifyAddress": "admins@your-domain.com"
  }
}
```

| Key | Description |
|-----|-------------|
| `BouncerUrl` | Base URL of MFAWeb. Used to generate the provisioning links sent in welcome emails. |
| `RulePrefix` | Must match `BouncerConfig:RulePrefix` in MFAService. Used by `diag` and `reset` commands. |

`Smtp:UseSsl` defaults to `true` and requires a validated STARTTLS connection. Set it to
`false` only when the SMTP relay runs on the same machine: `Smtp:Host` must be `localhost`, a
loopback address, or an IP address assigned to one of this machine's interfaces (for example
the address a local relay listens on). Hostnames other than `localhost` are never resolved for
this check, so use the IP address itself. The address must be on an interface that is up at
the time of each send, and should be statically assigned. Plaintext delivery to any other host
is refused. Provisioning messages contain the temporary password and enrollment link, so the
SMTP hop is part of the enrollment security boundary. On Linux, checking a non-loopback local
address needs `AF_NETLINK` in the service unit's `RestrictAddressFamilies` (see the units
below).

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
and call `ProtectedData.Unprotect` to recover the **plaintext TOTP secrets** and the current
password hash of every user — which, for any account that has confirmed TOTP, is that account's
actual ongoing login credential, not a one-time value.

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

# MFAWeb writes (and after 90 days deletes) its own log files, and nothing else in Logs.
# The gMSA may list the folder and create files in it; CREATOR OWNER then gives whichever
# account created a file Modify on that file only. So MFAWeb can manage its own logs but
# cannot alter or delete MFAService's.
icacls "C:\ProgramData\MFAAuth\Logs" `
    /grant 'YOURDOMAIN\MFA_Service$:(RX,WD)' `
    /grant 'CREATOR OWNER:(OI)(IO)M'

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
> valid one) so that a renewal is picked up without a restart and an expired certificate does
> not stop the service from starting. Kestrel's built-in `Certificate:Subject` binding does a
> CN-only lookup at startup and **crashes the service the moment that certificate expires**
> or is replaced by a SAN-only one. The `Https` endpoint should declare only its `Url`.

See [TLS Options](#tls-options) for obtaining the certificate with an external ACME client.

### 7. Open the Firewall Port

Allow inbound traffic on MFAWeb's port (default 8443). Scope the rule to the **specific
executable** as well as the port, so the opening belongs to MFAWeb rather than to whatever process
happens to bind 8443:

```powershell
New-NetFirewallRule `
    -DisplayName "MFA Web (HTTPS)" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8443 `
    -Program "C:\Services\MFAWeb\MFAWeb.exe" `
    -Action Allow
```

Points worth getting right:

- **Name the process that actually listens.** The self-contained publish produces an apphost, so
  `MFAWeb.exe` binds the port and is the correct target. If you run framework-dependent instead
  (`dotnet MFAWeb.dll`), the listener is `dotnet.exe` — and naming *that* would widen the rule to
  every .NET application on the host, which is worse than no program filter at all. Another reason
  to prefer the self-contained build here.
- **The path is matched literally.** Relocate or rename the install directory and the rule stops
  matching silently — MFAWeb simply becomes unreachable. Update it rather than recreating:

  ```powershell
  Get-NetFirewallRule -DisplayName "MFA Web (HTTPS)" |
      Set-NetFirewallApplicationFilter -Program "D:\Services\MFAWeb\MFAWeb.exe"
  ```

- **Verify the filter took effect**, then confirm reachability from another machine *before* you
  depend on it. A mistyped path fails closed, and a gate nobody can reach is a gate nobody can
  open:

  ```powershell
  Get-NetFirewallRule -DisplayName "MFA Web (HTTPS)" | Get-NetFirewallApplicationFilter
  ```

> **Optionally tighter still:** adding `-Service MFAWebService` restricts the rule to that service's
> SID, so another process running as the same account still cannot use the opening. This only works
> if the service has a service SID — check with `sc.exe qsidtype MFAWebService` and expect
> `UNRESTRICTED`. If it reports `NONE` the filter will never match and MFAWeb will be unreachable,
> so verify with the command above before relying on it.

### 8. Start the Services

```powershell
Start-Service MFAFirewallService
Start-Service MFAWebService
```

Check the logs at `C:\ProgramData\MFAAuth\Logs\` to verify startup. Each component writes one
file per UTC day and deletes its own files older than 90 days; archive them elsewhere first if
you need a longer history. Failures that anyone can trigger without signing in (addresses with no
passkey, invalid setup or registration links, failed passkey checks) are logged as `[PROBE]`
lines, up to 5 per source and 50 in total per hour, with one summary line counting the rest.

> If a service fails to start and its log file shows only the startup line, or nothing, the
> failure happened during configuration validation, which is reported outside the log file.
> Look in the Windows **Application** event log — a missing, too-short, or still-placeholder
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
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin mfaweb
sudo groupadd --system mfaipc
sudo usermod -aG mfaipc mfaweb

# Setgid keeps the mfaweb reader group on new database files written by either
# the root admin CLI or the service. The web account cannot write this directory.
sudo install -d -o root -g mfaweb -m 2750 /etc/mfa-auth

# Log directory shared by MFAService and MFAWeb. Group-writable so mfaweb can create
# its own files; setgid keeps them in mfaipc; the sticky bit means each account can
# delete only its own files, so MFAWeb cannot remove MFAService's logs.
sudo install -d -o root -g mfaipc -m 3770 /var/log/mfa-auth
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
- `/opt/mfa-admin/` (the complete MFAAdmin publish output, including its config)

Keep these installation directories and their executables owned by root, without group or
other write permission. Run the admin tool as `sudo /opt/mfa-admin/MFAAdmin ...`.

### 3. Configure appsettings.json

In each installation directory, copy `appsettings.example.json` to `appsettings.json`.
Generate a strong entropy string:

```bash
openssl rand -base64 32
```

Set the same value for `DpapiEntropy` in all three config files. On Linux, DPAPI is not
used — the user database is stored as plain JSON — but the value is still required by
the application to start.

In **MFAService's** config, replace the Windows account placeholder with the local web account:

```json
"FirewallService": { "GmsaAccount": "mfaweb" }
```

If this account is missing or cannot be resolved, MFAService rejects every IPC request and
logs/emails an error. It keeps running so existing firewall grants can still expire. Correct
the setting and restart `mfa-service` before retrying a login. Removing the setting does not
disable the identity check.

MFAWeb and MFAService both log to `/var/log/mfa-auth` on Linux by default (created in step 1),
so leave `LogPath` unset in both configs. If you set it, use that same directory: the MFAWeb unit
below grants write access to `/var/log/mfa-auth` only.

On Linux you **must** keep the `Kestrel:Endpoints:Https:Certificate` block and point `Path`
and `KeyPath` at your PEM files — there is no Windows certificate store, so it is the only
source of a certificate. See [TLS Options](#tls-options).

### 4. Set File Permissions

```bash
# Only the web config needs to be readable by mfaweb.
sudo chown root:root /opt/mfa-service/appsettings.json /opt/mfa-admin/appsettings.json
sudo chmod 600 /opt/mfa-service/appsettings.json /opt/mfa-admin/appsettings.json
sudo chown root:mfaweb /opt/mfa-web/appsettings.json
sudo chmod 640 /opt/mfa-web/appsettings.json

# Existing databases and backups need the same reader group. Do not create an empty
# JSON file: MFAAdmin creates the database on the first add.
for file in /etc/mfa-auth/users.json /etc/mfa-auth/users.json.bak; do
    if [ -f "$file" ]; then
        sudo chown root:mfaweb "$file"
        sudo chmod 640 "$file"
    fi
done

sudo -u mfaweb test -r /opt/mfa-web/appsettings.json
```

Both database writers create a temporary file and rename it into place. The directory's
**setgid bit (`2750`) is required**: chmod `640` alone does not preserve the reader group after
a root admin write. After provisioning and reprovisioning, verify `stat -c '%U:%G %a' /etc/mfa-auth/users.json`
reports `root:mfaweb 640`, and `sudo -u mfaweb test -r /etc/mfa-auth/users.json` succeeds.

### 5. Create systemd Service Units

**MFAService** (`/etc/systemd/system/mfa-service.service`):

```ini
[Unit]
Description=MFA Firewall Service
After=network.target
# Give up after five failures in five minutes and enter the failed state, where an operator
# can see it. Without a limit this unit can flap indefinitely if something else is holding
# /run/mfafirewall.sock -- a second copy started by hand, for instance. Type=notify reports
# READY before the IPC endpoint is claimed, so an attempt that then fails still counts as a
# successful start and resets systemd's rate limiting. Each cycle also sends an alert email,
# so an unbounded loop buries the mailbox and can get the relay to throttle the alerts that
# matter. These belong in [Unit]; systemd ignores them under [Service].
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=notify
ExecStart=/opt/mfa-service/MFAService
WorkingDirectory=/opt/mfa-service
Restart=on-failure
RestartSec=5

# Root is required for firewall rule management
User=root
Group=mfaipc
UMask=0027
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
# .NET's cross-process database mutex (shared with MFAAdmin, which runs unsandboxed) uses the
# shared /tmp namespace. Do not enable PrivateTmp, or MFAAdmin's view of the mutex diverges
# from this service's, defeating the serialization it exists for.
ReadWritePaths=/etc/mfa-auth /var/log/mfa-auth /run /tmp

# Sandboxing that doesn't depend on which capabilities this process happens to use, so it's
# safe regardless: this service never loads kernel modules, joins namespaces, execs a SUID
# binary, needs realtime scheduling, or changes its personality.
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictNamespaces=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true

# Deliberately NOT set: ProtectProc=invisible. Verified directly against a live host (Ubuntu
# 24.04, kernel 6.8, systemd 255) -- with every other directive above applied, adding this one
# alone makes systemd wait forever for the Type=notify readiness signal this app's AddSystemd()
# call sends, so the unit never leaves "activating" and cycles through StartLimitBurst until it
# gives up. This maps to procfs's hidepid=invisible (systemd 247+, kernel 5.8+), not an Ubuntu
# quirk -- Debian 12 and RHEL 9 both clear those thresholds too, so expect the same failure there.
# Everything else in this unit was verified working together with a real end-to-end login on the
# same host.

# Narrowed to what this process actually does: manage iptables/ip6tables (NET_ADMIN/NET_RAW, and
# NETLINK for the address family below -- the same capabilities cover both tables) and own files
# across users (DAC_OVERRIDE, CHOWN, FOWNER). CapabilityBoundingSet limits descendant processes
# too, including the iptables/ip6tables subprocess this service shells out to -- test a real login
# end to end (both an IPv4 and an IPv6 client, if you have one) after applying this,
# the same way INSTALL.md already asks for the gate itself (see "Verify the gate is actually
# gating"), since a too-narrow set fails firewall commands rather than refusing to start.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER
# AF_INET/AF_INET6 are for the SMTP connection that sends certificate-expiry and IPC alerts;
# without them this service cannot reach any relay, even a local one, and never alerts.
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6

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
Wants=mfa-service.service
# Deliberately Wants=, not Requires=: Requires= propagates STOP, so restarting
# MFAService would take MFAWeb down and leave it down.
# Give up after five failures in five minutes rather than restarting forever -- a bad
# certificate path or a port already in use will not fix itself, and the failed state is
# visible where a restart loop is not. These belong in [Unit], not [Service].
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=notify
ExecStart=/opt/mfa-web/MFAWeb
WorkingDirectory=/opt/mfa-web
Restart=on-failure
RestartSec=5
User=mfaweb
Group=mfaweb
SupplementaryGroups=mfaipc
UMask=0027
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
# MFAWeb logs to /var/log/mfa-auth, the directory shared with MFAService (see step 4) -- not a
# LogsDirectory= of its own. Verified directly: LogsDirectory=mfa-web here silently pointed
# write access at /var/log/mfa-web instead, and every log write failed under ProtectSystem=strict.
ReadWritePaths=/var/log/mfa-auth

# Same rationale as MFAService's unit: these don't depend on which capabilities this process
# happens to use, so they're safe regardless. This is the internet-facing half and the one
# SECURITY.md names as the residual risk if MFAWeb itself is ever compromised -- worth applying
# here at least as much as on the privileged side.
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictNamespaces=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true

# Deliberately NOT set: ProtectProc=invisible -- see MFAService's unit above. Verified the same
# failure here: this app's Type=notify readiness signal never reaches systemd with it set.

# Allow binding to ports below 1024 if using port 443. CapabilityBoundingSet narrows this to
# exactly that capability; RestrictAddressFamilies to the HTTPS listener and the Unix socket
# this process actually opens. Test a real login end to end after applying this, the same as
# for MFAService's unit above -- do not assume it's right just because the service starts.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
# Add AF_NETLINK only if Smtp:Host is a local non-loopback address with Smtp:UseSsl=false:
# checking that the address is this machine's needs to read the interface list.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

StandardOutput=journal
StandardError=journal
SyslogIdentifier=mfa-web

[Install]
WantedBy=multi-user.target
```

Complete the Linux [TLS setup](#linux--pem-files-from-certbot), including the initial
certificate copy, before starting MFAWeb. Then enable and start:

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
owned by root and the service's primary group. The account and unit steps above set
`Group=mfaipc` on MFAService and add `mfaweb` to that group. A supplemental group alone
does not change the group assigned to a newly created socket.

> **Keep the socket in a root-owned, non-world-writable directory.** This is a security
> invariant, not a convention. `/run` is root-owned, so an unprivileged user cannot create or
> replace `/run/mfafirewall.sock` and cannot impersonate the privileged service. Relocating the
> socket to somewhere world-writable such as `/tmp` would allow exactly that, and would silently
> undo the protection — the mode bits on the socket itself do not help if an attacker can put
> their own socket at the path first. Both sides also verify each other's credentials with
> `SO_PEERCRED` (MFAService requires the `mfaweb` uid; MFAWeb requires uid 0), but treat that as
> defence in depth rather than as permission to move the socket.

Verify the live socket after starting the service:

```bash
stat -c '%U:%G %a' /run/mfafirewall.sock   # root:mfaipc 660
id mfaweb                               # includes mfaipc, not root
```

Keep the `mfaipc` group limited to the web service account. Do not add it to the root group.

### 7. Linux Firewall Commands

MFAService contains separate code paths for Windows (PowerShell / `NetSecurity`) and
Linux (`iptables` for IPv4 grants, `ip6tables` for IPv6 ones). The Linux path is active
automatically when running on Linux — no source changes are required for a standard
`iptables`/`ip6tables` setup.

Rules are tracked using an `iptables`/`ip6tables` comment that embeds the rule name and
expiry timestamp (e.g. `MFA_Temp_1.2.3.4_22_TCP exp:1746000000`). Which table a grant's
rule lands in is decided by the client's own address family, not a config setting. The
sweeper reads `iptables -S INPUT` **and** `ip6tables -S INPUT` on every pass, finds rules
whose expiry has passed in either table, and deletes them. `MFAAdmin diag`/`reset` read
and clear both tables the same way.

**If your distro uses a different firewall backend**, replace the `iptables`/`ip6tables`
calls in the clearly-commented sections of `MFAService/Program.cs`:

- `OpenFirewallPort` — the `else` branch after the Windows block
- `SweepExpiredRules` — the `else` branch after the Windows block

and their mirrors in `MFAAdmin/Program.cs`'s `diag` and `reset` commands. Handle both
address families in your replacement, not just IPv4 — nftables and firewalld both support
mixed IPv4/IPv6 tables natively; ufw needs separate `ufw6`-style handling per its own docs.

Example equivalents for common backends:

```bash
# nftables (a single 'inet' table handles both families)
nft add rule inet filter INPUT ip saddr 1.2.3.4 tcp dport 22 accept comment "MFA_Temp_1.2.3.4_22_TCP exp:1746000000"
nft add rule inet filter INPUT ip6 saddr 2001:db8::1 tcp dport 22 accept comment "MFA_Temp_2001:db8::1_22_TCP exp:1746000000"
nft delete rule inet filter INPUT handle <handle>

# ufw
ufw allow from 1.2.3.4 to any port 22 proto tcp comment "MFA_Temp_1.2.3.4_22_TCP exp:1746000000"
ufw allow from 2001:db8::1 to any port 22 proto tcp comment "MFA_Temp_2001:db8::1_22_TCP exp:1746000000"
ufw delete allow from 1.2.3.4 to any port 22 proto tcp

# List active MFA rules (iptables / ip6tables)
iptables -S INPUT | grep MFA_Temp
ip6tables -S INPUT | grep MFA_Temp
```

---

## TLS Options

MFAWeb serves **HTTPS only** and never binds a cleartext listener. Certificates are obtained by
a dedicated ACME client, not by MFAWeb itself — the internet-facing service is deliberately not
also an ACME client.

> **Securing the TLS listener itself — protocol version, cipher suites — is the operator's
> responsibility, not something this project configures.** MFAWeb sets no minimum TLS version and
> no cipher suite policy; Kestrel uses whatever the OS (SChannel on Windows, OpenSSL on Linux)
> allows by default. On an unpatched or default-configured older host that can include weak or
> deprecated protocol versions. Harden this the same way you would for any other internet-facing
> web service on the host — OS-level TLS/cipher policy (registry settings on Windows, crypto
> policy on Linux), not an MFA Firewall Knocker setting, because there isn't one.

### Windows — certificate from the Windows store

Install into `LocalMachine\My` (win-acme, Certify, or an internal CA) and set
`HttpsCert:{Subject,Store,Location}`. Do **not** add a `Kestrel:...:Certificate` block.

MFAWeb selects the certificate at runtime: it matches the hostname against CN **and** SAN, keeps
only currently-valid certificates with a private key, picks the newest expiry, and re-checks once
a minute. A renewal is picked up **without a restart**, and an expired certificate no longer
crashes Kestrel at startup. A certificate within `CertAlert:WarnDays` of expiry is flagged on the
page shown after a passkey sign-in; once it has expired, browsers refuse the site, so the email
alert from MFAService is the warning that still arrives.

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
sudo certbot certonly --standalone --non-interactive --agree-tos \
    --cert-name your.domain.com -m admin@your-domain.com -d your.domain.com
```

Use a deploy hook to copy **only this certificate lineage** into a directory dedicated to
MFAWeb. Keep Certbot's own directories and every other site's private keys restricted to root.
Replace `your.domain.com` consistently in the command above and the hook below. If Certbot
already manages that hostname under another certificate name, use its exact existing lineage
path (shown by `sudo certbot certificates`).

```bash
sudo install -d -o root -g mfaweb -m 750 /etc/mfa-auth/tls
sudo tee /etc/letsencrypt/renewal-hooks/deploy/10-mfaweb-certificate.sh >/dev/null <<'HOOK'
#!/bin/sh
set -eu
umask 077

# Certbot invokes deploy hooks for every renewed certificate. Ignore all other lineages.
lineage=/etc/letsencrypt/live/your.domain.com
[ "${RENEWED_LINEAGE:-}" = "$lineage" ] || exit 0

# Prepare a new generation on the same filesystem. Until publication, current still
# selects the complete old pair, including if this hook fails or the service restarts.
tls_dir=/etc/mfa-auth/tls
generation=$(mktemp -d "$tls_dir/generation.XXXXXXXXXX")
pending_link="$tls_dir/.current.${generation##*/}"
trap 'rm -f -- "$pending_link"' 0
trap 'exit 1' 1 2 15
install -o root -g mfaweb -m 640 "$lineage/fullchain.pem" "$generation/fullchain.pem"
install -o root -g mfaweb -m 640 "$lineage/privkey.pem" "$generation/privkey.pem"

# Compare the public keys in canonical DER form. pkey supports both RSA and ECDSA;
# separate commands ensure a failed OpenSSL step cannot be hidden by a pipeline.
openssl x509 -in "$generation/fullchain.pem" -pubkey -noout > "$generation/certificate-public.pem"
openssl pkey -pubin -in "$generation/certificate-public.pem" -outform DER -out "$generation/certificate-public.der"
openssl pkey -in "$generation/privkey.pem" -passin pass: -pubout -outform DER -out "$generation/private-public.der"
openssl dgst -sha256 -binary -out "$generation/certificate-public.sha256" "$generation/certificate-public.der"
openssl dgst -sha256 -binary -out "$generation/private-public.sha256" "$generation/private-public.der"
if ! cmp -s "$generation/certificate-public.sha256" "$generation/private-public.sha256"; then
    echo 'MFAWeb certificate and private key do not match; current generation unchanged.' >&2
    exit 1
fi
rm -f -- "$generation/certificate-public.pem" "$generation/certificate-public.der" \
    "$generation/private-public.der" "$generation/certificate-public.sha256" "$generation/private-public.sha256"
chown root:mfaweb "$generation"
chmod 750 "$generation"

# Rename a sibling symlink atomically. Keep earlier generation directories for rollback.
previous=$(readlink "$tls_dir/current" 2>/dev/null || true)
ln -s "${generation##*/}" "$pending_link"
mv -Tf -- "$pending_link" "$tls_dir/current"
printf 'MFAWeb certificate generation: %s (previous: %s)\n' "${generation##*/}" "$previous"
HOOK
sudo chown root:root /etc/letsencrypt/renewal-hooks/deploy/10-mfaweb-certificate.sh
sudo chmod 700 /etc/letsencrypt/renewal-hooks/deploy/10-mfaweb-certificate.sh

# Install the existing certificate now; subsequent successful renewals call the hook.
sudo env RENEWED_LINEAGE=/etc/letsencrypt/live/your.domain.com \
    /etc/letsencrypt/renewal-hooks/deploy/10-mfaweb-certificate.sh
sudo -u mfaweb test -r /etc/mfa-auth/tls/current/privkey.pem && echo OK
```

Point Kestrel at these copies in MFAWeb's `appsettings.json`:

```json
"Kestrel": {
  "Endpoints": {
    "Https": {
      "Url": "https://*:8443",
      "Certificate": {
        "Path":    "/etc/mfa-auth/tls/current/fullchain.pem",
        "KeyPath": "/etc/mfa-auth/tls/current/privkey.pem"
      }
    }
  }
}
```

Set MFAService's `HttpsCert:PemPath` to `/etc/mfa-auth/tls/current/fullchain.pem` too, so expiry alerts
monitor the certificate actually served. Test that a renewal of an unrelated lineage leaves
these files unchanged and that `mfaweb` cannot read that other lineage's private key.

MFAWeb re-reads the PEM once a minute and swaps it in when the thumbprint changes, so a renewal
takes effect **without a restart and without downtime** — verified against a real forced renewal:
the served certificate changed while the process ID stayed the same. A failed copy, key check,
or symlink replacement leaves the previous complete pair on disk for both reload and restart.
A reload that straddles the symlink switch can still retry on the next poll; it retains the
last working certificate in memory. Investigate a failed deploy hook before the old certificate
expires.

The hook prints the new and previous generation names and retains the previous directories.
For rollback, select a known-good, still-valid generation from that record and atomically
switch `current` back (replace `generation.KNOWN_GOOD` before running):

```bash
(
set -eu
sudo test -s /etc/mfa-auth/tls/generation.KNOWN_GOOD/privkey.pem
sudo openssl x509 -in /etc/mfa-auth/tls/generation.KNOWN_GOOD/fullchain.pem -checkend 0 -noout
sudo ln -s generation.KNOWN_GOOD /etc/mfa-auth/tls/current.rollback
sudo mv -Tf -- /etc/mfa-auth/tls/current.rollback /etc/mfa-auth/tls/current
)
```

Never edit a published generation in place. Old and failed generations remain protected under
`/etc/mfa-auth/tls`; periodically remove only inspected generations that are neither current
nor needed for rollback. Do not automate removal during certificate publication.

**Do not add a `--pre-hook` that stops MFAWeb.** MFAWeb never binds port 80, so certbot
`--standalone` does not conflict with it; stopping the service would be pure downtime, and
certbot persists such hooks into `/etc/letsencrypt/renewal/<domain>.conf` where they silently
run on every future renewal.

The deploy hook performs no restart. The unit is named **`mfa-web.service`**; if an operator
needs to restart it for a configuration change, use `sudo systemctl restart mfa-web`.
If upgrading from the older guide, remove its exact legacy hook
`/etc/letsencrypt/renewal-hooks/deploy/10-restart-mfaweb.sh` after installing and testing this
replacement. Review the group access that the old recursive commands granted to other
certificate lineages and restore each lineage's intended permissions without disrupting its
other consumers.

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
4. The user visits MFAWeb and authenticates with their passkey (or TOTP code, in an
   `AllowTotp` build) to open the firewall for their current IP.

---

## Verify the gate is actually gating

**Do this after installing, and again after any firewall change.** It is the one check that
distinguishes a working deployment from a decorative one, and nothing else will tell you.

This tool only adds *allow* rules. It never removes anything. If the protected port is already
reachable for another reason, every grant it opens is redundant and the gate protects nothing —
while the logs, the web UI and the firewall rules all continue to look exactly as they would if it
were working. There is no symptom.

The usual causes are ordinary and easy to miss:

- a **standing allow rule** for the protected port, left from before the gate was installed
- a **blanket accept on the internet-facing interface** (`-A INPUT -i eth0 -j ACCEPT`) — check
  which interface actually carries the default route rather than assuming, since the public NIC is
  not always the first one
- a permissive default policy (`-P INPUT ACCEPT`, or a `ufw`/`firewalld` zone set to allow)
- a **port-forward or upstream firewall** that reaches the service without traversing this host's
  INPUT chain

**The test — from an address that has *not* authenticated:**

```bash
# Should FAIL / time out while you hold no grant.
nc -vz -w 5 your-host.example.com 51820      # UDP: use `nc -vzu`
```

Then authenticate through MFAWeb from that address and repeat: it should now succeed, and fail
again once the grant expires. A port that is reachable *before* you authenticate means the gate is
not in the path. On a dual-stack Linux host, run the test from both an IPv4 and an IPv6 client —
they land in separate tables (`iptables` vs `ip6tables`) and a standing rule or blanket accept in
one doesn't imply the same in the other.

Inspect the rules directly too:

```bash
sudo iptables -S INPUT     # look for any accept for the protected port that is not MFA_Temp_*
sudo ip6tables -S INPUT    # same check for IPv6
ip route get 8.8.8.8       # confirms which interface is internet-facing
```
```powershell
Get-NetFirewallRule -Enabled True -Direction Inbound |
  Where-Object { $_.Name -notlike 'MFA_Temp_*' } |
  Where-Object { ($_ | Get-NetFirewallPortFilter).LocalPort -contains '51820' }
```

If you deliberately keep a standing allow while testing — a reasonable thing to do so you don't
lock yourself out mid-install — write yourself a note to remove it. Until you do, the gate is
inert.

---

## Upgrading

> **Do the upgrade over a connection that does not depend on this gate.**
>
> A console session, a LAN address, out-of-band management, or any second path you keep for
> exactly this reason. Not a session whose port was opened by MFA Firewall Knocker.
>
> The reason is circular dependency: if an upgrade leaves MFAWeb or MFAService unable to start or
> unable to talk to each other, then nobody can open a port — including you, and the port you
> would need is the one you are trying to fix. Grants already issued expire on their own schedule,
> so a working session is a deadline, not a safety net. This is the same argument as
> [*Do not make this your only way in*](README.md#do-not-make-this-your-only-way-in), applied to
> the one moment when the gate is most likely to break.

Then:

1. **Back up first** — `users.dat` and the whole install directory. Rollback is putting the old
   directory back, so it is worth having.

   ```powershell
   # Windows
   robocopy "C:\Program Files\FirewallKnocker" "C:\Backups\FirewallKnocker\<date>" /E
   copy C:\ProgramData\MFAAuth\users.dat C:\Backups\FirewallKnocker\<date>\
   ```
   ```bash
   # Linux
   (
   set -eu
   # Stop database writers before taking a consistent application/config snapshot.
   # Existing firewall grants remain until the service is running and sweeping again.
   sudo systemctl stop mfa-web mfa-service
   backup=/var/backups/mfa-$(date -u +%Y%m%dT%H%M%SZ)
   sudo install -d -o root -g root -m 700 "$backup"
   sudo cp -a /opt/mfa-service /opt/mfa-web /opt/mfa-admin /etc/mfa-auth "$backup/"
   sudo cp -a /etc/systemd/system/mfa-service.service /etc/systemd/system/mfa-web.service "$backup/"
   if sudo test -f /etc/letsencrypt/renewal-hooks/deploy/10-mfaweb-certificate.sh; then
       sudo cp -a /etc/letsencrypt/renewal-hooks/deploy/10-mfaweb-certificate.sh "$backup/"
   fi
   printf 'Backup: %s\n' "$backup"
   )
   ```

2. **Keep your `appsettings.json`.** Release archives ship only `appsettings.example.json`, so
   copy your existing config into the new directory rather than re-deriving it.

3. **If upgrading from 0.3.0 or earlier, check `RulePrefix` first.** It may now contain only
   letters, digits, space, `_`, `.` and `-`, at most 64 characters. MFAService refuses to start
   with any other value, and MFAAdmin refuses to run. If yours has other characters, change it in
   both MFAService's config (`BouncerConfig:RulePrefix`) and MFAAdmin's (`RulePrefix`) before
   upgrading, then remove any rules still open under the old prefix by hand; the new prefix will
   not match them. The default `MFA_Temp_` is unaffected.

4. **If upgrading from 0.3.0 or earlier, tighten the log directory.** MFAWeb's service account
   previously had Modify on the whole log directory, which let it delete MFAService's logs too.
   Replace that with create-only access plus rights on its own files, then grant it its existing
   files explicitly, since those were covered only by the grant being removed:

   ```powershell
   # Windows
   $logs = "C:\ProgramData\MFAAuth\Logs"
   icacls $logs /remove:g 'YOURDOMAIN\MFA_Service$'
   icacls $logs /grant 'YOURDOMAIN\MFA_Service$:(RX,WD)' /grant 'CREATOR OWNER:(OI)(IO)M'
   Get-ChildItem $logs -Filter 'mfaweb_*.log' | ForEach-Object {
       icacls $_.FullName /grant 'YOURDOMAIN\MFA_Service$:M' | Out-Null
   }
   ```
   ```bash
   # Linux: the sticky bit limits deletion to each file's owner
   sudo chmod 3770 /var/log/mfa-auth
   ```

5. **Linux, if upgrading from 0.3.0 or earlier: let MFAService open network connections.** The
   earlier `mfa-service.service` had `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, which blocks
   the SMTP connection for certificate-expiry and IPC alerts, so those were never sent. Updating
   the binaries does not change the unit; edit it:

   ```bash
   sudo sed -i 's/^RestrictAddressFamilies=AF_UNIX AF_NETLINK$/RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6/' \
       /etc/systemd/system/mfa-service.service
   sudo systemctl daemon-reload
   systemctl show mfa-service -p RestrictAddressFamilies   # should list AF_INET and AF_INET6
   ```

6. **If upgrading from before 0.2.0, add `FirewallService:GmsaAccount` to MFAService's config.**
   The IPC identity check added in that release (see the next step) rejects every client —
   including a correctly upgraded MFAWeb — until this is set, because an older config simply
   doesn't have the key (see `FirewallService:GmsaAccount` under MFAWeb's configuration reference
   above — the same value belongs in MFAService's own config). On Windows this is the gMSA account
   MFAWeb runs as; on Linux it's the local account MFAWeb runs as (`mfaweb` in this guide's
   example). Restart MFAService after adding it and confirm the log line
   `[IPC] Peer verification enabled: only uid <n> ('mfaweb') may connect.` (Linux) or
   `[IPC] Claiming pipe name for gMSA '<name>'...` (Windows, `Debug` log level) before moving on.

7. **Upgrade MFAService before MFAWeb.** From 0.2.0 the client verifies the privileged service's
   identity before sending anything, so a newer MFAWeb against an older MFAService is the
   combination most likely to fail. The reverse order is safe.

8. **Deploy all three components together** when the release changes `users.dat`'s schema — they
   share it. Release notes say when that applies.

9. **Verify before you disconnect**, while you still have the independent path open:
   - both services are running, and the logs show the expected version at startup
   - MFAWeb serves HTTPS and selects a certificate
   - **a real passkey login opens a rule** — this is the only test that exercises the whole
     chain, including the IPC identity check added in 0.2.0
   - the rule disappears at expiry (or shorten `ExpirationHours` temporarily to watch it)

10. **If it fails**, stop both services, restore the backed-up directory, and start them again —
   privileged service first.

   On Linux, first move the failed installation directories aside under distinct names. Restore
   each snapshot directory to its now-absent original path (`mfa-service`, `mfa-web`, and
   `mfa-admin` under `/opt`; `mfa-auth` under `/etc`), preserving ownership and modes with `cp -a`.
   Do not overlay the old release onto new files. Restore the two unit files and, if backed up,
   the certificate hook to the paths above, run `sudo systemctl daemon-reload`,
   then `sudo systemctl start mfa-service mfa-web`. Do not run MFAAdmin or a certificate deployment
   concurrently with backup/restore. Keep the root-only backup permissions: it contains private keys,
   account data, and configuration secrets.

---

## Security Notes

- **`DpapiEntropy`** is a deployment-specific value mixed into the DPAPI key derivation
  on Windows. It prevents other processes on the same machine from reading the database
  without knowing this value. Keep it consistent across all three components and don't
  use the default or a publicly known value. On Linux it is unused for encryption (the
  database is plain JSON) but is still validated at startup — a missing value will
  prevent the service from starting.
- The user database contains **TOTP secrets** (not hashed) when TOTP is compiled in. A
  compromised database file allows an attacker to generate valid TOTP codes for every
  enrolled user. Protect the file with filesystem permissions as documented above.
  Passkey credentials stored in the database are public keys, not private keys — but the
  database is not "not sensitive" even without TOTP: it holds usernames, the current
  enrollment password hash of every account, and, during an active enrollment or
  reprovisioning window, a short-lived registration token. In the default passkey-only
  build that password hash is one-time — burned on successful registration or once its
  window expires unused. **In a TOTP-enabled build, once an account confirms TOTP, the
  same hash becomes that account's ongoing login credential** and is no longer burned by
  either path. See SECURITY.md's "A note on the user database" for the full breakdown.
- MFAWeb **only accepts authentication requests from public (internet) IP addresses**.
  Requests from private (RFC 1918), CGNAT, loopback and link-local ranges are rejected (HTTP 403
  on the login page). This prevents
  internal-only deployments from accidentally being used as a pivot point.
- Firewall rules opened by MFAService expire automatically after `ExpirationHours`.
  MFAService's sweeper runs every 5 minutes to remove expired rules.
