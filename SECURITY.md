# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Use GitHub's private vulnerability reporting on this repository: go to the **Security** tab →
**Report a vulnerability**. That creates a private advisory visible only to the maintainers.

<!-- If you would rather receive reports by email, replace the paragraph above with an
     address you are happy to publish. -->

Please include:

- What the issue is and which component is affected (MFAWeb, MFAService, or MFAAdmin)
- The impact — what an attacker gains, and what they need first (network position, an
  account, local access, an already-compromised MFAWeb, etc.)
- Steps to reproduce, or the reasoning if you have not built a proof of concept

A description of the impact and the preconditions is more useful than a working exploit.
Please don't test against a deployment you don't own.

You should get an acknowledgement within a few days. This is a small project, so please be
patient with the fix timeline; we'll keep you updated and credit you in the advisory unless
you'd rather not be.

## Threat model

This sets out what the design does and does not protect against. The boundary is not obvious,
and the limitations below are as much a part of the specification as the guarantees.

### The problem addressed: a credential that leaves the building

A WireGuard profile or a conventional file-backed SSH private key is a bearer credential:
possession of the file is the authentication test. OpenSSH FIDO credentials (`sk-ecdsa-*` and
`sk-ssh-ed25519-*`) are a material exception: since OpenSSH 8.2, the local key handle is unusable
without the security key, and deployments can also require touch or PIN verification. See the
[OpenSSH 8.2 release notes](https://www.openssh.com/txt/release-8.2).

Revocation is straightforward — remove the peer from the server, or the key from
`authorized_keys`. Every control available is post-incident: revoke, rotate, audit handshakes.
Each is a response, and each requires knowing that something happened.

Detection is the weak point. A copied file leaves the original working, so the usual indicators of
credential compromise do not appear: no failed login, no lockout, no loss of service for the
legitimate user.

Some signals exist. Conntrack records the flows, and two concurrent sessions from different
addresses on one peer key can be alerted on; some tools do this. Three limitations apply:

1. **It detects concurrent use, not theft.** The alert requires the attacker to be connected at
   the same time as the legitimate user, and the attacker controls when to connect. A stolen
   profile used while the owner is offline produces a single session indistinguishable from
   normal use.
2. **It is post-incident.** The alert follows the connection.
3. **Conntrack is not a security control.** It is kernel connection-tracking state and evicts
   entries under memory pressure by design, so its completeness degrades under load.

The interval between copy and discovery is therefore unbounded and may be indefinite. Remedies
that require discovery do not cover the case.

Worked example: a laptop is lost. The current response is to revoke the profile before whoever
finds it connects. If revocation loses that race, the holder is inside the perimeter, on the
internal network, holding that user's access. Revoking afterwards closes their route in; it does
not reverse anything done while they had it. The remedy arrives after the exposure and cannot
undo it.

**This is a pre-incident control.** A stolen file stops being usable when it is stolen rather than
when the theft is discovered, and no detection is required for that to hold. A lost laptop remains
a lost laptop: the holder cannot open the port.

#### What a stolen profile actually buys an attacker

Not everything, on a well-run network. SSH still wants its key; services still want their
credentials. The VPN is not the only control and should never be treated as one.

What it provides is position. The services behind the boundary are configured on the assumption
that only trusted parties can reach them.

That configuration is deliberate, not deficient. Security and usability trade against each other,
and a network hardened uniformly at every point becomes unusable — users spend their time
authenticating rather than working. Networks are therefore divided into zones, each given a
posture proportionate to its exposure. The arrangement is sound while the zone boundary holds.
Hypervisor management interfaces, NAS administration pages, databases bound to private addresses
and appliances no longer receiving firmware updates are not hardened for direct internet exposure,
and do not need to be while the boundary holds.

WireGuard is that boundary, which also makes it the most efficient place to require
authentication. One authentication at the boundary, valid for a working day, costs the user less
than equivalent friction applied to every service behind it.

#### Two gates that fail independently

This does not replace WireGuard's or SSH's authentication. It adds a second, independent one in
front: the two share no code, no protocol and no implementation.

**A remotely exploitable flaw in one is not a flaw in the other.** If such a flaw is found in
WireGuard or an SSH daemon, the port it would be reached through is closed to anyone who has not
completed a WebAuthn ceremony from that address. The flaw still requires patching, but during the
interval between disclosure and patch the vulnerable code is not reachable from the internet at
large — only by an address granted within the current expiry window.

The reverse case matters more, since this is one person's code and the component with the shorter
track record.

**This adds attack surface.** It is an internet-facing web application. The surface is narrow by
construction: a small number of routes, no user-supplied content rendered back, no database
engine, no file uploads, and a process that runs unprivileged, cannot write the user store and
cannot issue a firewall command.

Most outcomes of exploiting it leave the operator no worse off than not deploying it. Defeating
the gate opens a port to a service that still requires its own key — the position the operator
would have been in had the port been left open. The usual failure mode is loss of the protection
this adds, not loss of protection already in place.

The residual risk is the slice that reaches the host itself: remote code execution in the web
stack rather than a logic flaw in the gate. That category is real and should not be waved away.
But it is largely the generic risk of hosting *any* web application — the runtime, the TLS stack,
Kestrel — rather than anything specific to this code, and it is the reason MFAWeb runs
unprivileged and the privileged half re-validates every request instead of trusting it.

Netting it out: neither gate is redundant with the other, getting through the pair means two
unrelated failures lining up, and the price of that is one more small service to keep patched.

#### What happens if MFAService stops

Firewall rules are held by the firewall, not by this program. If MFAService is not running —
crashed, stopped, unable to claim its IPC endpoint, or never started — the current rule set does
not change:

- **The standing block remains.** Whatever denies the protected port by default is an
  operator-configured rule and is unaffected. The port stays closed.
- **No new access can be granted.** No one can authenticate while the service is down. This is the
  actual failure mode, and it is fail-closed.
- **Grants already open remain open past their expiry.** Expiry is enforced by the sweeper, not by
  the firewall: the `exp:` value is a comment the sweeper reads. With the sweeper stopped, an open
  rule persists until the service returns.

An outage therefore costs the ability to grant access and the timely removal of existing grants.
It does not open anything.

`MFAAdmin reset` removes every MFA-granted rule and does not require MFAService. It runs elevated
and issues the firewall commands directly — `Remove-NetFirewallRule` on Windows, `iptables -D` on
Linux — then re-reads the rule list and reports what remains rather than assuming the deletions
succeeded. This applies to emergency revocation generally, not only to outages. `MFAAdmin diag`
lists the rules without removing them.

`reset` is all-or-nothing; there is no per-user or per-rule revocation, so all users must
re-authenticate afterwards. To remove a single grant, delete that rule directly.

### Where the credential goes

Files leave. A laptop is lost or stolen. A backup or disk image ends up somewhere it shouldn't.
Malware copies `~/.ssh` or a `.conf` off the machine. Someone emails a profile to themselves to
work from home, or keeps it after leaving. A config gets committed to a repository. In every one
of those cases the credential is now in the world, working perfectly, and the usual remedy is to
rotate keys across the fleet and hope you were fast enough.

**Behind this gate, that file is inert on its own.** The port it would connect to does not exist
until someone completes a WebAuthn ceremony against a passkey that:

- **is managed by an authenticator rather than stored by this server** — stealing the server's
  user database does not reveal a private key. The configured `attestationPreference = None`
  does not prove secure hardware, device binding, or non-exportability; Apple, Google, Microsoft,
  and third-party providers may sync or back up passkeys according to their own policies.
- **requires authenticator-mediated user verification** — every assertion requests a biometric,
  device PIN, or equivalent local verification. This protects against simple device possession,
  while the authenticator provider's account-recovery and sync controls remain a trust boundary.
- **cannot be phished** — the assertion is bound to the origin, so a convincing fake site cannot
  harvest anything replayable.

So an attacker holding your profile has a key to a door that isn't there. They cannot open it
from their address, and no amount of possessing the file changes that. The credential's value
drops from "permanent access from anywhere" to nothing, without rotating a single key.

**It also removes standing exposure generally:** the port is closed by default, each grant covers
one source address, expires on its own, and is logged.

### The compromised endpoint

If an attacker is executing code on a machine that authenticates, they *are* that user — they
share the source address, so a door the user opens is open to them.

This is not a property of this design. A rooted endpoint defeats essentially every access control
ever built: VPNs, SSO, overlay networks, MFA of all kinds. Once the attacker is you, systems that
authenticate *you* have nothing left to check. Most provide exactly zero protection at that
point.

This provides a little more than zero, which is worth knowing but not worth overselling:

- With a plain profile, an attacker on your machine has access **continuously and indefinitely**.
  Here they have it only inside a window a human deliberately opened, from that one address.
- **Exfiltration still stops paying** — the copy they take off the machine is as useless to them
  as it is to anyone else.
- **Every window is logged**, so a grant the user did not perform, or one from an unfamiliar
  address, is a visible signal where a standing credential produces none.

Shortening `ExpirationHours` shortens how long a compromise rides a grant, traded against the
convenience of authenticating once a day. The real answer to a rooted endpoint is endpoint
security; no network gate can be one.

### A note on the user database

In the default passkey-only build, enrolled WebAuthn credentials are **public keys** and there is
no recoverable TOTP secret. The store still contains usernames and BCrypt password hashes. During
enrollment or reprovisioning it also contains short-lived passkey registration tokens and the
registration-ready state. A reader who can watch an active enrollment can race the legitimate
user after the password gate has made that token ready, so confidentiality still matters during
those windows.

Integrity is always critical: someone who can write the store can add their own passkey credential
and become that user. For an already-enrolled account with no active provisioning state, a read
does not reveal a credential that can produce a WebAuthn assertion, but it still discloses the user
list and password hashes.

The file permissions in INSTALL.md protect both properties. DPAPI encryption on Windows raises the
bar on reads, while filesystem permissions remain the primary boundary against unauthorized reads
and writes.

### Why TOTP changes this, and why it is off by default

Enable TOTP (`-p:AllowTotp=true`) and the calculus changes materially — not because of how this
project stores secrets, but because of how the protocol works.

TOTP verification computes `HMAC-SHA1(secret, timestep)` and compares it to the code the user
typed. The server must produce the same value the authenticator produced, so it must hold the
**shared secret in recoverable form**. There is no way around this: you cannot hash a TOTP secret
the way you hash a password, because a hash cannot generate codes. Encrypting the store — as
DPAPI does on Windows — protects against theft of the file alone, but the service must be able to
decrypt it to function, so the material remains recoverable to anything with sufficient access to
the host.

That produces a sharp asymmetry between the two build modes:

| | What the server stores | What a full database breach yields |
|---|---|---|
| Passkey-only | public keys, usernames, BCrypt password hashes, and any active enrollment state | account data, hashes, and usable enrollment tokens during their short validity window, but no private passkey key |
| **TOTP-enabled** | **all passkey-only data plus each TOTP secret** | **all of the above plus valid codes for every TOTP user until each secret is re-enrolled** |

A TOTP database breach is a mass-compromise event: every enrolled user's second factor becomes
forgeable at once, silently, and stays that way until every secret is re-enrolled. A passkey-only
database breach is still serious, but it does not disclose the private key needed to produce an
assertion for an already-enrolled credential.

This is the second independent reason TOTP is not compiled into the default build — the first
being that codes are phishable and replayable within their window. Neither is a criticism of TOTP
as a technology; it is a reasonable second factor where the alternative is a password alone. It
adds immediately usable shared authenticator secrets to a store that is already confidential and
integrity-sensitive.

If you do enable it, weigh it especially carefully on Linux, where the store is not encrypted at
rest.

### What it does not address

- **Anything behind the same public IP.** Rules are keyed on the source address, so every device
  sharing that NAT is inside the grant for its duration. At home that is your own devices; on an
  office, hotel, or café network it is not.
- **Per-connection authorisation.** Once a rule is open, the protocol behind the port applies its
  own authentication and nothing more. This gate is not consulted again until the rule expires.
- **Confidentiality or integrity of traffic.** No encryption of its own; that is entirely the job
  of whatever listens on the port.
- **A compromised host running the gate.** An attacker with root or LocalSystem there already
  owns the firewall and the user database.

## Scope

**In scope:** anything that lets someone open a firewall rule without completing
authentication, authenticate as another user, escalate from MFAWeb to MFAService, read or
modify `users.dat` without the required privileges, recover credentials from the database or
logs, or bypass the passkey-registration password gate.

**Out of scope** — these are documented design decisions, not oversights:

- **No per-account lockout.** Usernames are email addresses and therefore guessable, so
  lockout would be a trivial denial of service against any known user. Failed logins are
  detected and alerted on; per-IP rate limiting is the throttle.
- **Username enumeration** via response and timing differences. A direct consequence of the
  above: with no lockout and guessable usernames, hiding existence buys little.
- **A fully compromised MFAWeb.** MFAWeb performs the authentication, so compromising it is
  total within its trust scope. MFAService's independent re-validation bounds the blast
  radius (public IPs only, configured ports only, time-limited) rather than preventing it.
  Reports that assume arbitrary code execution as the MFAWeb service account are describing
  this known boundary.
- **TOTP code replay** within the code's validity window, when TOTP is explicitly enabled.
  This is inherent to TOTP and is why TOTP is not compiled into the default build.
- **Anything requiring Administrator or root** on the host. Those principals already own the
  database and the firewall.

## Supported versions

| Version | Security fixes |
|---------|----------------|
| Current `main` | Yes |
| Latest tagged release | Yes |
| Older tagged releases | No |

## Known issues

Tracked, understood, and not currently considered exploitable:

- **`Fido2` is pinned at 3.0.1.** Its dependency chain resolves `Microsoft.IdentityModel.*`
  to a version carrying GHSA-59j7-ghrg-fj52, so MFAWeb pins those transitives to 6.34.0 to
  lift the graph out of the vulnerable range. `dotnet list package --vulnerable` is clean;
  `--deprecated` reports the 6.x line as Legacy. The real fix is upgrading to Fido2 4.x,
  which needs the passkey ceremonies re-tested against real authenticators first.
- **The public-IP filter does not individually reject** multicast, reserved, broadcast, or
  TEST-NET ranges. None of these can be a live TCP source address, so there is no impact.
- **A local user can still deny service by holding the IPC pipe name** (Windows). Fixed in
  0.2.0 was the more serious half: a local, unprivileged user who pre-created
  `MFAFirewallPipe` before MFAService started used to receive MFAWeb's requests, which meant
  reading short-lived provisioning tokens *and* answering with forged responses — replying
  `SUCCESS` to a token-burn that never happened, for instance. MFAWeb now reads the pipe's
  owner SID before sending anything and refuses to transmit unless the endpoint is owned by
  LocalSystem or Administrators, neither of which an unprivileged process can claim. MFAService
  additionally claims the name with `FILE_FLAG_FIRST_PIPE_INSTANCE` and holds a pool of
  long-lived instances so the name is never released while it runs.
  What remains is availability: a squatter who wins the name during a restart window keeps
  MFAService from binding. That is unavoidable with a fixed pipe name and it now fails closed
  and loudly — the service logs an error, emails `Smtp:NotifyAddress` once, and retries with
  backoff until the name is free. Interception is closed even in that window.
- **This only adds allow rules; it never removes one.** If the protected port is reachable for
  some other reason — a standing allow rule, a blanket accept on the internet-facing interface, a
  permissive default policy, an upstream forward that bypasses the host's INPUT chain — then every
  grant is redundant and the gate protects nothing, while the logs, the UI and the rule list all
  look exactly as they would if it were working. There is no symptom, so it will not be noticed by
  accident. INSTALL.md has a "Verify the gate is actually gating" section; run it after install and
  after any firewall change.
- **On Linux the rule is created with `iptables`, so a client connecting over public IPv6 gets no
  rule.** Both sides accept a public IPv6 address as valid, and the user is shown ACCESS GRANTED,
  but the `iptables` call cannot create a v6 rule and the verification logs a failure. It fails
  closed — nothing is opened — but the report to the user is wrong. Until `ip6tables` support
  exists, publish an A record only, or disable the IPv6 listener on Linux deployments.
- **Email addresses with a quoted `|` in the local part cannot authenticate.** The IPC
  protocol is `|`-delimited and the privileged side rejects requests with the wrong field
  count, so such an address fails closed rather than open. Provisioning does not currently
  refuse these addresses at `add` time.
