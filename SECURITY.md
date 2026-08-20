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

Worth being explicit about what this does and does not buy you, because the boundary is not
obvious and the honest version is still a good deal.

### The problem it exists to solve: a credential that leaves the building

A WireGuard profile or an SSH private key is a **bearer token**. Whoever holds the file is you —
from any address, at any hour, with no further test. That property is the whole reason these
credentials are worth stealing.

Revoking one is easy enough: pull the peer from the server, or drop the key out of
`authorized_keys`. But notice what every control here has in common — pulling a peer, rotating
keys, auditing handshakes are all **post-incident**. Each is a *response*, and each depends on
knowing there was something to respond to.

That is the gap this exists to close. A copied file leaves the original in place and working, so
there is no failed login, no second session, no symptom of any kind. The window between the copy
and the discovery is unbounded, and frequently it never closes at all — which makes a set of
remedies that only fire after discovery a weak defence against precisely the case that matters.

Concretely: someone loses a laptop. Today that begins a race — revoke the profile before whoever
finds it gets curious, then establish what, if anything, was reached in the meantime. The second
half is the expensive half, because it means proving a negative from whatever logs happen to
exist.

**This is a pre-incident control.** The stolen file stops being useful the moment it is stolen,
not the moment somebody works out that it was — and nobody has to notice anything for that to
hold. A lost laptop becomes a lost laptop: whoever has it cannot open the port, so there is no
race. And because every grant is recorded with who, where and when, the question of whether
anything actually happened is answerable rather than a matter of inference.

Files leave. A laptop is lost or stolen. A backup or disk image ends up somewhere it shouldn't.
Malware copies `~/.ssh` or a `.conf` off the machine. Someone emails a profile to themselves to
work from home, or keeps it after leaving. A config gets committed to a repository. In every one
of those cases the credential is now in the world, working perfectly, and the usual remedy is to
rotate keys across the fleet and hope you were fast enough.

**Behind this gate, that file is inert on its own.** The port it would connect to does not exist
until someone completes a WebAuthn ceremony against a passkey that:

- **cannot be copied** — the private key is generated in and confined to the device's secure
  hardware, and is non-exportable by design. Stealing files does not steal it.
- **cannot be used without the person** — user verification is required on every assertion, so a
  biometric or device PIN is needed each time, not just at enrolment.
- **cannot be phished** — the assertion is bound to the origin, so a convincing fake site cannot
  harvest anything replayable.

So an attacker holding your profile has a key to a door that isn't there. They cannot open it
from their address, and no amount of possessing the file changes that. The credential's value
drops from "permanent access from anywhere" to nothing, without rotating a single key.

That is the case this is built for, and it is the one that actually happens.

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

In the default passkey-only build the store holds no directly usable credential. WebAuthn
credentials are **public keys**, and because TOTP is not compiled in there is no shared secret to
write — so the file contains a user list, BCrypt password hashes, and public key material.

In that build, that makes **integrity, not confidentiality, the property worth defending**. Someone who can
*read* `users.dat` learns which addresses have accounts and obtains BCrypt hashes whose value is
limited: for an already-enrolled account the password cannot register a passkey, because
`AddPasskey` refuses any account that already has one. Someone who can *write* it simply adds
their own passkey credential and becomes that user.

The file permissions in INSTALL.md exist primarily for that second case. DPAPI encryption on
Windows raises the bar on reads as well, but it is not what stands between an attacker and an
account — the permissions are.

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

That produces a sharp asymmetry between the three credential types:

| | What the server stores | What a full database breach yields |
|---|---|---|
| Password | a one-way hash | hashes an attacker must still crack |
| **TOTP** | **the secret itself** | **valid codes for every user, immediately and indefinitely** |
| WebAuthn / passkey | a public key | public keys — nothing that can authenticate |

A TOTP database breach is a mass-compromise event: every enrolled user's second factor becomes
forgeable at once, silently, and stays that way until every secret is re-enrolled. A passkey
database breach is a user list.

This is the second independent reason TOTP is not compiled into the default build — the first
being that codes are phishable and replayable within their window. Neither is a criticism of TOTP
as a technology; it is a reasonable second factor where the alternative is a password alone. It
is simply a poor fit for a component whose stored state is otherwise worth nothing to an
attacker.

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

This project has not yet cut a tagged release. Until it does, only the current `main` branch
receives fixes.

## Known issues

Tracked, understood, and not currently considered exploitable:

- **`Fido2` is pinned at 3.0.1.** Its dependency chain resolves `Microsoft.IdentityModel.*`
  to a version carrying GHSA-59j7-ghrg-fj52, so MFAWeb pins those transitives to 6.34.0 to
  lift the graph out of the vulnerable range. `dotnet list package --vulnerable` is clean;
  `--deprecated` reports the 6.x line as Legacy. The real fix is upgrading to Fido2 4.x,
  which needs the passkey ceremonies re-tested against real authenticators first.
- **The public-IP filter does not individually reject** multicast, reserved, broadcast, or
  TEST-NET ranges. None of these can be a live TCP source address, so there is no impact.
- **The Windows named-pipe client does not verify the server's identity.** A local,
  unprivileged user who pre-creates the pipe name before MFAService starts could observe
  MFAWeb's IPC traffic (short-lived provisioning tokens, passkey public keys) or cause a
  denial of service. It cannot forge a firewall change or a database write — those require
  the real privileged service. Local access is otherwise out of scope, so this is tracked
  rather than fixed.
- **Email addresses with a quoted `|` in the local part cannot authenticate.** The IPC
  protocol is `|`-delimited and the privileged side rejects requests with the wrong field
  count, so such an address fails closed rather than open. Provisioning does not currently
  refuse these addresses at `add` time.
