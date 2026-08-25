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

### The problem it exists to solve: a credential that leaves the building

A WireGuard profile or an SSH private key is a **bearer token**. Whoever holds the file is you —
from any address, at any hour, with no further test. That property is the whole reason these
credentials are worth stealing.

Revoking one is easy enough: pull the peer from the server, or drop the key out of
`authorized_keys`. But notice what every control here has in common — pulling a peer, rotating
keys, auditing handshakes are all **post-incident**. Each is a *response*, and each depends on
knowing there was something to respond to.

That is the gap this exists to close. A copied file leaves the original in place and working, so
the ordinary signs of a compromised credential never appear: no failed login, no lockout, nothing
that stops working for the legitimate user.

There are signals. Conntrack shows the flows, and two concurrent sessions from different
addresses on one peer key is a reasonable thing to alert on. Some tools are built on exactly that.

But look at what it detects: a **collision, not a theft**. It fires only if the attacker happens
to be connected at the same moment as the legitimate user — and the attacker chooses when to
connect. Someone who uses a stolen profile overnight, or simply checks that the owner is offline
first, produces one ordinary-looking session and trips nothing. That catches the careless and
misses anyone patient, which is the wrong way round for a control you would want to rely on.

Two further limits, even when it does fire. It is still post-incident: the alert arrives once the
attacker is already inside. And conntrack is kernel bookkeeping rather than a security control —
it evicts entries under memory pressure by design, so the evidence thins out exactly when the host
is busiest, and detection built on it depends on a facility documented to discard what it holds.

So the window between the copy and the discovery is unbounded, and frequently never closes at all
— which makes a set of remedies that only fire after discovery a weak defence against precisely
the case that matters.

Concretely: someone loses a laptop. Today that begins a race — revoke the profile before whoever
has it connects. Lose that race and they are inside the network holding that user's access:
reading file shares, copying whatever is reachable, planting something that outlives the
revocation. **Pulling the peer afterwards does not un-copy a file or remove an implant.** That is
what post-incident means in practice — the remedy arrives after the damage it was supposed to
prevent, and cannot reverse it.

**This is a pre-incident control.** The stolen file stops being useful the moment it is stolen,
not the moment somebody works out that it was — and nobody has to notice anything for that to
hold. A lost laptop becomes a lost laptop: whoever has it cannot open the port, so there is no
window to lose the race in.

#### What a stolen profile actually buys an attacker

Not everything, on a well-run network. SSH still wants its key; services still want their
credentials. The VPN is not the only control and should never be treated as one.

What it buys is **position** — and position is worth more than it sounds, because the rest of the
posture was designed on the assumption that only trusted parties could reach these services at
all.

Internal services are not weak in some absolute sense, and not weaker than they appear — they are
hardened **less than the internet-facing tier**, correctly and on purpose. Security and usability
trade against each other directly, and a network hardened to the maximum at every point is close
to unusable: users spend their day authenticating instead of working. So networks are split into
zones, each given a posture proportionate to what it holds and to who can reach it — and that
engineering is sound
right up until the zone boundary turns out not to be real. The hypervisor's management interface,
the NAS admin page, the database bound to a private address, the appliance that stopped receiving
firmware years ago: none of those are hardened for the open internet, and none of them need to be,
so long as the boundary holds.

WireGuard is that boundary. Which also makes it the highest-leverage place to spend a user's
patience: **one strong authentication at the gate, lasting a working day, buys more than the same
friction spread across every service inside — and costs the user far less.** That is the trade this
is built around.

#### Two gates that fail independently

This does not replace WireGuard's or SSH's authentication — it adds a second one in front, and the
two share no code, no protocol, and no implementation. That independence is worth something on its
own, separate from anything to do with stolen credentials.

**A zero-day in one is not a zero-day in the other.** If a remotely exploitable flaw turns up in
WireGuard or in an SSH daemon, the port it would be reached through is closed to anyone who has
not completed a WebAuthn ceremony from that address. The flaw is still there and still needs
patching, but the window between disclosure and patching is no longer a window in which the
internet at large can reach the vulnerable code. The exposure becomes "someone who already
authenticated with a passkey, from an address we granted, within the last few hours" — which is a
different problem from "anyone on the internet".

The other direction matters more, given this is one person's code and the component with the
shorter track record.

**This does add attack surface.** It is an internet-facing web application, and any claim that it
adds none would be false. What can fairly be said is that the surface is deliberately narrow: a
small number of routes, no user-supplied content rendered back, no database engine, no file
uploads, and a process that runs unprivileged, cannot write the user store, and cannot issue a
firewall command.

More to the point, **most of what an attacker gains by exploiting it leaves you no worse off than
not having deployed it at all**. Defeat the gate and you have opened a port — to a service that
still demands its own key, which is precisely the position you would have been in had the port
simply been left open. The usual failure mode is losing the protection this adds, not losing the
protection you already had.

The residual risk is the slice that reaches the host itself: remote code execution in the web
stack rather than a logic flaw in the gate. That category is real and should not be waved away.
But it is largely the generic risk of hosting *any* web application — the runtime, the TLS stack,
Kestrel — rather than anything specific to this code, and it is the reason MFAWeb runs
unprivileged and the privileged half re-validates every request instead of trusting it.

Netting it out: neither gate is redundant with the other, getting through the pair means two
unrelated failures lining up, and the price of that is one more small service to keep patched.

#### What happens if MFAService stops

Worth being precise, because the intuition tends to run the wrong way. Firewall rules live in the
firewall, not in this program. If MFAService is not running — crashed, stopped, blocked from its
IPC endpoint, or never started — **nothing about the current rule set changes**:

- **The standing block stays.** Whatever denies the protected port by default is a rule you
  configured; it is unaffected, so the port remains closed and unreachable. Protection is not lost.
- **No new access can be granted.** Nobody can authenticate their way in while the service is
  down. That is the actual failure, and it is fail-closed.
- **Grants already open stay open, past their expiry.** This is the part that surprises people.
  Expiry is not enforced by the firewall — the `exp:` value is a comment the sweeper reads. With
  the sweeper down, an open rule simply persists until the service returns and removes it.

So an outage costs you the ability to let people in, plus the timely removal of rules already
issued. It does not open anything.

If an outage runs long and an open grant concerns you, **`MFAAdmin reset` removes every
MFA-granted rule and does not need MFAService**. It runs elevated and issues the firewall commands
itself — `Remove-NetFirewallRule` on Windows, `iptables -D` on Linux — then re-reads the rule list
and tells you what is actually left rather than assuming the deletions worked. That makes it the
tool for exactly this situation, and for emergency revocation generally. `MFAAdmin diag` lists the
rules first if you want to look before removing.

It is all-or-nothing: there is no per-user or per-rule revocation, so everyone re-authenticates
afterwards. To drop a single grant, delete that one rule directly instead.

### Where the credential goes

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
