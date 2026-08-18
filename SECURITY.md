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
