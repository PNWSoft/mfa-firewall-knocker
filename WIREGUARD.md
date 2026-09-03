# Using this in front of WireGuard

WireGuard was the reason this project exists. Everything else it gates — SSH, RDP, FTP — came
later, once it was clear the mechanism wasn't specific to any one protocol. This page covers the
parts that are specific to WireGuard: exactly what problem it closes, how the two interact once
running, and a few WireGuard-specific behaviors worth knowing before you rely on it.

The general design, threat model and setup are in [README.md](README.md),
[SECURITY.md](SECURITY.md) and [INSTALL.md](INSTALL.md). This page assumes you've read the "Why
this exists" and "How this differs from Tailscale and similar products" sections of the README.

## The specific problem

A WireGuard config file is `[Interface]` + `[Peer]` — a private key and an endpoint. Whoever holds
that file *is* the peer, to the server, indefinitely, from any address. There's no password behind
it, no enrolment step it can fall back to proving, and no built-in way for the server to tell the
legitimate holder apart from a copy.

That's not a criticism of WireGuard — it's a VPN protocol, not an identity system, and it wasn't
trying to solve this. But it means the profile itself carries the entire access decision. Losing
the file — a synced backup, an unlocked laptop, a config emailed to yourself to set up on a second
machine — is losing the access, permanently, with no second factor to fall back on.

This project doesn't touch WireGuard's authentication at all. It adds a second, independent gate
in front of the port: closed by default, opened for one source IP after a WebAuthn passkey
ceremony, closed again automatically. A stolen `.conf` file is still useless from an address that
hasn't authenticated. The two gates share no code and no protocol — a flaw in one is not a flaw in
the other.

## What actually happens, in order

1. `wg-quick up` with a copied or legitimate profile does **nothing** until the port is open for
   your current IP. WireGuard doesn't respond to handshake packets in the meantime — the packets
   are simply dropped by the firewall before they reach it.
2. You authenticate to MFAWeb with your passkey. MFAService opens a rule scoped to
   `your-ip → wg-port/UDP` for `BouncerConfig:ExpirationHours` (clamped to 1-48; see INSTALL.md).
3. WireGuard now sees your handshake and the tunnel comes up exactly as it always would — this
   project is not in the data path and adds no latency or MTU overhead once the port is open.
4. When the rule expires, it's fully **removed** — `Remove-NetFirewallRule` on Windows,
   `iptables -D` on Linux — not disabled or narrowed. It is a plain allow rule matched on source IP
   and port; it carries no connection-tracking exception for the traffic it let through.

## What that means for a session in progress

Point 4 is worth being precise about, because "the rule expires" sounds like it might gracefully
degrade and it doesn't necessarily. WireGuard multiplexes its handshake and its data channel over
the same UDP port, and the rule this project manages doesn't distinguish between them — it's a
bare `port/protocol/source-IP` match, nothing more.

Whether an already-established tunnel keeps working for a little while past expiry depends on
**your own base firewall configuration**, not on this project:

- If your `INPUT` chain has no other rule permitting that traffic, removing the ACCEPT rule means
  the very next packet — handshake or data — is dropped. The tunnel dies close to immediately.
- If your base ruleset includes a general `-m state --state ESTABLISHED,RELATED -j ACCEPT` (a
  common hardening pattern, often placed above rules like this one), already-flowing WireGuard
  traffic can continue to match that broader rule even after this project's specific grant is gone,
  until conntrack forgets the flow or WireGuard needs to rekey with a fresh handshake.

Either way, **a new session cannot start once the rule is gone**, and this project makes no attempt
to detect or tear down an existing one — see "Revoking access does not end active sessions" in
SECURITY.md, which covers this at the protocol-agnostic level. If you need reliable, immediate
termination of a WireGuard session — not just closing the gate to new ones — you need your own
script that removes the peer or restarts the interface, run through your out-of-band access path.

## Roaming breaks differently than you're used to

WireGuard is well known for tolerating a client's address changing mid-session — switch from wifi
to LTE and the tunnel usually just keeps working, because the server updates the peer's endpoint to
whatever address the next valid handshake arrives from.

That still happens once the tunnel is up. But the firewall rule this project manages is scoped to
the IP address that authenticated, not to the WireGuard peer. If your address changes while the
gate's rule is only open for the old one, WireGuard's own roaming can't save you: the new address
hasn't passed a passkey ceremony, so the port is closed to it, and the handshake WireGuard would
otherwise send to re-establish the tunnel never arrives. **You will need to re-authenticate to
MFAWeb from the new address before the tunnel can pick back up.**

This is the direct trade for closing the "stolen profile" gap — vanilla WireGuard's forgiving
roaming and "anyone with the file connects from anywhere" are close to the same property. Keep
`ExpirationHours` generous enough to cover realistic session lengths, and expect to re-auth after a
genuine network change (not every NAT rebind — most home/office connections keep the same public
IP for a session), not on every packet loss blip.

## Config

Nothing WireGuard-specific to install — this project never sees your WireGuard keys, config, or
traffic. Point `BouncerConfig:AllowedPorts` at your WireGuard listen port and protocol:

```json
"BouncerConfig": {
  "AllowedPorts":      [ "51820/UDP" ],
  "ExpirationHours":   8,
  "RulePrefix":        "MFA_Temp_"
}
```

If you gate more than one service, list every port you want covered — `AllowedPorts` isn't
WireGuard-only:

```json
"AllowedPorts": [ "51820/UDP", "22/TCP" ]
```

One rule is opened per authenticated IP per port in `AllowedPorts` — gating both your WireGuard
port and SSH from the same login doesn't require two separate authentications.

## Why not just use WireGuard's own peer list as the control?

You could, in principle, pre-authorize a fixed set of peers and call it done — which is exactly
what plain WireGuard already gives you, and exactly the bearer-token problem this exists to close.
Narrowing `AllowedIPs` or maintaining a peer allowlist controls *which keys* can connect; it does
nothing about *whether the file matches the person holding it*. This project answers that second
question, at the cost of a small piece of infrastructure that isn't WireGuard's job to provide.

## IPv6 note

Known limitation, not specific to WireGuard: on Linux, rules are created with `iptables`, so a
client authenticating and connecting over public IPv6 gets no rule — the request appears to
succeed but the port never actually opens. If you run a dual-stack WireGuard listener on Linux,
either publish an A record only for the MFAWeb hostname or disable the IPv6 listener until
`ip6tables` support exists. See "Known issues" in SECURITY.md.
