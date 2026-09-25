// Copyright (c) 2026 Pacific Northwest Software, Inc.
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Compiled into MFAService, MFAWeb and MFAAdmin as a linked source file (see each .csproj), so
// all three apply exactly the same rule.

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Configuration;

// Whether an SMTP send may go without TLS. Provisioning emails carry a temporary password and
// setup links, so Smtp:UseSsl defaults to true and false is accepted only when the relay is on
// this machine, where the traffic never crosses a network. "On this machine" means localhost,
// a loopback address, or an IP literal assigned to one of this host's interfaces that is Up.
//
// Deliberately narrow:
// - Hostnames other than "localhost" are never resolved, so DNS cannot change the decision.
// - The check runs on every send, never cached: a local address stays local only while it is
//   assigned and its interface is Up. On Linux an address on a downed interface stays listed but
//   loses its local route, and a connection to it would leave by the default route.
// - Link-local (IPv6 and 169.254/16), zone IDs, unspecified, multicast and broadcast addresses
//   never qualify.
// There is no switch to relax this; an operator without a local relay configures TLS.
internal static class SmtpTransportPolicy
{
    internal static bool GetUseSsl(IConfiguration config, string host)
    {
        string? configured = config["Smtp:UseSsl"];
        if (string.IsNullOrWhiteSpace(configured)) return true;
        if (!bool.TryParse(configured, out bool useSsl))
            throw new InvalidOperationException($"Smtp:UseSsl value '{configured}' is not true or false.");
        if (useSsl) return true;

        string? reason = IsHostLocalRelay(host);
        if (reason != null)
            throw new InvalidOperationException(
                $"Smtp:UseSsl=false requires Smtp:Host to be localhost, a loopback address, or an IP address " +
                $"assigned to an interface on this machine that is Up; '{host}' is not ({reason}). " +
                "Hostnames are not resolved. Otherwise set Smtp:UseSsl to true.");
        return false;
    }

    // Returns null when the host is on this machine, otherwise a short reason.
    internal static string? IsHostLocalRelay(string host)
    {
        string candidate = host.Trim().TrimEnd('.');
        if (candidate.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return null;

        candidate = candidate.TrimStart('[').TrimEnd(']');
        if (candidate.Contains('%')) return "zone IDs are not accepted";
        if (!IPAddress.TryParse(candidate, out var address)) return "not an IP address";
        if (IPAddress.IsLoopback(address)) return null;

        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast)
            || address.IsIPv6LinkLocal || address.IsIPv6Multicast
            || (address.AddressFamily == AddressFamily.InterNetwork && IsIPv4LinkLocalOrMulticast(address)))
            return "link-local, multicast, broadcast and unspecified addresses do not qualify";

        NetworkInterface[] interfaces;
        try { interfaces = NetworkInterface.GetAllNetworkInterfaces(); }
        catch (Exception ex)
        {
            // Fails closed. On Linux, enumerating interfaces needs AF_NETLINK, which a systemd unit's
            // RestrictAddressFamilies may not allow.
            return $"this machine's interfaces could not be read: {ex.GetType().Name}; " +
                   "on Linux the service unit's RestrictAddressFamilies must include AF_NETLINK";
        }

        foreach (var nic in interfaces)
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
            {
                if (!unicast.Address.Equals(address)) continue;
                // Windows reports duplicate-address detection; a tentative or duplicate address is
                // not reliably this host's. Linux does not expose the property.
                if (OperatingSystem.IsWindows()
                    && unicast.DuplicateAddressDetectionState != DuplicateAddressDetectionState.Preferred)
                    continue;
                return null;
            }
        }
        return "not assigned to an interface on this machine that is Up";
    }

    private static bool IsIPv4LinkLocalOrMulticast(IPAddress address)
    {
        byte[] b = address.GetAddressBytes();
        return (b[0] == 169 && b[1] == 254) || b[0] >= 224;
    }
}
