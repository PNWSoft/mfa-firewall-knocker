using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

// Compiled into MFAWeb (which picks the certificate to serve) and MFAService (whose expiry monitor
// must watch the same one). Both prefer a certificate whose chain builds to a root this machine
// trusts, for TLS server authentication. Without that, any matching certificate with a later
// expiry won -- a leftover self-signed or test certificate in LocalMachine\My would be served
// instead of the real one, and every browser would refuse it.
//
// When no matching certificate chains to a trusted root, the newest one is still used, with a
// warning: a deployment whose private CA root is trusted by its clients but not by the server
// itself keeps working as before.
internal static class CertTrust
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    // No revocation check and no download of missing intermediates (AIA): the selection runs on
    // the TLS path under a lock and the host may have no outbound HTTP. A certificate whose
    // intermediate is not in the local store therefore counts as untrusted. (Windows may still try
    // its own root update for an untrusted root; Cached keeps that to once per certificate an
    // hour.) ignoreTime is for the expiry monitor, which must still recognize an expired one.
    internal static bool ChainsToTrustedRoot(X509Certificate2 cert, bool ignoreTime = false)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthenticationOid));
            if (ignoreTime) chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
            return chain.Build(cert);
        }
        catch (CryptographicException) { return false; }
    }

    // ChainsToTrustedRoot, remembered per certificate for an hour, for MFAWeb's once-a-minute
    // refresh. An hour, not forever: a root or intermediate installed later is picked up.
    private static readonly Dictionary<string, (bool Trusted, DateTime CheckedUtc)> _trustCache = new();

    internal static bool ChainsToTrustedRootCached(X509Certificate2 cert)
    {
        lock (_trustCache)
        {
            if (_trustCache.TryGetValue(cert.Thumbprint, out var hit) && DateTime.UtcNow - hit.CheckedUtc < TimeSpan.FromHours(1))
                return hit.Trusted;
        }
        bool trusted = ChainsToTrustedRoot(cert);
        lock (_trustCache)
        {
            if (_trustCache.Count > 256) _trustCache.Clear();
            _trustCache[cert.Thumbprint] = (trusted, DateTime.UtcNow);
        }
        return trusted;
    }

    // The latest-expiring trusted candidate, or else the latest-expiring candidate of any kind.
    internal static (X509Certificate2? Cert, bool Trusted) PickPreferred(
        IEnumerable<X509Certificate2> candidates, Func<X509Certificate2, bool> isTrusted)
    {
        X509Certificate2? fallback = null;
        foreach (var cert in candidates.OrderByDescending(c => c.NotAfter))
        {
            if (isTrusted(cert)) return (cert, true);
            fallback ??= cert;
        }
        return (fallback, false);
    }
}
