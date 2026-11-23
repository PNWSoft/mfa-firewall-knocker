using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

// Compiled into MFAService and MFAAdmin (linked from each .csproj), so the service that writes
// grants and the tool that lists, revokes and resets them build and read rules identically.
internal static class LinuxIptables
{
    internal static readonly string[] Tables = { "iptables", "ip6tables" };

    // Wait up to this long for the xtables lock instead of failing at once when another program
    // (fail2ban, Docker, a configuration-management run) is changing the firewall at the same
    // moment. Without it a grant fails and the user has to sign in again.
    internal const string LockWaitSeconds = "5";

    // iptables stores a comment of at most 255 bytes.
    internal const int MaxCommentLength = 255;

    // The binary is run directly, never through a shell. Arguments go into ArgumentList one by
    // one, so nothing in them is ever parsed as shell syntax. Absolute paths, so PATH is not
    // consulted: /usr/sbin first (merged-/usr distributions), then /sbin.
    internal static ProcessStartInfo StartInfo(string table, IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo(BinaryPath(table));
        foreach (string arg in Arguments(args)) psi.ArgumentList.Add(arg);
        psi.CreateNoWindow         = true;
        psi.UseShellExecute        = false;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError  = true;
        return psi;
    }

    internal static IEnumerable<string> Arguments(IEnumerable<string> args)
        => new[] { "-w", LockWaitSeconds }.Concat(args);

    internal static string BinaryPath(string table)
    {
        if (Array.IndexOf(Tables, table) < 0)
            throw new ArgumentException($"Unknown firewall table '{table}'.", nameof(table));
        foreach (string dir in new[] { "/usr/sbin", "/sbin" })
        {
            string path = Path.Combine(dir, table);
            if (File.Exists(path)) return path;
        }
        throw new InvalidOperationException($"{table} was not found in /usr/sbin or /sbin.");
    }

    // The comment on a grant: "<rule name> user:<email> exp:<epoch>". The user tag sits before
    // exp: so a rule written by this version is still recognized and expired by an older one,
    // whose parser takes everything before " exp:" as the rule name. Rules written before the
    // tag existed have no user part; they are still parsed and expired, only not attributable.
    internal static string Comment(string ruleName, string username, long expEpoch)
        => $"{ruleName} user:{username} exp:{expEpoch}";

    private static readonly Regex CommentPattern =
        new(@"(?:^|\s)--comment ""(?<body>[^""]+) exp:(?<expiry>\d+)""(?:\s|$)", RegexOptions.Compiled);

    // The rule prefix allows letters, digits, space, '_', '.' and '-' only, and the rest of a
    // rule name is an address, port and protocol, so " user:" cannot occur inside a name.
    private static readonly Regex UserTagPattern =
        new(@"^(?<name>.+) user:(?<user>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+)\z", RegexOptions.Compiled);

    // Matches only rules this program wrote: an INPUT rule whose quoted comment has the expected
    // shape and whose rule name starts with the configured prefix. Never a substring of the line,
    // which could match an unrelated operator rule containing the same text.
    internal static bool TryParseManagedRule(string line, string rulePrefix,
                                             out string name, out long expiry, out string? user)
    {
        name = string.Empty;
        expiry = 0;
        user = null;
        if (!line.TrimStart().StartsWith("-A INPUT ", StringComparison.Ordinal)) return false;
        var match = CommentPattern.Match(line);
        if (!match.Success || !long.TryParse(match.Groups["expiry"].Value, out expiry)) return false;

        string body = match.Groups["body"].Value;
        var tagged = UserTagPattern.Match(body);
        if (tagged.Success)
        {
            body = tagged.Groups["name"].Value;
            user = tagged.Groups["user"].Value;
        }
        if (!body.StartsWith(rulePrefix, StringComparison.Ordinal)) return false;
        name = body;
        return true;
    }

    // Turns a line of '-S INPUT' output into the arguments that delete that exact rule: the same
    // rule specification with -D in place of -A. iptables prints an argument in double quotes
    // when it contains a space, escaping double quote, backslash and single quote with a
    // backslash (checked against iptables 1.8.10, legacy and nft).
    internal static string[] DeleteArguments(string line)
    {
        var args = SplitRuleLine(line.Trim());
        if (args.Count < 2 || args[0] != "-A" || args[1] != "INPUT")
            throw new InvalidOperationException("Not an INPUT rule line.");
        args[0] = "-D";
        return args.ToArray();
    }

    internal static List<string> SplitRuleLine(string line)
    {
        var args = new List<string>();
        var current = new StringBuilder();
        bool inQuotes = false, any = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (c == '\\' && i + 1 < line.Length && line[i + 1] is '"' or '\\' or '\'')
                    current.Append(line[++i]);
                else if (c == '"')
                    inQuotes = false;
                else
                    current.Append(c);
            }
            else if (c == '"')
            {
                inQuotes = true;
                any = true;
            }
            else if (c == ' ')
            {
                if (any) args.Add(current.ToString());
                current.Clear();
                any = false;
            }
            else
            {
                current.Append(c);
                any = true;
            }
        }
        if (inQuotes) throw new InvalidOperationException("Unterminated quote in rule line.");
        if (any) args.Add(current.ToString());
        return args;
    }
}
