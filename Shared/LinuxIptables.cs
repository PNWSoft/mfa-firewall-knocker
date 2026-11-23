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

    // Where grants go when no chain is configured.
    internal const string DefaultChain = "INPUT";

    // An iptables chain name: at most 28 characters. The first character may not be '-', or
    // the name would be read as an option. FORWARD and OUTPUT are refused: a grant there would
    // not open anything to the host and could open forwarding instead (see also ChainProblem).
    private static readonly Regex ChainPattern = new(@"^[A-Za-z0-9_][A-Za-z0-9_-]{0,27}\z", RegexOptions.Compiled);

    // The chain to write grants into: the configured name, or INPUT when the setting is absent
    // or empty. Returns null for a name that is not allowed.
    internal static string? ValidateChain(string? configured)
    {
        if (string.IsNullOrEmpty(configured)) return DefaultChain;
        if (!ChainPattern.IsMatch(configured) || configured is "FORWARD" or "OUTPUT") return null;
        return configured;
    }

    // Everything that reads grants back -- the sweeper, the upsert, MFAAdmin's diag, delete and
    // reset -- lists the whole filter table ('-S' with no chain) and finds this program's rules by
    // their comment, in whatever chain they are. So the chain setting decides only where new
    // grants are written: changing it, or MFAAdmin not knowing it, strands nothing.
    internal static readonly string[] ListAllArguments = { "-S" };

    // Why grants must not be written to `chain` in this '-S' listing of a whole table, or null.
    // The chain must exist, and FORWARD and OUTPUT must not reach it: through a jump from FORWARD
    // (DOCKER-USER, for instance) a grant would open forwarding to hosts behind this one.
    internal static string? ChainProblem(string listing, string chain)
    {
        if (chain == DefaultChain) return null;
        var graph = JumpGraph(listing, out var declared);
        if (!declared.Contains(chain))
            return $"chain '{chain}' does not exist; create it and a jump to it from INPUT";
        foreach (string start in new[] { "FORWARD", "OUTPUT" })
            if (Reaches(graph, start, chain))
                return $"chain '{chain}' is reachable from {start}, so a grant there could open more than this host";
        return null;
    }

    // True if INPUT reaches `chain` through jumps (directly or through other chains).
    internal static bool ReachableFromInput(string listing, string chain)
        => chain == DefaultChain || Reaches(JumpGraph(listing, out _), DefaultChain, chain);

    private static bool Reaches(Dictionary<string, HashSet<string>> graph, string start, string target)
    {
        var seen = new HashSet<string> { start };
        var queue = new Queue<string>(seen);
        while (queue.Count > 0)
            foreach (string next in graph.GetValueOrDefault(queue.Dequeue()) ?? new HashSet<string>())
            {
                if (next == target) return true;
                if (seen.Add(next)) queue.Enqueue(next);
            }
        return false;
    }

    // chain -> chains it jumps or goes to (-j / -g), and the user chains declared with -N.
    private static Dictionary<string, HashSet<string>> JumpGraph(string listing, out HashSet<string> declared)
    {
        var graph = new Dictionary<string, HashSet<string>>();
        declared = new HashSet<string>();
        foreach (string line in listing.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            List<string> args;
            try { args = SplitRuleLine(line.Trim()); } catch (InvalidOperationException) { continue; }
            if (args.Count == 2 && args[0] == "-N") { declared.Add(args[1]); continue; }
            if (args.Count < 2 || args[0] != "-A") continue;
            for (int i = 2; i + 1 < args.Count; i++)
                if (args[i] is "-j" or "-g" or "--jump" or "--goto")
                {
                    if (!graph.TryGetValue(args[1], out var targets)) graph[args[1]] = targets = new HashSet<string>();
                    targets.Add(args[i + 1]);
                }
        }
        return graph;
    }

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

    // Matches only rules this program wrote: a rule, in any chain, whose quoted comment has the
    // expected shape and whose rule name starts with the configured prefix. Never a substring of
    // the line, which could match an unrelated operator rule containing the same text.
    internal static bool TryParseManagedRule(string line, string rulePrefix,
                                             out string name, out long expiry, out string? user)
    {
        name = string.Empty;
        expiry = 0;
        user = null;
        if (!line.TrimStart().StartsWith("-A ", StringComparison.Ordinal)) return false;
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

    // Turns a line of '-S' output into the arguments that delete that exact rule from the chain
    // it is in: the same rule specification with -D in place of -A. iptables prints an argument
    // in double quotes when it contains a space, escaping double quote, backslash and single
    // quote with a backslash (checked against iptables 1.8.10, legacy and nft).
    internal static string[] DeleteArguments(string line)
    {
        var args = SplitRuleLine(line.Trim());
        if (args.Count < 2 || args[0] != "-A" || !ChainPattern.IsMatch(args[1]))
            throw new InvalidOperationException("Not a rule line.");
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
