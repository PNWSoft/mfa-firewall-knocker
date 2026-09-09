using System.Diagnostics;

internal interface IFirewallCommands
{
    bool IsWindows { get; }
    string PowerShell(string script);
    string Bash(string script);
}

internal sealed class SystemFirewallCommands : IFirewallCommands
{
    public bool IsWindows => OperatingSystem.IsWindows();
    public string PowerShell(string script) => FirewallWorkerService.RunPowerShell(script);
    public string Bash(string script) => FirewallWorkerService.RunBash(script);
}

internal sealed record CommandOutput(string StandardOutput, string StandardError);

internal static class FirewallCommandRunner
{
    internal static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    // Read both streams concurrently: sequential ReadToEnd calls can deadlock when the child
    // fills stderr while the parent waits for stdout. The deadline covers stream draining too.
    internal static CommandOutput Run(ProcessStartInfo startInfo, TimeSpan? timeout = null)
        => RunAsync(startInfo, timeout ?? DefaultTimeout).GetAwaiter().GetResult();

    private static async Task<CommandOutput> RunAsync(ProcessStartInfo startInfo, TimeSpan timeout)
    {
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start {startInfo.FileName}.");
        using var deadline = new CancellationTokenSource(timeout);
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
        Task<string> stderr = process.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token))
                .WaitAsync(deadline.Token);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { /* already exited */ }
            catch (System.ComponentModel.Win32Exception ex)
            {
                throw new TimeoutException(
                    $"{startInfo.FileName} exceeded {timeout.TotalSeconds:0.###} seconds; could not terminate its process tree.", ex);
            }
            throw new TimeoutException($"{startInfo.FileName} exceeded {timeout.TotalSeconds:0.###} seconds.");
        }

        string output = (await stdout).Trim();
        string error = (await stderr).Trim();
        if (process.ExitCode != 0)
        {
            string detail = string.IsNullOrEmpty(error) ? output : error;
            if (detail.Length > 2048) detail = detail[..2048] + "...";
            throw new InvalidOperationException($"{startInfo.FileName} exited with code {process.ExitCode}: {detail}");
        }
        return new CommandOutput(output, error);
    }
}
