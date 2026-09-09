# Authentication alert regression checks

With the .NET 10 SDK, run both modes from the repository root:

```sh
dotnet run --project tests/MFAWeb.AlertTests -c Release
dotnet run --project tests/MFAWeb.AlertTests -c Release -p:AllowTotp=true
```

The package-free runner starts a child MFAWeb process on an ephemeral IPv4 loopback HTTP
listener with synthetic accounts in a temporary database, synthetic provisioning tokens,
and email disabled. No successful HTTP authentication, IPC request, firewall operation, or
privileged service is exercised. The temporary child is stopped and its files removed.
Set `DOTNET_HOST_PATH` to the SDK's `dotnet` executable when using a task-local SDK.

Checks cover the actual failed-assertion and provisioning-password routes, one alert per
window, and exclusion of malformed requests, unknown credentials/accounts, missing
challenges, and provisioning-token guesses. The monitor's success/reset behavior is tested
directly without completing a route that would contact a real firewall service.
