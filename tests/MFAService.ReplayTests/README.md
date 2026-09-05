# TOTP replay regression checks

Run both build modes from the repository root with the .NET 10 SDK:

```sh
dotnet build MFA.slnx -c Release
dotnet run --project tests/MFAService.ReplayTests -c Release
dotnet build MFA.slnx -c Release -p:AllowTotp=true
dotnet run --project tests/MFAService.ReplayTests -c Release -p:AllowTotp=true
```

The runner calls the production replay-consumption logic with a temporary JSON store and a
mutex. It does not start the web application or privileged service, open an IPC listener, or
modify the firewall. It checks sequential and concurrent replay, persisted state after a
fresh reader, older time-steps, missing historical state, reprovisioning, failed persistence,
and preservation of the watermark through all three components' serialized user models.

Deploy all three components together: an older admin or service writer does not know about
the new `LastAcceptedTotpTimeStep` field and could discard it. Stop old TOTP-serving processes
and let the existing 90-second acceptance window elapse before enabling the updated binaries;
previously accepted codes cannot be reconstructed from a database without replay history.
A code consumed before a later firewall/IPC failure remains consumed; wait for a new code.
