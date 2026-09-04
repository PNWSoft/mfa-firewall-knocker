Run `dotnet run --project tests/MFAWeb.RegistrationTests -c Release` from the repository root.

This package-free regression executable invokes the production registration authorization
gate with two synthetic accounts and their ready provisioning tokens. It verifies that the
challenge's canonical account must match the token's account and retains the existing token
readiness and expiry rules. It starts no web service and performs no database or IPC writes.

The completion endpoint continues to remove the challenge before parsing attestation or
resolving the token. Rejections therefore consume that challenge as before. Full authenticator
ceremonies are outside this focused authorization regression.
