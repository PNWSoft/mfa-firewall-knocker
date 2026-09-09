// Run only the production registration authorization gate. Referencing MFAWeb does not
// execute its entry point, start a listener, access the user database, or contact IPC.
var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
var alice = Account("Alice@example.com", "alice-ready-token");
var bob = Account("Bob@example.com", "bob-ready-token");
var users = new[] { alice, bob };
int failures = 0;

Check("same canonical account with a ready token is accepted",
    PasskeyRegistrationAuthorization.IsAuthorized(alice.Username, ResolveToken("alice-ready-token"), now));
Check("Alice challenge cannot complete under Bob's ready token",
    !PasskeyRegistrationAuthorization.IsAuthorized(alice.Username, ResolveToken("bob-ready-token"), now));
Check("Bob challenge cannot complete under Alice's ready token",
    !PasskeyRegistrationAuthorization.IsAuthorized(bob.Username, ResolveToken("alice-ready-token"), now));
Check("case changes cannot change the canonical account binding",
    !PasskeyRegistrationAuthorization.IsAuthorized("alice@example.com", alice, now));
Check("a missing token account is rejected",
    !PasskeyRegistrationAuthorization.IsAuthorized(alice.Username, ResolveToken("missing"), now));

alice.PasskeyRegistrationReady = false;
Check("same-account token still requires the password-ready gate",
    !PasskeyRegistrationAuthorization.IsAuthorized(alice.Username, alice, now));
alice.PasskeyRegistrationReady = true;
alice.PasskeyProvisioningExpiresUtc = now.AddTicks(-1);
Check("expired same-account token is rejected",
    !PasskeyRegistrationAuthorization.IsAuthorized(alice.Username, alice, now));
alice.PasskeyProvisioningExpiresUtc = null;
Check("same-account token without expiry is rejected",
    !PasskeyRegistrationAuthorization.IsAuthorized(alice.Username, alice, now));
alice.PasskeyProvisioningExpiresUtc = now;
Check("existing inclusive token-expiry boundary is preserved",
    PasskeyRegistrationAuthorization.IsAuthorized(alice.Username, alice, now));

Console.WriteLine(failures == 0 ? "All 9 registration binding checks passed." : $"{failures} check(s) failed.");
return failures == 0 ? 0 : 1;

UserEntry Account(string username, string token) => new()
{
    Username = username,
    PasskeyProvisioningToken = token,
    PasskeyRegistrationReady = true,
    PasskeyProvisioningExpiresUtc = now.AddMinutes(5)
};
UserEntry? ResolveToken(string token) => users.SingleOrDefault(user => user.PasskeyProvisioningToken == token);
void Check(string name, bool passed)
{
    Console.WriteLine($"{(passed ? "PASS" : "FAIL")} {name}");
    if (!passed) failures++;
}
