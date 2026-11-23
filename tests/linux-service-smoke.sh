#!/bin/bash
# Runs the real Linux build the way INSTALL.md deploys it and checks the paths only a deployment
# exercises:
#   - MFAService and MFAWeb start under the systemd units documented in INSTALL.md (read from
#     the file itself, so the documented units are what get tested);
#   - MFAAdmin provisions a user, and MFAWeb's passkey-setup flow calls MFAService over the Unix
#     socket (each side checking the other's identity);
#   - MFAService grants IPv4 and IPv6 access with iptables/ip6tables under its sandbox;
#   - MFAAdmin diag lists the grants with their user, delete removes that user's grants, and
#     reset clears the rest;
#   - with BouncerConfig:IptablesChain set, grants go into that chain; after the setting is
#     removed again, diag and reset (which do not know the setting) still find grants in both.
# No config carries DpapiEntropy, which Linux does not use.
#
# Why: 0.4.1 passed every other check and still failed at startup on Linux, because the .NET
# runtime it shipped (10.0.14) moved its named-mutex files into the home directory, which the
# documented unit's ProtectHome=true hides. Only starting the service under that unit shows a
# failure like that.
#
# Usage, from the repository root, as root (CI runs it with sudo on a throwaway runner):
#   tests/linux-service-smoke.sh <publish root containing MFAService/, MFAWeb/ and MFAAdmin/>
# It creates the mfaweb account and mfaipc group; writes /opt/mfa-service, /opt/mfa-web,
# /opt/mfa-admin, /etc/mfa-auth and /var/log/mfa-auth; installs and starts mfa-service and
# mfa-web; and adds and removes iptables/ip6tables rules for 203.0.113.10 (TEST-NET-3) and
# 2001:db8::10 (documentation prefix). Do not run it on a machine you care about.
set -euo pipefail

root_dir=${1:?usage: $0 <publish root with MFAService/, MFAWeb/, MFAAdmin/>}
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 2; }
for p in MFAService MFAWeb MFAAdmin; do
    [ -x "$root_dir/$p/$p" ] || { echo "no $p binary in $root_dir/$p" >&2; exit 2; }
done

USER_EMAIL=ci-smoke@example.com

fail() {
    echo "::error::$1"
    systemctl status mfa-service mfa-web --no-pager || true
    journalctl -u mfa-service -u mfa-web --no-pager -n 120 || true
    exit 1
}

unit_from_install_md() {   # $1 = heading name (MFAService / MFAWeb), $2 = unit file name
    awk -v h="**$1** (\`/etc/systemd/system/$2\`):" '
        $0 == h              { found = 1; next }
        found && /^```ini$/  { inblock = 1; next }
        inblock && /^```$/   { exit }
        inblock              { print }' INSTALL.md
}

# --- Units, accounts and directories as INSTALL.md sets them up -------------------------------
unit_from_install_md MFAService mfa-service.service > /etc/systemd/system/mfa-service.service
unit_from_install_md MFAWeb mfa-web.service > /etc/systemd/system/mfa-web.service
grep -qx 'ExecStart=/opt/mfa-service/MFAService' /etc/systemd/system/mfa-service.service \
    || fail "could not extract the MFAService unit from INSTALL.md"
grep -qx 'ExecStart=/opt/mfa-web/MFAWeb' /etc/systemd/system/mfa-web.service \
    || fail "could not extract the MFAWeb unit from INSTALL.md"
for u in mfa-service mfa-web; do
    grep -qx 'ProtectHome=true' /etc/systemd/system/$u.service \
        || echo "note: the documented $u unit no longer sets ProtectHome=true"
done

getent group mfaipc >/dev/null || groupadd --system mfaipc
id mfaweb >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin mfaweb
usermod -aG mfaipc mfaweb
install -d -o root -g mfaweb -m 2750 /etc/mfa-auth
install -d -o root -g mfaipc -m 3770 /var/log/mfa-auth
echo '[]' > /etc/mfa-auth/users.json

for p in MFAService MFAWeb MFAAdmin; do
    dest=/opt/mfa-$(echo $p | sed 's/^MFA//' | tr '[:upper:]' '[:lower:]')
    rm -rf "$dest"
    cp -r "$root_dir/$p" "$dest"
    chown -R root:root "$dest"
done

# A self-signed certificate where INSTALL.md's certbot hook puts the real one.
install -d -o root -g mfaweb -m 750 /etc/mfa-auth/tls/current
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 90 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost \
    -keyout /etc/mfa-auth/tls/current/privkey.pem -out /etc/mfa-auth/tls/current/fullchain.pem 2>/dev/null
chown root:mfaweb /etc/mfa-auth/tls/current/*.pem
chmod 640 /etc/mfa-auth/tls/current/*.pem

# --- Configuration: the example files, with test values ---------------------------------------
python3 - <<'PY'
import json, re

def load(path):
    src = open(path, encoding="utf-8").read()
    cfg = json.loads(re.sub(r"^\s*//.*$", "", src, flags=re.M))
    cfg.pop("DpapiEntropy", None)          # not used on Linux, so not required there
    return cfg

def smtp(cfg):                             # nothing listens on localhost:25, so sends fail fast
    cfg["Smtp"].update({"Host": "localhost", "Port": 25, "UseSsl": False})

svc = load("MFAService/appsettings.example.json")
svc["FirewallService"]["GmsaAccount"] = "mfaweb"
svc["BouncerConfig"]["AllowedPorts"] = ["22/TCP"]
smtp(svc)

web = load("MFAWeb/appsettings.example.json")
web["AppUrl"] = "https://localhost:8443"
web["AllowedDomains"] = ["example.com"]
web["Kestrel"]["Endpoints"]["Https"]["Certificate"] = {
    "Path": "/etc/mfa-auth/tls/current/fullchain.pem",
    "KeyPath": "/etc/mfa-auth/tls/current/privkey.pem"}
smtp(web)

adm = load("MFAAdmin/appsettings.example.json")
adm["AllowedDomains"] = ["example.com"]
adm["BouncerUrl"] = "https://localhost:8443"
smtp(adm)

for path, cfg in (("/opt/mfa-service/appsettings.json", svc),
                  ("/opt/mfa-web/appsettings.json", web),
                  ("/opt/mfa-admin/appsettings.json", adm)):
    json.dump(cfg, open(path, "w"), indent=2)
PY
chmod 600 /opt/mfa-service/appsettings.json /opt/mfa-admin/appsettings.json   # as INSTALL.md
chown root:mfaweb /opt/mfa-web/appsettings.json
chmod 640 /opt/mfa-web/appsettings.json

# --- What a compromised web account could plant in the shared log directory ----------------------
# Today's privileged logs, created first by mfaweb: MFAService's as a named pipe (opening it for
# writing would block, stalling every thread that logs, the sweeper included), MFAAdmin's as a
# regular file with forged lines that mfaweb keeps open. Neither may be used; both must be set
# aside and reported. (Symbolic and hard links are covered by the regression tests.)
today=$(date -u +%F)
rm -rf /var/log/mfa-auth/mfaservice_$today.log /var/log/mfa-auth/mfaadmin_$today.log /var/log/mfa-auth/untrusted-*
# And the log directory without its sticky bit, as an install that skipped an upgrade step has it.
# MFAService cannot change it under its sandbox (RestrictSUIDSGID), but must keep logging and report
# it; MFAAdmin, run as root outside the sandbox, repairs it.
chmod -t /var/log/mfa-auth
sudo -u mfaweb mkfifo /var/log/mfa-auth/mfaservice_$today.log
sudo -u mfaweb sh -c "echo '[forged] planted line' > /var/log/mfa-auth/mfaadmin_$today.log"
sudo -u mfaweb sh -c "exec 3>>/var/log/mfa-auth/mfaadmin_$today.log; sleep 600" &
holder=$!

# --- MFAService ----------------------------------------------------------------------------------
systemctl daemon-reload
systemctl start mfa-service || fail "mfa-service failed to start"
sleep 8
[ "$(systemctl is-active mfa-service)" = active ] || fail "mfa-service is not running 8 s after start"
[ -S /run/mfafirewall.sock ] || fail "IPC socket /run/mfafirewall.sock was not created"
# Before any MFAAdmin run: MFAService logged to a file of its own despite the non-sticky directory,
# and said so.
grep -q 'is not sticky' /var/log/mfa-auth/mfaservice_$today.log     || fail "MFAService did not log (or did not report the non-sticky log directory) before MFAAdmin ran"
# Owner-only, or the web account could hold the single-instance lock across a restart.
[ "$(stat -c %a /run/mfafirewall.lock)" = 600 ] || fail "/run/mfafirewall.lock is mode $(stat -c %a /run/mfafirewall.lock), not 600"

ipc() {   # a raw request as the web account, the only uid MFAService accepts
    sudo -u mfaweb python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(30)
s.connect("/run/mfafirewall.sock")
s.sendall(sys.argv[1].encode() + b"\n")
print(s.makefile().readline().strip())' "$1"
}

reply=$(ipc "DB:RENEW_PASSKEY_TOKEN|ci-smoke-unknown-token|$(printf %s guess | base64)")
echo "database request -> $reply"
[ "$reply" = "ERROR: Token not found or expired" ] || fail "database request: unexpected reply '$reply'"

# --- MFAAdmin add: no mail relay, so it prints the password and passkey link --------------------
add_out=$(/opt/mfa-admin/MFAAdmin add "$USER_EMAIL" 2>&1) || fail "MFAAdmin add failed: $add_out"
password=$(sed -n 's/^Password: *//p' <<< "$add_out")
setup_url=$(sed -n 's/^Passkey Link: *//p' <<< "$add_out")
[ -n "$password" ] && [ -n "$setup_url" ] || fail "MFAAdmin add printed no credentials: $add_out"
echo "MFAAdmin add -> user created, setup link ${setup_url%/*}/<token>"

# MFAService checks the enrolment password itself: the real token with a wrong password, as code
# running as the web account could send it, is refused, and the token stays usable.
reply=$(ipc "DB:RENEW_PASSKEY_TOKEN|${setup_url##*/}|$(printf %s wrong-password | base64)")
[ "$reply" = "ERROR: Invalid password" ] || fail "token renewal with a wrong password: unexpected reply '$reply'"
echo "token renewal with the wrong password -> refused by MFAService"

# --- MFAWeb ----------------------------------------------------------------------------------------
systemctl start mfa-web || fail "mfa-web failed to start"
sleep 8
[ "$(systemctl is-active mfa-web)" = active ] || fail "mfa-web is not running 8 s after start"

# MFAWeb refuses the login page to private and loopback clients, so connect from a public
# test address (TEST-NET-3) added to the loopback interface for the duration of the test.
CLIENT_IP=203.0.113.5
ip addr add $CLIENT_IP/32 dev lo 2>/dev/null || true
trap 'ip addr del $CLIENT_IP/32 dev lo 2>/dev/null || true' EXIT

# Login page, then the passkey-setup flow: the password POST makes MFAWeb ask MFAService to
# renew the token over the Unix socket, and only a successful renewal yields the register page.
python3 - "$setup_url" "$USER_EMAIL" "$password" "$CLIENT_IP" <<'PY' || fail "MFAWeb passkey-setup flow failed"
import http.client, http.cookiejar, re, ssl, sys, urllib.parse, urllib.request
setup_url, user, password, client_ip = sys.argv[1:]
base = f"https://{client_ip}:8443"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

class FromClientIp(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        kwargs["source_address"] = (client_ip, 0)
        super().__init__(*args, **kwargs)

class Handler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(FromClientIp, req, context=ctx)

opener = urllib.request.build_opener(Handler(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
r = opener.open(base + "/", timeout=30)
print("login page ->", r.status)
assert r.status == 200
page = opener.open(base + urllib.parse.urlsplit(setup_url).path, timeout=30).read().decode()
fields = dict(re.findall(r"<input type='hidden' name='([^']+)' value='([^']*)'", page))
assert "token" in fields and "username" in fields, "setup page has no form: " + page[:300]
fields["password"] = password
body = urllib.parse.urlencode(fields).encode()
done = opener.open(base + "/setup-passkey", data=body, timeout=30).read().decode()
assert "data-token='" in done, "no registration token in reply: " + done[:300]
print("passkey setup -> password accepted, MFAService renewed the token over IPC")
PY

# --- Grants, diag, delete, reset -----------------------------------------------------------------
CHAIN=INPUT
grant() {   # $1 = address; checks the reply and the rule (in $CHAIN)
    local reply table
    reply=$(ipc "$1|$USER_EMAIL")
    echo "firewall request $1 -> $reply"
    [ "$reply" = "SUCCESS" ] || fail "firewall request for $1: unexpected reply '$reply'"
    case $1 in *:*) table=ip6tables ;; *) table=iptables ;; esac
    grep -q "MFA_Temp_$1_22_TCP user:$USER_EMAIL exp:" <<< "$($table -S $CHAIN)" \
        || fail "granted rule for $1 not found in $table $CHAIN"
}
mfa_rules() { grep -c 'MFA_Temp_' <<< "$(iptables -S; ip6tables -S)" || true; }   # every chain

grant 203.0.113.10
grant 2001:db8::10

diag_out=$(/opt/mfa-admin/MFAAdmin diag 2>&1) || fail "MFAAdmin diag exited with status $?: $diag_out"
[ "$(grep -c "$USER_EMAIL" <<< "$diag_out")" -eq 2 ] || fail "MFAAdmin diag did not list both grants with their user: $diag_out"
echo "MFAAdmin diag -> both grants listed with their user"

del_out=$(/opt/mfa-admin/MFAAdmin delete "$USER_EMAIL" 2>&1) || fail "MFAAdmin delete exited with status $?: $del_out"
grep -q '2 active firewall rule(s) for this user were also removed' <<< "$del_out" \
    || fail "MFAAdmin delete did not report removing the user's 2 rules: $del_out"
[ "$(mfa_rules)" -eq 0 ] || fail "rules remain after MFAAdmin delete"
echo "MFAAdmin delete -> user and both grants removed"

# Running delete again retries the revocation: a grant that still carries the name is removed even
# though the account is gone, and with nothing left the command reports failure.
grant 203.0.113.11
del_out=$(/opt/mfa-admin/MFAAdmin delete "$USER_EMAIL" 2>&1) || fail "MFAAdmin delete (retry) exited with status $?: $del_out"
grep -q "is not in the database. 1 active firewall rule(s) for this user were also removed" <<< "$del_out" \
    || fail "MFAAdmin delete (retry) did not revoke the remaining grant: $del_out"
[ "$(mfa_rules)" -eq 0 ] || fail "rules remain after MFAAdmin delete (retry)"
rc=0; del_out=$(/opt/mfa-admin/MFAAdmin delete "$USER_EMAIL" 2>&1) || rc=$?
[ "$rc" -eq 1 ] || fail "MFAAdmin delete with nothing to delete exited with status $rc, not 1: $del_out"
echo "MFAAdmin delete again -> revoked a grant left for the deleted user; exit status 1 once nothing is left"

grant 203.0.113.10
grant 2001:db8::10
reset_out=$(echo Y | /opt/mfa-admin/MFAAdmin reset 2>&1) || fail "MFAAdmin reset exited with status $?: $reset_out"
grep -q 'Removed 2 MFA-managed iptables/ip6tables rule(s); chains verified clear' <<< "$reset_out" \
    || fail "MFAAdmin reset did not report clearing 2 rules: $reset_out"
[ "$(mfa_rules)" -eq 0 ] || fail "rules remain after MFAAdmin reset"
echo "MFAAdmin reset -> all grants removed"

# --- IptablesChain: grants in a chain of the operator's; readers find grants in any chain -------
grant 203.0.113.12                       # made before the switch, so it stays in INPUT
for t in iptables ip6tables; do $t -N MFA; $t -I INPUT 1 -j MFA; done
set_chain() {   # $1 = chain, or empty to remove the setting; then restart MFAService
    python3 - "$1" <<'PY'
import json, sys
path = "/opt/mfa-service/appsettings.json"
cfg = json.load(open(path))
cfg["BouncerConfig"].pop("IptablesChain", None)
if sys.argv[1]: cfg["BouncerConfig"]["IptablesChain"] = sys.argv[1]
json.dump(cfg, open(path, "w"), indent=2)
PY
    systemctl restart mfa-service; sleep 8
}
set_chain MFA
[ "$(systemctl is-active mfa-service)" = active ] || fail "mfa-service did not restart with IptablesChain set"
grep -q "New grants go into the 'MFA' chain" /var/log/mfa-auth/mfaservice_$today.log || fail "MFAService did not log the configured chain"
! grep -qE "does not jump to 'MFA'|chain 'MFA' does not exist|reachable from" /var/log/mfa-auth/mfaservice_$today.log \
    || fail "MFAService reported the MFA chain as missing or unlinked"
CHAIN=MFA
grant 203.0.113.13
grant 2001:db8::13
[ "$(grep -c MFA_Temp_ <<< "$(iptables -S INPUT; ip6tables -S INPUT)")" -eq 1 ] || fail "a grant made with IptablesChain set went into INPUT"
# Back to INPUT without a reset first: the grants in MFA are still found, listed and removed.
set_chain ""
[ "$(systemctl is-active mfa-service)" = active ] || fail "mfa-service did not restart without IptablesChain"
diag_out=$(/opt/mfa-admin/MFAAdmin diag 2>&1) || fail "MFAAdmin diag (chain) exited with status $?: $diag_out"
[ "$(grep -c "$USER_EMAIL" <<< "$diag_out")" -eq 3 ] || fail "MFAAdmin diag did not list the grants in MFA and INPUT: $diag_out"
reset_out=$(echo Y | /opt/mfa-admin/MFAAdmin reset 2>&1) || fail "MFAAdmin reset (chain) exited with status $?: $reset_out"
grep -q 'Removed 3 MFA-managed iptables/ip6tables rule(s); chains verified clear' <<< "$reset_out" \
    || fail "MFAAdmin reset did not clear the grants in MFA and INPUT: $reset_out"
[ "$(mfa_rules)" -eq 0 ] || fail "rules remain after MFAAdmin reset (chain)"
for t in iptables ip6tables; do $t -D INPUT -j MFA; $t -X MFA; done
echo "IptablesChain=MFA -> grants in MFA; with the setting removed again, diag listed both chains and reset cleared them"

for u in mfa-service mfa-web; do
    [ "$(systemctl is-active $u)" = active ] || fail "$u stopped during the test"
done

# The planted entries: each was set aside, the day's log is a fresh regular file owned by root
# that says what was found, and the forged line is not in it.
kill $holder 2>/dev/null || true; pkill -u mfaweb -x sleep 2>/dev/null || true
for f in mfaservice_$today.log mfaadmin_$today.log; do
    p=/var/log/mfa-auth/$f
    [ -f "$p" ] && [ ! -L "$p" ] || fail "$f is not a regular file"
    [ "$(stat -c %U "$p")" = root ] || fail "$f is owned by $(stat -c %U "$p")"
    # Owner only: readable by the group, the web account could lock it and stop every append.
    [ "$(stat -c %a "$p")" = 600 ] || fail "$f is mode $(stat -c %a "$p"), not 600"
    grep -q '\[SECURITY\] Log file:.*set aside' "$p" || fail "$f does not report the planted entry"
    ! grep -q 'forged' "$p" || fail "$f contains the planted content"
done
[ -p "$(ls -d /var/log/mfa-auth/untrusted-*-mfaservice_$today.log | head -1)" ] || fail "the planted pipe was not set aside"
grep -q 'forged' /var/log/mfa-auth/untrusted-*-mfaadmin_$today.log || fail "the planted file was not set aside"
[ "$(stat -c %a /var/log/mfa-auth)" = 3770 ] || fail "MFAAdmin did not restore the log directory's sticky bit (mode $(stat -c %a /var/log/mfa-auth))"
echo "planted log entries -> set aside and reported; fresh root-owned logs; MFAService kept logging in a non-sticky directory; MFAAdmin restored the sticky bit"
systemctl stop mfa-web mfa-service
echo "MFAService and MFAWeb ran under the documented systemd units; provisioning, IPC, grants, diag, delete and reset all worked, in INPUT and in a configured chain."
