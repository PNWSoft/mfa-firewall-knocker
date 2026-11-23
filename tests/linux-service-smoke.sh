#!/bin/bash
# Runs the real Linux build the way INSTALL.md deploys it and checks the paths only a deployment
# exercises:
#   - MFAService and MFAWeb start under the systemd units documented in INSTALL.md (read from
#     the file itself, so the documented units are what get tested);
#   - MFAAdmin provisions a user, and MFAWeb's passkey-setup flow calls MFAService over the Unix
#     socket (each side checking the other's identity);
#   - MFAService grants IPv4 and IPv6 access with iptables/ip6tables under its sandbox;
#   - MFAAdmin diag lists the grants with their user, delete removes that user's grants, and
#     reset clears the rest.
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
web["FirewallService"]["GmsaAccount"] = "mfaweb"
smtp(web)

adm = load("MFAAdmin/appsettings.example.json")
adm["AllowedDomains"] = ["example.com"]
adm["BouncerUrl"] = "https://localhost:8443"
adm["FirewallService"]["GmsaAccount"] = "mfaweb"
smtp(adm)

for path, cfg in (("/opt/mfa-service/appsettings.json", svc),
                  ("/opt/mfa-web/appsettings.json", web),
                  ("/opt/mfa-admin/appsettings.json", adm)):
    json.dump(cfg, open(path, "w"), indent=2)
PY
chmod 640 /opt/mfa-service/appsettings.json /opt/mfa-admin/appsettings.json
chown root:mfaweb /opt/mfa-web/appsettings.json
chmod 640 /opt/mfa-web/appsettings.json

# --- MFAService ----------------------------------------------------------------------------------
systemctl daemon-reload
systemctl start mfa-service || fail "mfa-service failed to start"
sleep 8
[ "$(systemctl is-active mfa-service)" = active ] || fail "mfa-service is not running 8 s after start"
[ -S /run/mfafirewall.sock ] || fail "IPC socket /run/mfafirewall.sock was not created"

ipc() {   # a raw request as the web account, the only uid MFAService accepts
    sudo -u mfaweb python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(30)
s.connect("/run/mfafirewall.sock")
s.sendall(sys.argv[1].encode() + b"\n")
print(s.makefile().readline().strip())' "$1"
}

reply=$(ipc 'DB:RENEW_PASSKEY_TOKEN|ci-smoke-unknown-token')
echo "database request -> $reply"
[ "$reply" = "ERROR: Token not found or expired" ] || fail "database request: unexpected reply '$reply'"

# --- MFAAdmin add: no mail relay, so it prints the password and passkey link --------------------
add_out=$(/opt/mfa-admin/MFAAdmin add "$USER_EMAIL" 2>&1) || fail "MFAAdmin add failed: $add_out"
password=$(sed -n 's/^Password: *//p' <<< "$add_out")
setup_url=$(sed -n 's/^Passkey Link: *//p' <<< "$add_out")
[ -n "$password" ] && [ -n "$setup_url" ] || fail "MFAAdmin add printed no credentials: $add_out"
echo "MFAAdmin add -> user created, setup link ${setup_url%/*}/<token>"

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
grant() {   # $1 = address; checks the reply and the rule
    local reply table
    reply=$(ipc "$1|$USER_EMAIL")
    echo "firewall request $1 -> $reply"
    [ "$reply" = "SUCCESS" ] || fail "firewall request for $1: unexpected reply '$reply'"
    case $1 in *:*) table=ip6tables ;; *) table=iptables ;; esac
    grep -q "MFA_Temp_$1_22_TCP user:$USER_EMAIL exp:" <<< "$($table -S INPUT)" \
        || fail "granted rule for $1 not found in $table"
}
mfa_rules() { grep -c 'MFA_Temp_' <<< "$(iptables -S INPUT; ip6tables -S INPUT)" || true; }

grant 203.0.113.10
grant 2001:db8::10

diag_out=$(/opt/mfa-admin/MFAAdmin diag 2>&1)
[ "$(grep -c "$USER_EMAIL" <<< "$diag_out")" -eq 2 ] || fail "MFAAdmin diag did not list both grants with their user: $diag_out"
echo "MFAAdmin diag -> both grants listed with their user"

del_out=$(/opt/mfa-admin/MFAAdmin delete "$USER_EMAIL" 2>&1)
grep -q '2 active firewall rule(s) for this user were also removed' <<< "$del_out" \
    || fail "MFAAdmin delete did not report removing the user's 2 rules: $del_out"
[ "$(mfa_rules)" -eq 0 ] || fail "rules remain after MFAAdmin delete"
echo "MFAAdmin delete -> user and both grants removed"

grant 203.0.113.10
grant 2001:db8::10
reset_out=$(echo Y | /opt/mfa-admin/MFAAdmin reset 2>&1)
grep -q 'Removed 2 MFA-managed iptables/ip6tables rule(s); chains verified clear' <<< "$reset_out" \
    || fail "MFAAdmin reset did not report clearing 2 rules: $reset_out"
[ "$(mfa_rules)" -eq 0 ] || fail "rules remain after MFAAdmin reset"
echo "MFAAdmin reset -> all grants removed"

for u in mfa-service mfa-web; do
    [ "$(systemctl is-active $u)" = active ] || fail "$u stopped during the test"
done
systemctl stop mfa-web mfa-service
echo "MFAService and MFAWeb ran under the documented systemd units; provisioning, IPC, grants, diag, delete and reset all worked."
