#!/bin/bash
# Starts the real MFAService under the systemd unit documented in INSTALL.md and checks that it
# stays up and serves requests from inside that sandbox.
#
# Why: 0.4.1 passed every other check and still failed at startup on Linux, because the .NET
# runtime it shipped (10.0.14) moved its named-mutex files into the home directory, which the
# documented unit's ProtectHome=true hides. Only starting the service under that unit shows a
# failure like that.
#
# The unit is read from INSTALL.md itself, so the documented unit is what gets tested.
#
# Usage, from the repository root, as root (CI runs it with sudo on a throwaway runner):
#   tests/linux-service-smoke.sh <MFAService linux-x64 publish directory>
# It creates the mfaweb account and mfaipc group, writes /opt/mfa-service, /etc/mfa-auth and
# /var/log/mfa-auth, installs and starts mfa-service.service, and adds one iptables rule for
# 203.0.113.10 (TEST-NET-3) and one ip6tables rule for 2001:db8::10 (documentation prefix).
# Do not run it on a machine you care about.
set -euo pipefail

publish_dir=${1:?usage: $0 <MFAService publish directory>}
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 2; }
[ -x "$publish_dir/MFAService" ] || { echo "no MFAService binary in $publish_dir" >&2; exit 2; }

fail() {
    echo "::error::$1"
    systemctl status mfa-service --no-pager || true
    journalctl -u mfa-service --no-pager -n 80 || true
    exit 1
}

# The MFAService unit block from INSTALL.md: the ```ini block after its "**MFAService**" heading.
awk '/^\*\*MFAService\*\* \(`\/etc\/systemd\/system\/mfa-service\.service`\):/ { found = 1; next }
     found && /^```ini$/ { inblock = 1; next }
     inblock && /^```$/  { exit }
     inblock             { print }' INSTALL.md > /etc/systemd/system/mfa-service.service
grep -qx 'ExecStart=/opt/mfa-service/MFAService' /etc/systemd/system/mfa-service.service \
    || fail "could not extract the MFAService unit from INSTALL.md"
grep -qx 'ProtectHome=true' /etc/systemd/system/mfa-service.service \
    || echo "note: the documented unit no longer sets ProtectHome=true"

# Accounts and directories as INSTALL.md sets them up.
getent group mfaipc >/dev/null || groupadd --system mfaipc
id mfaweb >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin mfaweb
usermod -aG mfaipc mfaweb
install -d -o root -g mfaweb -m 2750 /etc/mfa-auth
install -d -o root -g mfaipc -m 3770 /var/log/mfa-auth
echo '[]' > /etc/mfa-auth/users.json

rm -rf /opt/mfa-service
cp -r "$publish_dir" /opt/mfa-service
chown -R root:root /opt/mfa-service
python3 - <<'PY'
import json, re, secrets
src = open("MFAService/appsettings.example.json", encoding="utf-8").read()
cfg = json.loads(re.sub(r"^\s*//.*$", "", src, flags=re.M))
cfg["DpapiEntropy"] = secrets.token_urlsafe(32)
cfg["FirewallService"]["GmsaAccount"] = "mfaweb"
cfg["BouncerConfig"]["AllowedPorts"] = ["22/TCP"]
cfg["Smtp"]["Host"] = "localhost"
cfg["Smtp"]["UseSsl"] = False
json.dump(cfg, open("/opt/mfa-service/appsettings.json", "w"), indent=2)
PY
chmod 640 /opt/mfa-service/appsettings.json

systemctl daemon-reload
systemctl start mfa-service || fail "mfa-service failed to start"
sleep 8
[ "$(systemctl is-active mfa-service)" = active ] || fail "mfa-service is not running 8 s after start"
[ -S /run/mfafirewall.sock ] || fail "IPC socket /run/mfafirewall.sock was not created"

# Requests as the web account, the only uid MFAService accepts.
ipc() {
    sudo -u mfaweb python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(30)
s.connect("/run/mfafirewall.sock")
s.sendall(sys.argv[1].encode() + b"\n")
print(s.makefile().readline().strip())' "$1"
}

# A database request takes the cross-process database lock inside the sandbox.
reply=$(ipc 'DB:RENEW_PASSKEY_TOKEN|ci-smoke-unknown-token')
echo "database request -> $reply"
[ "$reply" = "ERROR: Token not found or expired" ] || fail "database request: unexpected reply '$reply'"

# A firewall grant runs iptables under the unit's capability bounding set.
reply=$(ipc '203.0.113.10|ci-smoke@example.com')
echo "firewall request -> $reply"
[ "$reply" = "SUCCESS" ] || fail "firewall request: unexpected reply '$reply'"
iptables -S INPUT | grep -q 'MFA_Temp_203.0.113.10_22_TCP' || fail "granted rule not found in iptables"

# The same for IPv6, which goes to ip6tables (2001:db8::/32 is the documentation prefix).
reply=$(ipc '2001:db8::10|ci-smoke@example.com')
echo "IPv6 firewall request -> $reply"
[ "$reply" = "SUCCESS" ] || fail "IPv6 firewall request: unexpected reply '$reply'"
ip6tables -S INPUT | grep -q 'MFA_Temp_2001:db8::10_22_TCP' || fail "granted rule not found in ip6tables"

[ "$(systemctl is-active mfa-service)" = active ] || fail "mfa-service stopped after handling requests"
systemctl stop mfa-service
echo "MFAService started and served requests under the documented systemd unit."
