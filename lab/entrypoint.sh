#!/bin/sh
set -e

# Host keys for this run
mkdir -p /var/empty /run/sshd
addgroup -S sshd 2>/dev/null || true
adduser -S -D -H -h /var/empty -s /sbin/nologin -G sshd sshd 2>/dev/null || true
chmod 755 /var/empty
ssh-keygen -A

# --- Lab accounts -----------------------------------------------------------
# donor  : has a real $6$ (SHA-512) hash -> donates the salt to sshd
# victim : shadow field is exactly "*"   -> should be unable to log in at all
#
# (adduser leaves "!" which is NOT vulnerable; we overwrite it with "*".)
adduser -D -s /bin/sh donor  2>/dev/null || true
adduser -D -s /bin/sh victim 2>/dev/null || true

sed -i 's|^donor:[^:]*:|donor:$6$abcdefgh$OHEEfDgChDISDDynq62NwK2t7J.78bf5aWfxCxAPZ9uBExqyEx9UFOZ86Zq8mHzEII4eQdiRHJ8E5P/IDnM6w0:|' /etc/shadow
sed -i 's|^victim:[^:]*:|victim:*:|' /etc/shadow
chmod 600 /etc/shadow
chown root:root /etc/shadow

echo "=================================================================="
echo " sshd: $(/usr/sbin/sshd -V 2>&1 | head -1)"
echo " libc: $(ldd /usr/sbin/sshd | head -1 | awk '{print $1}')"
echo " PAM : $(ldd /usr/sbin/sshd | grep -c libpam || true) (0 = built without PAM)"
echo " shadow entries:"
grep -E '^(victim|donor):' /etc/shadow | cut -d: -f1,2 | cut -c1-30 | sed 's/^/   /'
echo "=================================================================="

exec /usr/sbin/sshd -D -e
