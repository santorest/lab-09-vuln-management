#!/bin/sh
set -e
ssh-keygen -A
# The key is mounted from the runner (owned by the runner's uid); StrictModes needs a root-owned copy.
install -m 644 -o root -g root /run/keys/scan.pub /etc/ssh/authorized_keys/scan
/usr/sbin/sshd -E /var/log/sshd.log
exec /usr/sbin/vsftpd /etc/vsftpd.conf
