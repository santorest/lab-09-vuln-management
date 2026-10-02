#!/bin/sh
set -e
ssh-keygen -A
# The key is mounted from the runner (owned by the runner's uid); StrictModes needs a root-owned copy.
install -m 644 -o root -g root /run/keys/scan.pub /etc/ssh/authorized_keys/scan
# vsftpd runs in the background and is restarted if a probe crashes it; sshd is the main process, so a vsftpd crash
# can no longer stop the container (and silently empty the authenticated checks).
(while true; do /usr/sbin/vsftpd /etc/vsftpd.conf; echo "vsftpd exited ($?), restarting" >> /var/log/vsftpd-restarts.log; sleep 1; done) &
exec /usr/sbin/sshd -D -E /var/log/sshd.log
