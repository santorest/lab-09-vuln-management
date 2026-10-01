#!/bin/sh
set -e
ssh-keygen -A
# The key is mounted from the runner (owned by the runner's uid); StrictModes needs a root-owned copy.
install -m 644 -o root -g root /run/keys/scan.pub /etc/ssh/authorized_keys/scan
/usr/sbin/sshd -E /var/log/sshd.log
mkdir -p /var/run/postgresql && chown postgres:postgres /var/run/postgresql
exec su postgres -c "/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main -c config_file=/etc/postgresql/15/main/postgresql.conf"
