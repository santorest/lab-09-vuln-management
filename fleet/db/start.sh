#!/bin/sh
set -e
ssh-keygen -A
/usr/sbin/sshd
mkdir -p /var/run/postgresql && chown postgres:postgres /var/run/postgresql
exec su postgres -c "/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main -c config_file=/etc/postgresql/15/main/postgresql.conf"
