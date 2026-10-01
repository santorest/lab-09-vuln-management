#!/bin/sh
set -e
ssh-keygen -A
/usr/sbin/sshd
exec /usr/sbin/vsftpd /etc/vsftpd.conf
