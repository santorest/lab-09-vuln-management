#!/bin/sh
# Host keys are generated at start, so every container has its own.
set -e
ssh-keygen -A
/usr/sbin/sshd
exec nginx -g 'daemon off;'
