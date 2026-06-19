#!/bin/sh

# SSH
/usr/sbin/sshd &

# Telnet (port CRITIQUE — déclenche alerte NMAPPER)
busybox telnetd -F -l /bin/sh -p 23 &

echo "Legacy host started — SSH:22, Telnet:23"
wait
