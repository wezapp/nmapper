#!/bin/sh

BRAND=${PRINTER_BRAND:-HP}
MODEL=${PRINTER_MODEL:-LaserJet}
SERIAL=${PRINTER_SERIAL:-ABC123}

# Patch snmpd sysDescr
cat > /etc/snmp/snmpd.conf << EOF
rocommunity public default
sysdescr "${BRAND} ${MODEL} Firmware 20220101"
syslocation "Server Room"
syscontact "admin@corp.local"
agentaddress udp:161,tcp:161
view all included .1
access notConfigGroup "" any noauth exact all none none
EOF

# Start SNMP
snmpd -f -Lo -c /etc/snmp/snmpd.conf &

# LPD (515) — Line Printer Daemon
while true; do
    socat TCP4-LISTEN:515,reuseaddr EXEC:'printf "\x01printer\n"' 2>/dev/null || true
done &

# JetDirect raw printing (9100) — HP specific
while true; do
    socat TCP4-LISTEN:9100,reuseaddr EXEC:"printf '@PJL INFO ID\r\n${BRAND} ${MODEL}\r\n\x0c'" 2>/dev/null || true
done &

# IPP (631) — Internet Printing Protocol
while true; do
    socat TCP4-LISTEN:631,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nContent-Type: application/ipp\r\nServer: CUPS/2.3\r\n\r\n"' 2>/dev/null || true
done &

echo "Printer [${BRAND} ${MODEL}] started — SNMP:161, LPD:515, IPP:631, JetDirect:9100"
wait
