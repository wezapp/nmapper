#!/bin/sh

DEVICE_TYPE=${DEVICE_TYPE:-generic}

listen_port() {
    PORT="$1"
    BANNER="$2"
    while true; do
        socat TCP4-LISTEN:${PORT},reuseaddr EXEC:"printf '${BANNER}'" 2>/dev/null || true
    done &
}

listen_udp() {
    PORT="$1"
    BANNER="$2"
    while true; do
        socat UDP4-LISTEN:${PORT},reuseaddr EXEC:"printf '${BANNER}'" 2>/dev/null || true
    done &
}

case "$DEVICE_TYPE" in

  modbus)
    # Automate Modbus TCP — port CRITIQUE NMAPPER
    # Répond avec un Modbus Exception (function 0x90 = erreur)
    while true; do
        socat TCP4-LISTEN:502,reuseaddr EXEC:'printf "\x00\x01\x00\x00\x00\x03\x01\x90\x02"' 2>/dev/null || true
    done &
    # HTTP management
    while true; do
        socat TCP4-LISTEN:80,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nServer: Modicon M340\r\nContent-Type: text/html\r\n\r\n<html><h1>Schneider Electric - Modicon M340</h1></html>"' 2>/dev/null || true
    done &
    # SNMP
    cat > /tmp/snmpd.conf << EOF
rocommunity public default
sysdescr "Schneider Electric Modicon M340 Firmware 3.10"
agentaddress udp:161
view all included .1
access notConfigGroup "" any noauth exact all none none
EOF
    snmpd -f -Lo -c /tmp/snmpd.conf &
    echo "ICS Modbus PLC started — Modbus:502, HTTP:80, SNMP:161"
    ;;

  s7plc)
    # Automate Siemens S7 — port CRITIQUE NMAPPER (102)
    # S7comm TPKT/COTP connection response
    while true; do
        socat TCP4-LISTEN:102,reuseaddr EXEC:'printf "\x03\x00\x00\x16\x11\xd0\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a"' 2>/dev/null || true
    done &
    # HTTP management
    while true; do
        socat TCP4-LISTEN:80,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nServer: SIMATIC\r\nContent-Type: text/html\r\n\r\n<html><h1>Siemens SIMATIC S7-300</h1><p>CPU 315-2 PN/DP</p></html>"' 2>/dev/null || true
    done &
    echo "ICS Siemens S7 PLC started — S7comm:102, HTTP:80"
    ;;

  opcua)
    # OPC-UA Gateway — port CRITIQUE NMAPPER (4840)
    while true; do
        socat TCP4-LISTEN:4840,reuseaddr EXEC:'printf "OPC-UA Hello Message"' 2>/dev/null || true
    done &
    # HTTPS management
    while true; do
        socat TCP4-LISTEN:8080,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nServer: OPC-UA Gateway\r\nContent-Type: text/html\r\n\r\n<html><h1>OPC-UA Industrial Gateway</h1></html>"' 2>/dev/null || true
    done &
    echo "ICS OPC-UA Gateway started — OPC-UA:4840, HTTP:8080"
    ;;

  switch)
    # Switch manageable — SNMP community "public"
    cat > /tmp/snmpd.conf << EOF
rocommunity public default
rncommunity private default
sysdescr "Cisco Catalyst 2960 Series Switch - IOS 15.2(7)E5"
syslocation "Main Data Center Rack A"
syscontact "netadmin@corp.local"
agentaddress udp:161,tcp:161
view all included .1
access notConfigGroup "" any noauth exact all none none
EOF
    snmpd -f -Lo -c /tmp/snmpd.conf &
    # Telnet management (vulnérable — community string sniffable)
    while true; do
        socat TCP4-LISTEN:23,reuseaddr EXEC:'printf "\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f\r\nCisco IOS Software\r\nUser Access Verification\r\nUsername: "' 2>/dev/null || true
    done &
    echo "Switch started — SNMP:161, Telnet:23"
    ;;

  smarttv)
    # Smart TV — UPnP + HTTP management
    while true; do
        socat TCP4-LISTEN:7080,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nServer: Samsung SmartTV\r\nContent-Type: text/html\r\n\r\n<html><h1>Samsung Smart TV - Remote Management</h1></html>"' 2>/dev/null || true
    done &
    while true; do
        socat TCP4-LISTEN:8080,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nServer: Samsung SmartTV\r\nContent-Type: application/json\r\n\r\n{\"device\":\"Samsung QN90B\",\"model\":\"55inch\"}"' 2>/dev/null || true
    done &
    # UPnP (1900 UDP)
    while true; do
        socat UDP4-LISTEN:1900,reuseaddr EXEC:'printf "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:samsung-tv-2022::upnp:rootdevice\r\n"' 2>/dev/null || true
    done &
    echo "SmartTV started — HTTP:7080/8080, UPnP:1900"
    ;;

  vpn)
    # Passerelle VPN
    while true; do
        socat TCP4-LISTEN:1723,reuseaddr EXEC:'printf "\xff\x03\xc0\x21\x01\x01\x00\x14"' 2>/dev/null || true
    done &
    while true; do
        socat UDP4-LISTEN:1194,reuseaddr EXEC:'printf "OpenVPN"' 2>/dev/null || true
    done &
    while true; do
        socat UDP4-LISTEN:1701,reuseaddr EXEC:'printf "L2TP"' 2>/dev/null || true
    done &
    while true; do
        socat UDP4-LISTEN:500,reuseaddr EXEC:'printf "IKE"' 2>/dev/null || true
    done &
    while true; do
        socat TCP4-LISTEN:443,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nServer: FortiGate-60E\r\n\r\n"' 2>/dev/null || true
    done &
    echo "VPN Gateway started — PPTP:1723, OpenVPN:1194, L2TP:1701, ISAKMP:500"
    ;;

  exposed)
    # Hôte très exposé — déclenche la règle "8+ ports ouverts" de NMAPPER
    while true; do socat TCP4-LISTEN:21,reuseaddr EXEC:'printf "220 FTP Server\r\n"' 2>/dev/null || true; done &
    while true; do socat TCP4-LISTEN:22,reuseaddr EXEC:'printf "SSH-2.0-OpenSSH_7.4\r\n"' 2>/dev/null || true; done &
    while true; do socat TCP4-LISTEN:23,reuseaddr EXEC:'printf "login: "' 2>/dev/null || true; done &
    while true; do socat TCP4-LISTEN:80,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nServer: Apache/2.2.34\r\n\r\n"' 2>/dev/null || true; done &
    while true; do socat TCP4-LISTEN:443,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nServer: Apache/2.2.34\r\n\r\n"' 2>/dev/null || true; done &
    while true; do socat TCP4-LISTEN:3306,reuseaddr EXEC:'printf "\x4a\x00\x00\x00\x0a5.5.62-0ubuntu0.14\x00"' 2>/dev/null || true; done &
    while true; do socat TCP4-LISTEN:5900,reuseaddr EXEC:'printf "RFB 003.008\n"' 2>/dev/null || true; done &
    while true; do socat TCP4-LISTEN:6379,reuseaddr EXEC:'printf "+OK\r\n"' 2>/dev/null || true; done &
    while true; do socat TCP4-LISTEN:8080,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nServer: Tomcat/7.0\r\n\r\n"' 2>/dev/null || true; done &
    while true; do socat TCP4-LISTEN:8443,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\n\r\n"' 2>/dev/null || true; done &
    while true; do socat TCP4-LISTEN:9200,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"node-1\",\"version\":{\"number\":\"6.8.0\"}}"' 2>/dev/null || true; done &
    cat > /tmp/snmpd.conf << 'EOF'
rocommunity public default
sysdescr "Linux exposed-srv 3.10.0 x86_64"
agentaddress udp:161,tcp:161
view all included .1
access notConfigGroup "" any noauth exact all none none
EOF
    snmpd -f -Lo -c /tmp/snmpd.conf &
    echo "Exposed host started — 12 ports ouverts (FTP,SSH,Telnet,HTTP,HTTPS,MySQL,VNC,Redis,HTTP-alt,HTTPS-alt,ES,SNMP)"
    ;;

  *)
    # Generic
    while true; do socat TCP4-LISTEN:80,reuseaddr EXEC:'printf "HTTP/1.0 200 OK\r\n\r\nOK"' 2>/dev/null || true; done &
    echo "Generic device started — HTTP:80"
    ;;

esac

wait
