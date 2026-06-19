FROM alpine:3.19

RUN apk add --no-cache socat bash net-snmp

COPY start.sh /start.sh
RUN chmod +x /start.sh

# ICS ports: Modbus 502, S7comm 102, OPC-UA 4840, BACnet 47808
# Network: SNMP 161, Telnet 23
# VPN: OpenVPN 1194, L2TP 1701, PPTP 1723
# SmartTV: 7080, 1900
# Exposed: many ports
EXPOSE 21 22 23 80 102 161/udp 443 502 1194/udp 1701/udp 1723 1883 1900/udp 4840 7080 8080 8443 47808/udp 9200

CMD ["/start.sh"]
