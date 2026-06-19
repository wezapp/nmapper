FROM alpine:3.19

RUN apk add --no-cache net-snmp socat bash curl

COPY snmpd.conf /etc/snmp/snmpd.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh

# LPD, IPP, JetDirect 9100, SNMP, HTTPS IPP
EXPOSE 515 631 9100 161/udp 443

CMD ["/start.sh"]
