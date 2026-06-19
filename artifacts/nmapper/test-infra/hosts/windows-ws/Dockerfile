FROM alpine:3.19

RUN apk add --no-cache samba samba-client socat bash

RUN mkdir -p /shared /backup /finance && chmod 777 /shared /backup /finance

COPY smb.conf /etc/samba/smb.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 88 135 139 389 445 636 3268 3269 3389

CMD ["/start.sh"]
