FROM alpine:3.19

RUN apk add --no-cache vsftpd bash shadow && \
    adduser -D -s /bin/sh ftpuser && \
    echo "ftpuser:ftppass" | chpasswd && \
    mkdir -p /var/ftp/pub && \
    chmod 755 /var/ftp && \
    chown ftpuser:ftpuser /var/ftp/pub

# Ajouter quelques fichiers "intéressants" dans le FTP
RUN echo "Backup database dump 2024-01-15" > /var/ftp/pub/db_backup_jan.sql && \
    echo "admin:$apr1$xyz$hash" > /var/ftp/pub/passwd.txt && \
    echo "Server IP: 10.0.0.1, DB: 192.168.20.11" > /var/ftp/pub/config.txt

COPY vsftpd.conf /etc/vsftpd/vsftpd.conf

EXPOSE 21

CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]
