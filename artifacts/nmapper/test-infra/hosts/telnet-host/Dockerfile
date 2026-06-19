FROM alpine:3.19

RUN apk add --no-cache busybox-extras bash openssh-server socat shadow && \
    adduser -D -s /bin/sh admin && \
    echo "admin:admin123" | chpasswd && \
    adduser -D -s /bin/sh user1 && \
    echo "user1:user1" | chpasswd

# SSH config — accès par mot de passe
RUN ssh-keygen -A && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:toor" | chpasswd

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 22 23

CMD ["/start.sh"]
